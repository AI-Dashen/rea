#!/usr/bin/env python
"""REA Android Workbench v1.1 static analysis pipeline for APK, AAB and split sets."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

from android_container import ensure_target, inspect_target, materialize_apks_bundle
from android_signature import verify_target
from android_intelligence import build_android_intelligence
from evidence_contract import make_evidence, merge_evidence
from dynamic_evidence import load_dynamic_evidence
from android_resources import inspect_resources, zip_surface
from android_package_profile import build_profile
from runlog import BASE, JAVA, ROOT, run, sha

TASK = "b06dd042-8638-4a47-937d-8ae644a205b9"
JADX_JAR = ROOT / "run/rea-3a0be4d8/jadx-local/data/data/com.termux/files/usr/share/java/jadx-1.5.6-all.jar"
JOB_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def jadx_inputs(target: pathlib.Path, container: dict) -> list[pathlib.Path]:
    if container["kind"] == "SPLIT_SET":
        return [pathlib.Path(unit["path"]) for unit in container["units"]]
    if container["kind"] in {"APK", "AAB"}:
        return [target]
    raise ValueError("ANALYSIS_KIND_NOT_SUPPORTED")


def base_apk(container: dict) -> pathlib.Path | None:
    if container["kind"] == "APK":
        return pathlib.Path(container["units"][0]["path"])
    if container["kind"] == "SPLIT_SET":
        unit = next((item for item in container["units"] if item["role"] == "base"), None)
        return pathlib.Path(unit["path"]) if unit else None
    return None


def minimal_package(container: dict) -> dict:
    return {
        "package_name": "UNKNOWN_AAB",
        "manifest": {"text": ""},
        "analysis_semantics": container["analysis_semantics"],
    }


def profile_from_container(container: dict) -> dict:
    if container["kind"] == "APK":
        return build_profile(pathlib.Path(container["units"][0]["path"]))
    if container["kind"] == "SPLIT_SET":
        profiles = [build_profile(pathlib.Path(unit["path"])) for unit in container["units"]]
        native = []
        dex = []
        markers = []
        for unit, profile in zip(container["units"], profiles):
            label = pathlib.Path(unit["path"]).name
            native.extend({**item, "container": label} for item in profile["native_libraries"])
            dex.extend({**item, "container": label} for item in profile["dex"])
            markers.extend({**item, "container": label} for item in profile["packer_indicators"])
        if not native:
            summary = "NO_NATIVE_LIBRARIES"
        elif all(item["elf"]["valid"]
                 and item["elf"]["page_16k_load_alignment"] == "PASS"
                 and item["zip_16k_alignment"] in ("PASS", "NOT_APPLICABLE_COMPRESSED")
                 for item in native):
            summary = "PASS"
        else:
            summary = "FAIL_OR_REVIEW"
        return {
            "schema_version": 1, "sha256": None, "dex": dex, "multi_dex": len(dex) > 1,
            "native_libraries": native, "abis": sorted({item["abi"] for item in native}),
            "native_16k_summary": summary, "packer_indicators": markers,
            "packer_assessment": "HEURISTIC_ONLY" if markers else "NO_KNOWN_MARKER_FOUND",
            "analysis_semantics": "RECONSTRUCTED_LOGICAL_VIEW",
        }
    return {
        "sha256": container["units"][0]["sha256"],
        "dex": container["dex"],
        "native_libraries": [
            {
                **item,
                "zip_16k_alignment": "NOT_EVALUATED_IN_AAB",
                "elf": {"page_16k_load_alignment": "NOT_EVALUATED_IN_AAB"},
            }
            for item in container["native_libraries"]
        ],
        "native_16k_summary": "LOGICAL_VIEW_ONLY",
        "packer_indicators": [],
        "packer_assessment": "NOT_EVALUATED_IN_AAB",
    }


def choose_native(container: dict, preferred_member: str | None = None) -> tuple[pathlib.Path, str] | None:
    candidates = [item for item in container["native_libraries"] if item["abi"] == "arm64-v8a"]
    if not candidates:
        return None
    if preferred_member:
        matches = [
            item for item in candidates
            if item["path"] == preferred_member
            or pathlib.PurePosixPath(item["path"]).name == preferred_member
        ]
        if len(matches) != 1:
            raise ValueError("NATIVE_MEMBER_NOT_UNIQUE_OR_MISSING")
        selected = matches[0]
    else:
        selected = sorted(candidates, key=lambda item: (item["bytes"], item["path"]))[0]
    if container["kind"] in {"APK", "AAB"}:
        return pathlib.Path(container["units"][0]["path"]), selected["path"]
    unit = next(item for item in container["units"] if pathlib.Path(item["path"]).name == selected["container"])
    return pathlib.Path(unit["path"]), selected["path"]



def write_checkpoint(job: pathlib.Path, result: dict, phase: str) -> None:
    checkpoint = {
        "schema_version": 1,
        "pipeline": result["pipeline"],
        "phase": phase,
        "input": result["input"],
        "sha256": result.get("sha256"),
        "provider_status": result["provider_status"],
        "command_count": len(result["commands"]),
        "evidence_count": len(result["evidence"]),
    }
    path = job / "checkpoint.json"
    temporary = job / ".checkpoint.json.tmp"
    temporary.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n")
    os.replace(temporary, path)


def target_digest(target: pathlib.Path, container: dict) -> str:
    if target.is_file():
        return sha(target)
    import hashlib
    material = "\n".join(
        f"{pathlib.Path(unit['path']).name}\0{unit['sha256']}" for unit in container["units"]
    )
    return hashlib.sha256(material.encode()).hexdigest()


def analyze(target: pathlib.Path, job_name: str, with_native: bool, timeout: int,
            dynamic_evidence_path: str | None = None,
            native_member: str | None = None,
            native_symbol: str | None = None,
            native_address: str | None = None,
            native_string: str | None = None) -> dict:
    selectors = [native_symbol, native_address, native_string]
    if sum(value is not None for value in selectors) > 1:
        raise ValueError("NATIVE_SELECTOR_CONFLICT")
    if any(value is not None for value in selectors) and not with_native:
        raise ValueError("NATIVE_SELECTOR_REQUIRES_WITH_NATIVE")
    if not JOB_PATTERN.fullmatch(job_name):
        raise ValueError("INVALID_JOB")
    job = BASE / "jobs" / job_name
    if job.exists():
        raise ValueError("JOB_EXISTS")
    job.mkdir(parents=True)
    result = {
        "schema_version": 2,
        "pipeline": "rea-android-workbench-v1.1",
        "task_id": TASK,
        "status": "BLOCKED",
        "input": str(target.relative_to(ROOT)),
        "sha256": None,
        "static_only": True,
        "commands": [],
        "provider_status": {},
        "evidence": [],
        "limitations": [
            "Targets are statically inspected and never executed by this pipeline.",
            "Decompiled Java/C is approximate and is not original source.",
            "AAB and split results are reconstructed logical views, not proof of the installed device state.",
        ],
    }
    source_container = inspect_target(target)
    result["sha256"] = target_digest(target, source_container)
    analysis_target = target
    container = source_container
    if source_container["kind"] == "APKS":
        analysis_target = job / "apks-units"
        container = materialize_apks_bundle(target, analysis_target)
    result["container"] = container
    result["provider_status"]["container"] = "VERIFIED"
    write_checkpoint(job, result, "CONTAINER")
    signature = verify_target(analysis_target)
    result["signature"] = signature
    result["provider_status"]["signature"] = "VERIFIED" if signature["verified"] else "OBSERVED_NOT_VERIFIED"
    result["evidence"].append(make_evidence(
        provider="android-container", kind="package_container", fidelity="static_fact",
        locator={"target": result["input"], "kind": container["kind"]},
        summary=f"{container['kind']} container with {container['totals']['dex_count']} DEX and {container['totals']['native_count']} native libraries",
        digest=result["sha256"],
        metadata={"analysis_semantics": container["analysis_semantics"]},
    ))
    result["evidence"].append(make_evidence(
        provider="apksig", kind="package_signature", fidelity="static_fact",
        locator={"target": result["input"], "kind": container["kind"]},
        summary=signature["trust_statement"],
        digest=result["sha256"],
        confidence="HIGH",
    ))

    resource_apks = []
    if container["kind"] == "APK":
        resource_apks = [analysis_target]
    elif container["kind"] == "SPLIT_SET":
        resource_apks = [pathlib.Path(unit["path"]) for unit in container["units"]]
    if resource_apks:
        resources = inspect_resources(resource_apks, job, min(timeout, 120))
    else:
        resources = {
            "schema_version": 1, "provider": "android-resource-surface",
            "status": "VERIFIED", "units": [{
                "path": str(target), "aapt_status": "NOT_APPLICABLE_AAB",
                **zip_surface(target),
            }],
            "packages": [], "permissions": [], "commands": [],
            "limitations": ["AAB resource view is reconstructed from ZIP structure; aapt consumes APKs."],
        }
    result["resources"] = resources
    result["commands"].extend(resources["commands"])
    result["provider_status"]["resources"] = resources["status"]
    write_checkpoint(job, result, "RESOURCES")
    result["evidence"].append(make_evidence(
        provider="android-resource-surface", kind="resource_inventory", fidelity="static_fact",
        locator={"target": result["input"], "kind": container["kind"]},
        summary=f"Indexed {sum(unit['resource_entry_count'] for unit in resources['units'])} resource entries and {len(resources['permissions'])} permissions",
        digest=result["sha256"],
    ))

    package = minimal_package(container)
    apk = base_apk(container)
    if apk:
        provider_timeout = min(max(timeout, 30), 900)
        record = run(
            "rea-android",
            ["node", ROOT / "tools/rea/android-mcp.mjs", apk, str(provider_timeout * 1000)],
            job,
            provider_timeout + 30,
        )
        result["commands"].append(record)
        if record["exit_code"] == 0:
            try:
                payload = json.loads((ROOT / record["stdout"]).read_text())
                normalized = payload["package_evidence"]["normalized_result"]
                if normalized.get("class_count", 0) < 1:
                    raise ValueError("REA_ANDROID_EMPTY")
                result["rea_android"] = payload
                package = normalized
                result["provider_status"]["rea_android"] = "VERIFIED"
            except (KeyError, ValueError, json.JSONDecodeError):
                result["provider_status"]["rea_android"] = "FAILED"
                result["rea_android_error"] = "INVALID_OR_EMPTY_PROVIDER_RESULT"
        else:
            result["provider_status"]["rea_android"] = "FAILED"
            result["rea_android_error"] = "PROVIDER_EXIT_NONZERO"
    else:
        result["provider_status"]["rea_android"] = "NOT_APPLICABLE_AAB"
    write_checkpoint(job, result, "REA_ANDROID")

    sources = job / "jadx/sources"
    inputs = jadx_inputs(analysis_target, container)
    argv = [
        JAVA, "-Xmx768m", "-XX:ActiveProcessorCount=1",
        "-cp", JADX_JAR, "jadx.cli.JadxCLI", "-j", "1", "--no-res",
        "-d", job / "jadx", *inputs,
    ]
    record = run("jadx", argv, job, timeout)
    result["commands"].append(record)
    java_files = sorted(sources.rglob("*.java"))
    if not java_files:
        raise ValueError("JADX_EMPTY")
    result["decompiled_files"] = [
        {"path": str(path.relative_to(ROOT)), "sha256": sha(path), "bytes": path.stat().st_size}
        for path in java_files
    ]
    result["provider_status"]["jadx"] = "VERIFIED" if record["exit_code"] == 0 else "PARTIAL"
    write_checkpoint(job, result, "JADX")
    result["evidence"].append(make_evidence(
        provider="jadx", kind="decompiled_index", fidelity="decompiled_approx",
        locator={"target": result["input"], "output": str(sources.relative_to(ROOT))},
        summary=f"JADX produced {len(java_files)} approximate Java files",
        digest=sha(java_files[0]),
    ))

    profile = profile_from_container(container)
    result["package_profile"] = profile
    result["provider_status"]["package_profile"] = "VERIFIED"
    result["evidence"].append(make_evidence(
        provider="android-package-profile", kind="package_profile", fidelity="static_fact",
        locator={"target": result["input"], "profile": "dex-native-16k-packer"},
        summary=f"Native 16KiB assessment: {profile['native_16k_summary']}; packer: {profile['packer_assessment']}",
        digest=result["sha256"], confidence="HIGH",
    ))
    intelligence = build_android_intelligence(
        apk or analysis_target, sources, package, profile
    )
    result["android_intelligence"] = intelligence
    result["provider_status"]["evidence_graph"] = "VERIFIED"
    result["evidence"].append(make_evidence(
        provider="rea-intelligence", kind="evidence_graph", fidelity="heuristic",
        locator={"target": result["input"], "graph": "android_intelligence"},
        summary=f"{intelligence['verification']['graph_nodes']} nodes and {intelligence['verification']['graph_edges']} relations",
        digest=result["sha256"],
        confidence="MEDIUM",
    ))

    native_choice = choose_native(container, native_member) if with_native else None
    if native_choice:
        native_target, member = native_choice
        child_job = f"{job_name[:40]}-native"
        command = [
            sys.executable, ROOT / "tools/rea/ghidra-native-provider.py",
            "--task-id", TASK, "--input", native_target,
            "--member", member, "--job", child_job,
            "--timeout", str(min(max(timeout, 90), 600)),
        ]
        if native_symbol:
            command.extend(["--symbol", native_symbol])
        if native_address:
            command.extend(["--address", native_address])
        if native_string:
            command.extend(["--string", native_string])
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=min(max(timeout, 90), 630), check=False)
        result["native_provider_call"] = {
            "argv": [str(item) for item in command],
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
        if completed.returncode == 0:
            native_result_path = BASE / "native-jobs" / child_job / "result.json"
            native_result = json.loads(native_result_path.read_text())
            result["ghidra_native"] = native_result
            result["provider_status"]["ghidra_native"] = "VERIFIED"
            ev = native_result["evidence"]
            result["evidence"].append(make_evidence(
                provider="ghidra", kind="native_function", fidelity="disassembled",
                locator={"member": member, "function": ev["selected_function"], "entry": ev["selected_entry"]},
                summary=f"Ghidra disassembled and approximately decompiled {ev['selected_function']}",
                digest=native_result["native_sha256"],
            ))
        else:
            result["provider_status"]["ghidra_native"] = "FAILED"
    else:
        result["provider_status"]["ghidra_native"] = "NOT_REQUESTED_OR_NO_ARM64_LIBRARY"

    write_checkpoint(job, result, "NATIVE")

    if dynamic_evidence_path:
        dynamic_source, dynamic = load_dynamic_evidence(dynamic_evidence_path)
        result["dynamic_evidence"] = dynamic_source
        result["provider_status"]["dynamic_evidence"] = "VERIFIED"
        result["evidence"].extend(dynamic)
        result["static_only"] = False
    else:
        result["provider_status"]["dynamic_evidence"] = "NOT_PROVIDED"

    write_checkpoint(job, result, "DYNAMIC")
    result["evidence"] = merge_evidence([result["evidence"]])
    if target_digest(target, inspect_target(target)) != result["sha256"]:
        raise ValueError("INPUT_CHANGED")
    result["status"] = "VERIFIED" if not ({"FAILED", "PARTIAL"} & set(result["provider_status"].values())) else "PARTIAL"
    (job / "analysis.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    report = [
        "# REA Android Workbench v1.1 分析报告",
        f"结论：**{result['status']}**",
        f"目标：{result['input']}",
        f"容器：{container['kind']}（{container['analysis_semantics']}）",
        f"DEX：{container['totals']['dex_count']}；Native：{container['totals']['native_count']}",
        f"签名：{signature['trust_statement']}",
        f"Java近似反编译：{len(java_files)}个文件",
        f"证据：{len(result['evidence'])}项",
        "## Provider",
        *[f"- {name}: {state}" for name, state in sorted(result["provider_status"].items())],
        "## 边界",
        *[f"- {item}" for item in result["limitations"]],
    ]
    (job / "报告.md").write_text("\n\n".join(report) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--with-native", action="store_true")
    parser.add_argument("--native-member")
    parser.add_argument("--native-symbol")
    parser.add_argument("--native-address")
    parser.add_argument("--native-string")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--dynamic-evidence")
    args = parser.parse_args()
    if args.task_id != TASK:
        parser.error("TASK_MISMATCH")
    try:
        result = analyze(
            ensure_target(args.input), args.job, args.with_native, args.timeout,
            args.dynamic_evidence, args.native_member, args.native_symbol,
            args.native_address, args.native_string,
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({
        "status": result["status"],
        "analysis_json": str((BASE / "jobs" / args.job / "analysis.json").relative_to(ROOT)),
        "report": str((BASE / "jobs" / args.job / "报告.md").relative_to(ROOT)),
        "provider_status": result["provider_status"],
    }, ensure_ascii=False))
    return 0 if result["status"] == "VERIFIED" else 3


if __name__ == "__main__":
    raise SystemExit(main())
