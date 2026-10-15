#!/usr/bin/env python
"""Controlled Ghidra ARM64 native provider for authorized ELF or APK members."""
from __future__ import annotations

import argparse
import fcntl
import json
import pathlib
import re
import shutil
import zipfile

from android_container import ensure_target
from runlog import BASE, JAVA, ROOT, run, sha

TASK = "b06dd042-8638-4a47-937d-8ae644a205b9"
JOB_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MEMBER_PATTERN = re.compile(r"^(?:[A-Za-z0-9_.-]+/)?lib/[A-Za-z0-9_.-]+/[A-Za-z0-9_.+-]+\.so$")


def ghidra_root() -> pathlib.Path:
    record = json.loads((BASE / "c1/evidence/ghidra-install.json").read_text())
    root = (ROOT / record["root"]).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("GHIDRA_ROOT_INVALID")
    return root


def prepare_input(target: pathlib.Path, member: str | None, job_root: pathlib.Path) -> tuple[pathlib.Path, dict]:
    if target.is_dir():
        raise ValueError("NATIVE_TARGET_MUST_BE_FILE")
    head = target.read_bytes()[:4]
    if head == b"\x7fELF":
        if target.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("NATIVE_TARGET_TOO_LARGE")
        return target, {"source": "direct_elf", "member": None}
    if not zipfile.is_zipfile(target) or not member or not MEMBER_PATTERN.fullmatch(member):
        raise ValueError("APK_NATIVE_MEMBER_REQUIRED")
    with zipfile.ZipFile(target) as archive:
        try:
            info = archive.getinfo(member)
        except KeyError as error:
            raise ValueError("NATIVE_MEMBER_NOT_FOUND") from error
        if info.file_size > 64 * 1024 * 1024:
            raise ValueError("NATIVE_MEMBER_TOO_LARGE")
        output = job_root / pathlib.PurePosixPath(member).name
        with archive.open(info) as source, output.open("xb") as destination:
            shutil.copyfileobj(source, destination, 1024 * 1024)
    if output.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("NATIVE_MEMBER_NOT_ELF")
    return output, {
        "source": "android_archive_member",
        "member": member,
        "container_sha256": sha(target),
    }


def analyze(target: pathlib.Path, member: str | None, symbol: str | None,
            job: str, timeout: int, address: str | None = None,
            string_query: str | None = None) -> dict:
    if not JOB_PATTERN.fullmatch(job):
        raise ValueError("INVALID_JOB")
    selectors = [value is not None for value in (symbol, address, string_query)]
    if sum(selectors) > 1:
        raise ValueError("NATIVE_SELECTOR_CONFLICT")
    if address and not re.fullmatch(r"[0-9A-Fa-f]{1,16}", address):
        raise ValueError("INVALID_NATIVE_ADDRESS")
    if string_query is not None and (not string_query or len(string_query) > 512):
        raise ValueError("INVALID_NATIVE_STRING")
    job_root = BASE / "native-jobs" / job
    if job_root.exists():
        raise ValueError("JOB_EXISTS")
    job_root.mkdir(parents=True)
    native, provenance = prepare_input(target, member, job_root)
    root = ghidra_root()
    project = job_root / "project"
    project.mkdir()
    artifact = job_root / "native-evidence.json"
    flags = []
    for line in (root / "support/launch.properties").read_text().splitlines():
        if line.startswith(("VMARGS=", "VMARGS_LINUX=")) and line.split("=", 1)[1]:
            flags.append(line.split("=", 1)[1])
    argv = [
        "env",
        f"HOME={BASE / 'c1/home'}",
        f"TMPDIR={BASE / 'c1/tmp'}",
        f"XDG_CONFIG_HOME={BASE / 'c1/home/.config'}",
        f"XDG_CACHE_HOME={BASE / 'c1/home/.cache'}",
        JAVA,
        *flags,
        "-Xmx768m",
        "-XX:ActiveProcessorCount=1",
        "-XX:ParallelGCThreads=1",
        "-XX:CICompilerCount=2",
        "-Djava.awt.headless=true",
        f"-Duser.home={BASE / 'c1/home'}",
        f"-Djava.io.tmpdir={BASE / 'c1/tmp'}",
        "-cp", root / "Ghidra/Framework/Utility/lib/Utility.jar",
        "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
        project, "NativeAnalysis", "-import", native,
        "-max-cpu", "1", "-analysisTimeoutPerFile", str(max(30, timeout - 30)),
        "-scriptPath", ROOT / "tools/rea/ghidra-scripts",
        "-postScript", "ReaNativeExport.java", artifact,
    ]
    if symbol:
        argv.append(f"symbol:{symbol}")
    elif address:
        argv.append(f"address:{address}")
    elif string_query:
        argv.append(f"string:{string_query}")
    record = run("ghidra-native", argv, job_root, timeout, cwd=root)
    result = {
        "schema_version": 1,
        "provider": "rea-ghidra-android-arm64",
        "status": "BLOCKED",
        "target": str(target.relative_to(ROOT)),
        "target_sha256": sha(target),
        "native_sha256": sha(native),
        "provenance": provenance,
        "static_only": True,
        "command": record,
        "evidence": None,
        "limitations": [
            "The provider statically analyzes one authorized native library at a time.",
            "Decompiled C is approximate and is never labeled as original source.",
            "The target binary is not executed.",
        ],
    }
    if artifact.is_file():
        evidence = json.loads(artifact.read_text())
        result["evidence"] = evidence
        log = (job_root / "ghidra-native.stdout").read_text(errors="replace")
        good = (
            record["exit_code"] == 0
            and evidence.get("sha256") == result["native_sha256"]
            and evidence.get("fidelity") == "disassembled"
            and evidence.get("decompiled_fidelity") == "decompiled_approx"
            and evidence.get("decompile_completed") is True
            and bool(evidence.get("instructions"))
            and "REPORT: Analysis succeeded" in log
        )
        if good:
            result["status"] = "VERIFIED"
    (job_root / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--member")
    parser.add_argument("--symbol")
    parser.add_argument("--address")
    parser.add_argument("--string")
    parser.add_argument("--job", required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.task_id != TASK:
        parser.error("TASK_MISMATCH")
    try:
        target = ensure_target(args.input)
        with (BASE / "analysis.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError("ANALYSIS_LOCKED") from error
            result = analyze(target, args.member, args.symbol, args.job, args.timeout, args.address, args.string)
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({
        "status": result["status"],
        "result": str((BASE / "native-jobs" / args.job / "result.json").relative_to(ROOT)),
        "selected_function": (result.get("evidence") or {}).get("selected_function"),
    }, ensure_ascii=False))
    return 0 if result["status"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
