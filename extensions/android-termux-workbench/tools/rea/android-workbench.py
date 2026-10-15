#!/usr/bin/env python
"""Persistent, resumable REA Android Workbench v1.1 jobs."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from android_container import ensure_target, inspect_target
from android_analysis import target_digest
from flute_container import inspect_flute, write_result
from dex_layer import build_index, search_index, decompile_class
from android_version_diff import build_diff

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
WORKBENCH = BASE / "workbench"
TASK_ID = "b06dd042-8638-4a47-937d-8ae644a205b9"
PIPELINE_VERSION = "rea-android-workbench-v1.1"
JOB_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TERMINAL = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}
ACTIVE = {"PREFLIGHT", "ANALYZING", "MERGING", "REPORTED"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def append_event(path: pathlib.Path, state: str, **details) -> None:
    event = {"at": utc_now(), "state": state, **details}
    with path.open("a") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def allowed_target(value: str) -> pathlib.Path:
    return ensure_target(value)


def target_identity(target: pathlib.Path) -> tuple[str, dict]:
    container = inspect_target(target)
    return target_digest(target, container), container


def pipeline_fingerprint() -> str:
    digest = hashlib.sha256()
    for name in ("android-workbench.py", "android_analysis.py", "android_container.py",
                 "android_signature.py", "android_resources.py", "android_package_profile.py",
                 "dynamic_evidence.py", "flute_container.py", "dex_layer.py",
                 "android_version_diff.py", "dynamic_session_broker.py",
                 "evidence_contract.py", "ghidra-native-provider.py",
                 "ghidra-scripts/ReaNativeExport.java"):
        path = ROOT / "tools/rea" / name
        digest.update(name.encode())
        digest.update(path.read_bytes())
    digest.update(b"bin/rea-termux")
    digest.update((ROOT / "bin/rea-termux").read_bytes())
    return digest.hexdigest()


def content_key(target_sha256: str, dynamic_sha256: str | None = None,
                with_native: bool = False, native_member: str | None = None,
                native_symbol: str | None = None, native_address: str | None = None,
                native_string: str | None = None) -> str:
    return hashlib.sha256(
        f"{PIPELINE_VERSION}\0{pipeline_fingerprint()}\0{target_sha256}\0"
        f"{dynamic_sha256 or '-'}\0{int(with_native)}\0"
        f"{native_member or '-'}\0{native_symbol or '-'}\0"
        f"{native_address or '-'}\0{native_string or '-'}".encode()
    ).hexdigest()


def process_alive(pid: int | None) -> bool:
    return bool(pid and pathlib.Path(f"/proc/{pid}").exists())


def load_state(path: pathlib.Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def verified_result(state: dict) -> bool:
    result_path = ROOT / state.get("analysis_json", "")
    if not result_path.is_file():
        return False
    try:
        result = json.loads(result_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return (
        result.get("status") in {"VERIFIED", "PARTIAL"}
        and result.get("sha256") == state.get("target_sha256")
        and "android_intelligence" in result
        and "container" in result
        and bool(result.get("evidence"))
    )


def transition(state_path: pathlib.Path, events_path: pathlib.Path, state: dict,
               new_status: str, **details) -> None:
    state.update(status=new_status, updated_at=utc_now(), **details)
    atomic_json(state_path, state)
    append_event(events_path, new_status, attempt=state.get("attempt"), **details)


def preflight(target: pathlib.Path, dynamic: pathlib.Path | None) -> dict:
    digest, container = target_identity(target)
    jadx = ROOT / "run/rea-3a0be4d8/jadx-local/data/data/com.termux/files/usr/share/java/jadx-1.5.6-all.jar"
    checks = {
        "target": True,
        "kind": container["kind"],
        "jadx": jadx.is_file(),
        "dynamic_evidence": dynamic is None or dynamic.is_file(),
    }
    if not all(value for key, value in checks.items() if key != "kind"):
        raise ValueError("PREFLIGHT_FAILED")
    return {"target_sha256": digest, "container_kind": container["kind"], "checks": checks}


def analyze(args) -> int:
    selectors = [args.native_symbol, args.native_address, args.native_string]
    if sum(value is not None for value in selectors) > 1:
        raise ValueError("NATIVE_SELECTOR_CONFLICT")
    if any(value is not None for value in selectors) and not args.with_native:
        raise ValueError("NATIVE_SELECTOR_REQUIRES_WITH_NATIVE")
    if not JOB_PATTERN.fullmatch(args.job):
        raise ValueError("INVALID_JOB")
    target = allowed_target(args.input)
    dynamic = allowed_target(args.dynamic_evidence) if args.dynamic_evidence else None
    if dynamic is not None and not dynamic.is_file():
        raise ValueError("DYNAMIC_JSON_REQUIRED")
    target_hash, _ = target_identity(target)
    dynamic_hash = sha256_file(dynamic) if dynamic else None
    key = content_key(target_hash, dynamic_hash, args.with_native, args.native_member,
                      args.native_symbol, args.native_address, args.native_string)
    job_root = WORKBENCH / args.job
    job_root.mkdir(parents=True, exist_ok=True)
    state_path = job_root / "state.json"
    events_path = job_root / "events.jsonl"
    lock_path = job_root / "job.lock"

    with lock_path.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"status": "RUNNING", "job": args.job, "error": "JOB_LOCKED"}))
            return 3

        prior = load_state(state_path)
        if prior and prior.get("content_key") != key:
            print(json.dumps({
                "status": "FAILED", "job": args.job, "error": "JOB_IDENTITY_MISMATCH",
                "expected_target_sha256": prior.get("target_sha256"),
                "actual_target_sha256": target_hash,
            }))
            return 2
        if prior and prior.get("status") in {"COMPLETED", "PARTIAL"} and verified_result(prior):
            append_event(events_path, "REUSED", analysis_json=prior["analysis_json"])
            print(json.dumps({
                "status": prior["status"], "job": args.job, "reused": True,
                "analysis_json": prior["analysis_json"], "report": prior["report"],
            }, ensure_ascii=False))
            return 0 if prior["status"] == "COMPLETED" else 3
        if prior and prior.get("status") in ACTIVE and process_alive(prior.get("pid")):
            print(json.dumps({"status": prior["status"], "job": args.job, "error": "JOB_ACTIVE"}))
            return 3
        if prior and prior.get("status") in ACTIVE:
            append_event(events_path, "RECOVERING", orphaned_status=prior["status"],
                         orphaned_pid=prior.get("pid"))

        attempt = int((prior or {}).get("attempt", 0)) + 1
        backend_job = f"wb-{args.job[:32]}-{key[:8]}-a{attempt}"
        while (BASE / "jobs" / backend_job).exists():
            attempt += 1
            backend_job = f"wb-{args.job[:32]}-{key[:8]}-a{attempt}"

        state = {
            "schema_version": 2, "job": args.job, "status": "PREFLIGHT",
            "pipeline_version": PIPELINE_VERSION, "pipeline_fingerprint": pipeline_fingerprint(),
            "content_key": key,
            "target": str(target.relative_to(ROOT)), "target_sha256": target_hash,
            "dynamic_evidence_sha256": dynamic_hash, "with_native": args.with_native,
            "native_member": args.native_member, "native_symbol": args.native_symbol,
            "native_address": args.native_address, "native_string": args.native_string,
            "attempt": attempt, "backend_job": backend_job, "pid": os.getpid(),
            "started_at": (prior or {}).get("started_at", utc_now()), "updated_at": utc_now(),
            "checkpoint": None,
        }
        atomic_json(state_path, state)
        append_event(events_path, "PREFLIGHT", attempt=attempt)
        try:
            checkpoint = preflight(target, dynamic)
        except (OSError, ValueError) as error:
            transition(state_path, events_path, state, "FAILED", pid=None,
                       error=str(error), failed_at=utc_now())
            print(json.dumps({"status": "FAILED", "job": args.job, "error": str(error)}))
            return 2

        checkpoint_path = job_root / f"attempt-{attempt}-preflight.json"
        atomic_json(checkpoint_path, checkpoint)
        transition(state_path, events_path, state, "ANALYZING",
                   checkpoint=str(checkpoint_path.relative_to(ROOT)))

        command = [
            sys.executable, str(ROOT / "tools/rea/android_analysis.py"),
            "--task-id", TASK_ID, "--input", str(target), "--job", backend_job,
            "--timeout", str(args.timeout),
        ]
        if args.with_native:
            command.append("--with-native")
        if args.native_member:
            command.extend(["--native-member", args.native_member])
        if args.native_symbol:
            command.extend(["--native-symbol", args.native_symbol])
        if args.native_address:
            command.extend(["--native-address", args.native_address])
        if args.native_string:
            command.extend(["--native-string", args.native_string])
        if dynamic:
            command.extend(["--dynamic-evidence", str(dynamic)])
        try:
            completed = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True,
                timeout=args.timeout + 360 if args.with_native else args.timeout + 90,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            transition(state_path, events_path, state, "FAILED", pid=None,
                       error="ANALYSIS_TIMEOUT", failed_at=utc_now())
            (job_root / f"attempt-{attempt}.stdout").write_text(error.stdout or "")
            (job_root / f"attempt-{attempt}.stderr").write_text(error.stderr or "")
            print(json.dumps({"status": "FAILED", "job": args.job, "error": "ANALYSIS_TIMEOUT"}))
            return 2

        (job_root / f"attempt-{attempt}.stdout").write_text(completed.stdout)
        (job_root / f"attempt-{attempt}.stderr").write_text(completed.stderr)
        transition(state_path, events_path, state, "MERGING", exit_code=completed.returncode)

        analysis_path = BASE / "jobs" / backend_job / "analysis.json"
        report_path = BASE / "jobs" / backend_job / "报告.md"
        relative_analysis = str(analysis_path.relative_to(ROOT))
        relative_report = str(report_path.relative_to(ROOT))
        if analysis_path.is_file():
            result = json.loads(analysis_path.read_text())
            if result.get("status") in {"VERIFIED", "PARTIAL"} and result.get("sha256") == target_hash:
                transition(state_path, events_path, state, "REPORTED",
                           analysis_json=relative_analysis, report=relative_report,
                           evidence_sha256=sha256_file(analysis_path))
                final = "COMPLETED" if result["status"] == "VERIFIED" else "PARTIAL"
                transition(state_path, events_path, state, final, pid=None,
                           completed_at=utc_now(), exit_code=completed.returncode)
                print(json.dumps({
                    "status": final, "job": args.job, "reused": False,
                    "analysis_json": relative_analysis, "report": relative_report,
                    "evidence_sha256": state["evidence_sha256"],
                }, ensure_ascii=False))
                return 0 if final == "COMPLETED" else 3

        transition(state_path, events_path, state, "FAILED", pid=None,
                   failed_at=utc_now(), exit_code=completed.returncode,
                   error="ANALYSIS_FAILED",
                   analysis_json=relative_analysis if analysis_path.exists() else None)
        print(json.dumps({
            "status": "FAILED", "job": args.job, "error": "ANALYSIS_FAILED",
            "exit_code": completed.returncode,
        }))
        return 2


def status(args) -> int:
    if not JOB_PATTERN.fullmatch(args.job):
        raise ValueError("INVALID_JOB")
    state = load_state(WORKBENCH / args.job / "state.json")
    if state is None:
        print(json.dumps({"status": "NOT_FOUND", "job": args.job}))
        return 1
    visible = {key: value for key, value in state.items() if key not in {"stdout", "stderr"}}
    if state.get("status") in ACTIVE and not process_alive(state.get("pid")):
        visible["health"] = "ORPHANED_RECOVERABLE"
    print(json.dumps(visible, ensure_ascii=False))
    return 0


def flute(args) -> int:
    target = allowed_target(args.input)
    if not target.is_file():
        raise ValueError("FLUTE_FILE_REQUIRED")
    result = inspect_flute(target)
    if args.output:
        output = pathlib.Path(args.output).resolve()
        if not output.is_relative_to(BASE):
            raise ValueError("FLUTE_OUTPUT_DENIED")
        write_result(result, output)
    print(json.dumps(result, ensure_ascii=False))
    return 0


def dex_index(args) -> int:
    result = build_index(pathlib.Path(args.input), args.job, args.resume)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "VERIFIED" else 3


def dex_search(args) -> int:
    result = {
        "status": "VERIFIED",
        "kind": args.kind,
        "query": args.query,
        "results": search_index(args.index, args.query, args.kind, args.limit),
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0


def dex_class(args) -> int:
    result = decompile_class(args.index, args.name, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "VERIFIED" else 3


def version_diff(args) -> int:
    result = build_diff(args.old_index, args.new_index, args.job, args.resume)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "VERIFIED" else 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("analyze")
    run_parser.add_argument("--input", required=True)
    run_parser.add_argument("--job", required=True)
    run_parser.add_argument("--timeout", type=int, default=240)
    run_parser.add_argument("--with-native", action="store_true")
    run_parser.add_argument("--native-member")
    run_parser.add_argument("--native-symbol")
    run_parser.add_argument("--native-address")
    run_parser.add_argument("--native-string")
    run_parser.add_argument("--dynamic-evidence")
    run_parser.set_defaults(handler=analyze)
    query = commands.add_parser("status")
    query.add_argument("--job", required=True)
    query.set_defaults(handler=status)
    flute_parser = commands.add_parser("flute")
    flute_parser.add_argument("--input", required=True)
    flute_parser.add_argument("--output")
    flute_parser.set_defaults(handler=flute)
    index_parser = commands.add_parser("index", help="Build a resumable SQLite DEX index")
    index_parser.add_argument("--input", required=True)
    index_parser.add_argument("--job", required=True)
    index_parser.add_argument("--resume", action="store_true")
    index_parser.set_defaults(handler=dex_index)
    search_parser = commands.add_parser("search", help="Search an existing DEX index")
    search_parser.add_argument("--index", required=True)
    search_parser.add_argument("--kind", choices=("class", "method", "string"), default="class")
    search_parser.add_argument("--query", required=True)
    search_parser.add_argument("--limit", type=int, default=100)
    search_parser.set_defaults(handler=dex_search)
    class_parser = commands.add_parser("class", help="Decompile one exact indexed class")
    class_parser.add_argument("--index", required=True)
    class_parser.add_argument("--name", required=True)
    class_parser.add_argument("--timeout", type=int, default=180)
    class_parser.set_defaults(handler=dex_class)
    diff_parser = commands.add_parser("diff", help="Compare two DEX indexes")
    diff_parser.add_argument("--old-index", required=True)
    diff_parser.add_argument("--new-index", required=True)
    diff_parser.add_argument("--job", required=True)
    diff_parser.add_argument("--resume", action="store_true")
    diff_parser.set_defaults(handler=version_diff)
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
