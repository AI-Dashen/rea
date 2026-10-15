#!/usr/bin/env python
"""Bounded Android package signature reporting using installed official tools."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess

from android_container import ensure_target, inspect_target

SCHEME = re.compile(r"Verified using v(\d) scheme[^:]*:\s*(true|false)", re.I)
CERT_SHA256 = re.compile(r"(?:Signer #\d+|V\d+(?:\.\d+)? Signer): certificate SHA-256 digest:\s*([0-9a-f]+)", re.I)


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)


def verify_apk(path: pathlib.Path) -> dict:
    jar = pathlib.Path("/data/data/com.termux/files/usr/share/java/apksigner.jar")
    helper = pathlib.Path(__file__).with_name("ReaApkSig.java")
    idsig = path.with_suffix(path.suffix + ".idsig")
    argv = ["java", "--class-path", str(jar), str(helper), str(path)]
    if idsig.is_file():
        argv.append(str(idsig))
    completed = run(argv)
    payload = None
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            payload = None
    if payload is None:
        return {
            "path": str(path), "tool": "apksig-java", "exit_code": completed.returncode,
            "verified": False, "schemes": {}, "certificate_sha256": [],
            "v4": "VERIFICATION_FAILED",
            "error_summary": completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else "SIGNATURE_INVALID",
        }
    schemes = {key: bool(payload[key]) for key in ("v1", "v2", "v3", "v31", "v32", "v4")}
    return {
        "path": str(path), "tool": "apksig-java", "exit_code": completed.returncode,
        "verified": bool(payload["verified"]), "schemes": schemes,
        "certificate_sha256": payload["certificate_sha256"],
        "v4": "VERIFIED" if payload["v4"] else ("INVALID" if payload["idsig_present"] else "NO_COMPANION"),
        "error_count": payload["error_count"], "warning_count": payload["warning_count"],
        "error_summary": None if payload["verified"] else "SIGNATURE_INVALID",
    }


def verify_aab(path: pathlib.Path) -> dict:
    completed = run(["jarsigner", "-verify", "-strict", str(path)])
    text = completed.stdout + "\n" + completed.stderr
    verified = completed.returncode == 0 and "jar verified" in text.lower()
    return {
        "path": str(path), "tool": "jarsigner", "exit_code": completed.returncode,
        "verified": verified, "schemes": {"jar": verified}, "certificate_sha256": [],
        "v4": "NOT_APPLICABLE_TO_AAB",
        "error_summary": None if verified else "AAB_JAR_SIGNATURE_INVALID",
    }


def verify_target(target: pathlib.Path) -> dict:
    view = inspect_target(target)
    if view["kind"] == "APK":
        packages = [verify_apk(target)]
    elif view["kind"] == "SPLIT_SET":
        packages = [verify_apk(pathlib.Path(unit["path"])) for unit in view["units"]]
    elif view["kind"] == "AAB":
        packages = [verify_aab(target)]
    else:
        packages = []
    signer_sets = [tuple(item["certificate_sha256"]) for item in packages if item["verified"]]
    consistent = len(set(signer_sets)) <= 1 if signer_sets else None
    verified = bool(packages) and all(item["verified"] for item in packages) and consistent is not False
    return {
        "schema_version": 1, "target_kind": view["kind"], "verified": verified,
        "package_results": packages, "signer_consistent": consistent,
        "trust_statement": "SIGNATURE_VALID_NOT_IDENTITY_TRUST" if verified else "NOT_VERIFIED",
        "limitations": [
            "A valid package signature proves integrity and signer continuity, not that the signer is trustworthy.",
            "V4 requires a matching external .idsig and is reported separately when the installed apksigner cannot validate it.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        report = verify_target(ensure_target(args.target))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2
    status = "VERIFIED" if report["verified"] else "PARTIAL"
    print(json.dumps({"status": status, "signature": report}, ensure_ascii=False))
    return 0 if report["verified"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
