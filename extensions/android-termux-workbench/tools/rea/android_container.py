#!/usr/bin/env python
"""Bounded APK/AAB/APKS/split-container inspection without executing targets."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
ALLOWED_ROOT_NAMES = ("samples", "inbox")
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_ENTRY_COUNT = 50_000
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_RATIO = 500
DEX_NAME = re.compile(r"(?:^|.*/)classes(?:\d+)?\.dex$")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def allowed_roots() -> list[pathlib.Path]:
    return [(BASE / name).resolve() for name in ALLOWED_ROOT_NAMES if (BASE / name).exists()]


def ensure_target(value: str) -> pathlib.Path:
    raw = pathlib.Path(value)
    if raw.is_symlink():
        raise ValueError("SYMLINK_TARGET_DENIED")
    target = raw.resolve(strict=True)
    if not any(target.is_relative_to(root) for root in allowed_roots()):
        raise ValueError("TARGET_DENIED")
    if target.is_file() and target.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("TARGET_TOO_LARGE")
    if not target.is_file() and not target.is_dir():
        raise ValueError("TARGET_TYPE_DENIED")
    return target


def validate_members(infos: list[zipfile.ZipInfo]) -> None:
    if len(infos) > MAX_ENTRY_COUNT:
        raise ValueError("ZIP_ENTRY_LIMIT")
    names = [item.filename for item in infos]
    if len(set(names)) != len(names):
        raise ValueError("ZIP_DUPLICATE_MEMBER")
    expanded = 0
    for info in infos:
        member = pathlib.PurePosixPath(info.filename)
        if info.filename.startswith("/") or ".." in member.parts:
            raise ValueError("ZIP_UNSAFE_PATH")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError("ZIP_MEMBER_LIMIT")
        expanded += info.file_size
        if expanded > MAX_EXPANDED_BYTES:
            raise ValueError("ZIP_EXPANDED_LIMIT")
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise ValueError("ZIP_RATIO_LIMIT")


def inspect_zip(path: pathlib.Path, role: str = "single") -> dict:
    if not zipfile.is_zipfile(path):
        raise ValueError("NOT_ZIP")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        validate_members(infos)
        names = [item.filename for item in infos]
        name_set = set(names)
        is_apk = "AndroidManifest.xml" in name_set and any(DEX_NAME.fullmatch(name) for name in names)
        is_aab = "BundleConfig.pb" in name_set and any(name.endswith("/manifest/AndroidManifest.xml") for name in names)
        is_apks = any(name.endswith(".apk") for name in names) and not is_apk
        if is_apk:
            kind = "APK"
        elif is_aab:
            kind = "AAB"
        elif is_apks:
            kind = "APKS"
        else:
            raise ValueError("UNSUPPORTED_ANDROID_CONTAINER")
        dex = []
        native = []
        manifests = []
        nested_apks = []
        for info in infos:
            name = info.filename
            if DEX_NAME.fullmatch(name):
                dex.append({"path": name, "bytes": info.file_size, "sha256": sha256_member(archive, info)})
            parts = pathlib.PurePosixPath(name).parts
            if name.endswith("AndroidManifest.xml"):
                manifests.append({"path": name, "bytes": info.file_size})
            if name.endswith(".so") and ((len(parts) >= 3 and parts[-3] == "lib") or (len(parts) >= 4 and parts[-4] == "lib")):
                native.append({"path": name, "abi": parts[-2], "bytes": info.file_size, "sha256": sha256_member(archive, info)})
            if kind == "APKS" and name.endswith(".apk"):
                nested_apks.append({"path": name, "bytes": info.file_size})
        modules = sorted({name.split("/", 1)[0] for name in names if "/" in name}) if kind == "AAB" else []
        return {
            "path": str(path), "role": role, "kind": kind, "bytes": path.stat().st_size,
            "sha256": sha256_file(path), "entry_count": len(infos),
            "expanded_bytes": sum(item.file_size for item in infos), "dex": dex,
            "native_libraries": native, "manifests": manifests, "modules": modules,
            "nested_apks": nested_apks,
        }


def inspect_split_directory(target: pathlib.Path) -> dict:
    if any(item.is_symlink() for item in target.iterdir()):
        raise ValueError("SYMLINK_MEMBER_DENIED")
    files = sorted(item.resolve() for item in target.iterdir() if item.is_file() and item.suffix.lower() == ".apk")
    if not files:
        raise ValueError("SPLIT_SET_EMPTY")
    if sum(item.stat().st_size for item in files) > MAX_INPUT_BYTES:
        raise ValueError("TARGET_TOO_LARGE")
    bases = [item for item in files if item.name in {"base.apk", "base-master.apk"}]
    if len(bases) != 1:
        raise ValueError("SPLIT_BASE_REQUIRED")
    units = [inspect_zip(item, "base" if item == bases[0] else "split") for item in files]
    if any(unit["kind"] != "APK" for unit in units):
        raise ValueError("SPLIT_MEMBER_NOT_APK")
    return build_view("SPLIT_SET", target, units)


def build_view(kind: str, target: pathlib.Path, units: list[dict]) -> dict:
    dex = []
    native = []
    for unit in units:
        label = pathlib.Path(unit["path"]).name
        dex.extend({**item, "container": label} for item in unit["dex"])
        native.extend({**item, "container": label} for item in unit["native_libraries"])
    return {
        "schema_version": 1, "kind": kind, "target": str(target), "units": units,
        "dex": dex, "native_libraries": native,
        "abis": sorted({item["abi"] for item in native}),
        "totals": {
            "input_bytes": sum(item["bytes"] for item in units),
            "expanded_bytes": sum(item["expanded_bytes"] for item in units),
            "dex_count": len(dex),
            "native_count": len(native),
        },
        "analysis_semantics": "RECONSTRUCTED_LOGICAL_VIEW" if kind in {"AAB", "APKS", "SPLIT_SET"} else "DIRECT_PACKAGE_VIEW",
        "limitations": [
            "A reconstructed AAB or split view is not proof of the exact installed device state.",
            "Container inspection does not execute package code.",
        ],
    }



def materialize_apks_bundle(bundle: pathlib.Path, output: pathlib.Path) -> dict:
    """Extract only nested APK units from a validated .apks archive into a fresh job directory."""
    outer = inspect_zip(bundle)
    if outer["kind"] != "APKS":
        raise ValueError("APKS_REQUIRED")
    if output.exists():
        raise ValueError("APKS_OUTPUT_EXISTS")
    output.mkdir(parents=True)
    with zipfile.ZipFile(bundle) as archive:
        infos = [info for info in archive.infolist() if info.filename.endswith(".apk")]
        validate_members(archive.infolist())
        base_candidates = [
            info for info in infos
            if pathlib.PurePosixPath(info.filename).name in {"base.apk", "base-master.apk"}
        ]
        if len(base_candidates) != 1:
            raise ValueError("APKS_BASE_REQUIRED")
        for index, info in enumerate(sorted(infos, key=lambda item: item.filename)):
            name = "base.apk" if info == base_candidates[0] else f"split_{index:04d}.apk"
            destination = output / name
            with archive.open(info) as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
    view = inspect_split_directory(output)
    view["source_bundle"] = {
        "path": str(bundle), "sha256": outer["sha256"], "bytes": outer["bytes"],
        "nested_apk_count": len(outer["nested_apks"]),
    }
    view["source_kind"] = "APKS"
    return view

def inspect_target(target: pathlib.Path) -> dict:
    if target.is_dir():
        return inspect_split_directory(target)
    unit = inspect_zip(target)
    return build_view(unit["kind"], target, [unit])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        result = inspect_target(ensure_target(args.target))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "VERIFIED", "container": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
