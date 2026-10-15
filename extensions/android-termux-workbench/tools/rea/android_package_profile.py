#!/usr/bin/env python
"""Bounded Android APK structure profile for the REA Termux adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
MAX_FILE = 512 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024

PACKER_MARKERS = {
    "360_jiagu": ("libjiagu", "libjgdtc", "assets/jiagu"),
    "tencent_legu": ("libshell", "libtup", "assets/txshell"),
    "bangcle": ("libsecexe", "libsecmain", "assets/bangcle"),
    "ijiami": ("libexec", "libprotectclass", "assets/ijiami"),
    "dexprotector": ("libdexprotector", "assets/dp.arm"),
    "secneo": ("libdexhelper", "libsechelper"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_target(value: str) -> pathlib.Path:
    target = pathlib.Path(value).resolve(strict=True)
    roots = [(BASE / name).resolve() for name in ("samples", "inbox") if (BASE / name).exists()]
    if not target.is_file() or not any(target.is_relative_to(root) for root in roots):
        raise ValueError("TARGET_DENIED")
    if target.stat().st_size > MAX_FILE:
        raise ValueError("TARGET_TOO_LARGE")
    return target


def elf_profile(data: bytes) -> dict:
    if len(data) < 64 or not data.startswith(b"\x7fELF"):
        return {"valid": False, "reason": "NOT_ELF"}
    elf_class, byte_order = data[4], data[5]
    if elf_class not in (1, 2) or byte_order not in (1, 2):
        return {"valid": False, "reason": "UNSUPPORTED_ELF_HEADER"}
    endian = "<" if byte_order == 1 else ">"
    if elf_class == 2:
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize = struct.unpack_from(endian + "H", data, 54)[0]
        phnum = struct.unpack_from(endian + "H", data, 56)[0]
        align_offset = 48
    else:
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize = struct.unpack_from(endian + "H", data, 42)[0]
        phnum = struct.unpack_from(endian + "H", data, 44)[0]
        align_offset = 28
    if phnum > 1024 or phentsize < align_offset + (8 if elf_class == 2 else 4):
        return {"valid": False, "reason": "INVALID_PROGRAM_HEADERS"}
    load_alignments = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + phentsize > len(data):
            return {"valid": False, "reason": "TRUNCATED_PROGRAM_HEADERS"}
        p_type = struct.unpack_from(endian + "I", data, offset)[0]
        if p_type == 1:
            fmt = "Q" if elf_class == 2 else "I"
            load_alignments.append(struct.unpack_from(endian + fmt, data, offset + align_offset)[0])
    alignment_pass = bool(load_alignments) and all(value >= 16384 for value in load_alignments)
    return {
        "valid": True,
        "class_bits": 64 if elf_class == 2 else 32,
        "endianness": "little" if byte_order == 1 else "big",
        "load_segment_alignments": load_alignments,
        "page_16k_load_alignment": "PASS" if alignment_pass else "FAIL",
    }


def sha256_file(path: pathlib.Path) -> str:
    digest_value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest_value.update(chunk)
    return digest_value.hexdigest()


def payload_offset(apk_path: pathlib.Path, info: zipfile.ZipInfo) -> int:
    start = info.header_offset
    with apk_path.open("rb") as stream:
        stream.seek(start)
        header = stream.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError("INVALID_LOCAL_ZIP_HEADER")
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    return start + 30 + name_length + extra_length


def build_profile(target: pathlib.Path) -> dict:
    with zipfile.ZipFile(target) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        dex = []
        native = []
        for info in infos:
            lower = info.filename.lower()
            if info.file_size > MAX_MEMBER:
                continue
            if lower.endswith(".dex"):
                data = archive.read(info)
                dex.append(
                    {
                        "path": info.filename,
                        "bytes": len(data),
                        "sha256": digest(data),
                        "header_valid": data.startswith(b"dex\n") and len(data) >= 112,
                    }
                )
            parts = pathlib.PurePosixPath(info.filename).parts
            if len(parts) == 3 and parts[0] == "lib" and lower.endswith(".so"):
                data = archive.read(info)
                offset = payload_offset(target, info)
                compressed = info.compress_type != zipfile.ZIP_STORED
                native.append(
                    {
                        "path": info.filename,
                        "abi": parts[1],
                        "bytes": len(data),
                        "sha256": digest(data),
                        "zip_storage": "compressed" if compressed else "stored",
                        "zip_payload_offset": offset,
                        "zip_16k_alignment": (
                            "NOT_APPLICABLE_COMPRESSED"
                            if compressed
                            else ("PASS" if offset % 16384 == 0 else "FAIL")
                        ),
                        "elf": elf_profile(data),
                    }
                )
        lowered = [name.lower() for name in names]
        markers = []
        for family, needles in PACKER_MARKERS.items():
            hits = sorted(
                name
                for name, lower in zip(names, lowered)
                if any(needle in lower for needle in needles)
            )
            if hits:
                markers.append(
                    {
                        "family": family,
                        "confidence": "HEURISTIC",
                        "matched_paths": hits[:20],
                    }
                )
        if not native:
            native_summary = "NO_NATIVE_LIBRARIES"
        elif all(
            item["elf"]["valid"]
            and item["elf"]["page_16k_load_alignment"] == "PASS"
            and item["zip_16k_alignment"] in ("PASS", "NOT_APPLICABLE_COMPRESSED")
            for item in native
        ):
            native_summary = "PASS"
        else:
            native_summary = "FAIL_OR_REVIEW"
        return {
            "schema_version": 1,
            "target": str(target),
            "sha256": sha256_file(target),
            "entry_count": len(infos),
            "dex": dex,
            "multi_dex": len(dex) > 1,
            "native_libraries": native,
            "abis": sorted({item["abi"] for item in native}),
            "native_16k_summary": native_summary,
            "packer_indicators": markers,
            "packer_assessment": "HEURISTIC_ONLY" if markers else "NO_KNOWN_MARKER_FOUND",
            "limitations": [
                "Packer markers are filename heuristics, not proof of a protector.",
                "16KiB checks cover ELF PT_LOAD alignment and stored-library ZIP payload offsets; runtime compatibility still needs a real install/run test.",
                "Static package structure does not prove runtime behavior.",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    args = parser.parse_args()
    try:
        result = build_profile(ensure_target(args.apk))
    except (OSError, ValueError, zipfile.BadZipFile, struct.error) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "VERIFIED", "profile": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
