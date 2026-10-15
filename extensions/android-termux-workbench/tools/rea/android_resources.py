#!/usr/bin/env python
"""Bounded Android manifest/resource surface inventory without extracting target files."""
from __future__ import annotations

import pathlib
import re
import zipfile

from runlog import ROOT, run

PACKAGE = re.compile(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'")
SDK = re.compile(r"(sdkVersion|targetSdkVersion):'([^']*)'")
PERMISSION = re.compile(r"uses-permission(?:-[^:]+)?: name='([^']+)'")
COMPONENT = re.compile(r"^(launchable-activity|application-label|uses-feature|native-code):", re.M)


def zip_surface(path: pathlib.Path) -> dict:
    categories: dict[str, int] = {}
    resource_entries = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            prefix = name.split("/", 1)[0] if "/" in name else "(root)"
            categories[prefix] = categories.get(prefix, 0) + 1
            if name.startswith(("res/", "assets/", "base/res/", "base/assets/")):
                resource_entries.append({"path": name, "bytes": info.file_size})
    return {
        "categories": dict(sorted(categories.items())),
        "resource_entry_count": len(resource_entries),
        "largest_resources": sorted(resource_entries, key=lambda item: (-item["bytes"], item["path"]))[:20],
    }


def inspect_resources(apks: list[pathlib.Path], job: pathlib.Path, timeout: int = 90) -> dict:
    units = []
    permissions: set[str] = set()
    packages = []
    commands = []
    for index, apk in enumerate(apks):
        surface = zip_surface(apk)
        record = run(f"aapt-badging-{index}", ["aapt", "dump", "badging", apk], job, timeout)
        commands.append(record)
        stdout = ROOT / record["stdout"]
        text = stdout.read_text(errors="replace") if record["exit_code"] == 0 else ""
        match = PACKAGE.search(text)
        package = {
            "name": match.group(1), "version_code": match.group(2), "version_name": match.group(3)
        } if match else None
        if package:
            packages.append(package)
        unit_permissions = sorted(set(PERMISSION.findall(text)))
        permissions.update(unit_permissions)
        units.append({
            "path": str(apk), "aapt_status": "VERIFIED" if record["exit_code"] == 0 else "FAILED",
            "package": package, "sdk": {key: value for key, value in SDK.findall(text)},
            "permissions": unit_permissions,
            "declared_surface_line_count": len(COMPONENT.findall(text)),
            **surface,
        })
    return {
        "schema_version": 1, "provider": "android-resource-surface",
        "status": "VERIFIED" if all(item["aapt_status"] == "VERIFIED" for item in units) else "PARTIAL",
        "units": units, "packages": packages, "permissions": sorted(permissions),
        "commands": commands,
        "limitations": [
            "Resource inventory records names and sizes, not resource file contents.",
            "AAB resource views are reconstructed from ZIP structure because aapt consumes APKs.",
        ],
    }
