#!/usr/bin/env python
import json
import pathlib
import subprocess
import sys
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/rea/android-package-profile.py"
BASE = ROOT / "run/rea-b06dd042"
FIXTURE = BASE / "inbox/profile-test.apk"


class AndroidPackageProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(BASE / "samples/owned.apk") as source, zipfile.ZipFile(FIXTURE, "w") as target:
            for item in source.infolist():
                target.writestr(item, source.read(item))
            target.writestr(
                "lib/arm64-v8a/libjiagu.so",
                (BASE / "samples/owned.elf").read_bytes(),
                compress_type=zipfile.ZIP_STORED,
            )

    @classmethod
    def tearDownClass(cls):
        FIXTURE.unlink(missing_ok=True)

    def invoke(self, target):
        result = subprocess.run(
            [sys.executable, str(TOOL), str(target)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, json.loads(result.stdout)

    def test_owned_apk_without_native_libraries(self):
        result, payload = self.invoke(BASE / "samples/owned.apk")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(payload["status"], "VERIFIED")
        self.assertEqual(payload["profile"]["native_16k_summary"], "NO_NATIVE_LIBRARIES")
        self.assertEqual(payload["profile"]["dex"][0]["header_valid"], True)

    def test_native_alignment_and_packer_hint_are_separate(self):
        result, payload = self.invoke(FIXTURE)
        self.assertEqual(result.returncode, 0)
        native = payload["profile"]["native_libraries"][0]
        self.assertEqual(native["elf"]["page_16k_load_alignment"], "PASS")
        self.assertEqual(native["zip_16k_alignment"], "FAIL")
        self.assertEqual(payload["profile"]["packer_indicators"][0]["confidence"], "HEURISTIC")

    def test_outside_target_is_rejected(self):
        result, payload = self.invoke(ROOT / "AGENTS.md")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(payload, {"status": "FAILED", "error": "TARGET_DENIED"})


if __name__ == "__main__":
    unittest.main()
