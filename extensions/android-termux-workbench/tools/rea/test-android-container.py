#!/usr/bin/env python
import importlib.util
import pathlib
import shutil
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
WORK = BASE / "inbox/container-tests"
SPEC = importlib.util.spec_from_file_location("android_container", ROOT / "tools/rea/android_container.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def apk(path, dex_name="classes.dex"):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr(dex_name, b"dex\n035\x00" + b"\x00" * 120)


class AndroidContainerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shutil.rmtree(WORK, ignore_errors=True)
        WORK.mkdir(parents=True)
        cls.single = WORK / "single.apk"
        apk(cls.single)
        cls.aab = WORK / "owned.aab"
        with zipfile.ZipFile(cls.aab, "w") as archive:
            archive.writestr("BundleConfig.pb", b"config")
            archive.writestr("base/manifest/AndroidManifest.xml", b"proto")
            archive.writestr("base/dex/classes.dex", b"dex\n035\x00" + b"\x00" * 120)
            archive.writestr("base/lib/arm64-v8a/libowned.so", b"\x7fELF" + b"\x00" * 100)
        cls.splits = WORK / "splits"
        cls.splits.mkdir()
        apk(cls.splits / "base.apk")
        apk(cls.splits / "split_feature.apk", "classes2.dex")
        cls.apks = WORK / "owned.apks"
        with zipfile.ZipFile(cls.apks, "w") as archive:
            archive.write(cls.splits / "base.apk", "splits/base-master.apk")
            archive.write(cls.splits / "split_feature.apk", "splits/feature-x.apk")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(WORK, ignore_errors=True)

    def test_apk_direct_view(self):
        result = MODULE.inspect_target(MODULE.ensure_target(str(self.single)))
        self.assertEqual(result["kind"], "APK")
        self.assertEqual(result["analysis_semantics"], "DIRECT_PACKAGE_VIEW")
        self.assertEqual(result["totals"]["dex_count"], 1)

    def test_aab_reconstructed_view(self):
        result = MODULE.inspect_target(MODULE.ensure_target(str(self.aab)))
        self.assertEqual(result["kind"], "AAB")
        self.assertEqual(result["analysis_semantics"], "RECONSTRUCTED_LOGICAL_VIEW")
        self.assertIn("base", result["units"][0]["modules"])
        self.assertEqual(result["totals"]["dex_count"], 1)

    def test_split_set_requires_one_base(self):
        result = MODULE.inspect_target(MODULE.ensure_target(str(self.splits)))
        self.assertEqual(result["kind"], "SPLIT_SET")
        self.assertEqual(len(result["units"]), 2)
        self.assertEqual(result["totals"]["dex_count"], 2)

    def test_apks_materializes_as_reconstructed_split_set(self):
        outer = MODULE.inspect_target(MODULE.ensure_target(str(self.apks)))
        self.assertEqual(outer["kind"], "APKS")
        output = WORK / "materialized"
        result = MODULE.materialize_apks_bundle(self.apks, output)
        self.assertEqual(result["kind"], "SPLIT_SET")
        self.assertEqual(result["source_kind"], "APKS")
        self.assertEqual(result["totals"]["dex_count"], 2)

    def test_outside_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TARGET_DENIED"):
            MODULE.ensure_target(str(ROOT / "AGENTS.md"))


if __name__ == "__main__":
    unittest.main()
