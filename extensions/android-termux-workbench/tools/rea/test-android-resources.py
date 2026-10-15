#!/usr/bin/env python
import pathlib
import shutil
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
sys.path.insert(0, str(ROOT / "tools/rea"))
from android_resources import inspect_resources, zip_surface


class AndroidResourcesTest(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="resources-", dir=BASE / "inbox"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_real_owned_apk_resource_and_manifest_surface(self):
        apk = BASE / "samples/owned.apk"
        result = inspect_resources([apk], self.work)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["packages"][0]["name"], "owned.acceptance")
        self.assertIn("(root)", result["units"][0]["categories"])

    def test_surface_does_not_extract_content(self):
        result = zip_surface(BASE / "samples/owned.apk")
        self.assertIn("categories", result)
        self.assertNotIn("content", result)


if __name__ == "__main__":
    unittest.main()
