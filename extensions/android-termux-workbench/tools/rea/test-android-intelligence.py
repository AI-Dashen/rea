#!/usr/bin/env python
import hashlib
import pathlib
import shutil
import sys
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/rea"))
from android_intelligence import build_android_intelligence

BASE = ROOT / "run/rea-b06dd042"
WORK = BASE / "inbox/intelligence-test"


class AndroidIntelligenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        WORK.mkdir(parents=True, exist_ok=True)
        cls.sources = WORK / "sources"
        cls.sources.mkdir(exist_ok=True)
        (cls.sources / "MainActivity.java").write_text(
            """package com.example;
public class MainActivity {
  static { System.loadLibrary("owned"); }
  public native int bridge();
  void login() {
    String endpoint = "https://api.example.com/v1/login?token=secret";
    OkHttpClient client = null;
    Cipher cipher = null;
    boolean debug = Debug.isDebuggerConnected();
    String root = "/system/bin/su";
  }
}
"""
        )
        cls.native = (BASE / "samples/owned.elf").read_bytes() + (
            b"\0Java_com_example_MainActivity_bridge\0JNI_OnLoad\0"
        )
        cls.apk = WORK / "fixture.apk"
        with zipfile.ZipFile(cls.apk, "w") as archive:
            archive.writestr("lib/arm64-v8a/libowned.so", cls.native)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(WORK, ignore_errors=True)

    def test_architecture_hotspots_and_jni_links(self):
        profile = {
            "sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
            "dex": [{"path": "classes.dex", "sha256": "0" * 64, "bytes": 1}],
            "native_libraries": [
                {
                    "path": "lib/arm64-v8a/libowned.so",
                    "abi": "arm64-v8a",
                    "sha256": hashlib.sha256(self.native).hexdigest(),
                    "zip_16k_alignment": "FAIL",
                    "elf": {"page_16k_load_alignment": "PASS"},
                }
            ],
        }
        package = {
            "package_name": "com.example",
            "manifest": {
                "text": """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><application><activity android:name=".MainActivity" android:exported="true"/></application></manifest>"""
            },
        }
        result = build_android_intelligence(self.apk, self.sources, package, profile)
        self.assertEqual(result["components"][0]["kind"], "activity")
        self.assertEqual(result["network_origins"], ["https://api.example.com"])
        self.assertGreater(result["hotspots"]["authentication"]["count"], 0)
        self.assertGreater(result["hotspots"]["network"]["count"], 0)
        self.assertGreater(result["hotspots"]["cryptography"]["count"], 0)
        self.assertGreater(result["hotspots"]["root_detection"]["count"], 0)
        self.assertGreater(result["hotspots"]["debug_detection"]["count"], 0)
        self.assertEqual(
            result["native_links"]["load_libraries"],
            {"owned": ["com.example.MainActivity"]},
        )
        self.assertTrue(
            any(node["kind"] == "jni_symbol" for node in result["graph"]["nodes"])
        )
        serialized = repr(result)
        self.assertNotIn("token=secret", serialized)
        self.assertNotIn("/system/bin/su", serialized)

    def test_output_is_deterministic(self):
        profile = {
            "sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
            "dex": [],
            "native_libraries": [],
        }
        package = {"package_name": "com.example", "manifest": {"text": ""}}
        first = build_android_intelligence(self.apk, self.sources, package, profile)
        second = build_android_intelligence(self.apk, self.sources, package, profile)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
