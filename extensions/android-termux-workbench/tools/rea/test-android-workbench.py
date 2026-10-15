#!/usr/bin/env python
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/rea/android-workbench.py"
SPEC = importlib.util.spec_from_file_location("android_workbench", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AndroidWorkbenchTest(unittest.TestCase):
    def test_content_key_is_versioned_and_deterministic(self):
        first = MODULE.content_key("a" * 64)
        second = MODULE.content_key("a" * 64)
        other = MODULE.content_key("b" * 64)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        selector = MODULE.content_key("a" * 64, native_string="ASR")
        self.assertNotEqual(first, selector)

    def test_target_scope(self):
        owned = MODULE.allowed_target(
            str(ROOT / "run/rea-b06dd042/samples/owned.apk")
        )
        self.assertEqual(owned.name, "owned.apk")
        with self.assertRaisesRegex(ValueError, "TARGET_DENIED"):
            MODULE.allowed_target(str(ROOT / "AGENTS.md"))

    def test_verified_result_requires_real_evidence(self):
        output = ROOT / "run/rea-b06dd042/workbench-test-result.json"
        payload = {
            "status": "VERIFIED",
            "sha256": "c" * 64,
            "android_intelligence": {},
            "container": {},
            "evidence": [{"evidence_id": "owned"}],
        }
        output.write_text(json.dumps(payload))
        try:
            self.assertTrue(
                MODULE.verified_result(
                    {
                        "analysis_json": str(output.relative_to(ROOT)),
                        "target_sha256": "c" * 64,
                    }
                )
            )
            payload.pop("container")
            output.write_text(json.dumps(payload))
            self.assertFalse(
                MODULE.verified_result(
                    {
                        "analysis_json": str(output.relative_to(ROOT)),
                        "target_sha256": "c" * 64,
                    }
                )
            )
        finally:
            output.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
