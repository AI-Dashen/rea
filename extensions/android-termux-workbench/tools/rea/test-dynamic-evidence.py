#!/usr/bin/env python
import json
import pathlib
import shutil
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
sys.path.insert(0, str(ROOT / "tools/rea"))
from dynamic_evidence import load_dynamic_evidence


class DynamicEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="dynamic-", dir=BASE / "inbox"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def write(self, payload):
        path = self.work / "runtime.json"
        path.write_text(json.dumps(payload))
        return path

    def test_sanitized_runtime_observation_is_normalized(self):
        path = self.write({"schema_version": 1, "observations": [{
            "provider": "owned-runtime", "kind": "method_call",
            "locator": {"package": "owned.acceptance", "class": "OwnedArithmetic", "method": "add"},
            "summary": "Observed one authorized method call", "metadata": {"count": 1}
        }]})
        source, evidence = load_dynamic_evidence(str(path))
        self.assertEqual(source["observation_count"], 1)
        self.assertEqual(evidence[0]["fidelity"], "dynamic_observed")

    def test_secret_fields_are_rejected(self):
        path = self.write({"schema_version": 1, "observations": [{
            "kind": "network", "locator": {"event": "request"},
            "summary": "Observed", "metadata": {"token": "no"}
        }]})
        with self.assertRaisesRegex(ValueError, "FIELD_DENIED|SECRET_FIELD_DENIED"):
            load_dynamic_evidence(str(path))

    def test_outside_scope_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TARGET_DENIED"):
            load_dynamic_evidence(str(ROOT / "AGENTS.md"))


if __name__ == "__main__":
    unittest.main()
