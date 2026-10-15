#!/usr/bin/env python
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("evidence_contract", ROOT / "tools/rea/evidence_contract.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceContractTest(unittest.TestCase):
    def test_fidelity_is_explicit_and_merge_is_deterministic(self):
        item = MODULE.make_evidence(
            provider="jadx", kind="method", fidelity="decompiled_approx",
            locator={"class": "a.B", "method": "c"},
            summary="Approximate Java representation",
        )
        self.assertEqual(item["fidelity"], "decompiled_approx")
        self.assertEqual(MODULE.merge_evidence([[item], [item]]), [item])

    def test_invalid_fidelity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_FIDELITY"):
            MODULE.make_evidence(
                provider="x", kind="x", fidelity="source",
                locator={"x": 1}, summary="x",
            )


if __name__ == "__main__":
    unittest.main()
