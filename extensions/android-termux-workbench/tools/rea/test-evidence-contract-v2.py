#!/usr/bin/env python
"""Evidence Contract v2 compatibility and provenance tests."""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from evidence_contract import (
    make_evidence, make_evidence_graph_v2, make_evidence_v2,
    make_graph_edge_v2, merge_evidence, validate_evidence_v2,
)

SHA_A = "a" * 64
SHA_B = "b" * 64

def observation(*, session="session-one", observed="2026-10-15T08:30:00+08:00"):
    return make_evidence_v2(
        provider="rea-dex-layer", kind="class", fidelity="static_fact",
        locator={"class": "example.Main"}, summary="Indexed example.Main",
        input_sha256=SHA_A, tool_versions={"rea": "2.0", "jadx": "1.5.6"},
        config_sha256=SHA_B, evidence_type="STATIC", match_quality="EXACT",
        session_ref=session, authorization_ref="task:rea-upgrade-v2",
        invocation_ref="command:index", observed_at=observed,
        source_refs=[{"path": "classes.dex", "class": "example.Main"}],
        digest=SHA_A, confidence="HIGH", confidence_score=1.0,
        metadata={"dex_index": 0},
    )

class EvidenceContractV2Test(unittest.TestCase):
    def test_v1_shape_is_unchanged(self):
        item = make_evidence(provider="legacy", kind="fact", fidelity="static_fact",
                             locator={"path": "classes.dex"}, summary="legacy")
        self.assertEqual(set(item), {
            "schema_version", "evidence_id", "provider", "kind", "fidelity",
            "confidence", "locator", "summary", "sha256", "metadata",
        })
        self.assertEqual(item["schema_version"], "1.0")

    def test_v2_normalizes_time_and_contains_provenance(self):
        item = observation()
        self.assertEqual(item["observed_at"], "2026-10-15T00:30:00Z")
        self.assertEqual(item["evidence_type"], "STATIC")
        self.assertEqual(item["match_quality"], "EXACT")
        self.assertEqual(item["tool_versions"]["jadx"], "1.5.6")
        self.assertEqual(validate_evidence_v2(item), item)

    def test_same_claim_different_sessions_are_distinct_observations(self):
        first, second = observation(session="session-one"), observation(session="session-two")
        self.assertEqual(first["claim_fingerprint"], second["claim_fingerprint"])
        self.assertNotEqual(first["evidence_id"], second["evidence_id"])

    def test_invalid_fields_are_rejected(self):
        base = dict(provider="rea", kind="class", fidelity="static_fact",
                    locator={"class": "x.Y"}, summary="x", input_sha256=SHA_A,
                    tool_versions={"rea": "2"}, config_sha256=SHA_B,
                    evidence_type="STATIC", match_quality="EXACT",
                    session_ref="s", authorization_ref="a",
                    observed_at="2026-10-15T00:00:00Z")
        for key, value in (("input_sha256", "bad"), ("evidence_type", "LIVE"),
                           ("match_quality", "FUZZY"), ("confidence_score", 1.1),
                           ("observed_at", "2026-10-15T00:00:00")):
            candidate = dict(base); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                make_evidence_v2(**candidate)

    def test_review_requires_attribution_and_tamper_is_detected(self):
        with self.assertRaisesRegex(ValueError, "REVIEWER_REF_REQUIRED"):
            make_evidence_v2(provider="rea", kind="class", fidelity="static_fact",
                locator={"class": "x.Y"}, summary="x", input_sha256=SHA_A,
                tool_versions={"rea": "2"}, config_sha256=SHA_B,
                evidence_type="STATIC", match_quality="EXACT", session_ref="s",
                authorization_ref="a", human_confirmation="CONFIRMED")
        tampered = copy.deepcopy(observation()); tampered["summary"] = "tampered"
        with self.assertRaisesRegex(ValueError, "CLAIM_FINGERPRINT_MISMATCH"):
            validate_evidence_v2(tampered)

    def test_graph_validates_endpoints_and_deduplicates_nodes(self):
        first, second = observation(session="session-one"), observation(session="session-two")
        edge = make_graph_edge_v2(source=first["evidence_id"], target=second["evidence_id"],
                                  relation="CORROBORATES", match_quality="EXACT")
        graph = make_evidence_graph_v2([first, first, second], edges=[edge],
                                       generated_at="2026-10-15T00:31:00Z")
        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual(len(graph["edges"]), 1)
        invalid = dict(edge); invalid["target"] = "ev2_missing"
        with self.assertRaisesRegex(ValueError, "GRAPH_EDGE_ENDPOINT_MISSING"):
            make_evidence_graph_v2([first], edges=[invalid])

    def test_merge_accepts_v1_and_v2_but_v2_graph_rejects_v1(self):
        old = make_evidence(provider="legacy", kind="fact", fidelity="static_fact",
                            locator={"path": "classes.dex"}, summary="legacy")
        new = observation()
        self.assertEqual(len(merge_evidence([[old], [new]])), 2)
        with self.assertRaisesRegex(ValueError, "V2_GRAPH_REQUIRES_V2_EVIDENCE"):
            make_evidence_graph_v2([old, new])

if __name__ == "__main__":
    unittest.main()
