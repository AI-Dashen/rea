#!/usr/bin/env python
"""Versioned evidence contracts shared by REA Workbench providers.

The v1 API is intentionally frozen for existing providers. New providers should
use the explicit v2 constructors, which make an observation reproducible and
auditable without changing the current analysis pipeline.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Iterable

SCHEMA_VERSION = "1.0"
SCHEMA_VERSION_V2 = "2.0"
FIDELITIES = {
    "static_fact",
    "decompiled_approx",
    "disassembled",
    "dynamic_observed",
    "heuristic",
}
CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}
EVIDENCE_TYPES = {"STATIC", "DYNAMIC", "INFERRED"}
MATCH_QUALITIES = {"EXACT", "PARTIAL", "APPROXIMATE"}
HUMAN_CONFIRMATION_STATES = {"UNREVIEWED", "CONFIRMED", "REJECTED"}
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}_REQUIRED")
    return value.strip()


def _sha256(value: object, label: str) -> str:
    text = _required_text(value, label)
    if not _SHA256.fullmatch(text):
        raise ValueError(f"INVALID_{label}")
    return text.lower()


def _timestamp(value: str | None, label: str) -> str:
    if value is None:
        parsed = datetime.now(timezone.utc)
    else:
        text = _required_text(value, label)
        try:
            parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        except ValueError as error:
            raise ValueError(f"INVALID_{label}") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"INVALID_{label}")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(provider: str, kind: str, locator: dict, digest: str | None = None) -> str:
    """Return the unchanged v1 content identifier."""
    payload = {"provider": provider, "kind": kind, "locator": locator, "digest": digest}
    return "ev_" + hashlib.sha256(_canonical_json(payload).encode()).hexdigest()[:24]


def make_evidence(*, provider: str, kind: str, fidelity: str, locator: dict,
                  summary: str, digest: str | None = None,
                  confidence: str = "HIGH", metadata: dict | None = None) -> dict:
    """Build a v1 record. Kept shape-compatible with Workbench v1."""
    if fidelity not in FIDELITIES:
        raise ValueError("INVALID_FIDELITY")
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError("INVALID_CONFIDENCE")
    if not isinstance(locator, dict) or not locator:
        raise ValueError("LOCATOR_REQUIRED")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("SUMMARY_REQUIRED")
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": stable_id(provider, kind, locator, digest),
        "provider": provider,
        "kind": kind,
        "fidelity": fidelity,
        "confidence": confidence,
        "locator": locator,
        "summary": summary.strip(),
        "sha256": digest,
        "metadata": metadata or {},
    }


def merge_evidence(groups: Iterable[Iterable[dict]]) -> list[dict]:
    """Merge v1 or v2 records without silently losing provenance."""
    merged: dict[str, dict] = {}
    for group in groups:
        for item in group:
            version = item.get("schema_version", SCHEMA_VERSION)
            if version == SCHEMA_VERSION:
                if item.get("fidelity") not in FIDELITIES:
                    raise ValueError("INVALID_FIDELITY")
            elif version == SCHEMA_VERSION_V2:
                validate_evidence_v2(item)
            else:
                raise ValueError("UNSUPPORTED_SCHEMA_VERSION")
            key = item.get("evidence_id")
            if not key:
                raise ValueError("EVIDENCE_ID_REQUIRED")
            prior = merged.get(key)
            if prior is not None and prior != item:
                raise ValueError("EVIDENCE_ID_COLLISION")
            merged[key] = item
    return [merged[key] for key in sorted(merged)]


def _tool_versions(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValueError("TOOL_VERSIONS_REQUIRED")
    normalized = {}
    for name, version in value.items():
        normalized[_required_text(name, "TOOL_NAME")] = _required_text(version, "TOOL_VERSION")
    return dict(sorted(normalized.items()))


def _source_refs(value: Iterable[dict] | None) -> list[dict]:
    refs = []
    for raw in value or []:
        if not isinstance(raw, dict) or not raw:
            raise ValueError("INVALID_SOURCE_REF")
        refs.append(dict(raw))
    return sorted(refs, key=_canonical_json)


def make_human_confirmation(
    status: str = "UNREVIEWED",
    *,
    reviewer_ref: str | None = None,
    confirmed_at: str | None = None,
    note: str | None = None,
) -> dict:
    if status not in HUMAN_CONFIRMATION_STATES:
        raise ValueError("INVALID_HUMAN_CONFIRMATION")
    if status == "UNREVIEWED":
        if reviewer_ref is not None or confirmed_at is not None:
            raise ValueError("UNREVIEWED_CONFIRMATION_HAS_REVIEWER")
        return {"status": status, "reviewer_ref": None, "confirmed_at": None, "note": note}
    reviewer = _required_text(reviewer_ref, "REVIEWER_REF")
    return {
        "status": status,
        "reviewer_ref": reviewer,
        "confirmed_at": _timestamp(confirmed_at, "CONFIRMED_AT"),
        "note": note,
    }


def _claim_fingerprint(payload: dict) -> str:
    """Stable replay key; deliberately excludes run/session and review state."""
    claim = {
        key: payload[key]
        for key in (
            "provider", "kind", "fidelity", "locator", "summary", "sha256",
            "input_sha256", "tool_versions", "config_sha256", "evidence_type",
            "match_quality", "source_refs", "metadata",
        )
    }
    return "claim_" + hashlib.sha256(_canonical_json(claim).encode()).hexdigest()


def _observation_id(payload: dict) -> str:
    identity = {
        "claim_fingerprint": payload["claim_fingerprint"],
        "observed_at": payload["observed_at"],
        "session_ref": payload["session_ref"],
        "authorization_ref": payload["authorization_ref"],
        "invocation_ref": payload["invocation_ref"],
    }
    return "ev2_" + hashlib.sha256(_canonical_json(identity).encode()).hexdigest()[:32]


def make_evidence_v2(
    *,
    provider: str,
    kind: str,
    fidelity: str,
    locator: dict,
    summary: str,
    input_sha256: str,
    tool_versions: dict[str, str],
    config_sha256: str,
    evidence_type: str,
    match_quality: str,
    session_ref: str,
    authorization_ref: str,
    observed_at: str | None = None,
    invocation_ref: str | None = None,
    source_refs: Iterable[dict] | None = None,
    digest: str | None = None,
    confidence: str = "HIGH",
    confidence_score: float | None = None,
    human_confirmation: str = "UNREVIEWED",
    reviewer_ref: str | None = None,
    confirmed_at: str | None = None,
    confirmation_note: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Build a traceable Evidence Contract v2 observation.

    ``claim_fingerprint`` identifies the reproducible claim. ``evidence_id``
    identifies this concrete observation, so two sessions never overwrite each
    other's provenance or human review.
    """
    provider = _required_text(provider, "PROVIDER")
    kind = _required_text(kind, "KIND")
    if fidelity not in FIDELITIES:
        raise ValueError("INVALID_FIDELITY")
    if not isinstance(locator, dict) or not locator:
        raise ValueError("LOCATOR_REQUIRED")
    summary = _required_text(summary, "SUMMARY")
    input_sha256 = _sha256(input_sha256, "INPUT_SHA256")
    config_sha256 = _sha256(config_sha256, "CONFIG_SHA256")
    if digest is not None:
        digest = _sha256(digest, "SHA256")
    tools = _tool_versions(tool_versions)
    if evidence_type not in EVIDENCE_TYPES:
        raise ValueError("INVALID_EVIDENCE_TYPE")
    if match_quality not in MATCH_QUALITIES:
        raise ValueError("INVALID_MATCH_QUALITY")
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError("INVALID_CONFIDENCE")
    if confidence_score is not None:
        if isinstance(confidence_score, bool) or not isinstance(confidence_score, (int, float)):
            raise ValueError("INVALID_CONFIDENCE_SCORE")
        if not 0.0 <= float(confidence_score) <= 1.0:
            raise ValueError("INVALID_CONFIDENCE_SCORE")
        confidence_score = float(confidence_score)
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("INVALID_METADATA")

    payload = {
        "schema_version": SCHEMA_VERSION_V2,
        "provider": provider,
        "kind": kind,
        "fidelity": fidelity,
        "locator": dict(locator),
        "summary": summary,
        "sha256": digest,
        "input_sha256": input_sha256,
        "tool_versions": tools,
        "config_sha256": config_sha256,
        "invocation_ref": (
            _required_text(invocation_ref, "INVOCATION_REF")
            if invocation_ref is not None else None
        ),
        "observed_at": _timestamp(observed_at, "OBSERVED_AT"),
        "evidence_type": evidence_type,
        "match_quality": match_quality,
        "session_ref": _required_text(session_ref, "SESSION_REF"),
        "authorization_ref": _required_text(authorization_ref, "AUTHORIZATION_REF"),
        "source_refs": _source_refs(source_refs),
        "confidence": confidence,
        "confidence_score": confidence_score,
        "human_confirmation": make_human_confirmation(
            human_confirmation,
            reviewer_ref=reviewer_ref,
            confirmed_at=confirmed_at,
            note=confirmation_note,
        ),
        "metadata": dict(metadata or {}),
    }
    payload["claim_fingerprint"] = _claim_fingerprint(payload)
    payload["evidence_id"] = _observation_id(payload)
    return payload


def validate_evidence_v2(item: dict) -> dict:
    """Validate and return a v2 record without rewriting its provenance."""
    if not isinstance(item, dict) or item.get("schema_version") != SCHEMA_VERSION_V2:
        raise ValueError("V2_EVIDENCE_REQUIRED")
    confirmation = item.get("human_confirmation")
    if not isinstance(confirmation, dict):
        raise ValueError("INVALID_HUMAN_CONFIRMATION")
    expected = make_evidence_v2(
        provider=item.get("provider"), kind=item.get("kind"), fidelity=item.get("fidelity"),
        locator=item.get("locator"), summary=item.get("summary"),
        input_sha256=item.get("input_sha256"), tool_versions=item.get("tool_versions"),
        config_sha256=item.get("config_sha256"), invocation_ref=item.get("invocation_ref"),
        observed_at=item.get("observed_at"), evidence_type=item.get("evidence_type"),
        match_quality=item.get("match_quality"), session_ref=item.get("session_ref"),
        authorization_ref=item.get("authorization_ref"), source_refs=item.get("source_refs"),
        digest=item.get("sha256"), confidence=item.get("confidence"),
        confidence_score=item.get("confidence_score"), human_confirmation=confirmation.get("status"),
        reviewer_ref=confirmation.get("reviewer_ref"), confirmed_at=confirmation.get("confirmed_at"),
        confirmation_note=confirmation.get("note"), metadata=item.get("metadata"),
    )
    if item.get("claim_fingerprint") != expected["claim_fingerprint"]:
        raise ValueError("CLAIM_FINGERPRINT_MISMATCH")
    if item.get("evidence_id") != expected["evidence_id"]:
        raise ValueError("EVIDENCE_ID_MISMATCH")
    return item


def make_graph_edge_v2(
    *, source: str, target: str, relation: str,
    match_quality: str, confidence: str = "HIGH",
    confidence_score: float | None = None,
) -> dict:
    if match_quality not in MATCH_QUALITIES:
        raise ValueError("INVALID_MATCH_QUALITY")
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError("INVALID_CONFIDENCE")
    if confidence_score is not None and (
        isinstance(confidence_score, bool)
        or not isinstance(confidence_score, (int, float))
        or not 0.0 <= float(confidence_score) <= 1.0
    ):
        raise ValueError("INVALID_CONFIDENCE_SCORE")
    return {
        "source": _required_text(source, "EDGE_SOURCE"),
        "target": _required_text(target, "EDGE_TARGET"),
        "relation": _required_text(relation, "EDGE_RELATION"),
        "match_quality": match_quality,
        "confidence": confidence,
        "confidence_score": None if confidence_score is None else float(confidence_score),
    }


def make_evidence_graph_v2(
    evidence: Iterable[dict],
    *,
    edges: Iterable[dict] = (),
    generated_at: str | None = None,
) -> dict:
    """Create a deterministic v2 graph envelope from validated observations."""
    nodes = merge_evidence([evidence])
    if any(node.get("schema_version") != SCHEMA_VERSION_V2 for node in nodes):
        raise ValueError("V2_GRAPH_REQUIRES_V2_EVIDENCE")
    node_ids = {node["evidence_id"] for node in nodes}
    normalized_edges = []
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("INVALID_GRAPH_EDGE")
        normalized = make_graph_edge_v2(
            source=edge.get("source"), target=edge.get("target"),
            relation=edge.get("relation"), match_quality=edge.get("match_quality"),
            confidence=edge.get("confidence", "HIGH"),
            confidence_score=edge.get("confidence_score"),
        )
        if normalized["source"] not in node_ids or normalized["target"] not in node_ids:
            raise ValueError("GRAPH_EDGE_ENDPOINT_MISSING")
        normalized_edges.append(normalized)
    normalized_edges.sort(key=_canonical_json)
    fingerprint = hashlib.sha256(_canonical_json({
        "nodes": [node["evidence_id"] for node in nodes],
        "edges": normalized_edges,
    }).encode()).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION_V2,
        "graph_id": "graph_" + fingerprint[:32],
        "generated_at": _timestamp(generated_at, "GENERATED_AT"),
        "nodes": nodes,
        "edges": normalized_edges,
    }
