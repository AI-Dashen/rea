#!/usr/bin/env python
"""Validate and normalize explicitly supplied, sanitized Android runtime evidence."""
from __future__ import annotations

import json
import re

from android_container import ensure_target
from evidence_contract import make_evidence

ALLOWED_TOP = {"schema_version", "observations"}
ALLOWED_OBSERVATION = {"provider", "kind", "locator", "summary", "observed_at", "confidence", "metadata"}
ALLOWED_LOCATOR = {"package", "component", "class", "method", "native_symbol", "event"}
ALLOWED_METADATA = {"count", "duration_ms", "result", "source"}
SAFE_VALUE = re.compile(r"^[\w .:/@$+()#-]{1,256}$", re.UNICODE)
SECRET_KEY = re.compile(r"token|secret|password|cookie|authorization|credential|private[_-]?key", re.I)


def _clean_object(value: object, allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label}_OBJECT_REQUIRED")
    extra = set(value) - allowed
    if extra:
        raise ValueError(f"{label}_FIELD_DENIED:{sorted(extra)[0]}")
    if any(SECRET_KEY.search(str(key)) for key in value):
        raise ValueError("SECRET_FIELD_DENIED")
    return value


def _safe_scalar(value: object, label: str) -> object:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if not isinstance(value, str) or not SAFE_VALUE.fullmatch(value):
        raise ValueError(f"{label}_VALUE_DENIED")
    return value


def load_dynamic_evidence(path_value: str) -> tuple[dict, list[dict]]:
    path = ensure_target(path_value)
    if not path.is_file() or path.suffix.lower() != ".json":
        raise ValueError("DYNAMIC_JSON_REQUIRED")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("DYNAMIC_EVIDENCE_TOO_LARGE")
    payload = json.loads(path.read_text())
    _clean_object(payload, ALLOWED_TOP, "DYNAMIC")
    if payload.get("schema_version") != 1:
        raise ValueError("DYNAMIC_SCHEMA_UNSUPPORTED")
    observations = payload.get("observations")
    if not isinstance(observations, list) or len(observations) > 1000:
        raise ValueError("DYNAMIC_OBSERVATIONS_INVALID")
    evidence = []
    for index, raw in enumerate(observations):
        item = _clean_object(raw, ALLOWED_OBSERVATION, "OBSERVATION")
        provider = _safe_scalar(item.get("provider", "runtime-import"), "PROVIDER")
        kind = _safe_scalar(item.get("kind"), "KIND")
        summary = _safe_scalar(item.get("summary"), "SUMMARY")
        locator = _clean_object(item.get("locator"), ALLOWED_LOCATOR, "LOCATOR")
        locator = {key: _safe_scalar(value, "LOCATOR") for key, value in locator.items()}
        metadata = _clean_object(item.get("metadata", {}), ALLOWED_METADATA, "METADATA")
        metadata = {key: _safe_scalar(value, "METADATA") for key, value in metadata.items()}
        if not locator or not kind or not summary:
            raise ValueError(f"DYNAMIC_OBSERVATION_INCOMPLETE:{index}")
        if item.get("observed_at") is not None:
            metadata["observed_at"] = _safe_scalar(item["observed_at"], "OBSERVED_AT")
        evidence.append(make_evidence(
            provider=str(provider), kind=str(kind), fidelity="dynamic_observed",
            locator=locator, summary=str(summary),
            confidence=str(item.get("confidence", "HIGH")), metadata=metadata,
        ))
    return {"source": str(path), "observation_count": len(evidence)}, evidence
