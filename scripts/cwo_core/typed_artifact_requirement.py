"""Literal UTF-8 file requirements for the existing offline artifact observer.

The recorded requirement is the input, not a conclusion inferred from a digest
or delivered bytes. Prose requirements still need applicable independent review.
This adapter establishes consistency, not authenticity of the baseline's source.
"""
from __future__ import annotations

import hashlib
from typing import Any

from . import requirement_baseline as rb

PREFIX = "cwo-required-file-v1:"


def check_evidence_kind(requirement: str, evidence_kind: str) -> None:
    """A recognized literal file obligation needs the existing artifact observer."""
    if requirement.startswith(PREFIX) and evidence_kind != "artifact":
        raise ValueError("declared literal file requirement requires artifact evidence")


def artifact_expectation(requirement: str) -> dict[str, str] | None:
    """Translate an explicit literal requirement; leave ordinary prose unchanged.

    The existing baseline bounds the requirement text and records its reference
    independently of candidate observations. No reference is fetched or executed.
    """
    if not requirement.startswith(PREFIX):
        return None
    if len(requirement) > rb.MAX_TEXT:
        raise ValueError("literal requirement exceeds the baseline text limit")
    try:
        source = rb.load_record(requirement[len(PREFIX):])
    except rb.RequirementBaselineError as exc:
        raise ValueError("literal requirement must be an unambiguous JSON object") from exc
    if set(source) != {"path", "utf8"}:
        raise ValueError("literal requirement needs exactly path and utf8")
    if type(source["path"]) is not str or type(source["utf8"]) is not str:
        raise ValueError("literal requirement path and utf8 must be strings")
    return {"op": "regular-file-sha256", "path": source["path"],
            "sha256": hashlib.sha256(source["utf8"].encode("utf-8")).hexdigest()}


def check_artifact_expectation(requirement: str, predicate: dict[str, Any]) -> None:
    """Refuse a supplied predicate that contradicts the declared literal requirement."""
    expected = artifact_expectation(requirement)
    if expected is not None and predicate != expected:
        raise ValueError("artifact expectation contradicts the declared literal requirement")
