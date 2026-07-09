from __future__ import annotations

import re
from typing import Any

from .policy import load_contracting_controls


def malpractice_signal_weights() -> dict[str, int]:
    configured = load_contracting_controls().get("malpractice_policy", {}).get("signal_weights", {})
    defaults = {
        "missing_evidence": 20,
        "thin_evidence": 20,
        "claim_only_evidence": 25,
        "vague_evidence": 15,
        "weak_evidence_provenance": 10,
        "non_reproducible_validation": 15,
        "vague_recommendation": 15,
        "missing_confidence": 10,
        "unclear_scope": 10,
        "missing_evidence_provenance": 10,
        "missing_attestation_or_repro_note": 10,
        "missing_share_boundary_conformance": 10,
        "missing_peer_review_disposition": 10,
        "provider_policy_misrepresentation": 25,
        "provider_conflict_disposition_noncompliant": 20,
        "internal_narration_or_preamble": 15,
        "missing_research_evidence": 25,
        "missing_research_claim": 10,
        "missing_research_source_locator": 20,
        "missing_research_grounding": 20,
        "weak_research_source_type": 10,
        "weak_research_support_type": 10,
        "weak_research_access_status": 10,
        "weak_research_reliability": 10,
        "weak_research_relevance": 10,
        "inaccessible_research_support": 15,
        "unresolved_research_contradiction": 20,
        "missing_research_reflection": 15,
        "research_replan_recommended": 10,
        "research_reflection_gaps": 10,
    }
    defaults.update({key: int(value) for key, value in configured.items()})
    return defaults


def add_signal(signals: list[dict[str, Any]], *, category: str, reason: str, weight: int) -> None:
    if any(signal.get("category") == category and signal.get("reason") == reason for signal in signals):
        return
    signals.append({"category": category, "reason": reason, "weight": int(weight)})


def strip_fenced_blocks(text: str) -> str:
    return re.sub(r"(?ms)^\s*(```|~~~)[^\n]*\n.*?^\s*\1\s*$", "", text)


def negative_field(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    if re.match(r"^(compliant|approved|authorized|within scope|in scope)\b", normalized):
        return False
    return bool(
        re.match(r"^(no|false|none|not observed|not present|not applicable|n/a|na)\b", normalized)
        or re.search(r"\b(no|not observed|not present|none)\s+(boundary violation|secret|personal-data spill|scope creep|patch)\b", normalized)
    )


def affirmative_field(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized or negative_field(value):
        return False
    return bool(
        re.match(r"^(yes|true|required|present|observed|found|confirmed|compliant|approved|authorized|unauthorized|unapproved)\b", normalized)
        or re.search(r"\b(violation observed|secret spill|personal-data spill|outside assigned scope|broadened scope|without approval)\b", normalized)
    )


def nonempty_work_field(value: str) -> bool:
    return bool(value.strip()) and not negative_field(value)
