from __future__ import annotations

import json
import re
from typing import Any

from .return_common import add_signal, malpractice_signal_weights, strip_fenced_blocks
from .return_sections import SectionReader
from .types import EvidenceQuality, ResearchEvidenceQuality, ReturnSignal


RESEARCH_SOURCE_TYPES = {
    "academic-paper",
    "primary-doc",
    "official-doc",
    "reputable-news",
    "blog-forum",
    "internal-rag",
    "packet",
    "repo",
    "unknown",
}

RESEARCH_SUPPORT_TYPES = {"supports", "refutes", "contradicts", "background"}
RESEARCH_ACCESS_STATUSES = {"full", "abstract-only", "paywalled", "restricted", "inaccessible", "unknown"}


def structured_json_values(value: str) -> list[Any]:
    """Parse whole-value or fenced JSON blocks from a return section."""

    values: list[Any] = []
    stripped = value.strip()
    if stripped and stripped[0] in "[{":
        try:
            values.append(json.loads(stripped))
        except json.JSONDecodeError:
            pass

    fence_pattern = re.compile(r"(?ms)^\s*```([A-Za-z0-9_-]*)\s*\n(.*?)^\s*```\s*$")
    for match in fence_pattern.finditer(value):
        language = match.group(1).strip().lower()
        if language and language != "json":
            continue
        candidate = match.group(2).strip()
        if not candidate or candidate[0] not in "[{":
            continue
        try:
            values.append(json.loads(candidate))
        except json.JSONDecodeError:
            continue
    return values


def as_research_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        normalized: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                normalized.append(dict(item))
            elif str(item).strip():
                normalized.append({"claim": str(item).strip()})
        return normalized
    if isinstance(value, dict):
        return [dict(value)]
    if str(value).strip():
        return [{"claim": str(value).strip()}]
    return []


def as_research_reflection(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def research_score_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        score = int(value)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, score))


def booleanish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "required", "recommended"}


def research_sections_present(sections: dict[str, str], *, reader: "SectionReader | None" = None) -> bool:
    reader = reader or SectionReader(sections)
    return bool(
        reader.value("Research evidence")
        or reader.value("Research contradictions")
        or reader.value("Research reflection")
        or re.search(r"\bresearch_evidence_items\b", reader.value("Evidence"), re.I)
    )


def research_evidence_from_sections(sections: dict[str, str], *, reader: "SectionReader | None" = None) -> dict[str, Any]:
    reader = reader or SectionReader(sections)
    evidence_section = reader.value("Research evidence")
    contradiction_section = reader.value("Research contradictions")
    reflection_section = reader.value("Research reflection")
    legacy_evidence = reader.value("Evidence")

    items: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    reflection: dict[str, Any] = {}

    def merge_document(document: Any, *, source: str) -> None:
        nonlocal reflection
        if isinstance(document, dict):
            if isinstance(document.get("research_evidence_items"), list):
                items.extend(as_research_list(document["research_evidence_items"]))
            elif isinstance(document.get("evidence_items"), list) and source == "research-evidence":
                items.extend(as_research_list(document["evidence_items"]))
            elif source == "research-evidence" and any(
                key in document
                for key in ["claim", "source_locator", "citation_span", "quoted_excerpt", "support_type"]
            ):
                items.extend(as_research_list(document))

            if isinstance(document.get("research_contradictions"), list):
                contradictions.extend(as_research_list(document["research_contradictions"]))
            elif isinstance(document.get("contradictions"), list):
                contradictions.extend(as_research_list(document["contradictions"]))
            elif source == "research-contradictions" and document:
                contradictions.extend(as_research_list(document))

            if isinstance(document.get("research_reflection"), dict):
                reflection.update(as_research_reflection(document["research_reflection"]))
            elif isinstance(document.get("reflection"), dict):
                reflection.update(as_research_reflection(document["reflection"]))
            elif source == "research-reflection" and document:
                reflection.update(as_research_reflection(document))
        elif isinstance(document, list):
            if source == "research-contradictions":
                contradictions.extend(as_research_list(document))
            else:
                items.extend(as_research_list(document))

    for document in structured_json_values(evidence_section):
        merge_document(document, source="research-evidence")
    for document in structured_json_values(contradiction_section):
        merge_document(document, source="research-contradictions")
    for document in structured_json_values(reflection_section):
        merge_document(document, source="research-reflection")
    for document in structured_json_values(legacy_evidence):
        merge_document(document, source="legacy-evidence")

    unresolved = [
        item
        for item in contradictions
        if str(item.get("resolution_status") or item.get("status") or "").strip().lower()
        not in {"resolved", "handled", "accepted-risk", "open-risk", "not-applicable", "none", "n/a"}
    ]
    return {
        "research_evidence_present": bool(items or contradictions or reflection or research_sections_present(sections, reader=reader)),
        "research_evidence_items": items,
        "research_contradictions": contradictions,
        "research_reflection": reflection,
        "research_unresolved_contradiction_count": len(unresolved),
        "research_replan_recommended": booleanish(reflection.get("replan_recommended")),
    }


def score_research_evidence(
    sections: dict[str, str],
    *,
    reader: "SectionReader | None" = None,
) -> ResearchEvidenceQuality:
    weights = malpractice_signal_weights()
    reader = reader or SectionReader(sections)
    research = research_evidence_from_sections(sections, reader=reader)
    signals: list[ReturnSignal] = []
    if not research["research_evidence_present"]:
        return {
            **research,
            "research_evidence_score": 100,
            "research_evidence_signals": [],
            "research_evidence_signal_categories": [],
        }

    items: list[dict[str, Any]] = list(research["research_evidence_items"])
    if not items:
        add_signal(
            signals,
            category="missing_research_evidence",
            reason="research return has no structured research evidence items",
            weight=weights["missing_research_evidence"],
        )

    for index, item in enumerate(items, start=1):
        label = str(item.get("claim_id") or item.get("source_id") or f"item-{index}")
        claim = str(item.get("claim") or "").strip()
        source_locator = str(item.get("source_locator") or item.get("locator") or "").strip()
        citation_span = str(item.get("citation_span") or "").strip()
        quoted_excerpt = str(item.get("quoted_excerpt") or item.get("excerpt") or "").strip()
        source_type = str(item.get("source_type") or "unknown").strip().lower().replace("_", "-")
        support_type = str(item.get("support_type") or "").strip().lower().replace("_", "-")
        access_status = str(item.get("access_status") or "unknown").strip().lower().replace("_", "-")
        reliability = research_score_value(item.get("source_reliability_score") or item.get("reliability_score"))
        relevance = research_score_value(item.get("relevance_score"))

        if not claim:
            add_signal(
                signals,
                category="missing_research_claim",
                reason=f"{label} is missing a claim",
                weight=weights["missing_research_claim"],
            )
        if not source_locator:
            add_signal(
                signals,
                category="missing_research_source_locator",
                reason=f"{label} is missing a reusable source locator",
                weight=weights["missing_research_source_locator"],
            )
        if not citation_span and not quoted_excerpt:
            add_signal(
                signals,
                category="missing_research_grounding",
                reason=f"{label} is missing citation span or quoted excerpt",
                weight=weights["missing_research_grounding"],
            )
        if source_type not in RESEARCH_SOURCE_TYPES:
            add_signal(
                signals,
                category="weak_research_source_type",
                reason=f"{label} has unknown source type {source_type or 'empty'}",
                weight=weights["weak_research_source_type"],
            )
        if support_type not in RESEARCH_SUPPORT_TYPES:
            add_signal(
                signals,
                category="weak_research_support_type",
                reason=f"{label} has missing or unsupported support type",
                weight=weights["weak_research_support_type"],
            )
        if access_status not in RESEARCH_ACCESS_STATUSES:
            add_signal(
                signals,
                category="weak_research_access_status",
                reason=f"{label} has unknown access status {access_status or 'empty'}",
                weight=weights["weak_research_access_status"],
            )
        if reliability is None or reliability < 60:
            add_signal(
                signals,
                category="weak_research_reliability",
                reason=f"{label} has missing or low source reliability score",
                weight=weights["weak_research_reliability"],
            )
        if relevance is None or relevance < 60:
            add_signal(
                signals,
                category="weak_research_relevance",
                reason=f"{label} has missing or low relevance score",
                weight=weights["weak_research_relevance"],
            )
        if (
            support_type in {"supports", "refutes"}
            and access_status in {"abstract-only", "paywalled", "restricted", "inaccessible"}
            and (not quoted_excerpt or re.search(r"\babstract[- ]only|abstract\b", quoted_excerpt, re.I))
        ):
            add_signal(
                signals,
                category="inaccessible_research_support",
                reason=f"{label} treats limited-access evidence as full support",
                weight=weights["inaccessible_research_support"],
            )

    if research["research_unresolved_contradiction_count"]:
        add_signal(
            signals,
            category="unresolved_research_contradiction",
            reason="research contradictions are unresolved or missing a handled status",
            weight=weights["unresolved_research_contradiction"],
        )

    reflection = dict(research["research_reflection"])
    if not reflection:
        add_signal(
            signals,
            category="missing_research_reflection",
            reason="research return is missing coverage/factual-support reflection",
            weight=weights["missing_research_reflection"],
        )
    else:
        if research["research_replan_recommended"]:
            add_signal(
                signals,
                category="research_replan_recommended",
                reason="research reflection recommends replanning or follow-up queries",
                weight=weights["research_replan_recommended"],
            )
        gaps = reflection.get("gaps") or reflection.get("followup_queries") or reflection.get("follow_up_queries")
        if gaps and not research["research_replan_recommended"]:
            add_signal(
                signals,
                category="research_reflection_gaps",
                reason="research reflection names gaps without a replan recommendation",
                weight=weights["research_reflection_gaps"],
            )

    score = max(0, 100 - min(100, sum(int(signal["weight"]) for signal in signals)))
    return {
        **research,
        "research_evidence_score": score,
        "research_evidence_signals": signals,
        "research_evidence_signal_categories": sorted({str(signal["category"]) for signal in signals}),
    }


def evidence_items_from_sections(sections: dict[str, str], *, reader: "SectionReader | None" = None) -> list[dict[str, str]]:
    reader = reader or SectionReader(sections)
    evidence = strip_fenced_blocks(reader.value("Evidence"))
    items: list[dict[str, str]] = []
    for line in evidence.splitlines():
        normalized = line.strip().lstrip("-* ").strip()
        if not normalized:
            continue
        kind = "claim"
        if re.search(r"\b(test|pytest|compile|validate|command|bd |git )\b", normalized, re.I):
            kind = "command-or-test"
        elif re.search(
            r"\b(files?|paths?|lines?|schemas?|polic(?:y|ies)|packets?|manifests?|snippets?|artifacts?|"
            r"sha-?256|hash(?:es)?|sections?|docs?|readmes?|scripts?)\b",
            normalized,
            re.I,
        ):
            kind = "file-or-policy"
        items.append({"kind": kind, "text": normalized})
    return items


def score_evidence_quality(
    sections: dict[str, str],
    *,
    research_quality: dict[str, Any] | None = None,
    reader: "SectionReader | None" = None,
) -> EvidenceQuality:
    reader = reader or SectionReader(sections)
    weights = malpractice_signal_weights()
    signals: list[ReturnSignal] = []
    evidence = strip_fenced_blocks(reader.value("Evidence"))
    provenance = reader.value("Evidence provenance")
    items = evidence_items_from_sections(sections, reader=reader)
    research_quality = research_quality or score_research_evidence(sections, reader=reader)
    has_research_evidence = bool(research_quality["research_evidence_present"])
    supported_items = [item for item in items if item.get("kind") in {"command-or-test", "file-or-policy"}]
    claim_items = [item for item in items if item.get("kind") == "claim"]
    evidence_words = evidence.split()

    if not evidence and not has_research_evidence:
        add_signal(
            signals,
            category="missing_evidence",
            reason="evidence is missing or too thin",
            weight=weights["missing_evidence"],
        )
    elif not has_research_evidence and (len(evidence_words) < 8 or not items):
        add_signal(
            signals,
            category="thin_evidence",
            reason="evidence has too little detail for independent reuse",
            weight=weights["thin_evidence"],
        )

    if items and claim_items and not supported_items and not has_research_evidence:
        add_signal(
            signals,
            category="claim_only_evidence",
            reason="evidence contains only unsupported claim-style items",
            weight=weights["claim_only_evidence"],
        )

    generic_patterns = [
        r"\bappears?\s+(?:fine|good|reasonable|solid)\b",
        r"\blooks?\s+(?:fine|good|reasonable|solid)\b",
        r"\b(no\s+issues?|nothing\s+concerning)\b",
        r"\b(best\s+practice|robust|comprehensive|well[- ]structured)\b",
        r"\b(consider|ensure|should|could|might)\b.{0,80}\b(best|robust|clear|proper|appropriate)\b",
        r"\b(no\s+actionable\s+findings?)\b",
    ]
    generic_hits = [
        item
        for item in items
        if item.get("kind") == "claim"
        and any(re.search(pattern, str(item.get("text", "")), re.I) for pattern in generic_patterns)
    ]
    if generic_hits:
        add_signal(
            signals,
            category="vague_evidence",
            reason="evidence relies on generic or non-actionable wording",
            weight=weights["vague_evidence"],
        )

    if provenance and not has_research_evidence:
        provenance_supported = bool(
            re.search(
                r"\b(packet|manifest|snippet|artifact|file|path|line|schema|policy|command|test|log|diff|patch|section)\b",
                provenance,
                re.I,
            )
        )
        if not provenance_supported:
            add_signal(
                signals,
                category="weak_evidence_provenance",
                reason="evidence provenance does not identify a reusable source",
                weight=weights["weak_evidence_provenance"],
            )

    for signal in research_quality["research_evidence_signals"]:
        add_signal(
            signals,
            category=str(signal["category"]),
            reason=str(signal["reason"]),
            weight=int(signal["weight"]),
        )

    legacy_score = max(0, 100 - min(100, sum(int(signal["weight"]) for signal in signals)))
    score = min(legacy_score, int(research_quality["research_evidence_score"])) if has_research_evidence else legacy_score
    return {
        "evidence_quality_score": score,
        "evidence_quality_signals": signals,
        "evidence_quality_signal_categories": sorted({str(signal["category"]) for signal in signals}),
    }
