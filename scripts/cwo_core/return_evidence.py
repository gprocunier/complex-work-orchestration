from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from .policy_schema import strict_json_loads
from .return_common import add_weighted_signal, extend_signals, malpractice_signal_weights, strip_fenced_blocks
from .return_sections import SectionReader
from .types import EvidenceQuality, ResearchEvidenceQuality, ResearchEvidenceRejection, ReturnSignal


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
_RESEARCH_SCORE_FIELDS = ("source_reliability_score", "reliability_score", "relevance_score")
_RESEARCH_ITEM_FIELDS = ("claim", "source_locator", "citation_span", "quoted_excerpt", "support_type", *_RESEARCH_SCORE_FIELDS)
_RESEARCH_ITEM_WRAPPERS = ("research_evidence_items", "evidence_items")
_CONTRADICTION_WRAPPERS = ("research_contradictions", "contradictions")
_REFLECTION_WRAPPERS = ("research_reflection", "reflection")
_RESEARCH_WRAPPER_TYPES = {
    **dict.fromkeys(_RESEARCH_ITEM_WRAPPERS + _CONTRADICTION_WRAPPERS, list),
    **dict.fromkeys(_REFLECTION_WRAPPERS, dict),
}

MAX_RETURN_JSON_CHARS = 1_048_576
MAX_RETURN_JSON_DEPTH = 64
MAX_RETURN_JSON_DOCUMENTS = 64
_JSON_STRUCTURE = re.compile(r'\\.|"|[\[\]{}]', re.S)
_JSON_PREFIX = re.compile(r"\s*[\[{]")
_JSON_LIKE_PREFIX = re.compile(r'\s*(?:\{(?=\s*(?:["}]|$))|\[(?=\s*(?:[\[\]{"0-9-]|true\b|false\b|null\b|NaN\b|Infinity\b|$)))')
_MARKDOWN_CITATION = re.compile(r"\s*\[[0-9]+\]\s*\S")
_SURROGATE = re.compile(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}|[\ud800-\udfff]")
_FENCED_BLOCK = re.compile(
    r"(?ms)^[ \t]*(?P<fence>```|~~~)(?P<language>[A-Za-z0-9_-]*)[ \t]*(?:\n|\Z)"
    r"(?P<body>.*?)(?:^[ \t]*(?P=fence)[ \t]*(?:\n|\Z)|(?P<unclosed>\Z))"
)


class ReturnJsonError(ValueError):
    def __init__(self, code: str, *, field: str | None = None, item_index: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.field = field
        self.item_index = item_index

    def record(self, section: str, index: int, occurrence: int | None) -> ResearchEvidenceRejection:
        rejection: ResearchEvidenceRejection = {"section": section, "document_index": index, "code": self.code}
        if occurrence is not None:
            rejection["occurrence_index"] = occurrence
        if self.item_index is not None:
            rejection["item_index"] = self.item_index
        if self.field is not None:
            rejection["field"] = self.field
        return rejection


def _check_json_depth(text: str) -> None:
    quoted = False
    depth = 0
    for match in _JSON_STRUCTURE.finditer(text):
        token = match[0]
        if token == '"':
            quoted = not quoted
        elif not quoted and len(token) == 1:
            depth += 1 if token in "[{" else -1
            if depth > MAX_RETURN_JSON_DEPTH:
                raise ReturnJsonError("nesting-too-deep")


def _bounded_return_json(text: str) -> dict[str, Any] | list[Any]:
    _check_json_depth(text)
    try:
        value = strict_json_loads(text)
        if _SURROGATE.search(text):
            json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError) as exc:
        raise ReturnJsonError("invalid-json") from exc
    if not isinstance(value, (dict, list)):
        raise ReturnJsonError("invalid-document-type")
    return value


def _starts_structured_json(text: str, start: int, end: int, *, legacy: bool) -> bool:
    if legacy:
        return bool(_JSON_LIKE_PREFIX.match(text, start, end) and not _MARKDOWN_CITATION.match(text, start, end))
    return bool(_JSON_PREFIX.match(text, start, end))


def _structured_candidates(value: str, *, legacy: bool) -> Iterator[tuple[int, int, bool]]:
    if _starts_structured_json(value, 0, len(value), legacy=legacy):
        yield 0, len(value), False
        return
    for match in _FENCED_BLOCK.finditer(value):
        language = match["language"].lower()
        start, end = match.span("body")
        if language == "json" or (not language and _starts_structured_json(value, start, end, legacy=legacy)):
            yield start, end, match["unclosed"] is not None


def _structured_documents(
    value: str, *, section: str, rejections: list[ResearchEvidenceRejection] | None = None, occurrence: int | None = None,
) -> Iterator[dict[str, Any] | list[Any]]:
    for index, (start, end, unclosed) in enumerate(_structured_candidates(value, legacy=section == "Evidence"), start=1):
        try:
            if len(value) > MAX_RETURN_JSON_CHARS:
                raise ReturnJsonError("section-too-large")
            if index > MAX_RETURN_JSON_DOCUMENTS:
                raise ReturnJsonError("too-many-documents")
            if unclosed:
                raise ReturnJsonError("unterminated-fence")
            document = _bounded_return_json(value[start:end].strip())
            if rejections is not None:
                _check_research_document(document, section)
            yield document
        except ReturnJsonError as exc:
            if rejections is None:
                raise
            rejections.append(exc.record(section, index, occurrence))
            if exc.code in {"section-too-large", "too-many-documents"}:
                break


def structured_json_values(value: str) -> list[Any]:
    """Parse whole-value or fenced return JSON, raising on malformed data."""
    return list(_structured_documents(value, section="Research evidence"))


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
    return value if type(value) is int and 0 <= value <= 100 else None


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


def _research_items(document: dict[str, Any] | list[Any], section: str) -> list[Any]:
    if isinstance(document, list):
        return [] if section == "Research contradictions" else document
    if isinstance(document.get("research_evidence_items"), list):
        return document["research_evidence_items"]
    if section == "Research evidence":
        if isinstance(document.get("evidence_items"), list):
            return document["evidence_items"]
        if any(key in document for key in _RESEARCH_ITEM_FIELDS):
            return [document]
    return []


def _check_research_scores(item: dict[str, Any], index: int) -> None:
    for field in _RESEARCH_SCORE_FIELDS:
        if field in item and research_score_value(item[field]) is None:
            raise ReturnJsonError("invalid-score", field=field, item_index=index)


def _check_research_list(items: list[Any], *, scores: bool, field: str | None = None) -> None:
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            if scores:
                _check_research_scores(item, index)
        elif not isinstance(item, str):
            raise ReturnJsonError("invalid-list-item", field=field, item_index=index)


def _check_research_document(document: dict[str, Any] | list[Any], section: str) -> None:
    if isinstance(document, list):
        _check_research_list(document, scores=section != "Research contradictions")
        return
    for field, wrapper_type in _RESEARCH_WRAPPER_TYPES.items():
        if field not in document or (field == "evidence_items" and section != "Research evidence"):
            continue
        contents = document[field]
        if not isinstance(contents, wrapper_type):
            raise ReturnJsonError("invalid-wrapper-type", field=field)
        if isinstance(contents, list):
            _check_research_list(contents, scores=field in _RESEARCH_ITEM_WRAPPERS, field=field)
    if section == "Research evidence" and not any(field in document for field in _RESEARCH_ITEM_WRAPPERS):
        _check_research_scores(document, 1)


def research_evidence_from_sections(sections: dict[str, str], *, reader: "SectionReader | None" = None) -> dict[str, Any]:
    reader = reader or SectionReader(sections)
    items: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    reflection: dict[str, Any] = {}
    rejections: list[ResearchEvidenceRejection] = []

    def merge_document(document: dict[str, Any] | list[Any], *, section: str) -> None:
        if isinstance(document, dict):
            if isinstance(document.get("research_contradictions"), list):
                contradictions.extend(as_research_list(document["research_contradictions"]))
            elif isinstance(document.get("contradictions"), list):
                contradictions.extend(as_research_list(document["contradictions"]))
            elif section == "Research contradictions" and document:
                contradictions.extend(as_research_list(document))

            if isinstance(document.get("research_reflection"), dict):
                reflection.update(as_research_reflection(document["research_reflection"]))
            elif isinstance(document.get("reflection"), dict):
                reflection.update(as_research_reflection(document["reflection"]))
            elif section == "Research reflection" and document:
                reflection.update(as_research_reflection(document))
        elif section == "Research contradictions":
            contradictions.extend(as_research_list(document))

    for section in ("Research evidence", "Research contradictions", "Research reflection", "Evidence"):
        occurrences = reader.occurrences(section)
        for index, value in enumerate(occurrences, start=1):
            documents = _structured_documents(
                value, section=section, rejections=rejections, occurrence=index if len(occurrences) > 1 else None,
            )
            for document in documents:
                if index == len(occurrences):
                    items.extend(as_research_list(_research_items(document, section)))
                    merge_document(document, section=section)

    unresolved = [
        item
        for item in contradictions
        if str(item.get("resolution_status") or item.get("status") or "").strip().lower()
        not in {"resolved", "handled", "accepted-risk", "open-risk", "not-applicable", "none", "n/a"}
    ]
    return {
        "research_evidence_present": any((items, contradictions, reflection, rejections)) or research_sections_present(sections, reader=reader),
        "research_evidence_items": items,
        "research_contradictions": contradictions,
        "research_reflection": reflection,
        "research_unresolved_contradiction_count": len(unresolved),
        "research_replan_recommended": booleanish(reflection.get("replan_recommended")),
        **({"research_evidence_rejections": rejections} if rejections else {}),
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
        add_weighted_signal(
            signals, weights, "missing_research_evidence",
            "research return has no structured research evidence items",
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
        reliability = research_score_value(item.get("source_reliability_score", item.get("reliability_score")))
        relevance = research_score_value(item.get("relevance_score"))

        if not claim:
            add_weighted_signal(signals, weights, "missing_research_claim", f"{label} is missing a claim")
        if not source_locator:
            add_weighted_signal(
                signals, weights, "missing_research_source_locator",
                f"{label} is missing a reusable source locator",
            )
        if not citation_span and not quoted_excerpt:
            add_weighted_signal(
                signals, weights, "missing_research_grounding",
                f"{label} is missing citation span or quoted excerpt",
            )
        if source_type not in RESEARCH_SOURCE_TYPES:
            add_weighted_signal(
                signals, weights, "weak_research_source_type",
                f"{label} has unknown source type {source_type or 'empty'}",
            )
        if support_type not in RESEARCH_SUPPORT_TYPES:
            add_weighted_signal(
                signals, weights, "weak_research_support_type",
                f"{label} has missing or unsupported support type",
            )
        if access_status not in RESEARCH_ACCESS_STATUSES:
            add_weighted_signal(
                signals, weights, "weak_research_access_status",
                f"{label} has unknown access status {access_status or 'empty'}",
            )
        if reliability is None or reliability < 60:
            add_weighted_signal(
                signals, weights, "weak_research_reliability",
                f"{label} has missing or low source reliability score",
            )
        if relevance is None or relevance < 60:
            add_weighted_signal(
                signals, weights, "weak_research_relevance",
                f"{label} has missing or low relevance score",
            )
        if (
            support_type in {"supports", "refutes"}
            and access_status in {"abstract-only", "paywalled", "restricted", "inaccessible"}
            and (not quoted_excerpt or re.search(r"\babstract[- ]only|abstract\b", quoted_excerpt, re.I))
        ):
            add_weighted_signal(
                signals, weights, "inaccessible_research_support",
                f"{label} treats limited-access evidence as full support",
            )

    if research["research_unresolved_contradiction_count"]:
        add_weighted_signal(
            signals, weights, "unresolved_research_contradiction",
            "research contradictions are unresolved or missing a handled status",
        )

    reflection = dict(research["research_reflection"])
    if not reflection:
        add_weighted_signal(
            signals, weights, "missing_research_reflection",
            "research return is missing coverage/factual-support reflection",
        )
    else:
        if research["research_replan_recommended"]:
            add_weighted_signal(
                signals, weights, "research_replan_recommended",
                "research reflection recommends replanning or follow-up queries",
            )
        gaps = reflection.get("gaps") or reflection.get("followup_queries") or reflection.get("follow_up_queries")
        if gaps and not research["research_replan_recommended"]:
            add_weighted_signal(
                signals, weights, "research_reflection_gaps",
                "research reflection names gaps without a replan recommendation",
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
        add_weighted_signal(signals, weights, "missing_evidence", "evidence is missing or too thin")
    elif not has_research_evidence and (len(evidence_words) < 8 or not items):
        add_weighted_signal(
            signals, weights, "thin_evidence",
            "evidence has too little detail for independent reuse",
        )

    if items and claim_items and not supported_items and not has_research_evidence:
        add_weighted_signal(
            signals, weights, "claim_only_evidence",
            "evidence contains only unsupported claim-style items",
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
        add_weighted_signal(
            signals, weights, "vague_evidence",
            "evidence relies on generic or non-actionable wording",
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
            add_weighted_signal(
                signals, weights, "weak_evidence_provenance",
                "evidence provenance does not identify a reusable source",
            )

    extend_signals(signals, research_quality["research_evidence_signals"])

    legacy_score = max(0, 100 - min(100, sum(int(signal["weight"]) for signal in signals)))
    score = min(legacy_score, int(research_quality["research_evidence_score"])) if has_research_evidence else legacy_score
    return {
        "evidence_quality_score": score,
        "evidence_quality_signals": signals,
        "evidence_quality_signal_categories": sorted({str(signal["category"]) for signal in signals}),
    }
