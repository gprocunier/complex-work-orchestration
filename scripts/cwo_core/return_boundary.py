from __future__ import annotations

import re
import shlex

from .return_common import nonempty_work_field, strip_fenced_blocks
from .return_sections import SectionReader, section_value


def redacted_packet_command_allowed(value: str) -> bool:
    if not nonempty_work_field(value):
        return True
    normalized = value.strip().lower()
    safe_reader_commands = {
        "chatgpt-share-local-reader",
        "read_chatgpt_share.py",
        "ingest_chatgpt_share_return.py",
    }
    prohibited_command_patterns = [
        r"\bpython(?:3)?\s+scripts/",
        r"\bpython(?:3)?\s+-m\s+(unittest|pytest|compileall|mypy|ruff)\b",
        r"\b(pytest|tox|make|npm|pnpm|yarn|go test|cargo test)\b",
        r"(^|\s)(git|bd)\s+",
        r"(^|\s)\./scripts/",
    ]
    shell_control_patterns = [
        r"[;&|<>`$]",
        r"\$\(",
        r"\n",
        r"\r",
    ]
    if any(re.search(pattern, normalized, re.I) for pattern in prohibited_command_patterns + shell_control_patterns):
        return False
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        return False
    if not tokens:
        return True
    command = tokens[0].strip().lower().rstrip(".")
    command_basename = re.split(r"[\\/]", command)[-1]
    if command in safe_reader_commands or command_basename in safe_reader_commands:
        return True
    return False


def negates_direct_access_claim(line: str) -> bool:
    normalized = line.strip().lower()
    if not normalized:
        return False
    return bool(
        re.search(
            r"\b(no|not|never|without|cannot|can't|did not|does not|do not|has no|have no)\b.{0,80}"
            r"\b(repo|repository|checkout|workspace|local file|file inspection|command execution|test execution|"
            r"inspection|inspect|read|ran|run|executed|mutation)\b",
            normalized,
        )
        or re.search(
            r"\b(no|not|never|without|cannot|can't|did not|does not|do not|has no|have no)\b.{0,80}"
            r"\b(access|execute|executed|inspect|inspected|inspection|read|run|ran|mutation)\b",
            normalized,
        )
    )


def redacted_packet_direct_access_findings(text: str) -> list[str]:
    findings: list[str] = []
    patterns = [
        (
            r"\b(i|we)\s+(?:am|are|was|were)?\s*(?:analyz(?:e|ing|ed)|analys(?:e|ing|ed)|inspect(?:ing|ed)?|"
            r"read(?:ing)?|view(?:ing|ed)?|open(?:ing|ed)?|check(?:ing|ed)?)\s+"
            r"(?:the\s+)?(?:repo|repository|directory structure|workspace|checkout)\b",
            "redacted packet return claims direct repository or workspace inspection",
        ),
        (
            r"\b(i|we)\s+(?:will|did|have)?\s*(?:view|inspect|read|open|analyz(?:e|ed)|analys(?:e|ed)|check(?:ed)?)\s+"
            r"`?(?:scripts|docs|policy|tests|schemas|examples|/home/)[^`\n]*",
            "redacted packet return claims direct local file inspection",
        ),
        (
            r"\bfile:///",
            "redacted packet return cites local file URL evidence",
        ),
        (
            r"\b(all\s+)?(?:code paths|files|policy schemas|tests?)\b.{0,80}\b(analyzed|analysed|inspected|read|viewed)\b"
            r".{0,80}\b(local workspace|active checkout|repository)\b",
            "redacted packet return claims local workspace analysis",
        ),
    ]
    for line in strip_fenced_blocks(text).splitlines():
        if negates_direct_access_claim(line):
            continue
        for pattern, reason in patterns:
            if re.search(pattern, line, re.I) and reason not in findings:
                findings.append(reason)
    return findings


def redacted_packet_validation_claim_unsupported(value: str) -> bool:
    if not nonempty_work_field(value):
        return False
    normalized = value.strip().lower()
    packet_qualifiers = [
        "based on packet",
        "packet validation evidence",
        "reported validation",
        "reported in packet",
        "packet's reported",
        "provided evidence",
        "supplied evidence",
        "reviewed provided",
        "reviewed supplied",
        "cannot independently",
        "not independently",
        "share page parsed",
        "local chatgpt share reader",
        "local share reader",
        "direct-to-chatgpt/local parser",
    ]
    if any(qualifier in normalized for qualifier in packet_qualifiers):
        return False
    return bool(
        re.search(r"\b(passed|verified|validated|compiled|completed|ran|executed)\b", normalized)
        and re.search(r"\b(unit tests?|tests?|repository validation|validate_repository|install(?:ation)? dry-run|compileall)\b", normalized)
    )


def _normalized_declaration_value(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9_ \-]", " ", value.strip().lower())).strip()


def normalize_review_surface(value: str, *, share_boundary: str | None = None) -> str:
    normalized = _normalized_declaration_value(value).replace("_", "-").replace(" ", "-")
    aliases = {
        "packet": "packet-only",
        "packetonly": "packet-only",
        "redacted-packet": "packet-only",
        "packet-level": "packet-only",
        "packet-based": "packet-only",
        "public-pr": "public-pr-readonly",
        "public-pr-read-only": "public-pr-readonly",
        "public-pull-request": "public-pr-readonly",
        "public-pull-request-readonly": "public-pr-readonly",
        "pr-readonly": "public-pr-readonly",
        "pr-read-only": "public-pr-readonly",
        "repo-read-only": "repo-readonly",
        "repository-readonly": "repo-readonly",
        "repository-read-only": "repo-readonly",
        "patch": "patch-branch",
        "patchbranch": "patch-branch",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in {"packet-only", "public-pr-readonly", "repo-readonly", "patch-branch"}:
        return normalized
    boundary = (share_boundary or "").strip().lower()
    if boundary == "redacted-packet":
        return "packet-only"
    if boundary in {"repo-readonly", "patch-branch"}:
        return boundary
    return normalized or "unknown"


def is_packet_only_declared(value: str) -> bool:
    normalized = _normalized_declaration_value(value)
    if not normalized:
        return False
    return bool(
        re.search(r"\b(packet[- ]?only|redacted[- ]?packet|packet\s+only|packet-level|packet based|redacted[- ]packet)\b", normalized)
    ) or bool(re.search(r"\bpacket manifest only\b", normalized))


def is_merge_readiness_go_claim(text: str) -> bool:
    if not text.strip():
        return False
    positive_patterns = [
        r"\b(?:go for|going for)\b.{0,120}\b(?:pr|pull request|merge request|merge|readiness|release|deploy|publish|ship)\b",
        r"\bready for\b.{0,120}\b(?:pr|pull request|merge request|merge|readiness|release|deploy|publish|ship)\b",
        r"\b(?:approve|approved|approving)\b.{0,120}\b(?:pr|pull request|merge request|merge|readiness|release|deploy|publish|ship)\b",
        r"\bpr\b.{0,120}\b(?:is|looks|appears|seems|will be|would be)\b.{0,40}\b(?:ready|approved)\b",
        r"\b(?:good to go|g2g|good-to-go|go/no-go)\b",
        r"\bready\b.{0,120}\b(?:to|for)\b.{0,30}\b(?:merge|ship|release|deploy)\b",
    ]
    negative_nearby = re.compile(
        r"\b(not|no|never|can't|cannot|won't|do not|don't|not yet|not now|blocked|blocked on|blocked by)\b.{0,80}(?:go|ready|approve|approval|approved|approval)\b",
        re.I,
    )
    for sentence in re.split(r"[.!?]\s+|\n+", text.lower()):
        normalized = sentence.strip()
        if not normalized:
            continue
        for pattern in positive_patterns:
            match = re.search(pattern, normalized, re.I)
            if not match:
                continue
            if negative_nearby.search(normalized):
                continue
            return True
    return False


def parse_master_review_surface_controls(
    sections: dict[str, str],
    reader: "SectionReader | None" = None,
    *,
    share_boundary: str | None = None,
) -> dict[str, object]:
    reader = reader or SectionReader(sections)
    review_surface = reader.value("Review surface")
    source_inspection = reader.value("Source inspection")
    sources_inspected = reader.value("Sources inspected")
    sources_not_inspected = reader.value("Sources not inspected")
    independent_verification = reader.value("Independent verification")
    packet_reported_claims = reader.value("Packet-reported claims")
    status_text = reader.value("Status")
    summary_text = reader.value("Summary")
    next_bead_text = reader.value("Recommended next bead")
    readiness_text = " ".join(
        part
        for part in [status_text, summary_text, next_bead_text]
        if part.strip()
    )

    review_surface_normalized = normalize_review_surface(review_surface, share_boundary=share_boundary)
    source_inspection_normalized = _normalized_declaration_value(source_inspection)
    review_surface_packet_only = is_packet_only_declared(review_surface)
    source_inspection_packet_only = is_packet_only_declared(source_inspection)
    uninspected_text = "\n".join([source_inspection, sources_not_inspected, independent_verification])
    uninspected_pattern = (
        r"\b(not inspected|did not inspect|not reviewed|did not review|not read|did not read|not accessed|did not access|no direct)\b"
        r".{0,120}\b(pr|pull request|diff|repo|repository|source|code)\b"
    )
    source_first_uninspected_pattern = (
        r"\b(pr|pull request|diff|repo|repository|source|code)\b"
        r".{0,120}\b(was not|were not|is not|are not|not inspected|not reviewed|not read|not accessed|uninspected|unreviewed|unread|inaccessible)\b"
    )
    explicit_uninspected_required_source = bool(
        re.search(uninspected_pattern, uninspected_text, re.I)
        or re.search(source_first_uninspected_pattern, uninspected_text, re.I)
    )
    independently_inspected_required_source = bool(
        review_surface_normalized in {"public-pr-readonly", "repo-readonly", "patch-branch"}
        and re.search(
            r"\b(pr|pull request|diff|repo|repository|source|code)\b",
            "\n".join([source_inspection, sources_inspected, independent_verification]),
            re.I,
        )
    )
    go_claimed = bool(
        is_merge_readiness_go_claim(readiness_text)
        or is_merge_readiness_go_claim(reader.value("Attestation or reproducibility note", "Attestation/repro note"))
    )
    packet_only_go_hold = bool(
        (review_surface_packet_only or source_inspection_packet_only or review_surface_normalized == "packet-only")
        and go_claimed
        and not independently_inspected_required_source
    )
    source_mismatch_hold = bool(
        explicit_uninspected_required_source
        and go_claimed
        and not independently_inspected_required_source
    )
    mismatch_reasons: list[str] = []
    if packet_only_go_hold:
        mismatch_reasons.append("packet-only master review cannot provide unconditional PR/merge/readiness GO")
    if source_mismatch_hold:
        mismatch_reasons.append("return says required PR/diff/repo/source evidence was not inspected")
    return {
        "review_surface": review_surface_normalized,
        "source_inspection": source_inspection_normalized,
        "sources_inspected": sources_inspected,
        "sources_not_inspected": sources_not_inspected,
        "independent_verification": independent_verification,
        "packet_reported_claims": packet_reported_claims,
        "review_surface_packet_only": review_surface_packet_only,
        "source_inspection_packet_only": source_inspection_packet_only,
        "go_for_pr_merge_readiness_claimed": go_claimed,
        "review_surface_mismatch": bool(packet_only_go_hold or source_mismatch_hold),
        "review_surface_required_evidence_missing": bool(packet_only_go_hold or source_mismatch_hold),
        "review_surface_mismatch_reasons": mismatch_reasons,
        "packet_only_go_hold": packet_only_go_hold,
    }


def redacted_boundary_taint_findings(text: str, sections: dict[str, str], *, share_boundary: str | None) -> list[str]:
    if share_boundary != "redacted-packet":
        return []
    findings: list[str] = []
    commands_run = section_value(sections, "Commands run")
    validation = section_value(sections, "Validation result")
    if not redacted_packet_command_allowed(commands_run):
        findings.append("redacted packet return claims command or test execution")
    if redacted_packet_validation_claim_unsupported(validation):
        findings.append("redacted packet return claims unsupported validation")
    findings.extend(redacted_packet_direct_access_findings(text))
    deduped: list[str] = []
    for finding in findings:
        if finding not in deduped:
            deduped.append(finding)
    return deduped
