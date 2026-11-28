from __future__ import annotations

import re
import shlex
from collections.abc import Iterator

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


_ACCESS_NEGATION = re.compile(
    r"\b(?:no|not|never|without|cannot|can['’]t)\b.{0,80}\b(?:repo|repository|checkout|workspace|local file|"
    r"file inspection|command execution|test execution|inspection|inspect|inspected|read|ran|run|executed|mutation|access|execute)\b",
    re.I,
)


def negates_direct_access_claim(line: str) -> bool:
    return bool(_ACCESS_NEGATION.search(line))


_ACCESS_ACTOR = re.compile(r"\b(?:i|we)\s+")
_ACCESS_PAST = r"(?:analyzed|analysed|inspected|viewed|opened|checked)"
_ACCESS_PREDICATE = r"(?:analy[sz](?:e|ing|ed)|read(?:ing)?|(?:inspect|view|open|check)(?:ing|ed)?)"
_ACCESS_DENIED_CLAIM = r"(?P<denial>\b(?:did\s+not|didn['’]t)\s+claim\s+(?:that\s+)?)?"
_ACCESS_ASSERTION = (
    rf"{_ACCESS_DENIED_CLAIM}{_ACCESS_ACTOR.pattern}(?:(?:am|are|was|were|will|did|have|had)\s+)?{_ACCESS_PREDICATE}\s+"
)
_ACCESS_REPO = re.compile(rf"{_ACCESS_ASSERTION}(?:the\s+)?(?:repo|repository|directory structure|workspace|checkout)\b")
_ACCESS_FILE = re.compile(rf"{_ACCESS_ASSERTION}`?(?:scripts|docs|policy|tests|schemas|examples|/home/)")
_ACCESS_URL = re.compile(r"\bfile:///")
_ACCESS_PASSIVE_SUBJECT = r"(?:code paths|files|policy schemas|tests?)"
_ACCESS_PASSIVE = re.compile(
    rf"\b{_ACCESS_PASSIVE_SUBJECT}\b.{{0,80}}?\b(?P<predicate>analyzed|analysed|inspected|read|viewed)\b"
    r".{0,80}\b(?:local workspace|active checkout|repository)\b"
)
_ACCESS_SENTENCE_BREAK = re.compile(r"[.!?](?=\s|$)|[;\n]")
_ACCESS_CLAUSE_BREAK = re.compile(
    r"(?:,\s*|(?<!\s)\s*)\b(?:but|however|then|whereas|before|after|while|because)\b[\s,]+"
    rf"|(?:,\s*|\b(?:and|or|so)\s+)(?=(?:(?:and|or|so)\s+)?(?:i|we|they|he|she)\b|"
    rf"(?:(?:all|no|the|some)\s+)?{_ACCESS_PASSIVE_SUBJECT}\s+(?:was|were|has|have|had)\b)"
    rf"|(?:,\s*|\band\s+)(?={_ACCESS_PAST}\b)"
)
_ACCESS_IMPLIED_ACTOR = re.compile(rf"^\s*(?:{_ACCESS_PAST}|read)\b")


def _access_clauses(text: str) -> Iterator[str]:
    for sentence in _ACCESS_SENTENCE_BREAK.split(text):
        first_person = False
        for clause in _ACCESS_CLAUSE_BREAK.split(sentence):
            if first_person and _ACCESS_IMPLIED_ACTOR.match(clause):
                clause = f"i {clause}"
            first_person = bool(_ACCESS_ACTOR.search(clause))
            yield clause


def redacted_packet_direct_access_findings(text: str) -> list[str]:
    findings: dict[str, None] = {}
    for clause in _access_clauses(strip_fenced_blocks(text).lower()):
        if any(not claim["denial"] for claim in _ACCESS_REPO.finditer(clause)):
            findings["redacted packet return claims direct repository or workspace inspection"] = None
        if any(not claim["denial"] for claim in _ACCESS_FILE.finditer(clause)):
            findings["redacted packet return claims direct local file inspection"] = None
        url = _ACCESS_URL.search(clause)
        if url and not negates_direct_access_claim(clause[:url.start()]):
            findings["redacted packet return cites local file URL evidence"] = None
        passive = _ACCESS_PASSIVE.search(clause)
        if passive and not negates_direct_access_claim(clause[:passive.end("predicate")]):
            findings["redacted packet return claims local workspace analysis"] = None
    return list(findings)


_VALIDATION_ACTIVITY = r"(?:tests?|repository validation|validate_repository|install(?:ation)? dry[- ]run|compileall)"
_VALIDATION_PAST_VERB = r"(?:passed|failed(?!\s+to\b)|verified|validated|compiled|completed|ran|executed)"
_VALIDATION_RUN_VERB = (
    r"(?:ran|executed|did\s+(?:run|execute)|(?:have|has|had)\s+(?:already\s+)?(?:run|executed))"
)
_VALIDATION_ACTIVE_VERB = rf"(?:{_VALIDATION_RUN_VERB}|{_VALIDATION_PAST_VERB})"
_VALIDATION_OBJECT = (
    r"(?:(?:a|an|the|all|both|some|several|our|my|its|their|reported|unit|integration|regression|smoke|automated|local|full|\d+)\s+)*"
    rf"`?{_VALIDATION_ACTIVITY}\b"
)
_VALIDATION_ASSERTION = re.compile(
    rf"\b(?P<action>{_VALIDATION_ACTIVE_VERB})\s+{_VALIDATION_OBJECT}"
    rf"|\b{_VALIDATION_ACTIVITY}\b`?(?:\s+(?:suite|suites|execution|results?))?"
    rf"(?:\s+(?:for|of)\s+[\w./-]+(?:\s+[\w./-]+){{0,3}})?(?::\s*\d+)?"
    rf"(?:\s+(?:will|shall|would|should|could|might|may|must|be|been|has|have|had|was|were|is|are|not|never|\w+ly))*"
    rf"(?:\s+|:\s*)(?P<result>{_VALIDATION_PAST_VERB}|(?:was|were|has|have|had|been)\s+(?:\w+ly\s+)?run)\b"
)
_VALIDATION_CLAUSE_BREAK = re.compile(
    r";|\n[ \t]*\n|\n(?=[ \t]*(?:[-*+]|\d+\.)\s)|[.!?](?=\s|$)"
    r"|\b(?:but|however|whereas|before|after|while)\s+"
    rf"|(?:,\s*)?\b(?:and|or|then|so)\s+(?="
    rf"(?:i|we|they|reviewed|reviewing|(?:all|some|the|no|unit)\s+{_VALIDATION_ACTIVITY}|{_VALIDATION_ACTIVITY})\b)"
)
_VALIDATION_SOURCE = (
    r"(?:(?:the|this|an?)\s+)?(?:(?:attached|provided|supplied)\s+)?"
    r"(?:packet(?:['’]s)?(?:\s+(?:validation\s+)?(?:evidence|results?|report))?|"
    r"evidence|summary|report|logs?|attachment|manifest|results?|share page|local (?:chatgpt )?share reader)\b"
)
_VALIDATION_REPORTS = r"(?:says?|states?|notes?|reports?|records?|lists?|shows?|indicates?|confirms?|documents?)"
_VALIDATION_CITATION = (
    rf"(?:according to|per|based on|against|(?:as\s+)?(?:reported|recorded|shown|noted)\s+(?:in|by))\s+{_VALIDATION_SOURCE}"
    r"(?!\s+(?:instructions?|directions?|commands?)\b)"
)
_VALIDATION_REPORT_PREFIX = re.compile(
    rf"^\W*(?:packet validation evidence\s*:|{_VALIDATION_CITATION})|\b(?:verified|checked|confirmed)\s*,?\s+{_VALIDATION_CITATION}"
    rf"|\b{_VALIDATION_SOURCE}\s+{_VALIDATION_REPORTS}\b"
    r"|\b(?:its|their|(?:packet|summary|report)['’]s)\s+(?:reported|recorded)\b"
)
_VALIDATION_REPORT_SUFFIX = re.compile(
    rf"(?:\s+{_VALIDATION_PAST_VERB}\b)?\s*(?:,?\s*{_VALIDATION_CITATION}|,\s*{_VALIDATION_SOURCE}\s+{_VALIDATION_REPORTS}\s*$)"
)
_VALIDATION_EXECUTION = rf"(?:{_VALIDATION_RUN_VERB}|completed|compiled)"
_VALIDATION_DIRECT_RUN = re.compile(
    rf"^\W*(?:already\s+)?{_VALIDATION_EXECUTION}\b|\b(?:i|we)\s+(?:\w+ly\s+)?{_VALIDATION_EXECUTION}\s+{_VALIDATION_OBJECT}"
)
_VALIDATION_PERSONAL_AGENT = re.compile(r"\s+by\s+(?:me|us)\b")
_VALIDATION_COORDINATED_ACTION = re.compile(rf"(?:,\s*|\b(?:and|then)\s+)(?={_VALIDATION_ACTIVE_VERB}\b)")
_VALIDATION_BASE_FORM = re.compile(
    r"\b(?:did|do|does|will|shall|would|should|could|might|may|must)(?:n['’]t|\s+(?:not|never))?"
    r"(?:\s+\w+ly)?\s+(?:run|execute|verify|validate|compile|complete|pass|fail)\b"
)
_VALIDATION_NON_ASSERTION = re.compile(
    r"\b(?:will|shall|would|should|could|might|may|must|not|never|no|without|if|cannot|"
    r"plan(?:ned|ning)?|intend(?:ed)?|expect(?:ed|ing)?|scheduled|going to|(?:is|are) to be|yet to|"
    r"(?:ca|did|do|does|has|have|had|is|are|was|were|wo|should|could|would)n['’]t)\b"
)
_VALIDATION_RELATIVE_RUN = re.compile(
    rf"\b{_VALIDATION_ACTIVITY}\b(?:\s+(?:that|which))?\s+(?:i|we)\s+(?:already\s+)?{_VALIDATION_RUN_VERB}\b"
)
_VALIDATION_MARKDOWN_EMPHASIS = re.compile(r"(?<!\w)(?:\*\*?|__)(?=\w)|(?<=\w)(?:\*\*?|__)(?!\w)")


def _claims_completed_validation(clause: str) -> bool:
    if _VALIDATION_RELATIVE_RUN.search(clause):
        return True
    assertion = _VALIDATION_ASSERTION.search(clause)
    if not assertion:
        return False
    verb = "action" if assertion.group("action") else "result"
    if _VALIDATION_NON_ASSERTION.search(clause, 0, assertion.start(verb)):
        return False
    if _VALIDATION_DIRECT_RUN.search(clause) or _VALIDATION_PERSONAL_AGENT.match(clause, assertion.end()):
        return True
    return not (
        _VALIDATION_REPORT_PREFIX.search(clause, 0, assertion.end())
        or _VALIDATION_REPORT_SUFFIX.match(clause, assertion.end())
    )


def redacted_packet_validation_claim_unsupported(value: str) -> bool:
    normalized = _VALIDATION_MARKDOWN_EMPHASIS.sub("", value.lower())
    for clause in _VALIDATION_CLAUSE_BREAK.split(normalized):
        # A separate past-tense action can share a subject with a packet review
        # or a verb in the base form. Perfect-tense verbs can share an auxiliary.
        claims = [clause]
        if _VALIDATION_REPORT_PREFIX.search(clause) or _VALIDATION_BASE_FORM.search(clause):
            claims = _VALIDATION_COORDINATED_ACTION.split(clause)
        if any(_claims_completed_validation(claim) for claim in claims):
            return True
    return False


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
