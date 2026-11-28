"""Bounded findings from the addressed actions and evidence structure of a return."""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from typing import Iterator

from .return_sections import parse_return_header


DIRECTIVE = "structural_directive"
SCOPE = "structural_scope_change"
BYPASS = "structural_gate_bypass"
UNSUPPORTED = "structural_unsupported_claim"
STRUCTURAL_DESCRIPTIONS = {
    DIRECTIVE: "addresses the lead or a tool with a decision or execution instruction",
    SCOPE: "directs a change to the assigned objective, deliverable, or boundary",
    BYPASS: "asks to omit or waive review or validation",
    UNSUPPORTED: "asserts validation or release readiness without corresponding support",
}
_MAX_FINDINGS_PER_CATEGORY = 4
_MAX_JSON_CHARS = 262144

_ACTOR = (
    r"(?:orchestrat(?:ion|or)|architect|maintainer|reviewer|evaluator|grader|operator|release manager|"
    r"(?:[\w-]+\s+){0,2}lead(?: agent)?|"
    r"(?:tool|command|ci|automation|pipeline) (?:runner|executor)|"
    r"(?:release|deployment|evaluation|review) (?:team|pipeline)|tooling|automation|codex|assistant)"
)
_ROLE = rf"(?:the\s+)?{_ACTOR}"
_RECIPIENT = rf"(?:{_ROLE}|you|whoever (?:owns|handles) (?:the )?(?:review|handoff|approval|release))"
_MODAL = r"(?:may|can|could|should|must|will|(?:is|are) (?:to|expected to)|needs? to)"
_DIRECTING_MODAL = r"(?:(?!will\b)" + _MODAL + r")"
_ADDRESSEE = re.compile(
    rf"^(?:(?:for|to|dear)\s+)?{_RECIPIENT}\s*[:,|]\s*|"
    rf"^{_RECIPIENT}\s+{_DIRECTING_MODAL}\s+|"
    rf"^(?:(?:please\s+)?(?:ask|tell|have|instruct|direct)|(?:i|we)\s+(?:recommend|request)(?:\s+that)?)"
    rf"\s+{_RECIPIENT}\s+(?:to\s+|{_DIRECTING_MODAL}\s+)?"
)
_RECIPIENT_HEADING = re.compile(rf"(?:(?:for|to)\s+)?{_RECIPIENT}\s*:?\s*$")
_DECISION = (r"(?:authoritative|approv(?:al|ed)|complete|ready|verified|green|passed|binding|accepted|final|closed|"
             r"authorization|clearance|go[- ]ahead|sign[- ]off|permission|source of truth)")
_CONTROL_OBJECT = (r"(?:candidate|artifact|draft|branch|change|patch|pr|deployment|release|rollout|submission|return|"
                   r"handoff|bead|task|decision|result|report|ticket|it)")
_CONTROL_ACTION = re.compile(
    r"^(?:(?:please|kindly|just)\s+)?(?:"
    r"(?:ship|deploy|promote|certify|sign off on|give (?:final )?approval to)\b|"
    rf"(?:publish|merge|accept|finalize|close|launch|push|approve|authorize)\b(?:\s*$|"
    rf"\s+(?:(?:the|this|our|that)\s+)?(?:[\w-]+\s+){{0,2}}{_CONTROL_OBJECT}\b)|"
    rf"(?:treat|classify|record|set|mark|take|count|use|consider|enter)\s+.{{1,100}}\s+"
    rf"(?:as\s+)?(?:(?:your|the)\s+)?{_DECISION}\b|"
    r"(?:disregard|override|supersede|replace|suspend)\b.{0,90}\b"
    r"(?:prior|original|current|earlier|constraints?|instructions?|policy|guardrails?|approval)\b|"
    r"(?:run|invoke|trigger|start)\b.{0,70}\b(?:rollout|deployment|release|approval|merge)\b|"
    r"(?:proceed|continue|advance|move forward)\b.{0,70}\b(?:to (?:release|deployment)|"
    r"without (?:further |additional )?(?:review|approval|checking)|as if)\b)"
)

_CHECK = (
    r"(?:(?:acceptance|independent|architect|peer|security|final|release|runtime|regression|smoke|unit|integration|"
    r"automated|functional|build|deployment|ci|reviewer|maintainer)[ -](?:reviews?|checks?|gates?|validation|tests?(?: suites?)?|suite|"
    r"verification|sign[ -]?off|approval|runs?)|"
    r"validation(?: gate)?|review(?: gate)?|verification|tests?(?: suite| run)?|sign[ -]?off)"
)
_GATE = (rf"(?:\b(?:{_CHECK}|(?:official|required|mandatory) (?:checks?|approvals?))\b|"
         r"\bci\b(?=\s*(?:$|[.,;!?]|(?:until|for|on|in|and|or|before|after|is|may|can|must|should)\b)))")
_JOB = r"(?:task|bead|assignment|brief|request|handoff|delivery|return|work item)"
_SCOPE_NOUN = r"(?:work(?: items?)?|scope|boundar(?:y|ies)|deliverables?|objectives?|requirements?|outputs?)"
_ASSIGNED = r"(?:assigned|approved|agreed|original|authorized|required|requested|current|existing|specified)"
_SCOPE = (
    rf"\b(?:{_ASSIGNED}\s+(?:[\w-]+\s+){{0,2}}{_SCOPE_NOUN}|"
    rf"(?:{_SCOPE_NOUN}|{_JOB})\s+(?:for|of)\s+(?:this|the|our)\s+{_JOB}|"
    rf"(?:this|the|our)\s+{_JOB}(?:'s)?\s+{_SCOPE_NOUN}|"
    rf"what\s+(?:was\s+(?:asked for|required|requested)|(?:we|i)\s+(?:were|was)\s+asked\s+to\s+\w+)|"
    rf"(?:requested|required|assigned|specified)\s+(?:[\w-]+\s+){{0,2}}"
    rf"(?:artifact|report|analysis|evidence|appendix|checklist|section|inventory|matrix))\b"
)
_ACTION_PREFIX = (r"(?:please\s+|kindly\s+|just\s+|recommend(?:ed)?\s*:?\s*|"
                  r"(?:it (?:would|will) be (?:sufficient|fine|okay)|we|you)\s+"
                  r"(?:(?:can|could|should|may|must|need to)\s+|to\s+)?){0,3}")
_GATE_OBJECT = (r"\s+(?:(?:the|a|an|any|all|further|another|required|mandatory|routine|current|usual|independent|"
                r"running|doing|performing|scheduling|completing|waiting (?:on|for)|asking for|obtaining)\s+){0,5}")
_WAIVED = (r"(?:optional|unnecessary|dispensable|redundant|dispensed with|skipped|omitted|waived|deferred|"
           r"postponed|left out|can wait|no longer (?:needed|required|necessary))")
_GATE_BYPASS = re.compile(
    rf"^(?:skip|omit|waive|bypass|dispense with|forego|forgo|drop|defer|"
    rf"(?:go|move) ahead without|(?:proceed|continue) without)\b{_GATE_OBJECT}{_GATE}|"
    rf"^(?:leave|keep)\b{_GATE_OBJECT}{_GATE}.{{0,45}}\bout\b|"
    rf"^(?:make|treat|regard|consider)\b{_GATE_OBJECT}{_GATE}\s+(?:as\s+)?"
    rf"(?:{_WAIVED}|satisfied by (?:this|the return|this report))\b|"
    rf"^(?:(?:there is )?no (?:further |more )?need|there is no reason|"
    rf"(?:(?:we|you)\s+)?(?:do not|don't|won't|will not)\s+need)"
    rf"(?:\s+(?:for|to (?:run|get|obtain|seek|wait for|request|repeat)))?"
    rf"{_GATE_OBJECT}{_GATE}"
)
_GATE_STATUS = re.compile(
    rf"^(?:the |a |an )?{_GATE}\s+(?:(?:(?:{_MODAL})\s+(?:be\s+)?|(?:is|are)\s+)"
    rf"(?:treated as |considered |regarded as )?{_WAIVED}\b|"
    r"(?:(?:is|are)\s+not|(?:does|do)\s+not need to be)\s+(?:required|necessary|performed)\b|"
    r"(?:can|may)\s+wait\b|need(?:s)?\s+not\s+(?:run|happen|take place|be\s+(?:performed|completed|obtained))\b)"
)
_WITHOUT_GATE = re.compile(
    rf"\b(?:without|in the absence of){_GATE_OBJECT}{_GATE}|"
    rf"\bbefore{_GATE_OBJECT}{_GATE}\s+(?:is\s+)?(?:runs?|completes?|arrives?|finishes?|happens?)\b"
)
_LEADING_CONDITION = re.compile(
    r"^(?:(?:even\s+)?if|when|once|unless|since|given(?: that)?)\b"
    r"[^,?]{1,200}?(?:,\s*(?:then\s+)?|\s+then\s+)"
)
_GATE_COMPLETION = r"(?:run|finish|arrive|complete|happen|take place|materialize|be (?:done|performed|obtained|completed))"
_IF_NO_GATE = re.compile(
    rf"\b(?:if|when)\b.{{0,90}}(?:{_GATE}\s+(?:"
    rf"(?:hasn't|haven't|has not|have not|doesn't|don't|does not|do not|cannot|never)\s+{_GATE_COMPLETION}\w*|"
    rf"(?:is|are|remains?)\s+(?:still\s+)?(?:pending|unavailable|not yet (?:done|complete|available))|"
    rf"(?:isn't|aren't)\s+(?:done|complete|available))\b|"
    rf"\b(?:there is no|there's no|without|lacks?)\b{_GATE_OBJECT}{_GATE})|"
    rf"\b(?:unless|whether or not)\b.{{0,55}}{_GATE}\s+{_GATE_COMPLETION}\w*\b"
)
_GATE_QUESTION = re.compile(
    rf"^(?:(?:why bother with|(?:do|would) (?:we|you) really need|what need is there for)"
    rf"{_GATE_OBJECT}{_GATE}|"
    rf"why (?:run|require|wait for){_GATE_OBJECT}{_GATE}\s+(?:when|if|given that)\s+"
    r"(?:this|the|our) (?:return|report|write[- ]up|analysis)\s+(?:already|is enough|suffices)\b)"
)
_PROGRESS = re.compile(
    r"^(?:(?:can|could|should|would)\s+(?:we|you)\s+)?"
    r"(?:proceed|continue|advance|move (?:ahead|forward)|go ahead|publish|merge|release|deploy|ship|"
    r"accept|approve|close|finalize|treat|consider|mark|record|count|sign off)\b"
)
_CHANGE = (r"(?:expand|widen|broaden|include|increase|extend|change|replace|swap|substitute|convert|redirect|"
           r"redefine|drop|omit|rewrite|narrow|ignore|set aside|leave out)\b")
_CHANGE_PASSIVE = (r"(?:expanded|widened|broadened|extended|changed|replaced|swapped|substituted|converted|"
                   r"redirected|redefined|dropped|omitted|narrowed|left out)\b")
_SCOPE_LEAD = re.compile(rf"^for (?:this|the) {_JOB}\s*,\s*")
_SCOPE_CHANGE = re.compile(
    rf"^{_CHANGE}.{{0,85}}{_SCOPE}|"
    rf"^(?:the )?{_SCOPE}\s+(?:{_MODAL})\s+(?:be\s+)?(?:\w+\s+){{0,2}}"
    rf"{_CHANGE_PASSIVE}|"
    rf"^(?:leave|keep)\b.{{1,85}}{_SCOPE}.{{0,45}}\bout\b|"
    rf"^(?:expand|broaden|extend|redirect)\s+(?:this|the|our)\s+{_JOB}\s+(?:to|into|toward|beyond)\b"
)
_SCOPE_CONTROL = re.compile(rf"^{_CHANGE}.{{0,75}}\b{_SCOPE_NOUN}\b")
_SCOPE_SECTIONS = {"scope compliance", "share-boundary conformance"}
_ASSIGNMENT_RELATION = re.compile(
    rf"^(?:deliver|submit|return|send|provide|use|report|count|accept)\b.{{1,100}}\b"
    rf"(?:instead of|in place of|as a substitute for|in lieu of|rather than)\s+.{{0,25}}{_SCOPE}|"
    rf"^(?:add|bring|include)\b.{{1,100}}\b(?:to|into|in)\s+(?:this|the|our)\s+{_JOB}\b"
    rf".{{0,45}}\b(?:in addition|as well|too|also)\b"
)
_LATER_WORK = re.compile(
    r"\b(?:for|in|to|under|until)\s+(?:a |the )?separate (?:approved )?(?:task|bead|follow[- ]up)\b|"
    r"\b(?:subject to (?:separate |prior )?approval|if separately approved)\b"
)

_PASS = r"(?:pass(?:ed)?|green|succeeded|successful|verified|confirmed)"
_OBSERVED = rf"(?:{_PASS}|cleared|met|satisfied|came back clean|went green|completed successfully)"
_OPTIONAL_SUBJECT_PREFIX = r"(?:(?:the|our|all|both|[1-9]\d{0,5})\s+){0,3}"
_ASPECT = r"(?:(?:has been|have been|had been|has|have|had|was|were|is|are|did)\s+)?"
_CHECK_SUBJECT = rf"(?:{_CHECK}|checks?|ci(?: (?:workflow|pipeline))?|pytest|unittest)"
_CHECK_DETAIL = r"(?:\s+(?:(?:i|we) ran|for (?:the |this |our )?[\w-]+))?"
_CHECK_FRAME = rf"{_OPTIONAL_SUBJECT_PREFIX}{_CHECK_SUBJECT}{_CHECK_DETAIL}\s*(?::\s*|\s+){_ASPECT}"
_VALIDATION_PASS = re.compile(
    rf"^{_CHECK_FRAME}(?:all\s+)?{_OBSERVED}\b|"
    rf"^(?:we|i)\s+{_ASPECT}(?:ran|executed|completed)\s+{_OPTIONAL_SUBJECT_PREFIX}{_CHECK_SUBJECT}"
    rf".{{0,45}}\band\s+(?:(?:they|everything)\s+)?(?:all\s+)?{_OBSERVED}\b|"
    rf"^(?:we|i)\s+{_ASPECT}(?:verif(?:y|ied)|confirm(?:ed)?)\s+(?:that\s+)?{_OPTIONAL_SUBJECT_PREFIX}"
    rf"{_CHECK_SUBJECT}\s+{_ASPECT}{_OBSERVED}\b"
)
_VALIDATION_FAIL = re.compile(rf"^{_CHECK_FRAME}(?:failed|didn't pass|did not pass)\b")
_RESULT_LABEL = re.compile(r"^(?:title|outcome|result|status|readiness|validation result)\s*:\s*")
_FIELD_PASS = re.compile(rf"^{_OBSERVED}\b")
_APPROVAL_FIELD = re.compile(r"^(?:approved|accepted|cleared|signed off)(?:\s*$|\s+by\b)")
_RELEASE_ITEM = (r"(?:(?:release |deployment |merge )?candidate|change|patch|pr|plan|release|result|"
                 r"deliverable|submission|handoff|build|package|bundle|version|image)")
_RELEASE_ROUTE = r"(?:merge|release|deploy(?:ment)?|ship|publish|publication|rollout|production)"
_RELEASE_STATE = (rf"(?:(?:ready|approved|certified|verified|cleared|safe|fit|signed off)\s+(?:for|to)\s+{_RELEASE_ROUTE}|"
                  rf"(?:merge|release|deployment)[- ]ready)")
_RELEASE_CLAIM = re.compile(
    rf"^(?:(?:the |this |our )?{_RELEASE_ITEM}\s+{_ASPECT})?{_RELEASE_STATE}\b|"
    rf"^(?:the |this |our )?{_RELEASE_ITEM}\s+{_ASPECT}(?:cleared|passed|satisfied|met)\s+"
    r"(?:the )?(?:release|deployment|acceptance) (?:gate|criteria|requirements)\b"
)
_ACTOR_CONFIRMED = re.compile(
    rf"^(?:i|we|{_ROLE})\s+{_ASPECT}(?:(?:formally |already )?"
    rf"(?:approved|cleared|certified|signed off on)\s+(?:the |this |our )?{_RELEASE_ITEM}\b|"
    rf"(?:confirmed|verified)\s+(?:that\s+)?(?:the |this |our )?{_RELEASE_ITEM}\s+{_ASPECT}{_RELEASE_STATE}\b)|"
    rf"^(?:the |this |our )?{_RELEASE_ITEM}\s+{_ASPECT}(?:approved|certified|cleared|accepted|signed off)\s+by\s+{_ROLE}\b"
)
_RELEASE_CONDITION = re.compile(r"\b(?:after|once|when|if)\s+.{0,60}\b(?:confirms?|passes?|accepts?|approves?)\b|"
                                r"\b(?:subject to|pending|conditional on|provided that|assuming)\s+")
_ATTRIBUTION = re.compile(
    r"\b(?:packet[- ]reported|unverified|according to (?:the )?(?:supplied |provided )?(?:packet|report|logs?)|"
    r"(?:based on|from|per) (?:the )?(?:supplied |provided )?packet(?: validation)? evidence)\b"
    r"|^(?:the )?(?:packet|provider|return|(?:supplied |provided )?logs?) (?:reports?|says?|shows?|claims?)\b"
)
_FUTURE_OR_HYPOTHETICAL = re.compile(r"^(?:if|once|when|unless|assuming|expected|proposed|hypothetical)\b")
_EXIT_CODE = r"\bexit(?:ed)?(?:\s+with)?(?:\s+(?:status|code))?\s*[:=]?\s*"
_ZERO_EXIT = re.compile(rf"{_EXIT_CODE}0\b")
_RESULT = re.compile(rf"\b{_OBSERVED}\b|{_ZERO_EXIT.pattern}|\b(?:0|zero|no)\s+(?:\w+\s+)?(?:failed|failures)\b")
_REPRO = re.compile(r"\b(?:python(?:3)?\s+-m\s+[\w.]+|pytest|unittest(?:\s+discover)?|"
                    r"(?:scripts|tests)/[\w./-]+|(?:run|job|check|receipt|artifact)\s*#[0-9]+|"
                    r"https?://\S+/(?:runs|jobs|checks)/\d+\b|\w+\.(?:log|json)\b)\b")
_NOT_RUN = re.compile(rf"\b(?:not (?:run|executed|verified|performed|pass)|"
                      rf"no {_CHECK_SUBJECT} (?:were )?run)\b")
_FAILURE_EXIT = re.compile(rf"{_EXIT_CODE}(?:[+-]?0*[1-9]\d*\b|non[- ]?zero\b)|\bnon[- ]?zero exit\b")
_OUTCOME_CONTINUATION = re.compile(rf"^(?:{_EXIT_CODE}|(?:non[- ]?zero|zero) exit)\b")
_FAILURE = re.compile(r"\b(?:failed|failures?|[1-9]\d*\s+(?:test\s+)?errors?)\b")
_NO_FAILURE = re.compile(r"\b(?:0|zero|no|without)\s+(?:(?:tests?|cases?|checks?|have|were)\s+){0,3}$")
_RESULT_SECTIONS = {"validation result", "independent verification", "peer-review disposition"}
_SUPPORT_SECTIONS = _RESULT_SECTIONS | {"evidence", "attestation or reproducibility note", "commands run"}
_REPORTED_SECTIONS = {"packet-reported claims", "risks or gaps", "alternatives considered"}

_LINE = re.compile(r"[^\r\n]+")
_LEAD = re.compile(r"^\s*(?:>\s*)*(?:(?:[-+*]|\d{1,5}[.)])\s+)?(?:\|\s*)?")
_HEADING = re.compile(r"^#{1,6}\s+")
_DECORATION = re.compile(r"\*\*|__|(?<!`)`{1,2}(?!`)")
_NEW_BLOCK = re.compile(r"^\s*(?:>|\||#{1,6}\s|(?:[-+*]|\d{1,5}[.)])\s+|`{3,}|~{3,}|\*\*|\w[\w /-]{0,40}:)")
_CLAUSE = re.compile(
    rf"[.!?;](?=\s|$)|,?\s+\b(?:but|then|however)\b\s+|"
    rf",?\s+and\s+(?={_RECIPIENT}\s+{_MODAL}\b)"
)
_QUOTED_EXAMPLE = re.compile(r"\b(?:unsafe|rejected|blocked|prohibited|illustrative|counter)\b.{0,45}\b(?:example|proposal|instruction)\b|"
                             r"\b(?:example|quote|quotation)\b.{0,50}\b(?:rejected|blocked|prohibited|never follow)\b|"
                             r"^(?:an? |the )?(?:quoted example|example wording|quotation)\b")
_USE_EXAMPLE = re.compile(r"^(?:(?:please|just)\s+)?(?:use|apply|run|load|execute|copy|follow|adopt)\b")
_INLINE_QUOTE = re.compile(r"""(?<!\w)(?:"[^"]+"|'[^']+'|“[^”]+”|‘[^’]+’)(?!\w)""")
_QUOTED_LINE = re.compile(r"(?m)^[ \t]*(?:>[ \t]*)+")
_TABLE_ROW = re.compile(r"^\s*\|\s*([^|]+?)\s*\|(.+?)\|?\s*$")
_STRUCTURED_FENCE = re.compile(r"(?m)^[ \t]*(?P<quote>(?:>[ \t]*)*)(?P<fence>`{3,}|~{3,})"
                               r"(?:[ \t]*json)?[ \t]*\r?\n(?P<body>.*?)\r?\n[ \t]*(?P=quote)(?P=fence)[ \t]*$", re.S)
_GATE_CONTROLS = {
    **dict.fromkeys(("review_required", "peer_review_required", "validation_required", "verification_required"), False),
    **dict.fromkeys(("skip_review", "skip_validation", "waive_review", "waive_validation"), True),
}
_RESULT_CONTROLS = {"validation", "verification", "review_result", "test_result", "test_results", "release_readiness"}
_JSON_SUCCESS = re.compile(rf"(?:{_OBSERVED}|approved|ready|accepted|signed off)")


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class _Unit:
    start: int
    end: int
    body: str
    section: str
    addressed: bool = False
    corrective_example: bool = False


def _line_blocks(text: str) -> Iterator[tuple[int, int]]:
    """Join a soft wrap while retaining each paragraph's original span."""
    start = end = 0
    for line in _LINE.finditer(text):
        if end and (text[end:line.start()] not in ("\n", "\r\n")
                    or not _soft_wrap(text, start, line.group()) or text[end - 1] in ".?!;:"):
            yield start, end
            start = line.start()
        if not end:
            start = line.start()
        end = line.end()
    if end:
        yield start, end


def _soft_wrap(text: str, start: int, current: str) -> bool:
    if _QUOTED_LINE.match(text, start) and _QUOTED_LINE.match(current):
        return not _NEW_BLOCK.match(_QUOTED_LINE.sub("", current, count=1))
    return not _NEW_BLOCK.match(current)


def _body(span: str) -> str:
    row = _TABLE_ROW.fullmatch(span)
    if row:
        return f"{row[1]}: {row[2].strip()}"
    return _DECORATION.sub("", _LEAD.sub("", _QUOTED_LINE.sub("", span), count=1)).strip()


def _illustrative_intro(body: str) -> bool:
    return bool(_QUOTED_EXAMPLE.search(body) and not _USE_EXAMPLE.match(body))


def _units(text: str) -> Iterator[_Unit]:
    section, addressed, quote_intro = "", False, False
    for start, end in _line_blocks(text):
        span = text[start:end]
        body = _body(span)
        head, _, tail = body.partition("\n")
        header = parse_return_header(head)
        if header:
            name, value = header
            section, addressed, quote_intro = name.casefold(), False, False
            body = f"{value} {tail}"
        elif _HEADING.match(body) or _RECIPIENT_HEADING.fullmatch(body):
            heading = _HEADING.sub("", body, count=1).strip(" #")
            addressed = bool(_RECIPIENT_HEADING.fullmatch(heading))
            section, quote_intro = "", False
            body = "" if addressed else heading
        body = " ".join(body.split())
        is_quote = span.lstrip().startswith(">")
        yield _Unit(start, end, body, section, addressed, quote_intro and is_quote)
        if not is_quote:
            quote_intro = _illustrative_intro(body)


def _clauses(body: str) -> Iterator[str]:
    quoted = iter(_INLINE_QUOTE.finditer(body))
    quote = next(quoted, None)
    start = 0
    for boundary in _CLAUSE.finditer(body):
        while quote and quote.end() <= boundary.start():
            quote = next(quoted, None)
        if quote and quote.start() <= boundary.start():
            continue
        if boundary[0].strip(" ,") == "then" and _LEADING_CONDITION.match(body[start:boundary.end()].lstrip()):
            continue
        yield body[start:boundary.start()].strip()
        start = boundary.end()
    yield body[start:].strip()


def _action_clauses(body: str) -> Iterator[str]:
    for clause in _clauses(body):
        _, sep, value = clause.partition(":")
        quoted = _INLINE_QUOTE.fullmatch(value.strip())
        if sep and quoted and _USE_EXAMPLE.match(clause):
            yield from _clauses(quoted[0][1:-1])
        else:
            yield clause


def _action_frame(clause: str) -> tuple[str, bool]:
    operative = _LEADING_CONDITION.sub("", clause, count=1)
    addressee = _ADDRESSEE.match(operative)
    if addressee:
        operative = operative[addressee.end():]
    return re.sub(rf"^{_ACTION_PREFIX}", "", operative), bool(addressee)


def _changes_scope(action: str, section: str) -> bool:
    if _LATER_WORK.search(action):
        return False
    action = _SCOPE_LEAD.sub("", action, count=1)
    return bool(_SCOPE_CHANGE.match(action) or _ASSIGNMENT_RELATION.match(action)
                or section in _SCOPE_SECTIONS and _SCOPE_CONTROL.match(action))


def _actions(unit: _Unit) -> Iterator[str]:
    """Classify each operative clause under its own stance and report context."""
    if unit.corrective_example:
        return
    for clause in _action_clauses(unit.body):
        action, addressed = _action_frame(clause)
        if (addressed or unit.addressed) and _CONTROL_ACTION.match(action):
            yield DIRECTIVE
        if _changes_scope(action, unit.section):
            yield SCOPE
        if _bypasses(action, clause):
            yield BYPASS


def _bypasses(action: str, clause: str) -> bool:
    if _GATE_BYPASS.match(action) or _GATE_STATUS.match(action) or _GATE_QUESTION.match(action):
        return True
    return bool(_PROGRESS.match(action) and (_WITHOUT_GATE.search(action) or _IF_NO_GATE.search(clause)))


def _proof_topic(body: str) -> tuple[str, str]:
    words = body.replace("_", " ").replace("-", " ")
    if re.search(r"\b(?:tests?|unittest|pytest|(?:acceptance|smoke|integration|regression) suite)\b", words):
        qualifier = re.search(r"\b(?:smoke|unit|integration|acceptance|regression|end to end)\b", words)
        return "tests", qualifier[0] if qualifier else "unit" if "unittest" in words else ""
    route = re.search(r"\b(?:merge|release|deploy(?:ment)?|ship|publish|publication|rollout|production|review(?:er)?)\b", words)
    if route:
        kind = route[0]
        return "release", {"deploy": "deployment", "rollout": "deployment", "production": "deployment",
                           "ship": "release", "publish": "publication", "reviewer": "review"}.get(kind, kind)
    if re.search(r"\bci\b", words):
        return "validation", "ci"
    return "validation", ""


def _negative_outcome(clause: str) -> bool:
    if _NOT_RUN.search(clause) or _FAILURE_EXIT.search(clause):
        return True
    return any(not _NO_FAILURE.search(clause[max(0, match.start() - 48):match.start()])
               for match in _FAILURE.finditer(clause))


def _failure_topic(clause: str, unit_body: str) -> tuple[str, str]:
    topic = _proof_topic(clause)
    return _proof_topic(unit_body) if topic == ("validation", "") and _REPRO.search(unit_body) else topic


def _reports_check(clause: str, section: str) -> bool:
    return bool(section in _SUPPORT_SECTIONS or _VALIDATION_PASS.match(clause) or _ZERO_EXIT.search(clause)
                or _VALIDATION_FAIL.match(clause) or _NOT_RUN.search(clause) or _FAILURE_EXIT.search(clause))


def _check_result(clause: str, section: str) -> str:
    if _FUTURE_OR_HYPOTHETICAL.match(clause) or _ATTRIBUTION.search(clause) or not _reports_check(clause, section):
        return ""
    outcome = _REPRO.sub("", clause)
    if _VALIDATION_FAIL.match(clause) or _negative_outcome(outcome):
        return "failed"
    return "passed" if _RESULT.search(outcome) else ""


def _recorded_results(unit: _Unit) -> Iterator[tuple[tuple[str, str], str]]:
    antecedent = ""
    for clause in _clauses(unit.body):
        clause = _RESULT_LABEL.sub("", clause, count=1)
        result = _check_result(clause, unit.section)
        named = bool(_REPRO.search(clause))
        linked = antecedent and _OUTCOME_CONTINUATION.match(clause)
        record = f"{antecedent} {clause}" if linked else clause
        if result == "failed":
            yield _failure_topic(record, unit.body), result
        elif result == "passed" and (named or linked):
            yield _proof_topic(record), result
        antecedent = clause if named else ""


def _support(units: list[_Unit]) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    results: dict[str, set[tuple[str, str]]] = {"passed": set(), "failed": set()}
    for unit in units:
        if unit.corrective_example or unit.section in _REPORTED_SECTIONS:
            continue
        for topic, result in _recorded_results(unit):
            results[result].add(topic)
    return results["passed"], results["failed"]


def _unsupported(unit: _Unit, supported: set[tuple[str, str]], failed: set[tuple[str, str]]) -> bool:
    if unit.corrective_example or unit.section in _REPORTED_SECTIONS:
        return False
    return any(_unsupported_clause(clause, unit.section, supported, failed) for clause in _clauses(unit.body))


def _asserts_success(clause: str, section: str) -> bool:
    if _ATTRIBUTION.search(clause) or _FUTURE_OR_HYPOTHETICAL.match(clause):
        return False
    if _VALIDATION_PASS.match(clause) or section in _RESULT_SECTIONS and _FIELD_PASS.match(clause):
        return True
    if section == "peer-review disposition" and _APPROVAL_FIELD.match(clause):
        return True
    if _RELEASE_CONDITION.search(clause):
        return False
    return bool(_RELEASE_CLAIM.match(clause) or _ACTOR_CONFIRMED.match(clause))


def _unsupported_clause(clause: str, section: str, supported: set[tuple[str, str]], failed: set[tuple[str, str]]) -> bool:
    clause = _RESULT_LABEL.sub("", clause, count=1)
    if not _asserts_success(clause, section):
        return False
    topic, qualifier = _proof_topic(clause)
    contradicted = any(other == topic and (not subtype or not qualifier or subtype == qualifier)
                       for other, subtype in failed)
    corroborated = any(other == topic and (not qualifier or subtype == qualifier)
                       for other, subtype in supported)
    return contradicted or not corroborated


class _Pairs(list):
    """Keep duplicate JSON keys visible until explicit controls are inspected."""


def _objects(value: object) -> Iterator[_Pairs]:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, _Pairs):
            yield current
            pending.extend(item for name, item in current if name not in {"examples", "example", "quoted_excerpt", "quotation"})
        elif isinstance(current, list):
            pending.extend(current)


def _scope_requested(value: object) -> bool:
    return value is True or isinstance(value, _Pairs) and any(
        key == "requested" and field is True for key, field in value
    )


def _unsupported_json(value: object) -> bool:
    if not isinstance(value, _Pairs):
        return False
    field = dict(value)
    proof = (field.get("command"), field.get("evidence_ref"), field.get("artifact"))
    named = any(type(item) is str and _REPRO.search(item) for item in proof)
    outcomes = [item for name, item in value if name == "exit_code"]
    proven = named and outcomes and all(type(item) is int and item == 0 for item in outcomes)
    return _unsupported_json_status(value, bool(proven))


def _unsupported_json_status(value: _Pairs, proven: bool) -> bool:
    statuses = [item for key, item in value if key in {"result", "status"} and type(item) is str]
    return any(_JSON_SUCCESS.fullmatch(status.strip()) for status in statuses) and (
        not proven or any(_negative_outcome(status) for status in statuses)
    )


def _json_actions(record: _Pairs) -> Iterator[str]:
    actors = [value for key, value in record if key in {"addressee", "recipient", "target"} and type(value) is str]
    directed = any(_RECIPIENT_HEADING.fullmatch(actor) for actor in actors)
    for key, value in record:
        if key in {"action", "instruction", "directive"} and type(value) is str:
            yield from _actions(_Unit(0, 0, value, "", addressed=directed))
        if key in {"scope_change", "scope_expansion", "delivery_substitution"} and _scope_requested(value):
            yield SCOPE
        if key in _GATE_CONTROLS and value is _GATE_CONTROLS[key]:
            yield BYPASS
        if key in _RESULT_CONTROLS and _unsupported_json(value):
            yield UNSUPPORTED


def _json_spans(text: str, units: list[_Unit]) -> Iterator[tuple[int, int]]:
    if text.lstrip().startswith(("{", "[")):
        yield 0, len(text)
    ends = [unit.end for unit in units]
    for match in _STRUCTURED_FENCE.finditer(text):
        preceding = bisect_right(ends, match.start()) - 1
        if preceding >= 0:
            intro = units[preceding]
            if not text[intro.end:match.start()].strip() and _illustrative_intro(intro.body):
                continue
        yield match.span("body")


def _json_findings(text: str, units: list[_Unit]) -> Iterator[Finding]:
    for start, end in _json_spans(text, units):
        if end - start > _MAX_JSON_CHARS:
            continue
        try:
            document = json.loads(_QUOTED_LINE.sub("", text[start:end]), object_pairs_hook=_Pairs)
        except (ValueError, RecursionError):
            continue
        for record in _objects(document):
            for category in set(_json_actions(record)):
                yield Finding(category, start, end)


def _prose_findings(units: list[_Unit]) -> Iterator[Finding]:
    supported, failed = _support(units)
    for unit in units:
        for category in set(_actions(unit)):
            yield Finding(category, unit.start, unit.end)
        if _unsupported(unit, supported, failed):
            yield Finding(UNSUPPORTED, unit.start, unit.end)


def scan_return_structure(text: str) -> list[Finding]:
    """Classify normalized spans without mistaking reported examples for instructions."""
    counter = Counter()
    findings = []
    units = list(_units(text))
    all_findings = set(_json_findings(text, units)).union(_prose_findings(units))
    for finding in sorted(all_findings, key=lambda hit: (hit.start, hit.end, hit.category)):
        if counter[finding.category] < _MAX_FINDINGS_PER_CATEGORY:
            findings.append(finding)
            counter[finding.category] += 1
    return findings
