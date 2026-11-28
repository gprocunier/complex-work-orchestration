"""Bounded findings from the addressed actions and evidence structure of a return."""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterator

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

_LINE = re.compile(r"[^\r\n]+")
_LEAD = re.compile(r"^\s*(?:>\s*)*(?:(?:[-+*]|\d{1,5}[.)])\s+)?(?:\|\s*)?")
_HEADING = re.compile(r"^#{1,6}\s+")
_DECORATION = re.compile(r"\*\*|__|(?<!`)`{1,2}(?!`)")
_NEW_BLOCK = re.compile(r"^\s*(?:>|\||#{1,6}\s|(?:[-+*]|\d{1,5}[.)])\s+|`{3,}|~{3,}|\*\*|\w[\w /-]{0,40}:)")
_INLINE_QUOTE = re.compile(r"""(?<!\w)(?:"[^"]+"|'[^']+'|“[^”]+”|‘[^’]+’)(?!\w)""")
_QUOTED_LINE = re.compile(r"(?m)^[ \t]*(?:>[ \t]*)+")
_TABLE_ROW = re.compile(r"^\s*\|\s*([^|]+?)\s*\|(.+?)\|?\s*$")
_STRUCTURED_FENCE = re.compile(r"(?m)^[ \t]*(?P<quote>(?:>[ \t]*)*)(?P<fence>`{3,}|~{3,})"
                               r"(?:[ \t]*json)?[ \t]*\r?\n(?P<body>.*?)\r?\n[ \t]*(?P=quote)(?P=fence)[ \t]*$", re.S)


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


class _Pairs(list):
    """Keep duplicate JSON keys visible until explicit controls are inspected."""


class StructuralScanner:
    """Parse return structure with the compiled patterns of one policy snapshot."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.patterns = {name: re.compile(pattern) for name, pattern in data["patterns"].items()}
        self.selectors = {name: frozenset(values) for name, values in data["selectors"].items()}
        self.gate_controls = data["gate_controls"]
        self.release_aliases = data["release_aliases"]

    def _illustrative_intro(self, body: str) -> bool:
        return bool(self.patterns["quoted_example"].search(body) and not self.patterns["use_example"].match(body))

    def _units(self, text: str) -> Iterator[_Unit]:
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
            elif _HEADING.match(body) or self.patterns["recipient_heading"].fullmatch(body):
                heading = _HEADING.sub("", body, count=1).strip(" #")
                addressed = bool(self.patterns["recipient_heading"].fullmatch(heading))
                section, quote_intro = "", False
                body = "" if addressed else heading
            body = " ".join(body.split())
            is_quote = span.lstrip().startswith(">")
            yield _Unit(start, end, body, section, addressed, quote_intro and is_quote)
            if not is_quote:
                quote_intro = self._illustrative_intro(body)

    def _clauses(self, body: str) -> Iterator[str]:
        quoted = iter(_INLINE_QUOTE.finditer(body))
        quote = next(quoted, None)
        start = 0
        for boundary in self.patterns["clause"].finditer(body):
            while quote and quote.end() <= boundary.start():
                quote = next(quoted, None)
            if quote and quote.start() <= boundary.start():
                continue
            if boundary[0].strip(" ,") == "then" and self.patterns["leading_condition"].match(body[start:boundary.end()].lstrip()):
                continue
            yield body[start:boundary.start()].strip()
            start = boundary.end()
        yield body[start:].strip()

    def _action_clauses(self, body: str) -> Iterator[str]:
        for clause in self._clauses(body):
            _, sep, value = clause.partition(":")
            quoted = _INLINE_QUOTE.fullmatch(value.strip())
            if sep and quoted and self.patterns["use_example"].match(clause):
                yield from self._clauses(quoted[0][1:-1])
            else:
                yield clause

    def _action_frame(self, clause: str) -> tuple[str, bool]:
        operative = self.patterns["leading_condition"].sub("", clause, count=1)
        addressee = self.patterns["addressee"].match(operative)
        if addressee:
            operative = operative[addressee.end():]
        return self.patterns["action_prefix"].sub("", operative), bool(addressee)

    def _changes_scope(self, action: str, section: str) -> bool:
        if self.patterns["later_work"].search(action):
            return False
        action = self.patterns["scope_lead"].sub("", action, count=1)
        return bool(self.patterns["scope_change"].match(action) or self.patterns["assignment_relation"].match(action)
                    or section in self.selectors["scope_sections"] and self.patterns["scope_control"].match(action))

    def _actions(self, unit: _Unit) -> Iterator[str]:
        """Classify each operative clause under its own stance and report context."""
        if unit.corrective_example:
            return
        for clause in self._action_clauses(unit.body):
            action, addressed = self._action_frame(clause)
            if (addressed or unit.addressed) and self.patterns["control_action"].match(action):
                yield DIRECTIVE
            if self._changes_scope(action, unit.section):
                yield SCOPE
            if self._bypasses(action, clause):
                yield BYPASS

    def _bypasses(self, action: str, clause: str) -> bool:
        if self.patterns["gate_bypass"].match(action) or self.patterns["gate_status"].match(action) or self.patterns["gate_question"].match(action):
            return True
        return bool(self.patterns["progress"].match(action) and (self.patterns["without_gate"].search(action) or self.patterns["if_no_gate"].search(clause)))

    def _proof_topic(self, body: str) -> tuple[str, str]:
        words = body.replace("_", " ").replace("-", " ")
        if self.patterns["test_topic"].search(words):
            qualifier = self.patterns["test_qualifier"].search(words)
            return "tests", qualifier[0] if qualifier else "unit" if "unittest" in words else ""
        route = self.patterns["release_topic"].search(words)
        if route:
            kind = route[0]
            return "release", self.release_aliases.get(kind, kind)
        if self.patterns["ci_topic"].search(words):
            return "validation", "ci"
        return "validation", ""

    def _negative_outcome(self, clause: str) -> bool:
        if self.patterns["not_run"].search(clause) or self.patterns["failure_exit"].search(clause):
            return True
        return any(not self.patterns["no_failure"].search(clause[max(0, match.start() - 48):match.start()])
                   for match in self.patterns["failure"].finditer(clause))

    def _failure_topic(self, clause: str, unit_body: str) -> tuple[str, str]:
        topic = self._proof_topic(clause)
        return self._proof_topic(unit_body) if topic == ("validation", "") and self.patterns["repro"].search(unit_body) else topic

    def _reports_check(self, clause: str, section: str) -> bool:
        return bool(section in self.selectors["support_sections"] or self.patterns["validation_pass"].match(clause) or self.patterns["zero_exit"].search(clause)
                    or self.patterns["validation_fail"].match(clause) or self.patterns["not_run"].search(clause) or self.patterns["failure_exit"].search(clause))

    def _check_result(self, clause: str, section: str) -> str:
        if self.patterns["future_or_hypothetical"].match(clause) or self.patterns["attribution"].search(clause) or not self._reports_check(clause, section):
            return ""
        outcome = self.patterns["repro"].sub("", clause)
        if self.patterns["validation_fail"].match(clause) or self._negative_outcome(outcome):
            return "failed"
        return "passed" if self.patterns["result"].search(outcome) else ""

    def _recorded_results(self, unit: _Unit) -> Iterator[tuple[tuple[str, str], str]]:
        antecedent = ""
        for clause in self._clauses(unit.body):
            clause = self.patterns["result_label"].sub("", clause, count=1)
            result = self._check_result(clause, unit.section)
            named = bool(self.patterns["repro"].search(clause))
            linked = antecedent and self.patterns["outcome_continuation"].match(clause)
            record = f"{antecedent} {clause}" if linked else clause
            if result == "failed":
                yield self._failure_topic(record, unit.body), result
            elif result == "passed" and (named or linked):
                yield self._proof_topic(record), result
            antecedent = clause if named else ""

    def _support(self, units: list[_Unit]) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
        results: dict[str, set[tuple[str, str]]] = {"passed": set(), "failed": set()}
        for unit in units:
            if unit.corrective_example or unit.section in self.selectors["reported_sections"]:
                continue
            for topic, result in self._recorded_results(unit):
                results[result].add(topic)
        return results["passed"], results["failed"]

    def _unsupported(self, unit: _Unit, supported: set[tuple[str, str]], failed: set[tuple[str, str]]) -> bool:
        if unit.corrective_example or unit.section in self.selectors["reported_sections"]:
            return False
        return any(self._unsupported_clause(clause, unit.section, supported, failed) for clause in self._clauses(unit.body))

    def _asserts_success(self, clause: str, section: str) -> bool:
        if self.patterns["attribution"].search(clause) or self.patterns["future_or_hypothetical"].match(clause):
            return False
        if self.patterns["validation_pass"].match(clause) or section in self.selectors["result_sections"] and self.patterns["field_pass"].match(clause):
            return True
        if section == "peer-review disposition" and self.patterns["approval_field"].match(clause):
            return True
        if self.patterns["release_condition"].search(clause):
            return False
        return bool(self.patterns["release_claim"].match(clause) or self.patterns["actor_confirmed"].match(clause))

    def _unsupported_clause(self, clause: str, section: str, supported: set[tuple[str, str]], failed: set[tuple[str, str]]) -> bool:
        clause = self.patterns["result_label"].sub("", clause, count=1)
        if not self._asserts_success(clause, section):
            return False
        topic, qualifier = self._proof_topic(clause)
        contradicted = any(other == topic and (not subtype or not qualifier or subtype == qualifier)
                           for other, subtype in failed)
        corroborated = any(other == topic and (not qualifier or subtype == qualifier)
                           for other, subtype in supported)
        return contradicted or not corroborated

    def _objects(self, value: object) -> Iterator[_Pairs]:
        pending = [value]
        while pending:
            current = pending.pop()
            if isinstance(current, _Pairs):
                yield current
                pending.extend(item for name, item in current if name not in self.selectors["quoted_fields"])
            elif isinstance(current, list):
                pending.extend(current)

    @staticmethod
    def _scope_requested(value: object) -> bool:
        return value is True or isinstance(value, _Pairs) and any(
            key == "requested" and field is True for key, field in value
        )

    def _unsupported_json(self, value: object) -> bool:
        if not isinstance(value, _Pairs):
            return False
        field = dict(value)
        proof = (field.get(key) for key in self.selectors["proof_fields"])
        named = any(type(item) is str and self.patterns["repro"].search(item) for item in proof)
        outcomes = [item for name, item in value if name == "exit_code"]
        proven = named and outcomes and all(type(item) is int and item == 0 for item in outcomes)
        return self._unsupported_json_status(value, bool(proven))

    def _unsupported_json_status(self, value: _Pairs, proven: bool) -> bool:
        statuses = [item for key, item in value if key in self.selectors["outcome_fields"] and type(item) is str]
        return any(self.patterns["json_success"].fullmatch(status.strip()) for status in statuses) and (
            not proven or any(self._negative_outcome(status) for status in statuses)
        )

    def _json_actions(self, record: _Pairs) -> Iterator[str]:
        actors = [value for key, value in record if key in self.selectors["recipient_fields"] and type(value) is str]
        directed = any(self.patterns["recipient_heading"].fullmatch(actor) for actor in actors)
        for key, value in record:
            if key in self.selectors["action_fields"] and type(value) is str:
                yield from self._actions(_Unit(0, 0, value, "", addressed=directed))
            if key in self.selectors["scope_fields"] and self._scope_requested(value):
                yield SCOPE
            if key in self.gate_controls and value is self.gate_controls[key]:
                yield BYPASS
            if key in self.selectors["result_controls"] and self._unsupported_json(value):
                yield UNSUPPORTED

    def _json_spans(self, text: str, units: list[_Unit]) -> Iterator[tuple[int, int]]:
        if text.lstrip().startswith(("{", "[")):
            yield 0, len(text)
        ends = [unit.end for unit in units]
        for match in _STRUCTURED_FENCE.finditer(text):
            preceding = bisect_right(ends, match.start()) - 1
            if preceding >= 0:
                intro = units[preceding]
                if not text[intro.end:match.start()].strip() and self._illustrative_intro(intro.body):
                    continue
            yield match.span("body")

    def _json_findings(self, text: str, units: list[_Unit]) -> Iterator[Finding]:
        for start, end in self._json_spans(text, units):
            if end - start > _MAX_JSON_CHARS:
                continue
            try:
                document = json.loads(_QUOTED_LINE.sub("", text[start:end]), object_pairs_hook=_Pairs)
            except (ValueError, RecursionError):
                continue
            for record in self._objects(document):
                for category in set(self._json_actions(record)):
                    yield Finding(category, start, end)

    def _prose_findings(self, units: list[_Unit]) -> Iterator[Finding]:
        supported, failed = self._support(units)
        for unit in units:
            for category in set(self._actions(unit)):
                yield Finding(category, unit.start, unit.end)
            if self._unsupported(unit, supported, failed):
                yield Finding(UNSUPPORTED, unit.start, unit.end)

    def scan_return_structure(self, text: str) -> list[Finding]:
        """Classify normalized spans without mistaking reported examples for instructions."""
        counter = Counter()
        findings = []
        units = list(self._units(text))
        all_findings = set(self._json_findings(text, units)).union(self._prose_findings(units))
        for finding in sorted(all_findings, key=lambda hit: (hit.start, hit.end, hit.category)):
            if counter[finding.category] < _MAX_FINDINGS_PER_CATEGORY:
                findings.append(finding)
                counter[finding.category] += 1
        return findings
