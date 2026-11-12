"""Contextual tripwires for contractor and worker returns.

``scan_return_tripwires`` reads a normalized copy of the whole return (format
characters and combining marks removed, confusable letters folded, the
security normalizer's NFKC, lower case), one clause at a time (a line break inside a paragraph is a soft
wrap; each line of a code fence is read with the sentence that introduces
the fence), code fences and quotations included, and
reports clauses that ask the evaluator or agent to change the outcome, claim
authority over instructions, propose fetched-code execution, move
credentials, widen disclosure, weaken TLS or tests, or keep work out of the
audit record. Rules live in ``policy/return-tripwires.yaml``.

A hit holds the return for adjudication. This is a heuristic tripwire: it
does not detect arbitrary injection, verify facts, or grant anything when
nothing matches. Some rules apply only to directives (a clause that asks for
something). Within a match's own sub-clause (a comma, a semicolon or a
conjunction such as ``and``, ``then`` or ``before`` ends it), three kinds of
words can neutralize those rules, so a fix or a warning about the same code is
not a hit: a negation (``do not``, ``never``) only when it applies to the
match's action; a correcting verb (``remove``, ``revert``) only when it is that
action and the first in its sub-clause; and a critique (``unsafe``) only when no
action verb governs the match. The action is the match's own leading verb, or
the last action verb before it outside a relative clause. An adjective, an
unrelated action or a negated unrelated verb never cancels an instruction.
Markdown decoration (emphasis, inline code, headings, quote markers) is read
as spaces.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Iterator

from .policy import load_policy
from .return_language import normalize_security_text


@dataclass(frozen=True)
class TripwireHit:
    rule: str
    category: str
    description: str
    start: int
    end: int
    clause_sha256: str

    def as_record(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "category": self.category,
            "description": self.description,
            "start": self.start,
            "end": self.end,
            "clause_sha256": self.clause_sha256,
        }


@dataclass(frozen=True)
class _Rule:
    rule: str
    category: str
    description: str
    pattern: re.Pattern[str]
    negatable: bool
    directive: bool
    negations: re.Pattern[str]
    corrections: re.Pattern[str]
    critiques: re.Pattern[str]


@dataclass(frozen=True)
class _Language:
    """Policy patterns for directives and the action verbs that govern a match."""

    directive_markers: re.Pattern[str]
    actions: re.Pattern[str]
    imperative: re.Pattern[str]
    context_corrections: re.Pattern[str]
    commands: frozenset[str]


def _verb_forms(verb: str) -> set[str]:
    """Base, third-person, past and -ing forms of an action verb."""
    stem = verb[:-1] if verb.endswith("e") else verb
    forms = {verb, verb + "s", verb + "es", stem + "ed", stem + "ing"}
    if re.fullmatch(r"[^aeiou]*[aeiou][bdgklmnprt]", verb):  # set -> setting, skip -> skipped
        forms |= {verb + verb[-1] + "ing", verb + verb[-1] + "ed"}
    return forms


def _language(data: dict[str, Any]) -> _Language:
    verbs = [str(verb) for verb in data["action_verbs"]]
    forms = set().union(*(_verb_forms(verb) for verb in verbs), (str(form) for form in data.get("extra_action_verb_forms", [])))
    alternatives = "|".join(re.escape(form) for form in sorted(forms, key=len, reverse=True))
    bases = "|".join(re.escape(verb) for verb in sorted(verbs, key=len, reverse=True))
    return _Language(
        directive_markers=re.compile(str(data["directive_markers"])),
        actions=re.compile(rf"(?<![\w-])(?:{alternatives})(?![\w-])"),
        imperative=re.compile(rf"^\s*(?:(?:[-*+>]|\d{{1,3}}[.)])\s*)*(?:[\w .'`-]{{1,40}}:\s*)?(?:please\s+)?(?:{bases})\b"),
        context_corrections=re.compile(str(data["context_corrections"])),
        commands=frozenset(str(word) for word in data.get("command_words", [])),
    )


@lru_cache(maxsize=1)
def _compiled_policy(serialized: str) -> tuple[dict[str, str], tuple[_Rule, ...], _Language]:
    data = json.loads(serialized)
    confusables = {str(key): str(value) for key, value in data.get("confusables", {}).items()}

    def pattern(item: dict[str, Any], key: str) -> re.Pattern[str]:
        return re.compile(str(item.get(key) or data[key]))

    rules = tuple(
        _Rule(
            rule=str(item["id"]),
            category=str(item["category"]),
            description=str(item["description"]),
            pattern=re.compile(str(item["pattern"])),
            negatable=bool(item.get("negatable", False)),
            directive=bool(item.get("directive", False)),
            negations=pattern(item, "negations"),
            corrections=pattern(item, "corrections"),
            critiques=pattern(item, "critiques"),
        )
        for item in data["rules"]
    )
    return confusables, rules, _language(data)


def _policy() -> tuple[dict[str, str], tuple[_Rule, ...], _Language]:
    """Compile the currently loaded policy, reusing only an identical snapshot.

    Read through the validated loader on every call so its explicit cache refresh
    also refreshes scanner behavior, and malformed replacements cannot reuse a
    previously successful compilation.
    """
    data = load_policy("return-tripwires")
    return _compiled_policy(json.dumps(data, sort_keys=True))


# Existing callers explicitly reset or inspect the derived cache.
_policy.cache_clear = _compiled_policy.cache_clear
_policy.cache_info = _compiled_policy.cache_info
_policy.cache_parameters = _compiled_policy.cache_parameters


def _normalize(text: str, confusables: dict[str, str]) -> tuple[str, list[int]]:
    """A lower-cased comparison copy of ``text`` and the original offset of each of its characters."""
    characters: list[str] = []
    offsets: list[int] = []
    for index, character in enumerate(text):
        pieces = []
        for piece in unicodedata.normalize("NFKD", confusables.get(character, character)):
            if unicodedata.category(piece) in ("Mn", "Me", "Cf"):
                continue
            pieces.append(confusables.get(piece, piece))
        for piece in normalize_security_text("".join(pieces)).lower():
            # Folded again after lower-casing, for confusables listed only in one case.
            characters.append(confusables.get(piece, piece))
            offsets.append(index)
    return "".join(characters), offsets


# Clause model. A paragraph ends at a blank line and a list item starts a new
# segment; a single line break inside a paragraph is a soft wrap, not a clause
# boundary. Segments split into sentences at ., !, ? and ;. Each line of a
# fenced block is a clause whose context is the sentence right before the
# fence, so "Install it with:" makes the block an instruction and "Do not run
# this unsafe example:" makes it a quotation. A negation only cancels a match
# inside its own sub-clause: a conjunction or comma between them ends its reach.
_FENCE = re.compile(r"(?ms)^[ \t]*(```|~~~)[^\n]*\n(.*?)^[ \t]*\1[ \t]*$")
_PARAGRAPH_BREAK = re.compile(r"\n[ \t]*\n")
_LIST_ITEM = re.compile(r"(?m)^[ \t]*(?:[-*+]|\d{1,3}[.)])[ \t]+")
_SENTENCE = re.compile(r"[^.;!?]+(?:[.!?](?!\s|$)[^.;!?]*)*")
# "or" is not a boundary: "do not X or Y" keeps both actions negated.
_SUBCLAUSE = re.compile(r"(,|;|\b(?:and|then|but|also|before|after|once|until|when|while|so that)\b)")
_RELATIVE = re.compile(r"\b(?:that|which|who|whom|whose)\b")
_ADVERB = re.compile(r"\w+ly|ever|just|even|simply|again|actually|really")
# A word right after one of these is a noun ("the change", "this fix"), not an action.
_DETERMINER = re.compile(r"\b(?:the|a|an|this|these|those|my|your|our|its|their|his|her|any|each|every|some|no)\s+$")


def _actions(language: "_Language", text: str) -> list[re.Match[str]]:
    """Action verbs in ``text``, leaving out nouns that share their spelling."""
    return [verb for verb in language.actions.finditer(text) if not _DETERMINER.search(text, 0, verb.start())]
# Blanked to spaces of the same length before clauses are read, so offsets still map: a backslash-newline
# continues a line, and blockquote markers ("> ") do not split a quoted paragraph.
_ESCAPED_NEWLINE = re.compile(r"\\\r?\n")
_QUOTE_MARKERS = re.compile(r"(?m)^[ \t]*(?:>[ \t]?)+")
# Markdown decoration around words: inline code marks (not fence lines), emphasis asterisks and underscores
# (not list bullets, nor underscores inside identifiers such as verify_ssl) and heading markers, including a
# heading inside a list item ("- # Set ..."), whose list marker is kept.
_DECORATION = re.compile(r"(?<!`)`{1,2}(?!`)|(?<=\S)\*+|\*+(?=\S)|(?<!\w)_+|_+(?!\w)")
_HEADING = re.compile(r"^[ \t]*(?:(?:[-*+]|\d{1,3}[.)])[ \t]+)*(#{1,6})(?=[ \t])", re.M)


def _blank_headings(text: str) -> str:
    """``text`` with heading markers blanked to spaces, leaving any list marker before them."""
    return _HEADING.sub(lambda match: match.group(0)[: match.start(1) - match.start()] + " " * len(match.group(1)), text)
# A fenced line ending in a pipe or && continues on the next line.
_FENCED_LINE = re.compile(r"(?:[^\n]*(?:\||&&)[ \t]*\n)*[^\n]+")


def _blank(pattern: re.Pattern[str], text: str) -> str:
    return pattern.sub(lambda match: " " * len(match.group(0)), text)


def _stripped(text: str, start: int, end: int) -> tuple[int, int]:
    """The span without its leading and trailing whitespace."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _segments(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Paragraph and list-item segments of ``text[start:end]``, as absolute spans."""
    spans: list[tuple[int, int]] = []
    position = start
    for paragraph in [*_PARAGRAPH_BREAK.finditer(text, start, end), None]:
        paragraph_end = paragraph.start() if paragraph else end
        cuts = [match.start() for match in _LIST_ITEM.finditer(text, position, paragraph_end) if match.start() > position]
        for cut_start, cut_end in zip([position, *cuts], [*cuts, paragraph_end]):
            spans.append((cut_start, cut_end))
        position = paragraph.end() if paragraph else end
    return spans


def _units(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, context)`` clauses: sentences outside fences, and lines inside them."""
    units: list[tuple[int, int, str]] = []
    position = 0
    for fence in [*_FENCE.finditer(text), None]:
        prose_end = fence.start() if fence else len(text)
        for segment_start, segment_end in _segments(text, position, prose_end):
            for sentence in _SENTENCE.finditer(text, segment_start, segment_end):
                if sentence.group(0).strip():
                    units.append((*_stripped(text, sentence.start(), sentence.end()), ""))
        if fence is None:
            break
        context = ""
        if units and not text[units[-1][1]:fence.start()].strip(" \t\n:.") and units[-1][1] <= fence.start():
            context = text[units[-1][0]:units[-1][1]]
        for line in _FENCED_LINE.finditer(text, fence.start(2), fence.end(2)):
            if line.group(0).strip():
                units.append((*_stripped(text, line.start(), line.end()), context))
        position = fence.end()
    return units


def _own(before: str) -> str:
    """The part of ``before`` in the same sub-clause as what follows it."""
    return _SUBCLAUSE.split(before)[-1]


def _scope(language: _Language, before: str, match: str) -> str:
    """The text a cancelling word must sit in: the match's sub-clause, extended back over the one before it
    when the match's own has no action of its own and follows "and" or a comma ("Remove verify=False and
    check_hostname=False")."""
    parts = _SUBCLAUSE.split(before)
    own, index = parts[-1], len(parts) - 1
    while index >= 2 and parts[index - 1] in (",", "and") and _governing(language, own, match) is None:
        own, index = parts[index - 2] + parts[index - 1] + own, index - 2
    return own


def _governing(language: _Language, before: str, match: str) -> tuple[int, str] | None:
    """The action applied to the match, as (position in ``before + match``, verb): the match's own leading verb,
    unless it names a command, or else the last action verb before it that is not inside a relative clause."""
    lead = language.actions.match(match)
    if lead and lead.group(0) not in language.commands and not _DETERMINER.search(before):
        return len(before), lead.group(0)
    verbs = _actions(language, before)
    if verbs:
        relative = _RELATIVE.search(before, verbs[0].end())
        main = [verb for verb in verbs if relative is None or verb.start() < relative.start()]
        return main[-1].start(), main[-1].group(0)
    return None


def _negation_applies(rule: "_Rule", language: _Language, text: str, target: int) -> bool:
    """Whether a negation in ``text`` applies to the action starting at ``target``: the negation is followed,
    after at most two adverbs, by that action, or by an action joined to it with "or" or "nor"."""
    verbs = _actions(language, text)
    for negation in rule.negations.finditer(text):
        following = [verb for verb in verbs if verb.start() >= negation.end()]
        if not following:
            continue
        between = text[negation.end():following[0].start()].split()
        if len(between) > 2 or not all(_ADVERB.fullmatch(word) for word in between):
            continue
        if following[0].start() == target:
            return True
        for previous, verb in zip(following, following[1:]):
            if not re.search(r"\b(?:or|nor)\b", text[previous.end():verb.start()]):
                break
            if verb.start() == target:
                return True
    return False


def _cancelled(rule: "_Rule", language: _Language, before: str, match: str, corrections: re.Pattern[str]) -> bool:
    own = _scope(language, before, match)
    governing = _governing(language, own, match)
    if governing is None:
        return bool(rule.critiques.search(own))
    position, verb = governing
    if _negation_applies(rule, language, own + match, position):
        return True
    verbs = _actions(language, own + match)
    return bool(corrections.fullmatch(verb) and verbs and verbs[0].start() == position)


def _negated(rule: "_Rule", language: _Language, before: str, match: str, context: str) -> bool:
    """Whether the match's own sub-clause, or for a fenced line the sub-clause of the sentence introducing the
    fence, cancels it: a negation that applies to its action, a correcting verb that is its action, or a
    critique when no action verb governs it."""
    if not rule.negatable:
        return False
    if _cancelled(rule, language, before, match, rule.corrections):
        return True
    return bool(context) and _cancelled(rule, language, context + " ", "", language.context_corrections)


_WORD_START = re.compile(r"(?<![\w])\w")


def _candidates(rule: "_Rule", clause: str) -> "Iterator[re.Match[str]]":
    """Every match of the rule starting at the clause's start (for anchored rules) or at any word,
    overlapping ones included, so a negated match cannot hide a later action in the same clause."""
    for start in [0, *(word.start() for word in _WORD_START.finditer(clause) if word.start())]:
        match = rule.pattern.match(clause, start)
        if match:
            yield match


def scan_return_tripwires(text: str) -> list[TripwireHit]:
    """Every tripwire hit in ``text``, with offsets into the original text."""
    confusables, rules, language = _policy()
    normalized, offsets = _normalize(text, confusables)
    normalized = _blank_headings(_blank(_DECORATION, _blank(_QUOTE_MARKERS, _blank(_ESCAPED_NEWLINE, normalized))))
    hits: list[TripwireHit] = []
    seen: set[tuple[str, int]] = set()
    for unit_start, unit_end, context in _units(normalized):
        clause = normalized[unit_start:unit_end]
        for rule in rules:
            for match in _candidates(rule, clause):
                before = clause[: match.start()]
                if _negated(rule, language, before, match.group(0), context):
                    continue
                # An instruction may open the clause or one of its sub-clauses
                # ("Fix the docs, then disable the failing tests").
                own = _own(before) + clause[match.start():]
                if rule.directive and not (
                    language.directive_markers.search(before + match.group(0))
                    or language.imperative.match(clause) or language.imperative.match(own)
                    or (context and (language.directive_markers.search(context) or language.imperative.match(_own(context))))
                ):
                    continue
                start = offsets[unit_start + match.start()] if unit_start + match.start() < len(offsets) else len(text)
                end_index = unit_start + match.end() - 1
                end = offsets[end_index] + 1 if 0 <= end_index < len(offsets) else len(text)
                key = (rule.rule, start)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    TripwireHit(
                        rule=rule.rule,
                        category=rule.category,
                        description=rule.description,
                        start=start,
                        end=end,
                        clause_sha256=hashlib.sha256(" ".join(clause.split()).encode("utf-8")).hexdigest(),
                    )
                )
                break
    return hits


__all__ = ["TripwireHit", "scan_return_tripwires"]
