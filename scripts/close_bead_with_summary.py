#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import unicodedata
from typing import Any

from cwo_core.beads import run_bd

NO_VALUE = "None recorded."
# Successful closure is unavailable until CWO can verify, before any Beads
# write, a recorded requirement baseline, the exact delivered candidate and
# passing evidence for every requirement (issue #37). Until then only these
# accurate non-completion outcomes are recorded; anything else, including
# every way of saying the work succeeded, is refused before Beads is touched.
NON_COMPLETION_DISPOSITIONS = ("pending-acceptance", "deferred", "rejected", "abandoned", "superseded", "split")
# Outcomes after which the Bead stays open. pending-acceptance records delivered
# work whose acceptance CWO has not verified; the operator decides on closure.
OPEN_DISPOSITIONS = frozenset({"pending-acceptance", "deferred"})
SUCCESS_UNAVAILABLE = (
    "successful closure is unavailable: CWO cannot yet verify a recorded requirement baseline, the "
    "delivered candidate and passing evidence for every requirement before writing to Beads (issue #37). "
    "Nothing was written. To record the work without claiming success, use an accurate non-completion "
    "disposition (" + ", ".join(NON_COMPLETION_DISPOSITIONS) + ") or leave the Bead open; the operator "
    "decides whether to close it"
)
MEANINGFUL_REQUIRED_FIELDS = {
    "who_involved": "who was involved",
    "what_changed": "what changed",
    "how_validated": "how validated",
    "when_closed": "when closed",
    "where_executed": "where executed",
    "evidence": "evidence",
    "residual_risk": "residual risk",
    "follow_up": "follow-up",
}


def execute_offline_completed(
    bound: Any, target: Any, *, operation_id: str, expected_revision: int
) -> dict[str, Any]:
    """Consume an original BoundReview through the offline memory reliability path.

    The original MemoryClosureTarget and consumer retain all reliability checks.
    Returned reliability reports describe fake effects and saved persistence facts.
    This reliability entrypoint grants no production closure authority.
    """
    # Original producers import closure formatting; keep this reliability import local.
    from prepare_delivery_closure import close_offline

    return close_offline(bound, target, operation_id=operation_id, expected_revision=expected_revision)


def execute_qualified_completed(host: Any, *, dry_run: bool = False) -> dict[str, Any]:
    """Consume an active supervisor registration; public CLI activation stays disabled."""
    from qualified_closure import consume

    return consume(host, dry_run=dry_run)


def clean_text(value: str) -> str:
    return value.strip().replace("\\n", "\n")


def require_text(value: str, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


NARRATIVE_NOTE = "The sections below are the closer's own notes, shown verbatim; CWO records only the fields above."


def literal(value: str) -> str:
    """``value`` as a Markdown code span, which shows its text literally: no HTML, entities or emphasis."""
    fence = "`" * (max((len(run) for run in re.findall(r"`+", value)), default=0) + 1)
    pad = " " if value[:1] == "`" or value[-1:] == "`" else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def format_bullets(title: str, values: list[str], fallback: str = NO_VALUE) -> list[str]:
    """A narrative section: every line of every item indented four spaces, after a blank line.

    Markdown shows such lines verbatim as a code block, and none of them can start a line of its own, so
    narrative text can neither take the shape of the summary's fields nor be rendered as formatting.
    """
    items = [clean_text(value) for value in values if clean_text(value)]
    if not items:
        items = [fallback]

    lines = [f"{title}:", ""]
    for item in items:
        item_lines = item.splitlines() or [""]
        lines.append(f"    - {item_lines[0]}")
        for line in item_lines[1:]:
            lines.append(f"      {line}")
    return lines


def clean_items(values: list[str] | None) -> list[str]:
    return [clean_text(value) for value in (values or []) if clean_text(value)]


def closure_memory_missing_fields(
    *,
    who_involved: list[str] | None = None,
    what_changed: list[str] | None = None,
    how_validated: list[str] | None = None,
    when_closed: list[str] | None = None,
    where_executed: list[str] | None = None,
    evidence: list[str] | None = None,
    residual_risk: list[str] | None = None,
    follow_up: list[str] | None = None,
) -> list[str]:
    values = {
        "who_involved": who_involved,
        "what_changed": what_changed,
        "how_validated": how_validated,
        "when_closed": when_closed,
        "where_executed": where_executed,
        "evidence": evidence,
        "residual_risk": residual_risk,
        "follow_up": follow_up,
    }
    missing = [
        MEANINGFUL_REQUIRED_FIELDS[field]
        for field, field_values in values.items()
        if not clean_items(field_values)
    ]
    return missing


def closure_memory_warnings(missing_fields: list[str]) -> list[str]:
    if not missing_fields:
        return []
    return [
        "closure-memory is incomplete for meaningful work; missing "
        + ", ".join(missing_fields)
    ]


def render_closure_summary(
    *,
    bead: str,
    disposition: str,
    why: str,
    who_involved: list[str] | None = None,
    what_changed: list[str] | None = None,
    how_validated: list[str] | None = None,
    when_closed: list[str] | None = None,
    where_executed: list[str] | None = None,
    decisions: list[str],
    evidence: list[str],
    residual_risk: list[str],
    follow_up: list[str],
) -> str:
    bead = require_text(bead, "bead")
    disposition = require_text(disposition, "disposition")
    why = require_text(why, "why")

    lines = [
        "Closure summary:",
        f"- Bead: {literal(bead)}",
        f"- Disposition: {disposition}",
        f"- Why: {literal(why)}",
        "",
        NARRATIVE_NOTE,
        "",
        *format_bullets("Who was involved", who_involved or []),
        "",
        *format_bullets("What changed", what_changed or []),
        "",
        *format_bullets("How validated", how_validated or []),
        "",
        *format_bullets("When closed", when_closed or []),
        "",
        *format_bullets("Where executed", where_executed or []),
        "",
        *format_bullets("Key decisions", decisions),
        "",
        *format_bullets("Evidence", evidence),
        "",
        *format_bullets("Residual risk", residual_risk),
        "",
        *format_bullets("Follow-up", follow_up),
    ]
    return "\n".join(lines).rstrip() + "\n"


def default_close_reason(disposition: str, why: str) -> str:
    return f"{clean_text(disposition)}: {clean_text(why)}"


def checked_disposition(value: str, *, close: bool) -> str:
    """The disposition to record, or ValueError before any Beads write."""
    disposition = clean_text(value).lower()
    if disposition not in NON_COMPLETION_DISPOSITIONS:
        raise ValueError(SUCCESS_UNAVAILABLE + f" (disposition given: {clean_text(value)!r})")
    if disposition in OPEN_DISPOSITIONS and close:
        raise ValueError(f"a {disposition} Bead stays open: post the closure summary without --close. Nothing was written")
    return disposition


# Letters from other scripts that look like the Latin letters of the summary's field names.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    "ӏ": "l", "һ": "h", "ԝ": "w", "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "υ": "u", "ѡ": "w", "ɑ": "a", "ɡ": "g", "ı": "i", "ȷ": "j",
    # Characters that look like a colon but are not one, even after compatibility folding.
    "\u2236": ":", "\ua789": ":", "\u02d0": ":", "\u02f8": ":", "\u0589": ":", "\u05c3": ":", "\u1361": ":",
    "\u205a": ":", "\u2e2c": ":", "\u0703": ":", "\u0704": ":", "\u0903": ":",
})
_FIELD_NAMES = r"(?:closure summary|bead|disposition|why)"


def _separated(text: str, end: int) -> bool:
    """Whether a field name ending at ``end`` is followed, after optional spaces, by something that can separate a
    name from a value: a colon, equals sign or table bar; an arrow or any other mathematical or graphic symbol; other
    punctuation that is not ordinary sentence punctuation; markdown delimiters; or a dash followed by a space, so that
    "disposition-specific" stays ordinary prose."""
    rest = text[end:].lstrip()
    if not rest:
        return False
    first = rest[0]
    if first in "*_~`\\":
        return True
    category = unicodedata.category(first)
    if category == "Pd" or first == "\u2212":
        stripped = rest.lstrip(first)
        return stripped == "" or stripped[0].isspace() or stripped.startswith(">")
    return category in ("Sm", "So") or (category == "Po" and first not in ".,;!?'\"\u2019\u201c\u201d")


def _reads_as_field(line: str) -> bool:
    """Check if any representation of the line reads as a field: raw, delimiter-preserving normalized, or fully plain."""
    for representation in (line.casefold(), _plain_preserving_delimiters(line), _plain(line)):
        start = re.match(_FIELD_NAMES + r"\b", representation)
        if start and _separated(representation, start.end()):
            return True
        if any(_separated(representation, match.end()) for match in re.finditer(r"\bdisposition\b", representation)):
            return True
    return False


# HTML elements that start a new line when rendered; any other tag is removed without a trace, as inline
# markup such as "Dispos<b>i</b>tion" renders as one word.
_LINE_TAG = re.compile(r"</?(?:br|p|div|li|ul|ol|tr|td|th|table|h[1-6]|blockquote|pre|hr|section|details|summary)\b[^>]*>",
                       re.IGNORECASE)


def _reader_lines(text: str) -> list[str]:
    """``text`` split into the lines a reader sees, with character references decoded."""
    decoded = html.unescape(html.unescape(text))
    return re.sub(r"<[^>]*>", "", _LINE_TAG.sub("\n", decoded)).splitlines()


def _plain(line: str) -> str:
    """``line`` as a reader sees it: compatibility forms, invisible and combining marks, look-alike letters, case,
    emphasis and code marks, and leading list, quote, heading and table markers all removed."""
    text = "".join(c for c in unicodedata.normalize("NFKD", line) if unicodedata.category(c) not in ("Mn", "Me", "Cf"))
    text = unicodedata.normalize("NFKC", text).casefold().translate(_CONFUSABLES)
    text = re.sub(r"[*_~`\\]", "", text)
    return re.sub(r"^[\s\-+*>#=|.)\d]*", "", text)


def _plain_preserving_delimiters(line: str) -> str:
    """``line`` normalized but with markdown delimiters (*_~`\\) preserved so they can be classified as separators."""
    text = "".join(c for c in unicodedata.normalize("NFKD", line) if unicodedata.category(c) not in ("Mn", "Me", "Cf"))
    text = unicodedata.normalize("NFKC", text).casefold().translate(_CONFUSABLES)
    return re.sub(r"^[\s\-+>#=|.)\d]*", "", text)


def imitates_summary_fields(text: str) -> bool:
    """Whether ``text`` has a line that, however it is decorated or encoded, reads as one of the summary's fields:
    each physical line as written, and each line as rendered, are checked."""
    lines = [*text.splitlines(), *_reader_lines(text)]
    return any(_reads_as_field(line) for line in lines)


# Characters that change how text is displayed rather than adding text: C0 controls other than tab, newline and
# carriage return (escape sequences can move the cursor and redraw a line in a terminal), DEL, C1 controls and
# bidirectional overrides, isolates and marks.
_DISPLAY_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def checked_narrative(args: argparse.Namespace) -> None:
    """ValueError, before any Beads write, if input could pass for the summary's own fields."""
    if getattr(args, "close_reason", None):
        raise ValueError(
            "--close-reason is unavailable while successful closure is: the close reason is always "
            "'<disposition>: <why>'. Nothing was written"
        )
    for name in ("bead", "why"):
        value = clean_text(getattr(args, name) or "")
        # Any line boundary Python recognizes, not only newlines (for example U+2028 or NEL).
        if len(value.splitlines()) > 1:
            raise ValueError(f"--{name} must be a single line. Nothing was written")
        if _DISPLAY_CONTROL.search(value):
            raise ValueError(f"--{name} cannot contain control or text-direction characters. Nothing was written")
        if imitates_summary_fields(value):
            raise ValueError(f"--{name} cannot contain a summary field such as 'Disposition:'. Nothing was written")
    fields = ("who_involved", "what_changed", "how_validated", "when_closed", "where_executed", "decision", "evidence",
              "residual_risk", "follow_up")
    for name in fields:
        for item in getattr(args, name, None) or []:
            if _DISPLAY_CONTROL.search(clean_text(item)):
                raise ValueError("narrative fields cannot contain control or text-direction characters. Nothing was written")
            if imitates_summary_fields(clean_text(item)):
                raise ValueError(
                    "narrative fields cannot contain lines that read as the summary's fields (Bead:, Disposition:, "
                    "Why:, Closure summary:), however they are formatted. Nothing was written"
                )


def execute(args: argparse.Namespace) -> dict[str, Any]:
    disposition = checked_disposition(args.disposition, close=bool(args.close))
    checked_narrative(args)
    who_involved = getattr(args, "who_involved", []) or []
    what_changed = getattr(args, "what_changed", []) or []
    how_validated = getattr(args, "how_validated", []) or []
    when_closed = getattr(args, "when_closed", []) or []
    where_executed = getattr(args, "where_executed", []) or []
    evidence = args.evidence or []
    residual_risk = args.residual_risk or []
    follow_up = args.follow_up or []
    missing_fields = closure_memory_missing_fields(
        who_involved=who_involved,
        what_changed=what_changed,
        how_validated=how_validated,
        when_closed=when_closed,
        where_executed=where_executed,
        evidence=evidence,
        residual_risk=residual_risk,
        follow_up=follow_up,
    )
    if getattr(args, "meaningful", False) and missing_fields:
        raise ValueError("meaningful closure missing required fields: " + ", ".join(missing_fields))

    summary = render_closure_summary(
        bead=args.bead,
        disposition=disposition,
        why=args.why,
        who_involved=who_involved,
        what_changed=what_changed,
        how_validated=how_validated,
        when_closed=when_closed,
        where_executed=where_executed,
        decisions=args.decision or [],
        evidence=evidence,
        residual_risk=residual_risk,
        follow_up=follow_up,
    )
    close_reason = default_close_reason(disposition, args.why)
    result = {
        "bead": clean_text(args.bead),
        "summary": summary,
        "dry_run": bool(args.dry_run),
        "comment_posted": False,
        "close_requested": bool(args.close),
        "closed": False,
        "close_reason": close_reason,
        "meaningful": bool(getattr(args, "meaningful", False)),
        "closure_memory_quality": "complete" if not missing_fields else "incomplete",
        "closure_memory_missing_fields": missing_fields,
        "warnings": closure_memory_warnings(missing_fields),
    }

    if args.dry_run:
        return result

    run_bd(["comment", "--", clean_text(args.bead), summary])
    result["comment_posted"] = True

    if args.close:
        try:
            run_bd(["close", "--reason", close_reason, "--", clean_text(args.bead)])
        except (Exception, SystemExit) as exc:
            # The comment is already in Beads; say so and leave the closure unconfirmed.
            result["partial_persistence"] = True
            result["close_error"] = str(exc) or type(exc).__name__
            raise PartialPersistence(result) from exc
        result["closed"] = True

    return result


class PartialPersistence(Exception):
    """The closure comment was posted but the close did not complete."""

    def __init__(self, result: dict[str, Any]) -> None:
        super().__init__("the closure comment was posted, but closing the Bead failed; the closure is unconfirmed")
        self.result = result


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Add a final closure-memory comment to a Bead and optionally close it."
    )
    cli.add_argument("--bead", required=True, help="Bead ID to comment on.")
    cli.add_argument(
        "--disposition",
        required=True,
        help="One of " + ", ".join(NON_COMPLETION_DISPOSITIONS) + ". Successful closure (completed, done, validated, ...) "
        "is unavailable until verified acceptance exists, and is refused before any Beads write.",
    )
    cli.add_argument("--why", required=True, help="Short reason the Bead is being closed.")
    cli.add_argument("--who", dest="who_involved", action="append", default=[], help="Who was involved: agent, reviewer, operator, model lane, or team. Repeatable.")
    cli.add_argument("--what", dest="what_changed", action="append", default=[], help="What changed: file, behavior, result, or scope. Repeatable.")
    cli.add_argument("--how", dest="how_validated", action="append", default=[], help="How it was validated: command, review, CI, install smoke, or manual check. Repeatable.")
    cli.add_argument("--when", dest="when_closed", action="append", default=[], help="When it closed: date, branch, commit, run ID, or timeline marker. Repeatable.")
    cli.add_argument("--where", dest="where_executed", action="append", default=[], help="Where it ran: repo path, branch, environment, Beads local-only/Dolt-backed mode. Repeatable.")
    cli.add_argument("--decision", action="append", default=[], help="Key decision to preserve. Repeatable.")
    cli.add_argument("--evidence", action="append", default=[], help="Evidence, command, commit, file, or artifact. Repeatable.")
    cli.add_argument("--residual-risk", action="append", default=[], help="Residual risk future agents should know. Repeatable.")
    cli.add_argument("--follow-up", action="append", default=[], help="Follow-up Bead, action, or 'none'. Repeatable.")
    cli.add_argument("--meaningful", action="store_true", help="Require full closure-memory fields for non-trivial Beads.")
    cli.add_argument("--close", action="store_true", help="Close the Bead after posting the closure comment.")
    cli.add_argument("--close-reason", help="Unavailable while successful closure is; the reason is '<disposition>: <why>'.")
    cli.add_argument("--dry-run", action="store_true", help="Print what would be posted without calling bd.")
    cli.add_argument("--json", action="store_true", help="Print structured result JSON.")
    return cli


def main(argv: list[str] | None = None) -> None:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        result = execute(args)
    except PartialPersistence as exc:
        if args.json:
            print(json.dumps(exc.result, indent=2, sort_keys=True))
        print(f"close_bead_with_summary: {exc} ({exc.result['close_error']})", file=sys.stderr)
        raise SystemExit(2) from exc
    except (ValueError, SystemExit) as exc:
        print(f"close_bead_with_summary failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    print(result["summary"], end="")
    if result["warnings"]:
        print("\nClosure-memory warnings:")
        for warning in result["warnings"]:
            print(f"- {warning}")
    if args.dry_run:
        if args.close:
            print(f"\nDry run: would close {result['bead']} with reason: {result['close_reason']}")
        return
    if args.close:
        print(f"\nClosed {result['bead']} with reason: {result['close_reason']}")
    else:
        print(f"\nPosted closure summary to {result['bead']}.")


if __name__ == "__main__":
    main()
