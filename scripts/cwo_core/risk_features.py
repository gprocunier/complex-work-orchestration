"""Routing risk features, computed from the task text independently of expert matches.

Normalization and token boundaries: the text is normalized with Unicode NFKC and then
``str.casefold()``. A token is a maximal run of ASCII letters ``a``-``z`` and digits
``0``-``9``; every other character (whitespace, punctuation, hyphen, underscore, any
non-ASCII letter or combining mark left after NFKC) is a boundary. A curated term in
``policy/risk-features.yaml`` matches only as a whole token, and a multi-word term only as
the same consecutive sequence of whole tokens. There is no prefix matching and no stemming
beyond the inflections the policy lists, so "products" is not "prod" and "sign indicator" is
not "sign in". A feature found anywhere counts, negated or quoted mentions included.

Appended text: callers pass the original task text and each appended piece of free text as
separate segments, in order. ``assess_risk_features`` assesses the text as passed, each
segment alone and every cumulative prefix of the segments concatenated directly (segments
0..i for each i), and returns the union: every feature found in any of them, the floor of
that union and every expert any of them requires. A feature formed at any point in the
append history, including one formed across a segment boundary or mid-token
(``["Inspect sign ", "in"]``), therefore stays when later segments are appended
(``"g"``), and so do its floor and experts. Direct concatenation is the most adversarial
join, because an append can extend the last token; a prefix joined with a separator has the
same tokens as the start of the separator-joined text, which is assessed as passed. Text
joined into one string before it reaches the router is assessed as that one string, where
an append can extend the last token ("OIDC" + "s"); the guarantee is not claimed there. It
is tested on bounded generated suffixes, multi-segment histories and the labelled corpus,
not proven for every string.

Narrowing: not supported in this version. No scope, evidence file, path,
stage or flag resolves a feature or lowers its floor, and every narrowing input is refused with
``RISK_NARROWING_UNSUPPORTED`` before any routing output (``refuse_risk_narrowing``). The
assessment never records a resolution. Routing risk is a planning signal; it grants no dispatch
authority.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Sequence

from .errors import CWOValidationError
from .policy import RISK_ORDER, load_policy

_SEPARATOR = re.compile(r"[^0-9a-z]+")
RISK_NARROWING_UNSUPPORTED = "risk narrowing is not supported in this version"


def normalized_tokens(text: str) -> tuple[str, ...]:
    """The text's tokens: NFKC, case-folded, split at every character other than an ASCII letter or digit."""
    return tuple(token for token in _SEPARATOR.split(unicodedata.normalize("NFKC", text).casefold()) if token)


@lru_cache(maxsize=None)
def _term_tokens(term: str) -> tuple[str, ...]:
    return normalized_tokens(term)


@dataclass(frozen=True)
class RiskAssessment:
    features: dict[str, list[str]]
    floor: str | None
    floor_reasons: list[str]
    required_experts: list[str]
    segments: int = 1
    prefixes: int = 0

    def as_record(self) -> dict[str, Any]:
        """The route record. ``resolved`` is always null: this version never narrows a feature."""
        return {
            "version": _policy()["version"],
            "features": [{"feature": name, "terms": terms, "resolved": None} for name, terms in self.features.items()],
            "floor": self.floor,
            "floor_reasons": list(self.floor_reasons),
            "required_experts": list(self.required_experts),
            "assessed_segments": self.segments,
            "assessed_prefixes": self.prefixes,
        }


@lru_cache(maxsize=1)
def _policy() -> dict[str, Any]:
    data = load_policy("risk-features")
    for name, feature in data["features"].items():
        if feature["floor"] not in RISK_ORDER:
            raise ValueError(f"risk feature {name} has an unknown floor {feature['floor']!r}")
    if "validated_scope" in data:
        raise ValueError("risk narrowing is not supported in this version; policy must not declare validated_scope")
    return data


def _term_matches(tokens: tuple[str, ...], term: str) -> bool:
    """The term's own tokens occur in the text as a consecutive run of whole tokens."""
    needle = _term_tokens(term)
    width = len(needle)
    if not width or needle[0] not in tokens:
        return False
    return any(tokens[index:index + width] == needle for index in range(len(tokens) - width + 1))


def _floor(names: list[str]) -> tuple[str | None, list[str], list[str]]:
    policy = _policy()
    present = set(names)
    # A reason reads "<feature> sets the floor to <floor>", never "<feature>: <floor>": a manual export carries the
    # route, and the outbound screen reads "asset:credentials: high" as a credential-named field with a value.
    reasons = [f"{name} sets the floor to {policy['features'][name]['floor']}" for name in names]
    floors = [policy["features"][name]["floor"] for name in names]
    for combination in policy.get("combinations", []):
        if set(combination["all"]) <= present:
            floors.append(combination["floor"])
            reasons.append(" + ".join(combination["all"]) + f" sets the floor to {combination['floor']}")
    experts = sorted({expert for name in names for expert in policy["features"][name].get("experts", [])})
    floor = max(floors, key=RISK_ORDER.index) if floors else None
    return floor, reasons, experts


def assessed_texts(text: str, segments: Sequence[str] | None) -> list[str]:
    """The text as passed, each segment alone, and each cumulative prefix of the segments concatenated directly."""
    items = [text]
    if segments:
        items += list(segments)
        items += ["".join(segments[:index + 1]) for index in range(1, len(segments))]
    return list(dict.fromkeys(items))


def assess_risk_features(text: str, *, segments: Sequence[str] | None = None) -> RiskAssessment:
    """Assess ``text``; with ``segments`` (the original task text, then each appended segment) assess the history too.

    The result is the union over ``text``, every segment alone and every cumulative prefix join of the segments,
    so a feature or floor formed at any point in the append history is never lost when more segments are appended.
    """
    if segments is not None and (isinstance(segments, str) or not all(isinstance(item, str) for item in segments)):
        raise CWOValidationError("text segments must be a list of strings")
    segments = list(segments or [])
    token_sets = tuple(normalized_tokens(item) for item in assessed_texts(text, segments))
    features = {}
    for name, feature in _policy()["features"].items():
        terms = [term for term in feature["terms"] if any(_term_matches(tokens, term) for tokens in token_sets)]
        if terms:
            features[name] = terms
    floor, reasons, experts = _floor(list(features))
    return RiskAssessment(
        features=features, floor=floor, floor_reasons=reasons, required_experts=experts,
        segments=1 + len(segments), prefixes=len(segments),
    )


def narrowing_inputs(*, risk_scope: Any = None, risk_evidence_dir: Any = None) -> list[str]:
    """The narrowing inputs a caller supplied. Any value other than None counts, an empty one included."""
    supplied = []
    if risk_scope is not None:
        supplied.append("risk scope")
    if risk_evidence_dir is not None:
        supplied.append("risk evidence directory")
    return supplied


def refuse_risk_narrowing(*, risk_scope: Any = None, risk_evidence_dir: Any = None, source: str = "") -> None:
    """Refuse any narrowing input; this version has no risk-reduction path.

    Nothing is read or validated: a supplied scope or evidence directory is refused whatever it contains.
    """
    supplied = narrowing_inputs(risk_scope=risk_scope, risk_evidence_dir=risk_evidence_dir)
    if supplied:
        where = f" ({source})" if source else ""
        raise CWOValidationError(f"{RISK_NARROWING_UNSUPPORTED}; refused {', '.join(supplied)}{where}")


RISK_NARROWING_FLAG_HELP = (
    "Not supported in this version: risk narrowing is unavailable. Any value is refused before routing; "
    "--file-path and --stage never resolve a risk feature either."
)


def add_risk_narrowing_arguments(parser: Any) -> None:
    """The --risk-scope and --risk-evidence-dir flags, kept only so that using them is refused explicitly."""
    parser.add_argument("--risk-scope", help=RISK_NARROWING_FLAG_HELP)
    parser.add_argument("--risk-evidence-dir", help=RISK_NARROWING_FLAG_HELP)


def refuse_risk_narrowing_arguments(args: Any, *, source: str) -> None:
    """Exit with the refusal, before any routing output, when a CLI was given a narrowing flag."""
    try:
        refuse_risk_narrowing(risk_scope=getattr(args, "risk_scope", None),
                              risk_evidence_dir=getattr(args, "risk_evidence_dir", None), source=source)
    except CWOValidationError as exc:
        raise SystemExit(str(exc)) from None


__all__ = [
    "RISK_NARROWING_UNSUPPORTED",
    "RiskAssessment",
    "add_risk_narrowing_arguments",
    "assess_risk_features",
    "assessed_texts",
    "narrowing_inputs",
    "normalized_tokens",
    "refuse_risk_narrowing",
    "refuse_risk_narrowing_arguments",
]


# Cooperative host-only use registry; task submissions cannot enroll validators.
@dataclass(frozen=True, eq=False)
class RiskUse:
    """Opaque one-call identity; constructing or copying it grants nothing."""


# Entries live only during the host's bounded classification call.
_TASK_RISK_USES = {}


def _register_task_risk_use(check, text, segments, paths):
    use = RiskUse()
    _TASK_RISK_USES[use] = (check, text, tuple(segments), tuple(paths), False)
    return use


def _remove_task_risk_use(use):
    _TASK_RISK_USES.pop(use, None)


def _task_risk_entry(use):
    if type(use) is not RiskUse or use not in _TASK_RISK_USES:
        raise CWOValidationError('task-risk use is not registered by the current host')
    return _TASK_RISK_USES[use]


def registered_assessment(use, text, segments, paths, stage, original_assessor):
    if use is None:
        return original_assessor(text, segments=segments)
    entry = _task_risk_entry(use)
    check, expected_text, expected_segments, expected_paths, started = entry
    if started:
        raise CWOValidationError('task-risk use was already started')
    _TASK_RISK_USES[use] = (*entry[:4], True)
    if (text, tuple(segments or ()), tuple(paths or ()), stage) != (
            expected_text, expected_segments, expected_paths, None):
        raise CWOValidationError('task-risk use conflicts with the exact original caller scope')
    return check()


def finish_registered_assessment(use, result):
    if use is not None:
        check = _task_risk_entry(use)[0]
        _remove_task_risk_use(use)  # Spend before the final callout; never replay a live token.
        check()
    return result
