from __future__ import annotations

import unicodedata
from typing import Any

from .errors import CWOPolicyError
from .policy import load_contracting_controls
from .return_common import add_signal, strip_fenced_blocks
from .types import ReturnLanguageResult, ReturnSignal


BIDI_CONTROL_CODEPOINTS = {
    0x061C,
    0x200E,
    0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}
ZERO_WIDTH_CODEPOINTS = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
SCRIPT_NAME_MARKERS = (
    ("LATIN", "Latin"),
    ("GREEK", "Greek"),
    ("CYRILLIC", "Cyrillic"),
    ("ARMENIAN", "Armenian"),
    ("HEBREW", "Hebrew"),
    ("ARABIC", "Arabic"),
    ("SYRIAC", "Syriac"),
    ("THAANA", "Thaana"),
    ("DEVANAGARI", "Devanagari"),
    ("BENGALI", "Bengali"),
    ("GURMUKHI", "Gurmukhi"),
    ("GUJARATI", "Gujarati"),
    ("ORIYA", "Oriya"),
    ("ODIA", "Oriya"),
    ("TAMIL", "Tamil"),
    ("TELUGU", "Telugu"),
    ("KANNADA", "Kannada"),
    ("MALAYALAM", "Malayalam"),
    ("SINHALA", "Sinhala"),
    ("THAI", "Thai"),
    ("LAO", "Lao"),
    ("TIBETAN", "Tibetan"),
    ("MYANMAR", "Myanmar"),
    ("GEORGIAN", "Georgian"),
    ("HANGUL", "Hangul"),
    ("HIRAGANA", "Hiragana"),
    ("KATAKANA", "Katakana"),
    ("CHEROKEE", "Cherokee"),
    ("ETHIOPIC", "Ethiopic"),
    ("CANADIAN SYLLABICS", "Canadian_Aboriginal"),
    ("YI SYLLABLE", "Yi"),
)


def language_guard_policy() -> dict[str, Any]:
    configured = load_contracting_controls().get("sabotage_policy", {}).get("language_guard", {})
    return configured if isinstance(configured, dict) else {}


def supported_expected_languages() -> list[str]:
    configured = language_guard_policy().get("supported_expected_languages", ["en"])
    if not isinstance(configured, list):
        return ["en"]
    return [str(item).strip().lower() for item in configured if str(item).strip()]


def default_expected_return_language() -> str:
    value = str(language_guard_policy().get("default_expected_language", "en")).strip().lower()
    if value not in supported_expected_languages():
        raise CWOPolicyError(f"default expected return language {value!r} is not supported")
    return value


def validate_expected_return_language(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    normalized = str(value).strip().lower()
    if normalized not in supported_expected_languages():
        raise CWOPolicyError(f"unsupported expected return language: {normalized!r}")
    return normalized


def normalize_security_text(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def character_script(character: str) -> str | None:
    category = unicodedata.category(character)
    if not category.startswith("L"):
        if category.startswith("M"):
            return "Inherited"
        return None
    name = unicodedata.name(character, "")
    for marker, script in SCRIPT_NAME_MARKERS:
        if marker in name:
            return script
    if "CJK UNIFIED IDEOGRAPH" in name or "CJK COMPATIBILITY IDEOGRAPH" in name:
        return "Han"
    codepoint = ord(character)
    if 0x3400 <= codepoint <= 0x9FFF or 0x20000 <= codepoint <= 0x323AF:
        return "Han"
    return "Other"


def _letter_words(text: str) -> list[str]:
    words: list[str] = []
    current: list[str] = []
    for character in text:
        category = unicodedata.category(character)
        if category.startswith("L") or (category.startswith("M") and current):
            current.append(character)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    return words


def _word_scripts(word: str) -> set[str]:
    return {
        script
        for character in word
        if (script := character_script(character)) not in {None, "Common", "Inherited"}
    }


def _dangerous_control_findings(text: str, weights: dict[str, int]) -> list[ReturnSignal]:
    findings: list[ReturnSignal] = []
    bidi = sorted({f"U+{ord(character):04X}" for character in text if ord(character) in BIDI_CONTROL_CODEPOINTS})
    if bidi:
        add_signal(
            findings,
            category="unicode_control_evasion",
            reason="dangerous bidirectional controls present: " + ", ".join(bidi),
            weight=weights["unicode_control_evasion"],
        )
    embedded: set[str] = set()
    for index, character in enumerate(text):
        if ord(character) not in ZERO_WIDTH_CODEPOINTS or index == 0 or index + 1 >= len(text):
            continue
        if unicodedata.category(text[index - 1]).startswith("L") and unicodedata.category(text[index + 1]).startswith("L"):
            embedded.add(f"U+{ord(character):04X}")
    if embedded:
        add_signal(
            findings,
            category="unicode_control_evasion",
            reason="zero-width controls embedded between letters: " + ", ".join(sorted(embedded)),
            weight=weights["unicode_control_evasion"],
        )
    return findings


def analyze_return_language(
    text: str,
    *,
    expected_language: str | None,
    expected_language_source: str = "not-enforced",
) -> ReturnLanguageResult:
    expected_language = validate_expected_return_language(expected_language)
    normalized_text = normalize_security_text(text)
    if expected_language is None:
        return {
            "expected_return_language": None,
            "expected_return_language_source": expected_language_source,
            "return_language_status": "not-enforced",
            "return_language_findings": [],
            "detected_letter_scripts": [],
            "unexpected_script_ratio": 0.0,
            "unicode_normalization_changed": normalized_text != text,
        }
    if expected_language != "en":
        raise CWOPolicyError(f"language guard has no implementation for {expected_language!r}")

    policy = language_guard_policy()
    configured_weights = policy.get("signal_weights", {})
    weights = {
        "unicode_control_evasion": int(configured_weights.get("unicode_control_evasion", 50)),
        "unicode_mixed_script_evasion": int(configured_weights.get("unicode_mixed_script_evasion", 45)),
        "unexpected_return_script": int(configured_weights.get("unexpected_return_script", 30)),
        "return_language_mismatch": int(configured_weights.get("return_language_mismatch", 25)),
    }
    findings = _dangerous_control_findings(text, weights)

    minimum_word_letters = int(policy.get("minimum_mixed_script_word_letters", 3))
    mixed_script_sets: set[tuple[str, ...]] = set()
    for word in _letter_words(normalized_text):
        letter_count = sum(unicodedata.category(character).startswith("L") for character in word)
        scripts = _word_scripts(word)
        if letter_count >= minimum_word_letters and len(scripts) >= 2:
            mixed_script_sets.add(tuple(sorted(scripts)))
    if mixed_script_sets:
        add_signal(
            findings,
            category="unicode_mixed_script_evasion",
            reason="mixed-script words detected: " + "; ".join("+".join(item) for item in sorted(mixed_script_sets)),
            weight=weights["unicode_mixed_script_evasion"],
        )

    prose = strip_fenced_blocks(normalized_text)
    letter_scripts = [
        script
        for character in prose
        if (script := character_script(character)) not in {None, "Common", "Inherited"}
    ]
    detected_scripts = sorted(set(letter_scripts))
    unexpected_count = sum(script != "Latin" for script in letter_scripts)
    unexpected_ratio = unexpected_count / len(letter_scripts) if letter_scripts else 0.0

    longest_unexpected_run = 0
    current_run = 0
    for character in prose:
        script = character_script(character)
        if script not in {None, "Common", "Inherited", "Latin"}:
            current_run += 1
            longest_unexpected_run = max(longest_unexpected_run, current_run)
        elif script == "Inherited" and current_run:
            continue
        else:
            current_run = 0

    minimum_letters = int(policy.get("minimum_letter_count", 20))
    ratio_threshold = float(policy.get("unexpected_script_ratio", 0.20))
    run_threshold = int(policy.get("unexpected_script_run_length", 4))
    if (
        len(letter_scripts) >= minimum_letters
        and unexpected_ratio >= ratio_threshold
    ) or longest_unexpected_run >= run_threshold:
        add_signal(
            findings,
            category="unexpected_return_script",
            reason=(
                f"English return contains unexpected scripts; ratio={unexpected_ratio:.3f}, "
                f"longest_run={longest_unexpected_run}"
            ),
            weight=weights["unexpected_return_script"],
        )
    if len(letter_scripts) >= minimum_letters and unexpected_ratio >= 0.80:
        add_signal(
            findings,
            category="return_language_mismatch",
            reason="return prose is predominantly outside the expected Latin script",
            weight=weights["return_language_mismatch"],
        )

    latin_words = [word.casefold() for word in _letter_words(prose) if _word_scripts(word) <= {"Latin"}]
    minimum_words = int(policy.get("minimum_english_words", 40))
    function_words = {
        str(item).casefold()
        for item in policy.get("english_function_words", [])
        if str(item).strip()
    }
    function_hits = [word for word in latin_words if word in function_words]
    distinct_hits = set(function_hits)
    function_ratio = len(function_hits) / len(latin_words) if latin_words else 0.0
    if len(latin_words) >= minimum_words and (
        len(distinct_hits) < int(policy.get("minimum_distinct_function_words", 2))
        or function_ratio < float(policy.get("minimum_function_word_ratio", 0.03))
    ):
        add_signal(
            findings,
            category="return_language_mismatch",
            reason=(
                f"English prose likelihood below policy threshold; words={len(latin_words)}, "
                f"distinct_function_words={len(distinct_hits)}, ratio={function_ratio:.3f}"
            ),
            weight=weights["return_language_mismatch"],
        )

    score = sum(int(item["weight"]) for item in findings)
    thresholds = load_contracting_controls().get("sabotage_policy", {}).get("thresholds", {})
    if score >= int(thresholds.get("quarantine", 50)):
        status = "quarantine"
    elif score >= int(thresholds.get("peer_review", 20)):
        status = "review"
    else:
        status = "clear"
    return {
        "expected_return_language": expected_language,
        "expected_return_language_source": expected_language_source,
        "return_language_status": status,
        "return_language_findings": findings,
        "detected_letter_scripts": detected_scripts,
        "unexpected_script_ratio": round(unexpected_ratio, 6),
        "unicode_normalization_changed": normalized_text != text,
    }
