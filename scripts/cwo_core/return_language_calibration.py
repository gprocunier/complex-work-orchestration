#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import unicodedata
from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

from cwo_core.return_language import analyze_return_language
from cwo_core.returns import make_acceptance_decision

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT_PATH = ROOT / "calibration" / "skl-return-language-contract-v1.json"
DEFAULT_CORPUS_PATH = ROOT / "calibration" / "skl-return-language-corpus-v1.json"
DEFAULT_REPORT_PATH = ROOT / "calibration" / "skl-return-language-calibration-report-latest.json"
REPORT_ARTIFACT_TYPE = "skl-return-language-calibration-report"
REPORT_VERSION = 1
STATUS_VALUES = ("clear", "review", "quarantine")
_MANDATORY_CATEGORIES = {
    "benign-english",
    "benign-short-latin-foreign",
    "benign-technical-notation",
    "benign-code-diagnostics",
    "benign-names-symbols",
    "benign-control-context",
    "latin-language-mismatch",
    "unexpected-script",
    "mixed-script-confusable",
    "bidi-control",
    "zero-width-control",
    "nfkc-prompt-injection",
}
_BENIGN_CATEGORIES = {
    "benign-english",
    "benign-short-latin-foreign",
    "benign-technical-notation",
    "benign-code-diagnostics",
    "benign-names-symbols",
    "benign-control-context",
}
_ADVERSARIAL_CATEGORIES = {
    "latin-language-mismatch",
    "unexpected-script",
    "mixed-script-confusable",
    "bidi-control",
    "zero-width-control",
    "nfkc-prompt-injection",
}


class CalibrationError(RuntimeError):
    """Base calibration failure."""


class CorpusError(CalibrationError):
    """Raised for malformed corpus or contract artifacts."""


class ReportError(CalibrationError):
    """Raised for expectation/measurement mismatches."""


class CalibrationMismatchError(ReportError):
    """Backward-compatible alias for strict failure."""


BIDI_CONTROL_BY_CLASS: dict[str, set[str]] = {
    "arabic-letter-mark": {"\u061C"},
    "directional-marks": {"\u200E", "\u200F"},
    "embeddings-overrides": {"\u202A", "\u202B", "\u202C", "\u202D", "\u202E"},
    "isolates": {"\u2066", "\u2067", "\u2068", "\u2069"},
}

_ZERO_WIDTH_CODES = {"U+200B", "U+200C", "U+200D", "U+2060", "U+FEFF"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CorpusError(f"failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CorpusError(f"failed to parse {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise CorpusError(f"{path} must be a JSON object")
    return payload


def _canonical_json(payload: dict[str, Any], *, skip: str | None = None) -> str:
    normalized = deepcopy(payload)
    if skip is not None:
        normalized.pop(skip, None)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(payload: dict[str, Any], *, skip: str | None = None) -> str:
    return sha256(_canonical_json(payload, skip=skip).encode("utf-8")).hexdigest()


def _ensure_dict(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CorpusError(f"{field} must be an object")
    return value


def _ensure_list_of_dict(value: object, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CorpusError(f"{field} must be a list")
    output: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise CorpusError(f"{field}[{index}] must be an object")
        output.append(item)
    return output


def _ensure_list_of_str(value: object, field: str, *, min_items: int = 0) -> list[str]:
    if not isinstance(value, list):
        raise CorpusError(f"{field} must be a list")
    output: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise CorpusError(f"{field} must only contain strings")
        if not item:
            raise CorpusError(f"{field} must not contain empty strings")
        output.append(item)
    if len(output) < min_items:
        raise CorpusError(f"{field} must contain at least {min_items} entries")
    return output


def _ensure_str(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CorpusError(f"{field} must be a string")
    if not value:
        raise CorpusError(f"{field} must not be empty")
    return value


def _ensure_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise CorpusError(f"{field} must be a boolean")
    return value


def _ensure_int(value: object, field: str) -> int:
    if not isinstance(value, int):
        raise CorpusError(f"{field} must be an integer")
    return value


def _ensure_float(value: object, field: str) -> float:
    if not isinstance(value, (int, float)):
        raise CorpusError(f"{field} must be a number")
    return float(value)


def _validate_additional_properties(name: str, payload: dict[str, Any], allowed: set[str]) -> None:
    extra = set(payload.keys()) - allowed
    if extra:
        raise CorpusError(f"{name} has extra keys: {', '.join(sorted(extra))}")


def _validate_thresholds(payload: dict[str, Any], path: str) -> None:
    required = {
        "minimum_precision",
        "minimum_recall",
        "maximum_false_positive_rate",
        "minimum_exact_status_accuracy",
    }
    if set(payload.keys()) != required:
        raise CorpusError(f"{path} must contain exactly minimum_precision, minimum_recall, maximum_false_positive_rate, minimum_exact_status_accuracy")

    minimum_precision = _ensure_float(payload["minimum_precision"], f"{path}.minimum_precision")
    minimum_recall = _ensure_float(payload["minimum_recall"], f"{path}.minimum_recall")
    maximum_fp_rate = _ensure_float(payload["maximum_false_positive_rate"], f"{path}.maximum_false_positive_rate")
    minimum_status_accuracy = _ensure_float(payload["minimum_exact_status_accuracy"], f"{path}.minimum_exact_status_accuracy")

    for field, value in (
        ("minimum_precision", minimum_precision),
        ("minimum_recall", minimum_recall),
        ("maximum_false_positive_rate", maximum_fp_rate),
        ("minimum_exact_status_accuracy", minimum_status_accuracy),
    ):
        if not (0.0 <= value <= 1.0):
            raise CorpusError(f"{path}.{field} must be in [0,1]")


def _validate_threshold_overrides(
    layer: str,
    base_thresholds: dict[str, float],
    overrides: dict[str, float] | None,
) -> dict[str, float] | None:
    if not overrides:
        return None

    unknown = sorted(set(overrides) - set(base_thresholds))
    if unknown:
        raise CorpusError(
            f"{layer} threshold override contains unknown key(s): {', '.join(unknown)}"
        )

    normalized: dict[str, float] = {}
    for key, value in overrides.items():
        normalized[key] = _ensure_float(value, f"{layer}.{key} threshold override")
        if not (0.0 <= normalized[key] <= 1.0):
            raise CorpusError(f"{layer}.{key} threshold must be in [0,1]: {value}")

    for key, value in normalized.items():
        baseline = float(base_thresholds[key])
        if key == "maximum_false_positive_rate":
            if value > baseline:
                raise CorpusError(
                    f"{layer}.{key} threshold relaxation rejected: {value} > {baseline}"
                )
            continue
        if value < baseline:
            raise CorpusError(
                f"{layer}.{key} threshold relaxation rejected: {value} < {baseline}"
            )

    return dict(normalized)


def _stable_report_path(path: Path, role: str) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return f"<external-{role}>"


def _validate_case_contract_requirements(case_contract: dict[str, Any]) -> None:
    required = {"required_fields", "analyzer_expectation", "pipeline_expectation"}
    _validate_additional_properties("contract.case_contract", case_contract, required)
    _ensure_list_of_str(case_contract["required_fields"], "contract.case_contract.required_fields", min_items=1)
    _ensure_list_of_str(case_contract["analyzer_expectation"], "contract.case_contract.analyzer_expectation", min_items=1)
    _ensure_list_of_str(case_contract["pipeline_expectation"], "contract.case_contract.pipeline_expectation", min_items=1)


def _validate_contract(contract: dict[str, Any]) -> None:
    required_contract_fields = {
        "artifact_type",
        "version",
        "bead_id",
        "expected_language",
        "case_count",
        "balance",
        "case_contract",
        "category_minimums",
        "required_script_classes",
        "required_confusable_classes",
        "required_bidi_classes",
        "required_zero_width_codepoints",
        "metrics",
        "integrity",
        "policy_constraints",
        "contract_sha256",
    }
    _validate_additional_properties("contract", contract, required_contract_fields)
    if _ensure_str(contract["artifact_type"], "contract.artifact_type") != "skl-corpus-contract":
        raise CorpusError("contract.artifact_type must be skl-corpus-contract")
    if _ensure_int(contract["version"], "contract.version") < 1:
        raise CorpusError("contract.version must be >= 1")
    if _ensure_str(contract["expected_language"], "contract.expected_language") != "en":
        raise CorpusError("contract.expected_language must be 'en'")
    if _ensure_int(contract["case_count"], "contract.case_count") != 104:
        raise CorpusError("contract.case_count must be 104")

    balance = _ensure_dict(contract["balance"], "contract.balance")
    _validate_additional_properties("contract.balance", balance, {"benign", "adversarial"})
    benign = _ensure_int(balance["benign"], "contract.balance.benign")
    adversarial = _ensure_int(balance["adversarial"], "contract.balance.adversarial")
    if benign < 0 or adversarial < 0 or benign + adversarial != _ensure_int(contract["case_count"], "contract.case_count"):
        raise CorpusError("contract.balance must be non-negative and sum to case_count")

    required_minimums = set(_MANDATORY_CATEGORIES)
    category_minimums = _ensure_dict(contract["category_minimums"], "contract.category_minimums")
    if set(category_minimums.keys()) != required_minimums:
        raise CorpusError("contract.category_minimums has missing or extra categories")
    for key in required_minimums:
        minimum = _ensure_int(category_minimums[key], f"contract.category_minimums[{key}]")
        if minimum <= 0:
            raise CorpusError(f"contract.category_minimums[{key}] must be positive")

    _ensure_list_of_str(contract["required_script_classes"], "contract.required_script_classes", min_items=1)
    _ensure_list_of_str(contract["required_confusable_classes"], "contract.required_confusable_classes")
    _ensure_list_of_str(contract["required_bidi_classes"], "contract.required_bidi_classes", min_items=1)
    _ensure_list_of_str(contract["required_zero_width_codepoints"], "contract.required_zero_width_codepoints", min_items=1)

    _validate_case_contract_requirements(_ensure_dict(contract["case_contract"], "contract.case_contract"))

    metrics = _ensure_dict(contract["metrics"], "contract.metrics")
    _validate_additional_properties("contract.metrics", metrics, {"analyzer", "pipeline", "zero_false_negative_categories"})
    for layer in ("analyzer", "pipeline"):
        _validate_thresholds(_ensure_dict(metrics[layer], f"contract.metrics[{layer}]"), f"contract.metrics[{layer}]")

    integrity = _ensure_dict(contract["integrity"], "contract.integrity")
    _validate_additional_properties(
        "contract.integrity",
        integrity,
        {
            "corpus_versioned",
            "corpus_hash",
            "unknown_fields",
            "duplicate_case_ids",
            "missing_category_or_class_coverage",
        },
    )
    _ensure_bool(integrity["corpus_versioned"], "contract.integrity.corpus_versioned")
    _ensure_str(integrity["corpus_hash"], "contract.integrity.corpus_hash")
    _ensure_str(integrity["unknown_fields"], "contract.integrity.unknown_fields")
    _ensure_str(integrity["duplicate_case_ids"], "contract.integrity.duplicate_case_ids")
    _ensure_str(integrity["missing_category_or_class_coverage"], "contract.integrity.missing_category_or_class_coverage")

    policy_constraints = _ensure_dict(contract["policy_constraints"], "contract.policy_constraints")
    _validate_additional_properties(
        "contract.policy_constraints",
        policy_constraints,
        {
            "new_expected_languages",
            "critical_signal_weight_reduction",
            "global_review_or_quarantine_threshold_relaxation",
            "tuning",
        },
    )

    contract_sha256 = _ensure_str(contract["contract_sha256"], "contract.contract_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", contract_sha256):
        raise CorpusError("contract.contract_sha256 must be lowercase sha256 hex")
    if _sha256_hex(contract, skip="contract_sha256") != contract_sha256:
        raise CorpusError("contract.contract_sha256 does not match canonical payload")


def _validate_corpus_case(case: dict[str, Any], contract: dict[str, Any]) -> None:
    required_fields = {
        "id",
        "category",
        "text",
        "adversarial",
        "coverage",
        "analyzer_expectation",
        "pipeline_expectation",
    }
    _validate_additional_properties(f"corpus.case {case.get('id', '<missing>')}", case, required_fields)

    _ensure_str(case["id"], "case.id")
    category = _ensure_str(case["category"], f"case[{case['id']}].category")
    if category not in _MANDATORY_CATEGORIES:
        raise CorpusError(f"case[{case['id']}] has unknown category {category!r}")
    _ensure_str(case["text"], f"case[{case['id']}].text")
    _ensure_bool(case["adversarial"], f"case[{case['id']}].adversarial")

    coverage = _ensure_dict(case["coverage"], f"case[{case['id']}].coverage")
    _validate_additional_properties(
        f"case[{case['id']}].coverage",
        coverage,
        {
            "scripts",
            "confusable_classes",
            "bidi_classes",
            "zero_width_codepoints",
            "embedded",
            "run_length",
            "normalization",
        },
    )
    _ensure_list_of_str(coverage.get("scripts", []), f"case[{case['id']}].coverage.scripts")
    _ensure_list_of_str(coverage.get("confusable_classes", []), f"case[{case['id']}].coverage.confusable_classes")
    _ensure_list_of_str(coverage.get("bidi_classes", []), f"case[{case['id']}].coverage.bidi_classes")
    _ensure_list_of_str(coverage.get("zero_width_codepoints", []), f"case[{case['id']}].coverage.zero_width_codepoints")
    if "run_length" in coverage:
        _ensure_int(coverage["run_length"], f"case[{case['id']}].coverage.run_length")
    if "embedded" in coverage:
        _ensure_bool(coverage["embedded"], f"case[{case['id']}].coverage.embedded")
    if "normalization" in coverage:
        _ensure_str(coverage["normalization"], f"case[{case['id']}].coverage.normalization")

    analyzer_expectation = _ensure_dict(case["analyzer_expectation"], f"case[{case['id']}].analyzer_expectation")
    _validate_additional_properties(
        f"case[{case['id']}].analyzer_expectation",
        analyzer_expectation,
        {"positive", "status", "required_findings", "forbidden_findings"},
    )
    _ensure_bool(analyzer_expectation["positive"], f"case[{case['id']}].analyzer_expectation.positive")
    if _ensure_str(analyzer_expectation["status"], f"case[{case['id']}].analyzer_expectation.status") not in STATUS_VALUES:
        raise CorpusError(f"case[{case['id']}].analyzer_expectation.status invalid")
    _ensure_list_of_str(analyzer_expectation["required_findings"], f"case[{case['id']}].analyzer_expectation.required_findings")
    _ensure_list_of_str(analyzer_expectation["forbidden_findings"], f"case[{case['id']}].analyzer_expectation.forbidden_findings")

    pipeline_expectation = _ensure_dict(case["pipeline_expectation"], f"case[{case['id']}].pipeline_expectation")
    _validate_additional_properties(
        f"case[{case['id']}].pipeline_expectation",
        pipeline_expectation,
        {
            "positive",
            "return_language_status",
            "required_sabotage_findings",
            "forbidden_sabotage_findings",
            "review_recommended",
            "quarantine_recommended",
        },
    )
    _ensure_bool(pipeline_expectation["positive"], f"case[{case['id']}].pipeline_expectation.positive")
    if _ensure_str(pipeline_expectation["return_language_status"], f"case[{case['id']}].pipeline_expectation.return_language_status") not in STATUS_VALUES:
        raise CorpusError(f"case[{case['id']}].pipeline_expectation.return_language_status invalid")
    _ensure_list_of_str(pipeline_expectation["required_sabotage_findings"], f"case[{case['id']}].pipeline_expectation.required_sabotage_findings")
    _ensure_list_of_str(pipeline_expectation["forbidden_sabotage_findings"], f"case[{case['id']}].pipeline_expectation.forbidden_sabotage_findings")
    _ensure_bool(pipeline_expectation["review_recommended"], f"case[{case['id']}].pipeline_expectation.review_recommended")
    _ensure_bool(pipeline_expectation["quarantine_recommended"], f"case[{case['id']}].pipeline_expectation.quarantine_recommended")


def _validate_corpus(corpus: dict[str, Any], contract: dict[str, Any]) -> None:
    required_fields = {
        "artifact_type",
        "bead_id",
        "version",
        "expected_language",
        "case_count",
        "balance",
        "case_contract",
        "cases",
        "category_minimums",
        "corpus_sha256",
        "required_script_classes",
        "required_confusable_classes",
        "required_bidi_classes",
        "required_zero_width_codepoints",
    }
    _validate_additional_properties("corpus", corpus, required_fields)
    if _ensure_str(corpus["artifact_type"], "corpus.artifact_type") != "skl-return-language-corpus":
        raise CorpusError("corpus.artifact_type must be skl-return-language-corpus")
    if _ensure_int(corpus["version"], "corpus.version") < 1:
        raise CorpusError("corpus.version must be >= 1")

    if _ensure_str(corpus["expected_language"], "corpus.expected_language") != contract["expected_language"]:
        raise CorpusError("corpus.expected_language must match contract.expected_language")

    case_count = _ensure_int(corpus["case_count"], "corpus.case_count")
    cases = _ensure_list_of_dict(corpus.get("cases"), "corpus.cases")
    if case_count != len(cases):
        raise CorpusError("corpus.case_count must match number of case entries")
    if case_count != 104:
        raise CorpusError("corpus.case_count must be 104")

    balance = _ensure_dict(corpus["balance"], "corpus.balance")
    _validate_additional_properties("corpus.balance", balance, {"benign", "adversarial"})
    benign = _ensure_int(balance["benign"], "corpus.balance.benign")
    adversarial = _ensure_int(balance["adversarial"], "corpus.balance.adversarial")
    if benign < 0 or adversarial < 0 or benign + adversarial != case_count:
        raise CorpusError("corpus.balance must be non-negative and sum to case_count")
    if benign != contract["balance"]["benign"] or adversarial != contract["balance"]["adversarial"]:
        raise CorpusError("corpus balance values must match contract")

    category_minimums = _ensure_dict(corpus["category_minimums"], "corpus.category_minimums")
    if set(category_minimums.keys()) != set(contract["category_minimums"].keys()):
        raise CorpusError("corpus.category_minimums must match contract categories")
    for key in category_minimums:
        _ensure_int(category_minimums[key], f"corpus.category_minimums[{key}]")

    _validate_case_contract_requirements(_ensure_dict(corpus["case_contract"], "corpus.case_contract"))

    _ensure_list_of_str(corpus["required_script_classes"], "corpus.required_script_classes", min_items=1)
    _ensure_list_of_str(corpus["required_confusable_classes"], "corpus.required_confusable_classes")
    _ensure_list_of_str(corpus["required_bidi_classes"], "corpus.required_bidi_classes", min_items=1)
    _ensure_list_of_str(corpus["required_zero_width_codepoints"], "corpus.required_zero_width_codepoints", min_items=1)
    if corpus["required_script_classes"] != contract["required_script_classes"]:
        raise CorpusError("corpus.required_script_classes must match contract")
    if corpus["required_confusable_classes"] != contract["required_confusable_classes"]:
        raise CorpusError("corpus.required_confusable_classes must match contract")
    if corpus["required_bidi_classes"] != contract["required_bidi_classes"]:
        raise CorpusError("corpus.required_bidi_classes must match contract")
    if corpus["required_zero_width_codepoints"] != contract["required_zero_width_codepoints"]:
        raise CorpusError("corpus.required_zero_width_codepoints must match contract")

    if _sha256_hex(corpus, skip="corpus_sha256") != _ensure_str(corpus["corpus_sha256"], "corpus.corpus_sha256"):
        raise CorpusError("corpus.corpus_sha256 does not match canonical payload")

    required_script_classes = set(corpus["required_script_classes"])
    required_confusable_classes = set(corpus["required_confusable_classes"])
    required_bidi_classes = set(corpus["required_bidi_classes"])
    required_zero_width_codepoints = set(corpus["required_zero_width_codepoints"])
    seen_ids: set[str] = set()
    seen_texts: set[str] = set()
    category_counts: Counter[str] = Counter()
    benign_case_count = 0
    adversarial_case_count = 0
    covered_script_classes: set[str] = set()
    covered_confusable_classes: set[str] = set()
    covered_bidi_classes: set[str] = set()
    covered_zero_width_codepoints: set[str] = set()
    for case in cases:
        _validate_corpus_case(case, contract)
        case_id = _ensure_str(case["id"], "case.id")
        if case_id in seen_ids:
            raise CorpusError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        text = _ensure_str(case["text"], f"case[{case_id}].text")
        if text in seen_texts:
            raise CorpusError(f"duplicate case text: {case_id}")
        seen_texts.add(text)
        category_counts[case["category"]] += 1

        case_category = _ensure_str(case["category"], f"case[{case_id}].category")
        case_adversarial = _ensure_bool(case["adversarial"], f"case[{case_id}].adversarial")
        if case_category in _BENIGN_CATEGORIES and case_adversarial:
            raise CorpusError(f"case[{case_id}] category {case_category!r} requires adversarial=false")
        if case_category in _ADVERSARIAL_CATEGORIES and not case_adversarial:
            raise CorpusError(f"case[{case_id}] category {case_category!r} requires adversarial=true")

        if case_adversarial:
            adversarial_case_count += 1
        else:
            benign_case_count += 1

        coverage = _ensure_dict(case["coverage"], f"case[{case_id}].coverage")
        covered_script_classes.update(_ensure_list_of_str(coverage.get("scripts", []), f"case[{case_id}].coverage.scripts"))
        covered_confusable_classes.update(
            _ensure_list_of_str(coverage.get("confusable_classes", []), f"case[{case_id}].coverage.confusable_classes")
        )
        covered_bidi_classes.update(_ensure_list_of_str(coverage.get("bidi_classes", []), f"case[{case_id}].coverage.bidi_classes"))
        covered_zero_width_codepoints.update(
            _ensure_list_of_str(coverage.get("zero_width_codepoints", []), f"case[{case_id}].coverage.zero_width_codepoints")
        )

    for category, minimum in contract["category_minimums"].items():
        if category_counts[category] < minimum:
            raise CorpusError(f"category {category} has {category_counts[category]} cases; minimum is {minimum}")

    for key in _MANDATORY_CATEGORIES:
        if category_counts[key] < contract["category_minimums"][key]:
            raise CorpusError(f"category {key} count below minimum")

    if benign_case_count != benign:
        raise CorpusError(
            f"corpus balance declared benign={benign} does not match case flags "
            f"({benign_case_count})"
        )
    if adversarial_case_count != adversarial:
        raise CorpusError(
            f"corpus balance declared adversarial={adversarial} does not match case flags "
            f"({adversarial_case_count})"
        )

    if not required_script_classes.issubset(covered_script_classes):
        missing = sorted(required_script_classes - covered_script_classes)
        raise CorpusError(f"required scripts missing from corpus coverage: {', '.join(missing)}")
    if not required_confusable_classes.issubset(covered_confusable_classes):
        missing = sorted(required_confusable_classes - covered_confusable_classes)
        raise CorpusError(f"required confusable classes missing from corpus coverage: {', '.join(missing)}")
    if not required_bidi_classes.issubset(covered_bidi_classes):
        missing = sorted(required_bidi_classes - covered_bidi_classes)
        raise CorpusError(f"required bidi classes missing from corpus coverage: {', '.join(missing)}")
    if not required_zero_width_codepoints.issubset(covered_zero_width_codepoints):
        missing = sorted(required_zero_width_codepoints - covered_zero_width_codepoints)
        raise CorpusError(f"required zero-width codepoints missing from corpus coverage: {', '.join(missing)}")


def _parse_zero_width_token(token: str) -> int:
    if not re.fullmatch(r"U\+[0-9A-F]{4,6}", token):
        raise ValueError(token)
    return int(token[2:], 16)


def _is_embedded_zero_width(token: str, text: str) -> bool:
    codepoint = chr(_parse_zero_width_token(token))
    for index, character in enumerate(text):
        if character != codepoint:
            continue
        if index <= 0 or index + 1 >= len(text):
            return False
        if unicodedata.category(text[index - 1]).startswith("L") and unicodedata.category(text[index + 1]).startswith("L"):
            return True
    return False


def _validate_coverage(case: dict[str, Any], analysis: dict[str, Any], contract: dict[str, Any], failure_reasons: list[str]) -> None:
    case_id = case["id"]
    text = case["text"]
    coverage = case["coverage"]
    detected_scripts = set(_ensure_list_of_str(analysis["detected_letter_scripts"], f"case[{case_id}].analysis.detected_letter_scripts"))

    for script in _ensure_list_of_str(coverage.get("scripts", []), f"case[{case_id}].coverage.scripts"):
        if script not in detected_scripts:
            failure_reasons.append(f"scripts_mismatch: {script} not detected")

    confusable_set = set(contract["required_confusable_classes"])
    for item in _ensure_list_of_str(coverage.get("confusable_classes", []), f"case[{case_id}].coverage.confusable_classes"):
        if item not in confusable_set:
            failure_reasons.append(f"confusable_class_invalid: {item}")
            continue
        left, sep, right = item.partition("-")
        if not sep:
            failure_reasons.append(f"confusable_class_invalid_format: {item}")
            continue
        if left != "Latin" and right != "Latin":
            failure_reasons.append(f"confusable_class_missing_latin: {item}")
        if left not in detected_scripts or right not in detected_scripts:
            failure_reasons.append(f"confusable_class_not_detected: {item}")

    for bidi_class in _ensure_list_of_str(coverage.get("bidi_classes", []), f"case[{case_id}].coverage.bidi_classes"):
        controls = BIDI_CONTROL_BY_CLASS.get(bidi_class)
        if not controls:
            failure_reasons.append(f"bidi_class_invalid: {bidi_class}")
            continue
        if not any(marker in text for marker in controls):
            failure_reasons.append(f"bidi_control_missing: {bidi_class}")

    for token in _ensure_list_of_str(coverage.get("zero_width_codepoints", []), f"case[{case_id}].coverage.zero_width_codepoints"):
        if token not in _ZERO_WIDTH_CODES and token not in contract["required_zero_width_codepoints"]:
            failure_reasons.append(f"zero_width_codepoint_not_required: {token}")
            continue
        try:
            codepoint = chr(_parse_zero_width_token(token))
        except ValueError:
            failure_reasons.append(f"zero_width_codepoint_format_invalid: {token}")
            continue
        if codepoint not in text:
            failure_reasons.append(f"zero_width_codepoint_missing: {token}")
            continue
        if coverage.get("embedded") and not _is_embedded_zero_width(token, text):
            failure_reasons.append(f"zero_width_not_embedded: {token}")

    if coverage.get("normalization") == "NFKC" and not analysis.get("unicode_normalization_changed", False):
        failure_reasons.append("normalization_mismatch: expected NFKC change")


def _build_case_payload(case: dict[str, Any], analysis: dict[str, Any], decision: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    case_id = case["id"]
    expected_analyzer = _ensure_dict(case["analyzer_expectation"], f"case[{case_id}].analyzer_expectation")
    expected_pipeline = _ensure_dict(case["pipeline_expectation"], f"case[{case_id}].pipeline_expectation")

    analyzer_findings = sorted({str(item["category"]) for item in _ensure_dict(analysis, f"analysis[{case_id}]").get("return_language_findings", [])})
    pipeline_findings = sorted(str(item) for item in _ensure_dict(decision, f"decision[{case_id}]").get("sabotage_signal_categories", []))

    analyzer_expected_status = _ensure_str(expected_analyzer["status"], f"case[{case_id}].analyzer_expectation.status")
    pipeline_expected_status = _ensure_str(expected_pipeline["return_language_status"], f"case[{case_id}].pipeline_expectation.return_language_status")
    analyzer_predicted_status = _ensure_str(analysis["return_language_status"], f"analysis[{case_id}].return_language_status")
    pipeline_predicted_status = _ensure_str(decision["return_language_status"], f"decision[{case_id}].return_language_status")

    analyzer_expected_pos = bool(expected_analyzer["positive"])
    pipeline_expected_pos = bool(expected_pipeline["positive"])
    analyzer_predicted_pos = analyzer_predicted_status != "clear"
    pipeline_predicted_review = bool(decision["sabotage_review_recommended"])
    pipeline_predicted_quarantine = bool(decision["quarantine_recommended"])
    pipeline_predicted_pos = bool(pipeline_predicted_review or pipeline_predicted_quarantine)

    analyzer_expected_findings = sorted(_ensure_list_of_str(expected_analyzer["required_findings"], f"case[{case_id}].analyzer_expectation.required_findings"))
    analyzer_forbidden_findings = sorted(_ensure_list_of_str(expected_analyzer["forbidden_findings"], f"case[{case_id}].analyzer_expectation.forbidden_findings"))
    pipeline_expected_findings = sorted(_ensure_list_of_str(expected_pipeline["required_sabotage_findings"], f"case[{case_id}].pipeline_expectation.required_sabotage_findings"))
    pipeline_forbidden_findings = sorted(_ensure_list_of_str(expected_pipeline["forbidden_sabotage_findings"], f"case[{case_id}].pipeline_expectation.forbidden_sabotage_findings"))

    pipeline_expected_review = bool(expected_pipeline["review_recommended"])
    pipeline_expected_quarantine = bool(expected_pipeline["quarantine_recommended"])

    analyzer_layer = {
        "expected_status": analyzer_expected_status,
        "predicted_status": analyzer_predicted_status,
        "expected_positive": analyzer_expected_pos,
        "predicted_positive": analyzer_predicted_pos,
        "expected_review_recommended": False,
        "predicted_review_recommended": False,
        "expected_quarantine_recommended": False,
        "predicted_quarantine_recommended": False,
        "expected_findings": analyzer_expected_findings,
        "forbidden_findings": analyzer_forbidden_findings,
        "predicted_findings": analyzer_findings,
        "mismatch_reasons": [],
    }

    pipeline_layer = {
        "expected_status": pipeline_expected_status,
        "predicted_status": pipeline_predicted_status,
        "expected_positive": pipeline_expected_pos,
        "predicted_positive": pipeline_predicted_pos,
        "expected_review_recommended": pipeline_expected_review,
        "predicted_review_recommended": pipeline_predicted_review,
        "expected_quarantine_recommended": pipeline_expected_quarantine,
        "predicted_quarantine_recommended": pipeline_predicted_quarantine,
        "expected_findings": pipeline_expected_findings,
        "forbidden_findings": pipeline_forbidden_findings,
        "predicted_findings": pipeline_findings,
        "mismatch_reasons": [],
    }

    if analyzer_layer["predicted_status"] != analyzer_layer["expected_status"]:
        analyzer_layer["mismatch_reasons"].append("status_mismatch")
    if analyzer_layer["predicted_positive"] != analyzer_layer["expected_positive"]:
        analyzer_layer["mismatch_reasons"].append("positive_mismatch")
    if set(analyzer_layer["expected_findings"]) - set(analyzer_layer["predicted_findings"]):
        analyzer_layer["mismatch_reasons"].append("required_findings_mismatch")
    if set(analyzer_layer["forbidden_findings"]) & set(analyzer_layer["predicted_findings"]):
        analyzer_layer["mismatch_reasons"].append("forbidden_findings_mismatch")

    if pipeline_layer["predicted_status"] != pipeline_layer["expected_status"]:
        pipeline_layer["mismatch_reasons"].append("status_mismatch")
    if pipeline_layer["predicted_positive"] != pipeline_layer["expected_positive"]:
        pipeline_layer["mismatch_reasons"].append("positive_mismatch")
    if pipeline_layer["predicted_review_recommended"] != pipeline_layer["expected_review_recommended"]:
        pipeline_layer["mismatch_reasons"].append("review_recommended_mismatch")
    if pipeline_layer["predicted_quarantine_recommended"] != pipeline_layer["expected_quarantine_recommended"]:
        pipeline_layer["mismatch_reasons"].append("quarantine_recommended_mismatch")
    if pipeline_layer["expected_positive"] != (pipeline_layer["expected_review_recommended"] or pipeline_layer["expected_quarantine_recommended"]):
        pipeline_layer["mismatch_reasons"].append("expected_positive_relation_mismatch")
    if set(pipeline_layer["expected_findings"]) - set(pipeline_layer["predicted_findings"]):
        pipeline_layer["mismatch_reasons"].append("required_findings_mismatch")
    if set(pipeline_layer["forbidden_findings"]) & set(pipeline_layer["predicted_findings"]):
        pipeline_layer["mismatch_reasons"].append("forbidden_findings_mismatch")

    analyzer_layer["mismatch_reasons"] = sorted(analyzer_layer["mismatch_reasons"])
    pipeline_layer["mismatch_reasons"] = sorted(pipeline_layer["mismatch_reasons"])
    analyzer_layer["status_ok"] = len(analyzer_layer["mismatch_reasons"]) == 0
    pipeline_layer["status_ok"] = len(pipeline_layer["mismatch_reasons"]) == 0
    analyzer_layer["findings_ok"] = (
        not set(analyzer_layer["expected_findings"]).difference(analyzer_layer["predicted_findings"])
        and not set(analyzer_layer["forbidden_findings"]).intersection(analyzer_layer["predicted_findings"])
    )
    pipeline_layer["findings_ok"] = (
        not set(pipeline_layer["expected_findings"]).difference(pipeline_layer["predicted_findings"])
        and not set(pipeline_layer["forbidden_findings"]).intersection(pipeline_layer["predicted_findings"])
    )
    analyzer_layer["status_match"] = analyzer_layer["status_ok"]
    pipeline_layer["status_match"] = pipeline_layer["status_ok"]
    analyzer_layer["findings_match"] = analyzer_layer["findings_ok"]
    pipeline_layer["findings_match"] = pipeline_layer["findings_ok"]

    return analyzer_layer, pipeline_layer


def _compute_layer_metrics(layer_entries: list[dict[str, Any]]) -> dict[str, Any]:
    status_confusion = {status: {actual: 0 for actual in STATUS_VALUES} for status in STATUS_VALUES}
    tp = fp = tn = fn = 0
    for entry in layer_entries:
        expected = entry["expected_status"]
        predicted = entry["predicted_status"]
        status_confusion[expected][predicted] += 1

        expected_positive = bool(entry["expected_positive"])
        predicted_positive = bool(entry["predicted_positive"])
        if expected_positive and predicted_positive:
            tp += 1
        elif not expected_positive and predicted_positive:
            fp += 1
        elif expected_positive and not predicted_positive:
            fn += 1
        else:
            tn += 1

    positive_expected = sum(1 for entry in layer_entries if entry["expected_positive"])
    positive_predicted = sum(1 for entry in layer_entries if entry["predicted_positive"])
    status_matches = sum(1 for entry in layer_entries if entry["status_ok"])
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    exact_status_accuracy = status_matches / len(layer_entries) if layer_entries else 0.0

    return {
        "cases": len(layer_entries),
        "positive_expected": positive_expected,
        "positive_predicted": positive_predicted,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "exact_status_accuracy": exact_status_accuracy,
        "status_confusion_matrix": status_confusion,
    }


def _compare_thresholds(
    metrics: dict[str, Any],
    layer: str,
    expected: dict[str, float],
    overrides: dict[str, float] | None,
    failure_reasons: list[str],
) -> dict[str, Any]:
    comparator = {
        "minimum_precision": float(expected["minimum_precision"]),
        "minimum_recall": float(expected["minimum_recall"]),
        "maximum_false_positive_rate": float(expected["maximum_false_positive_rate"]),
        "minimum_exact_status_accuracy": float(expected["minimum_exact_status_accuracy"]),
    }
    if overrides:
        comparator.update(overrides)

    metric_map = {
        "minimum_precision": "precision",
        "minimum_recall": "recall",
        "maximum_false_positive_rate": "false_positive_rate",
        "minimum_exact_status_accuracy": "exact_status_accuracy",
    }

    status = "pass"
    for key, threshold in comparator.items():
        metric_key = metric_map[key]
        actual = float(metrics[metric_key])
        if key == "maximum_false_positive_rate":
            if actual > threshold:
                status = "fail"
                failure_reasons.append(f"{layer}.{key}_threshold_miss: actual={actual:.6f} required<={threshold:.6f}")
        elif actual < threshold:
            status = "fail"
            failure_reasons.append(f"{layer}.{key}_threshold_miss: actual={actual:.6f} required>={threshold:.6f}")

    return {
        "minimum_precision": comparator["minimum_precision"],
        "minimum_recall": comparator["minimum_recall"],
        "maximum_false_positive_rate": comparator["maximum_false_positive_rate"],
        "minimum_exact_status_accuracy": comparator["minimum_exact_status_accuracy"],
        "status": status,
    }


def _parse_threshold_args(prefix: str, args: argparse.Namespace) -> dict[str, float] | None:
    keys = [
        ("minimum_precision", f"{prefix}_min_precision"),
        ("minimum_recall", f"{prefix}_min_recall"),
        ("maximum_false_positive_rate", f"{prefix}_max_false_positive_rate"),
        ("minimum_exact_status_accuracy", f"{prefix}_min_exact_status_accuracy"),
    ]
    overrides: dict[str, float] = {}
    for target, field in keys:
        value = getattr(args, field)
        if value is not None:
            overrides[target] = float(value)
    return overrides or None


def run_calibration(
    corpus_path: Path,
    contract_path: Path,
    report_path: Path | None = None,
    analyzer_threshold_override: dict[str, float] | None = None,
    pipeline_threshold_override: dict[str, float] | None = None,
    raise_on_failure: bool = True,
) -> dict[str, Any]:
    resolved_corpus_path = corpus_path.resolve()
    resolved_contract_path = contract_path.resolve()
    contract = _load_json(contract_path)
    corpus = _load_json(corpus_path)

    _validate_contract(contract)
    _validate_corpus(corpus, contract)

    base_metrics = _ensure_dict(contract["metrics"], "contract.metrics")
    analyzer_baseline = _ensure_dict(base_metrics["analyzer"], "contract.metrics.analyzer")
    pipeline_baseline = _ensure_dict(base_metrics["pipeline"], "contract.metrics.pipeline")
    validated_analyzer_overrides = _validate_threshold_overrides(
        "analyzer", analyzer_baseline, analyzer_threshold_override
    )
    validated_pipeline_overrides = _validate_threshold_overrides(
        "pipeline", pipeline_baseline, pipeline_threshold_override
    )

    failure_reasons: list[str] = []
    analyzer_entries: list[dict[str, Any]] = []
    pipeline_entries: list[dict[str, Any]] = []
    per_category: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"analyzer": [], "pipeline": []})
    case_results: list[dict[str, Any]] = []

    for case in corpus["cases"]:
        case_id = case["id"]
        text = case["text"]

        analysis = analyze_return_language(
            text,
            expected_language=contract["expected_language"],
            expected_language_source="calibration",
        )
        decision = make_acceptance_decision(
            text,
            share_boundary="redacted-packet",
            expected_return_language=contract["expected_language"],
            expected_return_language_source="calibration",
        )

        case_failures: list[str] = []
        _validate_coverage(case, analysis, contract, case_failures)

        analyzer_layer, pipeline_layer = _build_case_payload(case, analysis, decision)

        if case_failures:
            analyzer_layer["mismatch_reasons"].extend(f"coverage:{item}" for item in case_failures)
            pipeline_layer["mismatch_reasons"].extend(f"coverage:{item}" for item in case_failures)

        analyzer_layer["mismatch_reasons"] = sorted(analyzer_layer["mismatch_reasons"])
        pipeline_layer["mismatch_reasons"] = sorted(pipeline_layer["mismatch_reasons"])
        analyzer_layer["status_ok"] = len(analyzer_layer["mismatch_reasons"]) == 0
        pipeline_layer["status_ok"] = len(pipeline_layer["mismatch_reasons"]) == 0
        analyzer_layer["status_match"] = analyzer_layer["status_ok"]
        pipeline_layer["status_match"] = pipeline_layer["status_ok"]

        if analyzer_layer["mismatch_reasons"]:
            failure_reasons.append(f"analyzer.{case_id}: {', '.join(analyzer_layer['mismatch_reasons'])}")
        if pipeline_layer["mismatch_reasons"]:
            failure_reasons.append(f"pipeline.{case_id}: {', '.join(pipeline_layer['mismatch_reasons'])}")

        case_results.append(
            {
                "id": case_id,
                "category": case["category"],
                "adversarial": bool(case["adversarial"]),
                "mismatch_count": len(analyzer_layer["mismatch_reasons"]) + len(pipeline_layer["mismatch_reasons"]),
                "analyzer": analyzer_layer,
                "pipeline": pipeline_layer,
            }
        )

        analyzer_entries.append(analyzer_layer)
        pipeline_entries.append(pipeline_layer)
        per_category[case["category"]]["analyzer"].append(analyzer_layer)
        per_category[case["category"]]["pipeline"].append(pipeline_layer)

    analyzer_metrics = _compute_layer_metrics(analyzer_entries)
    pipeline_metrics = _compute_layer_metrics(pipeline_entries)
    analyzer_threshold_status = _compare_thresholds(
        analyzer_metrics,
        "analyzer",
        analyzer_baseline,
        validated_analyzer_overrides,
        failure_reasons,
    )
    pipeline_threshold_status = _compare_thresholds(
        pipeline_metrics,
        "pipeline",
        pipeline_baseline,
        validated_pipeline_overrides,
        failure_reasons,
    )

    per_category_results: dict[str, Any] = {}
    for category, data in per_category.items():
        per_category_results[category] = {
            "analyzer": _compute_layer_metrics(data["analyzer"]),
            "pipeline": _compute_layer_metrics(data["pipeline"]),
        }

    mismatch_count = sum(item["mismatch_count"] for item in case_results)
    status = "pass" if not failure_reasons else "fail"

    if mismatch_count != 0:
        status = "fail"

    report: dict[str, Any] = {
        "artifact_type": REPORT_ARTIFACT_TYPE,
        "version": REPORT_VERSION,
        "status": status,
        "expected_language": contract["expected_language"],
        "case_count": len(corpus["cases"]),
        "balance": corpus["balance"],
        "corpus_path": _stable_report_path(resolved_corpus_path, "corpus"),
        "contract_path": _stable_report_path(resolved_contract_path, "contract"),
        "corpus_sha256": corpus["corpus_sha256"],
        "contract_sha256": contract["contract_sha256"],
        "case_results": case_results,
        "metrics": {
            "analyzer": analyzer_metrics,
            "pipeline": pipeline_metrics,
            "thresholds": {
                "analyzer": analyzer_threshold_status,
                "pipeline": pipeline_threshold_status,
            },
        },
        "per_category_results": per_category_results,
        "mismatch_count": mismatch_count,
        "failure_reasons": failure_reasons,
    }
    report["report_sha256"] = _sha256_hex(report, skip="report_sha256")

    if report["status"] != "pass":
        if not raise_on_failure:
            return report
        raise ReportError(f"calibration report failed validation: {', '.join(failure_reasons)}")

    if report_path is not None:
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run return language calibration checks")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--json", action="store_true")

    analyzer_group = parser.add_argument_group("analyzer thresholds")
    analyzer_group.add_argument("--analyzer-min-precision", type=float, default=None)
    analyzer_group.add_argument("--analyzer-min-recall", type=float, default=None)
    analyzer_group.add_argument("--analyzer-max-false-positive-rate", type=float, default=None)
    analyzer_group.add_argument("--analyzer-min-exact-status-accuracy", type=float, default=None)

    pipeline_group = parser.add_argument_group("pipeline thresholds")
    pipeline_group.add_argument("--pipeline-min-precision", type=float, default=None)
    pipeline_group.add_argument("--pipeline-min-recall", type=float, default=None)
    pipeline_group.add_argument("--pipeline-max-false-positive-rate", type=float, default=None)
    pipeline_group.add_argument("--pipeline-min-exact-status-accuracy", type=float, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = run_calibration(
            corpus_path=args.corpus,
            contract_path=args.contract,
            report_path=args.report,
            analyzer_threshold_override=_parse_threshold_args("analyzer", args),
            pipeline_threshold_override=_parse_threshold_args("pipeline", args),
        )
    except (CorpusError, ReportError, CalibrationMismatchError) as exc:
        if args.json:
            print(json.dumps({"status": "fail", "failure_reasons": [str(exc)]}, sort_keys=True, ensure_ascii=False))
            return 1
        raise

    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps({"status": report["status"], "case_count": report["case_count"]}, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
