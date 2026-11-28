"""Current calibration artifact checks and exact-source generator replay."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

from tests.historical_campaign_launcher import run_archived_cases  # noqa: E402

CONTRACT_PATH = ROOT / "calibration" / "skl-return-language-contract-v1.json"
CORPUS_PATH = ROOT / "calibration" / "skl-return-language-corpus-v1.json"
TUNING_PATH = ROOT / "calibration" / "skl-return-language-tuning-v1.json"
POLICY_PATH = ROOT / "policy" / "contracting-controls.yaml"
DOC_PATH = ROOT / "docs" / "malpractice-sabotage.html"
REPORT_PATH = ROOT / "calibration" / "skl-return-language-calibration-report-latest.json"


def _sha256_canonical(payload: dict[str, object], *, skip: str | None = None) -> str:
    normalized = copy.deepcopy(payload)
    if skip is not None:
        normalized.pop(skip)
    raw = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(raw).hexdigest()


class ReturnLanguageCalibrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        cls.contract_schema = json.loads((ROOT / "schemas" / "return-language-calibration-contract.schema.json").read_text(encoding="utf-8"))
        cls.corpus_schema = json.loads((ROOT / "schemas" / "return-language-corpus.schema.json").read_text(encoding="utf-8"))
        cls.report_schema = json.loads((ROOT / "schemas" / "return-language-calibration-report.schema.json").read_text(encoding="utf-8"))
        cls.tuning_schema = json.loads((ROOT / "schemas" / "return-language-calibration-tuning.schema.json").read_text(encoding="utf-8"))
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def test_schemas_are_closed_and_have_expected_required_fields(self) -> None:
        for schema in (self.contract_schema, self.corpus_schema, self.report_schema):
            self.assertFalse(schema["additionalProperties"])

        for required in (
            self.tuning_schema["required"],
            self.contract_schema["required"],
            self.corpus_schema["required"],
            self.report_schema["required"],
        ):
            self.assertIsInstance(required, list)

        self.assertEqual(
            {
                "artifact_type",
                "version",
                "status",
                "expected_language",
                "case_count",
                "balance",
                "corpus_path",
                "contract_path",
                "corpus_sha256",
                "contract_sha256",
                "case_results",
                "metrics",
                "per_category_results",
                "mismatch_count",
                "failure_reasons",
                "report_sha256",
            },
            set(self.report_schema["required"]),
        )

        self.assertEqual(
            {
                "artifact_type",
                "version",
                "immutable_baseline_minimum_english_words",
                "selected_threshold",
                "nearest_higher_failing_threshold",
                "language",
                "contract_path",
                "corpus_path",
                "latest_report_path",
                "contract_sha256",
                "corpus_sha256",
                "analyzer",
                "pipeline",
                "mismatch_count_by_threshold",
                "failure_case_ids_by_threshold",
                "signal_weight_hash",
                "global_threshold_hash",
                "sweep_results",
                "canonical_sha256",
            },
            set(self.tuning_schema["required"]),
        )

    def test_baseline_calibration_report_is_clean(self) -> None:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["report_sha256"], _sha256_canonical(report, skip="report_sha256"))
        self.assertEqual(report["contract_sha256"], self.contract["contract_sha256"])
        self.assertEqual(report["corpus_sha256"], self.corpus["corpus_sha256"])
        self.assertEqual(report["case_count"], self.corpus["case_count"])
        self.assertEqual(report["mismatch_count"], 0)
        self.assertEqual(report["failure_reasons"], [])
        self.assertEqual(sum(item["mismatch_count"] for item in report["case_results"]), 0)
        for item in report["case_results"]:
            self.assertEqual(item["mismatch_count"], 0)

    def test_tuning_artifact_is_valid_and_matches_sweep(self) -> None:
        tuning = json.loads(TUNING_PATH.read_text(encoding="utf-8"))
        self.assertEqual(tuning["selected_threshold"], 21)
        self.assertEqual(tuning["nearest_higher_failing_threshold"], 22)
        self.assertEqual(tuning["immutable_baseline_minimum_english_words"], 40)

        self.assertEqual(
            tuning["selected_threshold"],
            self.policy["sabotage_policy"]["language_guard"]["minimum_english_words"],
        )
        self.assertEqual(_sha256_canonical(tuning, skip="canonical_sha256"), tuning["canonical_sha256"])
        self.assertEqual(
            tuning["contract_sha256"],
            _sha256_canonical(self.contract, skip="contract_sha256"),
        )
        self.assertEqual(
            tuning["corpus_sha256"],
            _sha256_canonical(self.corpus, skip="corpus_sha256"),
        )
        self.assertEqual(
            tuning["signal_weight_hash"],
            _sha256_canonical(self.policy["sabotage_policy"]["signal_weights"]),
        )
        self.assertEqual(
            tuning["global_threshold_hash"],
            _sha256_canonical(self.policy["sabotage_policy"]["thresholds"]),
        )

        self.assertEqual(tuning["analyzer"]["selected"]["precision"], 1.0)
        self.assertEqual(tuning["analyzer"]["selected"]["recall"], 1.0)
        self.assertEqual(tuning["analyzer"]["selected"]["exact_status_accuracy"], 1.0)
        self.assertEqual(tuning["pipeline"]["selected"]["precision"], 1.0)
        self.assertEqual(tuning["pipeline"]["selected"]["recall"], 1.0)
        self.assertEqual(tuning["pipeline"]["selected"]["exact_status_accuracy"], 1.0)

        sweep = tuning["sweep_results"]
        expected_thresholds = list(range(40, 20, -1))
        observed_thresholds = [entry["minimum_english_words"] for entry in sweep]
        self.assertEqual(observed_thresholds, expected_thresholds)
        by_minimum = {entry["minimum_english_words"]: entry for entry in sweep}

        for minimum_english_words in expected_thresholds:
            sweep_entry = by_minimum[minimum_english_words]
            self.assertEqual(
                tuning["mismatch_count_by_threshold"][str(minimum_english_words)],
                sweep_entry["mismatch_count"],
            )
            self.assertEqual(
                sorted(tuning["failure_case_ids_by_threshold"][str(minimum_english_words)]),
                sorted(sweep_entry["failure_case_ids"]),
            )
            if minimum_english_words >= 22:
                self.assertEqual(sweep_entry["status"], "fail")
            else:
                self.assertEqual(sweep_entry["status"], "pass")

        self.assertEqual(by_minimum[21]["status"], "pass")
        self.assertEqual(by_minimum[22]["status"], "fail")
        self.assertEqual(tuning["nearest_higher_failing_threshold"], 22)
        self.assertEqual(by_minimum[21]["failure_case_ids"], [])
        self.assertEqual(tuning["mismatch_count_by_threshold"]["21"], 0)
        try:
            import jsonschema  # type: ignore
        except Exception:
            self.skipTest("jsonschema package unavailable")
            return

        jsonschema.validate(instance=tuning, schema=self.tuning_schema)

    def test_no_work_packet_references_in_tracked_skl_files(self) -> None:
        tracked_texts = [
            DOC_PATH.read_text(encoding="utf-8"),
            CORPUS_PATH.read_text(encoding="utf-8"),
            CONTRACT_PATH.read_text(encoding="utf-8"),
            REPORT_PATH.read_text(encoding="utf-8"),
            POLICY_PATH.read_text(encoding="utf-8"),
            TUNING_PATH.read_text(encoding="utf-8"),
        ]
        for text in tracked_texts:
            self.assertNotIn("work-packets/skl-corpus-contract.json", text)

    def test_policy_constraints_do_not_expand(self) -> None:
        constraints = self.contract["policy_constraints"]
        self.assertEqual(constraints["critical_signal_weight_reduction"], "forbidden")
        self.assertEqual(constraints["global_review_or_quarantine_threshold_relaxation"], "forbidden")

    def test_jsonschema_validation_for_artifacts(self) -> None:
        try:
            import jsonschema  # type: ignore
        except Exception:
            self.skipTest("jsonschema package unavailable")
            return

        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        jsonschema.validate(instance=self.contract, schema=self.contract_schema)
        jsonschema.validate(instance=self.corpus, schema=self.corpus_schema)
        jsonschema.validate(instance=report, schema=self.report_schema)
        jsonschema.validate(instance=json.loads(TUNING_PATH.read_text(encoding="utf-8")), schema=self.tuning_schema)


class ArchivedReturnLanguageGeneratorTests(unittest.TestCase):
    def test_pinned_calibration_generator_and_cli(self) -> None:
        revision = "7b2f3db802d7b1d1c4c555960d65d2502220f93b"  # v1.48.0
        suite = "tests.test_return_language_calibration.ReturnLanguageCalibrationTests."
        cases = (
            "test_baseline_calibration_report_is_clean",
            "test_no_work_packet_references_in_tracked_skl_files",
            "test_unknown_fields_and_structure_rejected",
            "test_threshold_override_unknown_keys_are_rejected",
            "test_duplicate_case_ids_and_texts_fail",
            "test_required_scripts_missing_from_corpus_coverage",
            "test_mismatched_adversarial_balance_fails",
            "test_benign_case_marked_adversarial_fails",
            "test_adversarial_case_marked_benign_fails",
            "test_fail_closed_hash_checks",
            "test_unsupported_expected_language_rejected",
            "test_exact_case_mismatch_is_a_failure",
            "test_coverage_mismatch_forces_report_failure",
            "test_threshold_override_rejects_relaxation",
            "test_threshold_override_accepts_tightening",
            "test_exact_case_mismatch_after_rehash",
            "test_bidi_and_zero_width_pipeline_match_quarantine",
            "test_nfkc_prompt_injection_detects_normalization_evasion",
            "test_deterministic_external_subprocess_output",
            "test_default_cli_json_output_is_deterministic",
            "test_report_hash_changes_when_inputs_change",
            "test_zero_critical_misses_and_supported_langs",
        )
        run_archived_cases(self, revision, *(suite + name for name in cases), all_paths=True)


if __name__ == "__main__":
    unittest.main()
