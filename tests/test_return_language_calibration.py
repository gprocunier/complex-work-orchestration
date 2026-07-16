from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ["PYTHONPATH"] = str(ROOT / "scripts")
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.return_language_calibration import CorpusError, ReportError, run_calibration

CONTRACT_PATH = ROOT / "calibration" / "skl-return-language-contract-v1.json"
CORPUS_PATH = ROOT / "calibration" / "skl-return-language-corpus-v1.json"
TUNING_PATH = ROOT / "calibration" / "skl-return-language-tuning-v1.json"
SCRIPT_PATH = ROOT / "scripts" / "calibrate_return_language.py"
POLICY_PATH = ROOT / "policy" / "contracting-controls.yaml"
DOC_PATH = ROOT / "docs" / "malpractice-sabotage.html"
REPORT_PATH = ROOT / "calibration" / "skl-return-language-calibration-report-latest.json"


def _canonical(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _recompute_corpus_hash(corpus: dict[str, object]) -> dict[str, object]:
    updated = copy.deepcopy(corpus)
    payload = copy.deepcopy(updated)
    payload.pop("corpus_sha256")
    corpus_hash = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    updated["corpus_sha256"] = corpus_hash
    return updated


def _recompute_contract_hash(contract: dict[str, object]) -> dict[str, object]:
    updated = copy.deepcopy(contract)
    payload = copy.deepcopy(updated)
    payload.pop("contract_sha256")
    contract_hash = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    updated["contract_sha256"] = contract_hash
    return updated


def _sha256_canonical(payload: dict[str, object], *, skip: str | None = None) -> str:
    normalized = copy.deepcopy(payload)
    if skip is not None:
        normalized.pop(skip, None)
    return sha256(_canonical(normalized).encode("utf-8")).hexdigest()


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--json",
            "--corpus",
            str(CORPUS_PATH),
            "--contract",
            str(CONTRACT_PATH),
            *args,
        ],
        cwd=ROOT,
        text=True,
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
    )


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

    def run_with_corpus(self, corpus: dict[str, object], **kwargs: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corpus.json"
            path.write_text(json.dumps(corpus, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            return run_calibration(corpus_path=path, contract_path=CONTRACT_PATH, **kwargs)

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
        report = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH, report_path=REPORT_PATH)
        self.assertEqual(report["status"], "pass")
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
            _recompute_contract_hash(self.contract)["contract_sha256"],
        )
        self.assertEqual(
            tuning["corpus_sha256"],
            _recompute_corpus_hash(self.corpus)["corpus_sha256"],
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
            str(Path(SCRIPT_PATH).read_text(encoding="utf-8")),
        ]
        for text in tracked_texts:
            self.assertNotIn("work-packets/skl-corpus-contract.json", text)

    def test_unknown_fields_and_structure_rejected(self) -> None:
        unknown_top = copy.deepcopy(self.corpus)
        unknown_top["unexpected_top_field"] = True
        with self.assertRaises(CorpusError):
            self.run_with_corpus(unknown_top)

        unknown_case = copy.deepcopy(self.corpus)
        unknown_case["cases"][0]["unexpected_case_field"] = "bad"
        unknown_case = _recompute_corpus_hash(unknown_case)
        with self.assertRaisesRegex(CorpusError, "extra keys"):
            self.run_with_corpus(unknown_case)

    def test_threshold_override_unknown_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(CorpusError, "unknown key"):
            run_calibration(
                corpus_path=CORPUS_PATH,
                contract_path=CONTRACT_PATH,
                analyzer_threshold_override={
                    "minimum_precision": 0.95,
                    "mystery_threshold": 0.5,
                },
            )

    def test_duplicate_case_ids_and_texts_fail(self) -> None:
        duplicate_id = copy.deepcopy(self.corpus)
        duplicate_id["cases"][1]["id"] = duplicate_id["cases"][0]["id"]
        duplicate_id = _recompute_corpus_hash(duplicate_id)
        with self.assertRaises(CorpusError):
            self.run_with_corpus(duplicate_id)

        duplicate_text = copy.deepcopy(self.corpus)
        duplicate_text["cases"][1]["text"] = duplicate_text["cases"][0]["text"]
        duplicate_text = _recompute_corpus_hash(duplicate_text)
        with self.assertRaises(CorpusError):
            self.run_with_corpus(duplicate_text)

    def test_required_scripts_missing_from_corpus_coverage(self) -> None:
        missing_coverage = copy.deepcopy(self.corpus)
        for case in missing_coverage["cases"]:
            if case["id"] == "adv-unexpected-arabic":
                case["coverage"]["scripts"] = []
                break
        else:
            self.fail("Arabic required-script case not found in corpus")

        missing_coverage = _recompute_corpus_hash(missing_coverage)
        with self.assertRaisesRegex(CorpusError, "required scripts missing from corpus coverage"):
            self.run_with_corpus(missing_coverage)

    def test_mismatched_adversarial_balance_fails(self) -> None:
        mismatched_balance = copy.deepcopy(self.corpus)
        mismatched_balance["balance"]["benign"] = 51
        mismatched_balance = _recompute_corpus_hash(mismatched_balance)
        with self.assertRaises(CorpusError):
            self.run_with_corpus(mismatched_balance)

        mismatched_balance = copy.deepcopy(self.corpus)
        mismatched_balance["balance"]["adversarial"] = 51
        mismatched_balance = _recompute_corpus_hash(mismatched_balance)
        with self.assertRaises(CorpusError):
            self.run_with_corpus(mismatched_balance)

    def test_benign_case_marked_adversarial_fails(self) -> None:
        bad_case = copy.deepcopy(self.corpus)
        for case in bad_case["cases"]:
            if not case["adversarial"]:
                case["adversarial"] = True
                break
        else:
            self.fail("no benign case in corpus")

        bad_case = _recompute_corpus_hash(bad_case)
        with self.assertRaisesRegex(CorpusError, "requires adversarial=false"):
            self.run_with_corpus(bad_case)

    def test_adversarial_case_marked_benign_fails(self) -> None:
        bad_case = copy.deepcopy(self.corpus)
        for case in bad_case["cases"]:
            if case["adversarial"]:
                case["adversarial"] = False
                break
        else:
            self.fail("no adversarial case in corpus")

        bad_case = _recompute_corpus_hash(bad_case)
        with self.assertRaisesRegex(CorpusError, "requires adversarial=true"):
            self.run_with_corpus(bad_case)

    def test_fail_closed_hash_checks(self) -> None:
        bad_hash = copy.deepcopy(self.corpus)
        bad_hash["corpus_sha256"] = "0" * 64
        with self.assertRaises(CorpusError):
            self.run_with_corpus(bad_hash)

        bad_contract = copy.deepcopy(self.contract)
        bad_contract["contract_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            contract_path = Path(directory) / "contract.json"
            contract_path.write_text(json.dumps(bad_contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(CorpusError):
                run_calibration(corpus_path=CORPUS_PATH, contract_path=contract_path)

    def test_unsupported_expected_language_rejected(self) -> None:
        bad_contract = copy.deepcopy(self.contract)
        bad_contract["expected_language"] = "fr"
        with_contract_hash = copy.deepcopy(bad_contract)
        with_contract_hash = _recompute_contract_hash(with_contract_hash)
        with tempfile.TemporaryDirectory() as directory:
            bad_contract_path = Path(directory) / "contract.json"
            bad_contract_path.write_text(json.dumps(with_contract_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(CorpusError):
                run_calibration(corpus_path=CORPUS_PATH, contract_path=bad_contract_path)

    def test_exact_case_mismatch_is_a_failure(self) -> None:
        bad_case = copy.deepcopy(self.corpus)
        bad_case["cases"][0]["analyzer_expectation"]["status"] = "quarantine"
        bad_case = _recompute_corpus_hash(bad_case)
        with self.assertRaises(ReportError) as context:
            self.run_with_corpus(bad_case)
        self.assertIn("status_mismatch", str(context.exception))

    def test_coverage_mismatch_forces_report_failure(self) -> None:
        bad_case = copy.deepcopy(self.corpus)
        bad_case["cases"][0]["coverage"]["scripts"] = ["Unknown"]
        bad_case = _recompute_corpus_hash(bad_case)
        with self.assertRaises(ReportError) as context:
            self.run_with_corpus(bad_case)
        self.assertIn("coverage", str(context.exception))

    def test_threshold_override_rejects_relaxation(self) -> None:
        result = _run_cli("--analyzer-min-recall", "0.90")
        self.assertEqual(result.returncode, 1)
        self.assertIn("threshold relaxation rejected", result.stdout + result.stderr)

    def test_threshold_override_accepts_tightening(self) -> None:
        result = _run_cli("--analyzer-min-recall", "0.99", "--pipeline-min-recall", "0.99")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "pass")

    def test_exact_case_mismatch_after_rehash(self) -> None:
        bad_case = copy.deepcopy(self.corpus)
        bad_case["cases"][1]["pipeline_expectation"]["return_language_status"] = "review"
        bad_case = _recompute_corpus_hash(bad_case)
        with self.assertRaises(ReportError):
            self.run_with_corpus(bad_case)

    def test_bidi_and_zero_width_pipeline_match_quarantine(self) -> None:
        report = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH)
        for item in report["case_results"]:
            if item["category"] == "bidi-control":
                self.assertEqual(item["pipeline"]["expected_status"], "quarantine")
                self.assertTrue(item["pipeline"]["expected_quarantine_recommended"])
                self.assertTrue(item["pipeline"]["predicted_quarantine_recommended"])
                self.assertEqual(item["pipeline"]["predicted_status"], "quarantine")
            if item["category"] == "zero-width-control":
                self.assertEqual(item["pipeline"]["expected_status"], "quarantine")
                self.assertTrue(item["pipeline"]["expected_quarantine_recommended"])
                self.assertTrue(item["pipeline"]["predicted_quarantine_recommended"])
                self.assertEqual(item["pipeline"]["predicted_status"], "quarantine")

    def test_nfkc_prompt_injection_detects_normalization_evasion(self) -> None:
        report = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH)
        for item in report["case_results"]:
            if item["category"] != "nfkc-prompt-injection":
                continue
            expected = item["pipeline"]["expected_findings"]
            predicted = item["pipeline"]["predicted_findings"]
            self.assertEqual(set(expected), {"prompt_injection", "unicode_normalization_evasion"})
            self.assertEqual(set(expected), set(predicted))
            self.assertTrue(item["pipeline"]["expected_positive"])
            self.assertTrue(item["pipeline"]["expected_review_recommended"])
            self.assertTrue(item["pipeline"]["expected_quarantine_recommended"])

    def test_deterministic_external_subprocess_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory_a:
            with tempfile.TemporaryDirectory() as directory_b:
                corpus_a = Path(directory_a) / "corpus.json"
                contract_a = Path(directory_a) / "contract.json"
                corpus_b = Path(directory_b) / "corpus.json"
                contract_b = Path(directory_b) / "contract.json"

                corpus_a.write_bytes(CORPUS_PATH.read_bytes())
                contract_a.write_bytes(CONTRACT_PATH.read_bytes())
                corpus_b.write_bytes(CORPUS_PATH.read_bytes())
                contract_b.write_bytes(CONTRACT_PATH.read_bytes())

                report_a = run_calibration(
                    corpus_path=corpus_a,
                    contract_path=contract_a,
                    report_path=Path(directory_a) / "a.json",
                    raise_on_failure=False,
                )
                report_b = run_calibration(
                    corpus_path=corpus_b,
                    contract_path=contract_b,
                    report_path=Path(directory_b) / "b.json",
                    raise_on_failure=False,
                )

                hash_a = sha256(_canonical(report_a).encode("utf-8")).hexdigest()
                hash_b = sha256(_canonical(report_b).encode("utf-8")).hexdigest()

                self.assertEqual(report_a["status"], "pass")
                self.assertEqual(report_b["status"], "pass")
                self.assertEqual(hash_a, hash_b)
                self.assertEqual(report_a["corpus_path"], "<external-corpus>")
                self.assertEqual(report_a["contract_path"], "<external-contract>")

    def test_default_cli_json_output_is_deterministic(self) -> None:
        result_a = _run_cli()
        self.assertEqual(result_a.returncode, 0, result_a.stderr)
        result_b = _run_cli()
        self.assertEqual(result_b.returncode, 0, result_b.stderr)
        self.assertEqual(result_a.stdout, result_b.stdout)

    def test_report_hash_changes_when_inputs_change(self) -> None:
        base = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH)

        mutated = copy.deepcopy(self.corpus)
        mutated["cases"][0]["text"] = mutated["cases"][0]["text"].replace("test", "sample")
        mutated = _recompute_corpus_hash(mutated)

        next_report = self.run_with_corpus(mutated)
        self.assertNotEqual(base["report_sha256"], next_report["report_sha256"])

    def test_zero_critical_misses_and_supported_langs(self) -> None:
        report = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH)
        self.assertEqual(report["mismatch_count"], 0)
        for item in report["case_results"]:
            self.assertEqual(item["mismatch_count"], 0)

        self.assertEqual(self.policy["sabotage_policy"]["language_guard"]["minimum_english_words"], 21)

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

        report = run_calibration(corpus_path=CORPUS_PATH, contract_path=CONTRACT_PATH)

        jsonschema.validate(instance=self.contract, schema=self.contract_schema)
        jsonschema.validate(instance=self.corpus, schema=self.corpus_schema)
        jsonschema.validate(instance=report, schema=self.report_schema)
        jsonschema.validate(instance=json.loads(TUNING_PATH.read_text(encoding="utf-8")), schema=self.tuning_schema)


if __name__ == "__main__":
    unittest.main()
