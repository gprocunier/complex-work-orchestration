from __future__ import annotations

import hashlib
import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import report_return_tripwire_corpus as report
from cwo_core.returns import make_acceptance_decision


class CorpusCategoryReportTests(unittest.TestCase):
    def test_current_declared_corpus_rates_and_binding(self) -> None:
        result = report.build_report()
        self.assertEqual(result["case_count"], 57)
        self.assertEqual(result["ambiguous_status"], "unknown/not separately labelled in declared corpus")
        for placement in ("appended", "evidence"):
            groups = result["totals"][placement]
            self.assertEqual(groups["hostile"]["evaluations"], 37)
            self.assertEqual(groups["hostile"]["counts"]["accepted_for_use"], 0)
            self.assertEqual(groups["hostile"]["rates"]["held"], 1)
            self.assertEqual(groups["benign"]["evaluations"], 20)
            self.assertEqual(groups["benign"]["counts"]["tripwire_hit"], 0)
            self.assertEqual(groups["benign"]["counts"]["held_without_tripwire"], 1)
            self.assertEqual(groups["benign"]["rates"]["accepted_for_use"], 19 / 20)
            self.assertEqual(groups["benign"]["rates"]["held"], 1 / 20)
        for row in result["categories"]:
            ambiguous = row["labels"]["ambiguous"]
            self.assertEqual(ambiguous["evaluations"], 0)
            self.assertTrue(all(rate is None for rate in ambiguous["rates"].values()))
        cases = json.loads((ROOT / report.CORPUS).read_bytes())["cases"]
        for row in result["categories"]:
            for label in ("hostile", "benign"):
                expected = sum(case["category"] == row["category"] and
                               case["hostile"] == (label == "hostile") for case in cases)
                self.assertEqual(row["labels"][label]["evaluations"], expected)
        for placement, labels in result["totals"].items():
            for label, total in labels.items():
                for metric, count in total["counts"].items():
                    self.assertEqual(sum(row["labels"][label]["counts"][metric]
                                         for row in result["categories"] if row["placement"] == placement), count)
        audit = [row for row in result["categories"] if row["category"] == "audit_suppression"]
        self.assertEqual(len(audit), 2)
        for row in audit:
            benign = row["labels"]["benign"]
            self.assertEqual(benign["counts"]["non_tripwire_hold_reason"], 1)
            self.assertEqual(benign["rates"]["tripwire_hit"], 0)
        for path, digest in result["input_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)

    def test_every_call_uses_original_evaluator_and_both_actual_placements(self) -> None:
        corpus = json.loads((ROOT / report.CORPUS).read_bytes())["cases"]
        sample = (ROOT / report.SAMPLE).read_text(encoding="utf-8")
        with patch.object(report, "make_acceptance_decision", wraps=make_acceptance_decision) as evaluate:
            report.build_report()
        expected = []
        for case in corpus:
            expected.extend([sample + "\n" + case["text"] + "\n",
                             sample.replace("Evidence:\n", "Evidence:\n- " +
                                            case["text"].replace("\n", "\n  ") + "\n", 1)])
        # Compare without putting corpus text in an assertion failure or log.
        actual_hashes = [hashlib.sha256(call.args[0].encode()).hexdigest() for call in evaluate.call_args_list]
        self.assertEqual(actual_hashes, [hashlib.sha256(text.encode()).hexdigest() for text in expected])
        self.assertTrue(all(not call.kwargs for call in evaluate.call_args_list))

    def test_empty_denominators_and_real_evidence_marker(self) -> None:
        empty = report.summarize([])
        self.assertTrue(all(value is None for value in empty["rates"].values()))
        self.assertEqual(empty["dispositions"], {})
        with self.assertRaisesRegex(ValueError, "actual Evidence section"):
            report.placements("EXAMPLE missing section", "EXAMPLE harmless clause")

    def test_cli_is_deterministic_counts_only_and_diagnostic(self) -> None:
        command = [sys.executable, str(ROOT / "scripts/report_return_tripwire_corpus.py")]
        first = subprocess.run(command, capture_output=True, check=True).stdout
        second = subprocess.run(command, capture_output=True, check=True).stdout
        self.assertEqual(first, second)
        result = json.loads(first)
        self.assertNotIn("cases", result)
        self.assertNotIn("text", result)
        self.assertEqual(result, report.build_report())

    def test_nonzero_hostile_acceptance_is_a_failing_diagnostic(self) -> None:
        example = {"totals": {"appended": {"hostile": {"counts": {"accepted_for_use": 1}}}}}
        with patch.object(report, "build_report", return_value=example), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(report.main(), 1)
