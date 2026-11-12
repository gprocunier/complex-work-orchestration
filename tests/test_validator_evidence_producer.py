"""Disposable reliability fixtures for actual checked-command observation production."""
from __future__ import annotations

import contextlib
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import close_bead_with_summary as closure  # noqa: E402
import prepare_validator_receipts as preparation  # noqa: E402
import produce_validator_evidence as producer  # noqa: E402
from cwo_core import beads  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import checked_command as cc  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import stage_completion  # noqa: E402
from test_validator_receipt_preparation import (  # noqa: E402
    AFTER, OUTPUT, TempGit, amendment, criterion, external_edit, sha, spec, spec_hash, validator,
)


class ValidatorEvidenceProducerTests(unittest.TestCase):
    def begin(self, variant: str = "passed", *, two: bool = False, additive: bool = False,
              duplicate: bool = False, expected: bytes | None = None, extra=(),
              criterion_updates=()) -> None:
        self.workspace = TempGit(self)
        self.repo = self.workspace.root
        sources = {
            "passed": "print('EXAMPLE validator output')\n# EXAMPLE reliable observation\n",
            "failed": "raise SystemExit(7)\n",
            "refused": "def EXAMPLE_invalid(:\n",
            "timeout": "import time\ntime.sleep(60)\n",
            "timeout-output": (
                "import sys\n"
                "import time\n"
                "print('EXAMPLE validator output', flush=True)\n"
                "print('EXAMPLE timeout reliability diagnostic', file=sys.stderr, flush=True)\n"
                "time.sleep(3)\n"),
        }
        chosen = spec(self.repo, "EXAMPLE-command-A", sources[variant])
        if variant in ("timeout", "timeout-output"):
            chosen["timeout_seconds"] = 1
        stdout = b"" if variant in ("failed", "refused", "timeout") else OUTPUT
        if expected is not None:
            stdout = expected
        self.commands = {"EXAMPLE-alpha": chosen}
        self.commands.update({
            item["id"]: spec(
                self.repo, item["id"] + "-command", "print('EXAMPLE required reliability observation')\n")
            for item in extra})
        declared = validator("EXAMPLE-alpha", chosen, stdout)
        declared.update(criterion_updates)
        self.initial = {
            "record_type": rb.BASELINE_RECORD_TYPE, "version": 1,
            "bead_id": "EXAMPLE-bead", "baseline_version": 1,
            "criteria": [declared, *extra],
        }
        self.amendments = []
        if two or additive:
            second = chosen if duplicate else spec(
                self.repo, "EXAMPLE-command-B", "print('EXAMPLE validator output')\n# EXAMPLE second observation\n")
            added = validator("EXAMPLE-beta", second, OUTPUT)
            self.commands = {"EXAMPLE-beta": second, **self.commands}
            if additive:
                new = copy.deepcopy(self.initial)
                new["baseline_version"] = 2
                new["criteria"].append(added)
                self.amendments.append(amendment(self.initial, new))
            else:
                self.initial["criteria"].append(added)
        self.chain = rb.resolve_chain(self.initial, self.amendments)
        self.bead = {"id": self.chain["bead_id"], "comments": [
            {"text": rb.reference_line(self.chain["bead_id"], entry["version"], entry["digest"])}
            for entry in self.chain["baselines"]]}
        # Reliability obligations and baseline references precede candidate changes.
        (self.repo / "src/item.txt").write_bytes(AFTER)
        self.candidate = ci.capture_candidate(
            self.repo, chain=self.chain, base_commit=self.workspace.base, scope_paths=["src"])
        self.bead["comments"].append({"text": ci.candidate_reference_line(
            self.chain["bead_id"], ci.candidate_digest(self.candidate))})

    def arguments(self) -> dict:
        return {
            "root": str(self.repo), "initial": self.initial,
            "candidate": self.candidate, "bead": self.bead,
            "commands": self.commands, "amendments": self.amendments,
        }

    def run_production(self, **changes) -> dict:
        arguments = self.arguments()
        arguments.update(changes)
        with patch.object(cc, "execute_checked_command", wraps=cc.execute_checked_command) as execute:
            result = producer.produce(**arguments)
        self.call_specs = [copy.deepcopy(call.args[0]) for call in execute.call_args_list]
        for key in preparation.AUTHORITY_FIELDS:
            self.assertIs(result[key], False)
            if result["consumer_diagnostic"] is not None:
                self.assertIs(result["consumer_diagnostic"][key], False)
        return result

    def changed(self, path: tuple, value) -> dict:
        arguments = copy.deepcopy(self.arguments())
        target = arguments
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return arguments

    def assert_predeclared_refusal(self, criterion_id: str, reason: str) -> dict:
        self.assertEqual(set(self.commands), set(rb.required_criterion_ids(self.chain["baseline"])))
        checked = ci.check_candidate(
            self.candidate, root=self.repo, chain=self.chain, bead=self.bead)
        self.assertIs(checked["valid"], True, checked["errors"])
        result = self.run_production()
        self.assertEqual(self.call_specs, [])
        self.assertEqual(result["checked_command_calls"], 0)
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(result["validator_evidence"], [])
        self.assertFalse(result["observations_complete"])
        self.assertEqual(result["errors"], ["production refused: PreparationError: " + reason])
        diagnostic = result["consumer_diagnostic"]
        self.assertIsNotNone(diagnostic)
        self.assertFalse(diagnostic["observations_complete"])
        entry = next(item for item in diagnostic["criteria"] if item["id"] == criterion_id)
        self.assertEqual(entry["state"], "UNASSESSABLE")
        self.assertEqual(entry["reason"], reason)
        return result

    def test_complete_compact_delivery_retains_actual_receipt_and_real_consumer(self) -> None:
        self.begin()
        real_execute = cc.execute_checked_command
        observed = []

        def observe(command):
            result = real_execute(command)
            observed.append(copy.deepcopy(result))
            return result

        with patch.object(cc, "execute_checked_command", side_effect=observe), \
                patch.object(preparation, "prepare", wraps=preparation.prepare) as consumer:
            result = self.run_production()
        consumer.assert_called_once()
        self.assertEqual(len(self.call_specs), 1)
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["state"], "OBSERVED_CONSISTENT")
        self.assertTrue(result["consumer_diagnostic"]["observations_complete"])
        wrapper = result["validator_evidence"][0]
        self.assertEqual(wrapper, {
            "record_type": preparation.EVIDENCE_TYPE, "version": 1, "criterion_id": "EXAMPLE-alpha",
            "baseline_digest": self.chain["digest"], "candidate_digest": ci.candidate_digest(self.candidate),
            "spec": self.commands["EXAMPLE-alpha"], "result": observed[0],
        })
        self.assertEqual(set(wrapper["result"]), preparation.RESULT_FIELDS)
        self.assertEqual(wrapper["result"]["executed_sha256"], sha(self.commands["EXAMPLE-alpha"]["source"].encode("utf-8")))
        self.assertEqual(wrapper["result"]["spec_sha256"], spec_hash(cc.normalize_command_spec(wrapper["spec"])))
        self.assertEqual(consumer.call_args.args[4], result["validator_evidence"])
        body = {key: value for key, value in result.items() if key != "report_digest"}
        self.assertEqual(result["report_digest"], rb.record_digest(body))

    def test_all_mappings_are_checked_before_any_execution(self) -> None:
        self.begin(two=True)
        cases = (
            (("commands",), {}),
            (("commands",), {"EXAMPLE-replaced": self.commands["EXAMPLE-alpha"],
                             "EXAMPLE-beta": self.commands["EXAMPLE-beta"]}),
            (("commands",), {**self.commands, "EXAMPLE-unknown": self.commands["EXAMPLE-alpha"]}),
            (("commands", "EXAMPLE-beta", "source"), "print('EXAMPLE wrong command')\n"),
            (("commands", "EXAMPLE-beta", "command_id"), "EXAMPLE-unrelated"),
            (("commands", "EXAMPLE-beta", "cwd"), str(self.repo.parent)),
            (("commands", "EXAMPLE-beta", "version"), True),
            (("commands", "EXAMPLE-beta", "timeout_seconds"), True),
            (("commands", "EXAMPLE-beta", "timeout_seconds"), 1.0),
            (("commands", "EXAMPLE-beta", "mutation_intent"), "workspace-scoped"),
            (("commands", "EXAMPLE-beta", "result"), {"execution_status": "passed"}),
            (("commands", "EXAMPLE-beta", "status"), "passed"),
            (("commands", "EXAMPLE-beta"), {"spec": self.commands["EXAMPLE-beta"], "result": {}}),
        )
        for path, value in cases:
            with self.subTest(path=path, value_type=type(value).__name__):
                result = self.run_production(**self.changed(path, value))
                self.assertEqual(self.call_specs, [])
                self.assertEqual(result["validator_evidence"], [])
                self.assertFalse(result["observations_complete"])
                self.assertTrue(result["errors"])

    def test_baseline_candidate_and_reference_refusals_have_zero_producer_calls(self) -> None:
        self.begin()
        changed_outcome = validator(
            "EXAMPLE-alpha", self.commands["EXAMPLE-alpha"], b"EXAMPLE changed reliability expectation\n")["expected_outcome"]
        cases = (
            (("initial", "criteria"), []),
            (("initial", "criteria", 0, "id"), "EXAMPLE-replaced"),
            (("initial", "criteria", 0, "id"), True),
            (("initial", "version"), True),
            (("initial", "criteria", 0, "expected_outcome"), changed_outcome),
            (("candidate", "commit"), "0" * 40),
            (("candidate", "version"), True),
            (("candidate", "baseline", "digest"), "sha256:" + "0" * 64),
            (("bead",), []),
            (("bead", "id"), "EXAMPLE-other"),
            (("bead", "comments"), []),
            (("bead", "comments", 0, "text"), "cwo-requirement-baseline EXAMPLE malformed reference"),
            (("bead", "comments", 1, "text"), "cwo-candidate-identity EXAMPLE malformed reference"),
            (("amendments",), [{}]),
            (("amendments",), False),
            (("root",), str(self.repo.parent)),
        )
        for path, value in cases:
            with self.subTest(path=path):
                arguments = self.changed(path, value)
                changed_valid_baseline = path == ("initial", "criteria", 0, "expected_outcome")
                if changed_valid_baseline:
                    changed_chain = rb.resolve_chain(arguments["initial"], arguments["amendments"])
                    self.assertNotEqual(changed_chain["digest"], self.chain["digest"])
                    binding_errors = ci.baseline_binding_errors(arguments["candidate"], changed_chain)
                    self.assertIn("which is not in this baseline chain", " ".join(binding_errors))
                result = self.run_production(**arguments)
                self.assertEqual(self.call_specs, [])
                self.assertFalse(result["observations_complete"])
                self.assertTrue(result["errors"])
                if changed_valid_baseline:
                    self.assertIn("which is not in this baseline chain", " ".join(result["errors"]))

    def test_unsupported_contracts_refuse_with_valid_baseline_and_candidate_joins(self) -> None:
        cases = (
            ("EXAMPLE unsupported reliability outcome",
             "an independently predeclared validator contract is required"),
            (preparation.PREFIX + json.dumps({
                "command_id": "EXAMPLE-command-A", "spec_sha256": "0" * 64,
                "stdout_sha256": "0" * 64, "result": "passed"}),
             "unsupported validator contract fields"),
        )
        for outcome, reason in cases:
            with self.subTest(reason=reason):
                self.begin(criterion_updates={"expected_outcome": outcome})
                self.assert_predeclared_refusal("EXAMPLE-alpha", reason)

    def test_duplicate_receipt_and_unsupported_required_kinds_refuse_before_execution(self) -> None:
        self.begin(two=True, duplicate=True)
        result = self.run_production()
        self.assertEqual(self.call_specs, [])
        self.assertIn("mapped more than once", " ".join(result["errors"]))
        for kind in ("artifact", "review-gate"):
            with self.subTest(kind=kind):
                self.begin(extra=[criterion("EXAMPLE-extra", "EXAMPLE required reliability outcome", kind)])
                result = self.assert_predeclared_refusal(
                    "EXAMPLE-extra", "unsupported evidence kind remains UNASSESSABLE")
                self.assertIn("EXAMPLE-extra", result["required_criterion_ids"])

    def test_real_failure_refusal_and_timeout_keep_original_receipts(self) -> None:
        for variant in ("failed", "refused", "timeout"):
            with self.subTest(variant=variant):
                self.begin(variant)
                real_execute = cc.execute_checked_command
                observed = []

                def observe(command):
                    result = real_execute(command)
                    observed.append(copy.deepcopy(result))
                    return result

                with patch.object(cc, "execute_checked_command", side_effect=observe):
                    result = self.run_production()
                self.assertEqual(len(self.call_specs), 1)
                self.assertEqual(result["validator_evidence"][0]["result"], observed[0])
                self.assertFalse(result["observations_complete"])
                self.assertFalse(result["consumer_diagnostic"]["observations_complete"])
                if variant == "refused":
                    self.assertFalse(observed[0]["execution_started"])
                    self.assertEqual(observed[0]["preflight_status"], "failed")
                else:
                    expected = "execution-timeout" if variant == "timeout" else "execution-failed"
                    self.assertEqual(observed[0]["failure_class"], expected)

    def test_output_bearing_timeout_retains_original_receipt_and_real_consumer_evidence(self) -> None:
        self.begin("timeout-output", expected=OUTPUT)
        real_execute = cc.execute_checked_command
        observed = []

        def observe(command):
            receipt = real_execute(command)
            observed.append(copy.deepcopy(receipt))
            return receipt

        with patch.object(cc, "execute_checked_command", side_effect=observe), \
                patch.object(preparation, "prepare", wraps=preparation.prepare) as consumer:
            result = self.run_production()
        consumer.assert_called_once()
        self.assertEqual(len(self.call_specs), 1)
        self.assertEqual(result["checked_command_calls"], 1)
        self.assertEqual(len(observed), 1)
        self.assertEqual(result["required_criterion_ids"], ["EXAMPLE-alpha"])
        self.assertEqual(result["unobserved_criterion_ids"], [])
        self.assertEqual(len(result["validator_evidence"]), 1)
        wrapper = result["validator_evidence"][0]
        receipt = wrapper["result"]
        self.assertEqual(wrapper, {
            "record_type": preparation.EVIDENCE_TYPE, "version": 1, "criterion_id": "EXAMPLE-alpha",
            "baseline_digest": self.chain["digest"], "candidate_digest": ci.candidate_digest(self.candidate),
            "spec": self.commands["EXAMPLE-alpha"], "result": observed[0],
        })
        self.assertEqual(set(receipt), preparation.RESULT_FIELDS)
        self.assertEqual(receipt["failure_class"], "execution-timeout")
        self.assertEqual(receipt["preflight_status"], "passed")
        self.assertEqual(receipt["execution_status"], "failed")
        self.assertIs(receipt["execution_started"], True)
        self.assertIsNone(receipt["exit_code"])
        self.assertEqual(receipt["diagnostics"], {
            "stdout": OUTPUT.decode("utf-8"),
            "stderr": "EXAMPLE timeout reliability diagnostic\n",
        })
        self.assertEqual(receipt["linted_sha256"], sha(wrapper["spec"]["source"].encode("utf-8")))
        self.assertEqual(receipt["executed_sha256"], receipt["linted_sha256"])
        self.assertEqual(receipt["spec_sha256"], spec_hash(cc.normalize_command_spec(wrapper["spec"])))
        self.assertIs(receipt["hash_match"], True)
        self.assertIs(receipt["mutation_started"], False)
        self.assertEqual(receipt["mutated_paths"], [])
        self.assertIs(receipt["quarantine_required"], False)
        self.assertEqual(self.call_specs[0]["timeout_seconds"], 1)
        self.assertEqual(result["state"], "INCOMPLETE")
        self.assertFalse(result["observations_complete"])
        self.assertEqual(result["errors"], [])
        diagnostic = result["consumer_diagnostic"]
        self.assertFalse(diagnostic["observations_complete"])
        self.assertEqual(diagnostic["criteria"][0]["state"], "INCONSISTENT")
        self.assertEqual(consumer.call_args.args[4], result["validator_evidence"])
        self.assertEqual(diagnostic["validator_evidence"], result["validator_evidence"])
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_expected_stdout_is_independent_of_passing_execution(self) -> None:
        self.begin(expected=b"EXAMPLE independently required different bytes\n")
        result = self.run_production()
        self.assertEqual(result["validator_evidence"][0]["result"]["execution_status"], "passed")
        self.assertFalse(result["observations_complete"])
        self.assertFalse(result["consumer_diagnostic"]["observations_complete"])

    def test_additive_chain_executes_in_sorted_criterion_order_and_stale_candidate_refuses(self) -> None:
        self.begin(additive=True)
        result = self.run_production()
        self.assertTrue(result["observations_complete"])
        self.assertEqual([item["command_id"] for item in self.call_specs], ["EXAMPLE-command-A", "EXAMPLE-command-B"])
        stale = copy.deepcopy(self.candidate)
        stale["baseline"] = {"version": 1, "digest": rb.record_digest(self.initial)}
        result = self.run_production(candidate=stale)
        self.assertEqual(self.call_specs, [])
        self.assertFalse(result["observations_complete"])

    def test_candidate_drift_before_execution_has_zero_producer_calls(self) -> None:
        self.begin()
        external_edit(self.repo / "src/item.txt", b"EXAMPLE earlier drift\n")
        result = self.run_production()
        self.assertEqual(self.call_specs, [])
        self.assertFalse(result["observations_complete"])

    def test_interleaved_candidate_drift_stops_second_validator(self) -> None:
        self.begin(two=True)
        real_execute = cc.execute_checked_command
        observed = []

        def drift(command):
            result = real_execute(command)
            observed.append(copy.deepcopy(result))
            external_edit(self.repo / "src/item.txt", b"EXAMPLE interleaved drift\n")
            return result

        with patch.object(cc, "execute_checked_command", side_effect=drift):
            result = self.run_production()
        self.assertEqual(len(self.call_specs), 1)
        self.assertEqual(result["validator_evidence"][0]["result"], observed[0])
        self.assertEqual(result["unobserved_criterion_ids"], ["EXAMPLE-beta"])
        self.assertFalse(result["observations_complete"])
        self.assertFalse(result["consumer_diagnostic"]["observations_complete"])

    def test_exception_stops_execution_and_retains_prior_receipt(self) -> None:
        self.begin(two=True)
        real_execute = cc.execute_checked_command
        observed = []

        def fail_second(command):
            if observed:
                raise RuntimeError("EXAMPLE checked command reliability failure")
            result = real_execute(command)
            observed.append(copy.deepcopy(result))
            return result

        with patch.object(cc, "execute_checked_command", side_effect=fail_second):
            result = self.run_production()
        self.assertEqual(len(self.call_specs), 2)
        self.assertEqual(len(result["validator_evidence"]), 1)
        self.assertEqual(result["validator_evidence"][0]["result"], observed[0])
        self.assertFalse(result["observations_complete"])
        self.assertIn("EXAMPLE checked command reliability failure", " ".join(result["errors"]))

    def test_consumer_callback_drift_invalidates_top_level_completeness(self) -> None:
        self.begin()
        real_consumer = preparation.prepare

        def drift(*args, **kwargs):
            result = real_consumer(*args, **kwargs)
            self.assertTrue(result["observations_complete"])
            external_edit(self.repo / "src/item.txt", b"EXAMPLE consumer callback drift\n")
            return result

        with patch.object(preparation, "prepare", side_effect=drift):
            result = self.run_production()
        self.assertTrue(result["consumer_diagnostic"]["observations_complete"])
        self.assertFalse(result["observations_complete"])
        self.assertTrue(result["errors"])

    def test_later_edits_are_rejected_by_real_consumer(self) -> None:
        self.begin()
        result = self.run_production()
        self.assertTrue(result["observations_complete"])
        external_edit(self.repo / "src/item.txt", b"EXAMPLE later drift\n")
        diagnostic = preparation.prepare(
            str(self.repo), self.initial, self.candidate, self.bead, result["validator_evidence"], self.amendments)
        self.assertFalse(diagnostic["observations_complete"])
        self.assertTrue(diagnostic["candidate_checks"]["before"])

    def test_caller_and_executor_mutations_do_not_replace_private_input(self) -> None:
        self.begin(additive=True)
        saved = copy.deepcopy(self.arguments())
        real_resolve = rb.resolve_chain
        real_execute = cc.execute_checked_command

        def reentrant(*args):
            chain = real_resolve(*args)
            self.initial["criteria"].clear()
            self.candidate["commit"] = "0" * 40
            self.bead["comments"].clear()
            self.commands["EXAMPLE-alpha"]["source"] = "EXAMPLE changed caller input"
            self.amendments.clear()
            return chain

        def mutate_command(command):
            result = real_execute(command)
            command["source"] = "EXAMPLE changed private execution copy"
            return result

        with patch.object(rb, "resolve_chain", side_effect=reentrant), \
                patch.object(cc, "execute_checked_command", side_effect=mutate_command):
            result = self.run_production()
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["validator_evidence"][0]["spec"], saved["commands"]["EXAMPLE-alpha"])
        self.assertEqual(result["bindings"]["candidate_digest"], ci.candidate_digest(saved["candidate"]))

    def test_named_bead_audit_and_closure_boundaries_are_unused(self) -> None:
        self.begin()
        targets = (
            (beads, "run_bd"), (beads, "run_bd_structured"), (closure, "run_bd"),
            (closure, "execute"), (stage_completion, "consume"),
        )
        with contextlib.ExitStack() as stack:
            watched = [stack.enter_context(patch.object(
                module, name, side_effect=AssertionError("EXAMPLE forbidden reliability effect")))
                for module, name in targets]
            result = self.run_production()
            self.assertTrue(result["observations_complete"])
            for boundary in watched:
                boundary.assert_not_called()
        self.assertFalse((self.repo / ".beads").exists())
        self.assertFalse((self.repo / ".orchestration-audit").exists())


if __name__ == "__main__":
    unittest.main()
