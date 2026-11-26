"""Offline witnesses for the configured Codex effort selection."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cwo_core import host_records
from cwo_core.policy import load_policy
from cwo_core.routing import classify_work
from dispatch_work import main as dispatch_main, record_route_preparation


class ReasoningEffortRoutingTests(unittest.TestCase):
    def test_default_and_narrow_architecture_keep_default_effort(self):
        for task in ("Change the color of the team badge.", "Sketch an architecture for one local module.",
                     "Fix a typo in docs. No network or approvals are needed.",
                     "Fix a typo in docs. Do not change network access.",
                     "Update the network diagram caption to fix a typo."):
            with self.subTest(task=task):
                self.assertEqual(classify_work(task)["codex_reasoning"]["worker"],
                                 {"reasoning_effort": "high", "reasoning_effort_reason": "default"})

    def test_security_and_containment_use_escalation(self):
        tasks = [f"Review the {scope} controls for the worker."
                 for scope in ("sandbox", "network", "credential", "approval", "containment")]
        tasks.extend(("Update the container isolation policy for worker processes.",
                      "Patch SQL injection in the query builder.",
                      "Fix a cross-site scripting vulnerability in the dashboard."))
        for task in tasks:
            with self.subTest(task=task):
                route = classify_work(task)
                self.assertEqual(route["codex_reasoning"]["worker"],
                                 {"reasoning_effort": "xhigh", "reasoning_effort_reason": "security-or-containment"})
                self.assertEqual(route["codex_reasoning"]["lead"]["reasoning_effort"], "high")

    def test_high_risk_review_and_adjudication_use_escalation(self):
        route = classify_work("Delete the production cache.")
        for role in ("reviewer", "adjudicator"):
            with self.subTest(role=role):
                self.assertEqual(route["codex_reasoning"][role],
                                 {"reasoning_effort": "xhigh", "reasoning_effort_reason": "high-risk-review"})
        self.assertEqual(route["codex_reasoning"]["worker"]["reasoning_effort"], "high")
        self.assertEqual(route["codex_reasoning"]["lead"]["reasoning_effort"], "high")

    def test_wide_architecture_and_planning_escalate(self):
        for task in ("Design a cross-cutting architecture for persistent state.", "Plan a cross-cutting migration."):
            with self.subTest(task=task):
                route = classify_work(task)
                self.assertEqual(route["codex_reasoning"]["worker"],
                                 {"reasoning_effort": "xhigh", "reasoning_effort_reason": "wide-architecture-or-planning"})
                self.assertEqual(route["codex_reasoning"]["lead"]["reasoning_effort"], "high")
        self.assertEqual(classify_work("Fix the cross-cutting helper.")["codex_reasoning"]["worker"]["reasoning_effort"],
                         "high")

    def test_configured_counter_review_carries_the_codex_launch_settings(self):
        from cwo_core.model_identities import resolve_model

        route = classify_work("Use Codex counter-review on the cross-cutting architecture migration with production rollback.",
                              execution_environment="connected-codex-glm-primary", model_synthesis=True)
        critic = next(item for item in route["critic_route"]["contracts"]
                      if item["executor"] == "codex_architecture_critic")
        self.assertEqual(critic["reasoning_effort"], "xhigh")
        self.assertEqual(critic["reasoning_effort_reason"], "high-risk-review")
        self.assertEqual(critic["codex_effort_arguments"], ["-c", 'model_reasoning_effort="xhigh"'])
        panel = next(item for item in route["model_synthesis"]["recommended_panel"]
                     if item["executor"] == "codex_architecture_critic")
        self.assertEqual(panel["effort"], resolve_model("astra"))
        self.assertEqual(panel["reasoning_effort"], critic["reasoning_effort"])
        self.assertEqual(route["codex_reasoning"]["lead"]["reasoning_effort"], "high")

    def test_preparation_records_selected_effort_without_claiming_observation(self):
        task = "Change the color of the team badge."
        with TemporaryDirectory() as directory:
            store = host_records.HostRecordStore.for_tests(Path(directory) / "state")
            args = SimpleNamespace(audit=True, bead="test-bead")
            with patch("dispatch_work.configured_store", return_value=store):
                record_route_preparation(args, classify_work(task), task, "prepared", None, None)
            record = store.require_dispatch("prepared")
            self.assertEqual(record["evaluation_metadata"]["codex_reasoning"],
                             {"reasoning_effort": "high", "reasoning_effort_reason": "default"})
            self.assertIsNone(record["reasoning_effort"])

    def test_failed_default_delivery_requires_bound_evidence(self):
        from cwo_core.reasoning_effort import failed_default_delivery

        task = b"Change the color of the team badge."
        request_digest = hashlib.sha256(task).hexdigest()
        result_digest = hashlib.sha256(b"original return").hexdigest()
        with TemporaryDirectory() as directory:
            store = host_records.HostRecordStore.for_tests(Path(directory) / "state")
            prepared = store.write_dispatch(dispatch_id="first", dispatch_role="executor",
                provider="openai", model_family=None, model_id=None, reasoning_effort=None, session_id=None,
                request_sha256=request_digest, bead_id="work",
                evaluation_metadata={"dispatch_mode": "codex_worker",
                    "codex_reasoning": {"reasoning_effort": "high", "reasoning_effort_reason": "default"}})
            observed = store.write_observed_dispatch("first", prepared_record_sha256=prepared,
                observation_sha256="a" * 64, provider="openai", model_family="gpt", model_id="gpt-6-luna",
                reasoning_effort="high", session_id="original")
            receipt = store.write_return_received("first", result_digest, capture_provenance="host-capture-v1")
            evidence = {"dispatch_id": "first", "bead_id": "work", "dispatch_record_sha256": observed,
                        "return_sha256": result_digest, "return_record_sha256": receipt}
            self.assertIsNone(failed_default_delivery(store, "first", "work", request_digest))
            rejected = {"verdict": "reject", "recommended_disposition": "reject",
                        "screening_eligible": True, "implementation_blocked": False}
            store.write_record("evaluation", **evidence, evaluation={**rejected, "implementation_blocked": True})
            self.assertIsNone(failed_default_delivery(store, "first", "work", request_digest))
            store.write_record("evaluation", **evidence, evaluation=rejected)
            failure = failed_default_delivery(store, "first", "work", request_digest)
            self.assertIsNotNone(failure)
            route = classify_work(task.decode(), failed_delivery=failure)
            self.assertEqual(route["codex_reasoning"]["worker"]["reasoning_effort"], "xhigh")
            self.assertEqual(route["codex_reasoning"]["worker"]["reasoning_effort_reason"],
                             "delivery-failed-at-default-effort")
            self.assertIsNone(failed_default_delivery(store, "first", "different-work", request_digest))
            self.assertIsNone(failed_default_delivery(store, "first", "work", result_digest))
            output = StringIO()
            command = ["dispatch_work.py", "--bead", "work", "--retry-dispatch", "first",
                       "--dispatch-id", "second", "--json", task.decode()]
            with host_records.using_test_store(store), patch.object(sys, "argv", command), redirect_stdout(output):
                dispatch_main()
            prepared = json.loads(output.getvalue())
            self.assertEqual(prepared["codex_effort_arguments"], ["-c", 'model_reasoning_effort="xhigh"'])
            record = store.require_dispatch("second")["evaluation_metadata"]
            self.assertEqual(record["codex_reasoning"]["reasoning_effort_reason"], "delivery-failed-at-default-effort")
            self.assertEqual(record["codex_retry_evidence"]["dispatch_record_sha256"], observed)

    def test_configured_values_drive_worker_command_configuration(self):
        import tomllib
        from registered_delegation_preparation import _configuration
        from cwo_core.reasoning_effort import reasoning_effort_selection

        policy = load_policy("model-roles")
        self.assertEqual(policy["roles"]["sol"]["reasoning_effort"], "high")
        self.assertEqual(policy["roles"]["sol"]["escalation_reasoning_effort"], "xhigh")
        policy["roles"]["sol"].update(reasoning_effort="medium", escalation_reasoning_effort="high")
        with patch("cwo_core.reasoning_effort.load_policy", return_value=policy):
            for role, scope, effort in (("worker", False, "medium"), ("worker", True, "high"),
                                        ("lead", True, "medium")):
                with self.subTest(role=role, scope=scope):
                    selected = reasoning_effort_selection(role, security_scope=scope)
                    config = _configuration(Path("/test/worker"), "gpt-6-luna", selected["reasoning_effort"])
                    self.assertEqual(tomllib.loads(config["config.toml"])["model_reasoning_effort"], effort)


if __name__ == "__main__":
    unittest.main()
