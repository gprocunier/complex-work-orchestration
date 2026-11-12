"""The GLM-primary worker binding follows the general deprecated-model path.

Operator decision 2026-10-22: Spark is deprecated, and the connected-codex-glm-primary
worker binding (gpt-5.3-codex-spark) gets exactly the outcome the general path gives any
model the active task_selected_routing v3 marks historical-nonoperative. No special case,
no substitute model, no new authority. These tests drive real entry points
(``render_harness_dispatch.main``, ``route_work.main``, ``coach_prompt``) with spies on
their effect boundaries:

- the harness render: ``record_audit_event`` in ``render_harness_dispatch`` (and, as a
  guard, in ``cwo_core.audit``), the audit file, and the envelope on stdout;
- the route: the operative route printed by ``route_work`` (it has no other effect).

Each refusal is paired with a positive control through the same entry point (the
connected-codex Luna worker, the GLM-primary architect and project manager) that reaches
the caller's audit spy and writes one audit event, so a zero count there means the render
was stopped, not that the spy was unwired. The ``cwo_core.audit`` spy is a guard only: the
CLI imports ``record_audit_event`` by name, so no positive control reaches it.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import render_harness_dispatch  # noqa: E402
import route_work  # noqa: E402
from cwo_core import audit, harness, operative_routing, policy  # noqa: E402
from cwo_core.coach import coach_orchestration_prompt  # noqa: E402

from tests.historical_policy_fixtures import historical_v2_policy  # noqa: E402

GLM = "connected-codex-glm-primary"
CONNECTED = "connected-codex"
SPARK = "gpt-5.3-codex-spark"
LUNA = "gpt-5.6-luna"
CURRENT_MODELS = ("gpt-5.6-luna", "gpt-5.6-terra", "gpt-6.1-sol")
GENERAL_OUTCOME = (
    f"model {SPARK!r} is historical-nonoperative under task_selected_routing v3: historical records stay "
    "readable, but it is nonoperative for v3 and has no new dispatch authority; no other model is substituted"
)
# The two digests v2 and v3 route records bind for each environment, recorded on fa6f604.
BASE_DIGESTS = {
    CONNECTED: ("c3e1db87e8ddf2417f30ca68065c416091f4accdd8d839d97b943e081ecf7f22",
                "26257b1b997ada4a9583c0ed7cd09c99ecff4923aff84d2486ab0587c6e9902a"),
    GLM: ("c3e1db87e8ddf2417f30ca68065c416091f4accdd8d839d97b943e081ecf7f22",
          "26257b1b997ada4a9583c0ed7cd09c99ecff4923aff84d2486ab0587c6e9902a"),
}


@contextlib.contextmanager
def isolated_audit() -> Iterator[Path]:
    """A fresh audit file for the shipped policy; nothing is written into the source tree."""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy.clear_policy_cache()
        try:
            with mock.patch.object(audit, "AUDIT_LOG", Path(tmpdir) / "audit" / "audit.jsonl"):
                yield Path(tmpdir) / "audit" / "audit.jsonl"
        finally:
            policy.clear_policy_cache()


def run_render(argv: list[str]) -> tuple[dict[str, int], str, BaseException | None, int]:
    """Run render_harness_dispatch.main; return spy counts, stdout, any exit, and the audit events written."""
    with isolated_audit() as audit_file, mock.patch.object(sys, "argv", ["render_harness_dispatch.py", *argv]):
        stdout = io.StringIO()
        raised: BaseException | None = None
        with mock.patch.object(render_harness_dispatch, "record_audit_event",
                               wraps=render_harness_dispatch.record_audit_event) as caller_spy, \
                mock.patch.object(audit, "record_audit_event", wraps=audit.record_audit_event) as core_spy, \
                contextlib.redirect_stdout(stdout):
            try:
                render_harness_dispatch.main()
            except SystemExit as exc:
                raised = exc
        # render_harness_dispatch imports record_audit_event by name, so a render reaches the caller
        # spy and the audit file; the cwo_core.audit spy is an additional guard that a render never hits.
        counts = {"render_harness_dispatch.record_audit_event": caller_spy.call_count,
                  "cwo_core.audit.record_audit_event (guard)": core_spy.call_count}
        events = len(audit_file.read_text(encoding="utf-8").splitlines()) if audit_file.exists() else 0
        return counts, stdout.getvalue(), raised, events


def run_route(environment: str) -> dict[str, Any]:
    argv = ["route_work.py", "Implement the bounded operative packet for the parser module.",
            "--execution-environment", environment, "--json"]
    stdout = io.StringIO()
    with isolated_audit(), mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
        route_work.main()
    return json.loads(stdout.getvalue())


class GeneralNonoperativeOutcomeTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_general_rule_marks_only_the_policy_s_nonoperative_model(self) -> None:
        self.assertEqual(operative_routing.nonoperative_model_refusal(SPARK), GENERAL_OUTCOME)
        for respelled in ("GPT-5.3-Codex-Spark", f" {SPARK}\n"):
            with self.subTest(model=respelled):
                refusal = operative_routing.nonoperative_model_refusal(respelled)
                self.assertEqual(refusal, GENERAL_OUTCOME.replace(repr(SPARK), repr(respelled)))
        for model in (*CURRENT_MODELS, "gpt-5.5", "gpt-5.3-codex", "glm-5.2-bf16-128k", "", "  ", None, 7):
            with self.subTest(model=model):
                self.assertIsNone(operative_routing.nonoperative_model_refusal(model))

    def test_general_rule_follows_the_v3_policy_activation(self) -> None:
        # The inactive (historical) policy gives the historical v2 behavior: no v3 refusal.
        with historical_v2_policy():
            self.assertIsNone(operative_routing.nonoperative_model_refusal(SPARK))
        native = json.loads((ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8"))
        native["task_selected_routing"]["operative_roles"][SPARK] = "spark-worker"
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir) / "policy"
            shutil.copytree(ROOT / "policy", policy_dir)
            (policy_dir / "native-worker-execution.yaml").write_text(json.dumps(native), encoding="utf-8")
            policy.clear_policy_cache()
            with mock.patch.object(policy, "POLICY_DIR", policy_dir):
                with self.assertRaisesRegex(ValueError, "operative roles"):
                    operative_routing.nonoperative_model_refusal(SPARK)
                with self.assertRaisesRegex(SystemExit, "cannot check the task selected routing policy"):
                    harness.build_harness_dispatch(task="t", dispatch_id="d", environment_key=GLM, role="worker")


class HarnessRenderTests(unittest.TestCase):
    """render_harness_dispatch is the consumer that reads the binding's model directly."""

    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def assert_general_refusal_without_effects(self, argv: list[str]) -> str:
        counts, stdout, raised, events = run_render(argv)
        self.assertIsNotNone(raised, f"render was accepted: {stdout[:200]!r}")
        message = str(raised)
        self.assertEqual(message, f"harness dispatch refused: {GENERAL_OUTCOME}")
        for model in CURRENT_MODELS:
            self.assertNotIn(model, message)
        self.assertEqual(counts, {label: 0 for label in counts})
        self.assertEqual(stdout, "")
        self.assertEqual(events, 0)
        return message

    def test_glm_primary_worker_binding_gets_the_general_refusal_with_zero_effects(self) -> None:
        self.assert_general_refusal_without_effects(["--environment", GLM, "--role", "worker", "Implement it."])
        self.assert_general_refusal_without_effects(["--environment", GLM, "--role", "worker", "--json", "Implement it."])

    def test_the_outcome_is_the_same_for_any_route_to_the_deprecated_model(self) -> None:
        # Not a GLM-primary special case: the same model reached by an explicit argument in the default
        # environment, or for another role, gets the identical refusal.
        messages = {
            self.assert_general_refusal_without_effects(argv)
            for argv in (
                ["--environment", GLM, "--role", "worker", "Implement it."],
                ["--environment", GLM, "--role", "worker", "--model", SPARK, "Implement it."],
                ["--environment", CONNECTED, "--role", "worker", "--model", SPARK, "Implement it."],
                ["--environment", CONNECTED, "--role", "architect", "--model", SPARK, "Review it."],
            )
        }
        self.assertEqual(len(messages), 1)
        with self.assertRaises(SystemExit) as raised:
            harness.build_harness_dispatch(task="Implement it.", dispatch_id="d-glm", environment_key=GLM, role="worker")
        self.assertEqual(str(raised.exception), messages.pop())

    def test_positive_controls_reach_the_audit_spies(self) -> None:
        for argv, model in (
            (["--environment", CONNECTED, "--role", "worker", "--json", "Implement it."], LUNA),
            (["--environment", GLM, "--role", "architect", "--json", "Review it."], "glm-5.2-bf16-128k"),
            (["--environment", GLM, "--role", "project_manager", "--json", "Coordinate it."], None),
        ):
            with self.subTest(argv=argv):
                counts, stdout, raised, events = run_render(argv)
                self.assertIsNone(raised)
                self.assertEqual(counts["render_harness_dispatch.record_audit_event"], 1)
                self.assertEqual(events, 1)
                self.assertEqual(json.loads(stdout)["model"], model)

    def test_an_exact_current_model_request_stays_exact(self) -> None:
        # The deprecated binding does not change what an explicit current model request gets.
        counts, stdout, raised, _ = run_render(
            ["--environment", GLM, "--role", "worker", "--model", LUNA, "--json", "Implement it."])
        self.assertIsNone(raised)
        self.assertEqual(json.loads(stdout)["model"], LUNA)
        self.assertEqual(counts["render_harness_dispatch.record_audit_event"], 1)

    def test_the_historical_policy_keeps_the_historical_render(self) -> None:
        with historical_v2_policy():
            envelope = harness.build_harness_dispatch(
                task="Implement it.", dispatch_id="d-historical", environment_key=GLM, role="worker")
        self.assertEqual(envelope["model"], SPARK)


class RouteAndCoachTests(unittest.TestCase):
    """Operative selection never reads the binding: both environments get the same v3 outcome."""

    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_route_work_gives_the_glm_primary_environment_the_general_v3_route(self) -> None:
        routes = {environment: run_route(environment) for environment in (CONNECTED, GLM)}
        operative = {environment: route["operative_route"] for environment, route in routes.items()}
        for environment, value in operative.items():
            with self.subTest(environment=environment):
                self.assertEqual(value["version"], 3)
                self.assertIsNone(value["selected_model"])
                self.assertFalse(value["dispatch_authorized"])
                self.assertTrue(value["protected_stop"])
                self.assertEqual(value["stop_reason"], "current-authority-missing")
                self.assertNotIn(SPARK, json.dumps(value))

        def comparable(value: dict[str, Any]) -> dict[str, Any]:
            return {key: item for key, item in value.items()
                    if key not in {"execution_environment", "evaluated_at", "route_sha256"}}

        self.assertEqual(comparable(operative[CONNECTED]), comparable(operative[GLM]))

    def test_route_summary_keeps_the_binding_inspectable_and_marks_it_nonoperative(self) -> None:
        glm = run_route(GLM)["execution_environment_profile"]["role_bindings"]
        self.assertEqual(glm["worker"]["model"], SPARK)
        self.assertEqual(glm["worker"]["model_status"], "historical-nonoperative")
        self.assertNotIn("model_status", glm["architect"])
        connected = run_route(CONNECTED)["execution_environment_profile"]["role_bindings"]
        self.assertEqual(connected["worker"]["model"], LUNA)
        for binding in connected.values():
            self.assertNotIn("model_status", binding)

    def test_route_and_bound_authority_naming_the_deprecated_model_cannot_authorize(self) -> None:
        for environment in (CONNECTED, GLM):
            with self.subTest(environment=environment):
                route = operative_routing.resolve_operative_route(
                    execution_environment=environment, current_authority={"bound_model": SPARK},
                    evaluated_at="2026-10-22T00:00:00Z")
                self.assertFalse(route["dispatch_authorized"])
                self.assertIsNone(route["selected_model"])
                self.assertEqual(route["stop_reason"], "current-authority-invalid")
                self.assertEqual(
                    operative_routing.validate_operative_route_for_model(route, SPARK),
                    ["task selected route requires current authority"])

    def test_coach_never_recommends_the_deprecated_model_in_either_environment(self) -> None:
        # The two environments route this text differently (GLM-primary implies a local architect),
        # so their workerbee advice differs; neither names the deprecated model or authorizes dispatch.
        text = "Implement the parser change with workerbees and validate it."
        for environment in (CONNECTED, GLM):
            with self.subTest(environment=environment):
                result = coach_orchestration_prompt(text, execution_environment=environment)
                parallelism = result["workerbee_parallelism"]
                self.assertIsNone(parallelism["recommended_model"])
                self.assertNotEqual(parallelism["spark_dispatch"]["requested_model"], SPARK)
                operative = result["route"]["operative_route"]
                self.assertEqual((operative["version"], operative["selected_model"], operative["dispatch_authorized"]),
                                 (3, None, False))
                self.assertNotIn(SPARK, json.dumps(operative))


class HistoricalIdentityTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_bound_digests_are_unchanged_for_both_environments(self) -> None:
        for environment, (v2, v3) in BASE_DIGESTS.items():
            with self.subTest(environment=environment):
                self.assertEqual(operative_routing.operative_policy_sha256(environment), v2)
                self.assertEqual(operative_routing.task_selected_policy_sha256(environment), v3)

    def test_the_recorded_binding_is_unchanged(self) -> None:
        environments = json.loads((ROOT / "policy" / "execution-environments.yaml").read_text(encoding="utf-8"))
        glm = environments["profiles"][GLM]
        self.assertEqual(glm["role_bindings"]["worker"],
                         {"harness": "codex_cli", "executor": "internal_worker", "model": SPARK, "variant": "spark"})
        self.assertEqual(glm["operative_routing"]["primary_model"], SPARK)


if __name__ == "__main__":
    unittest.main()
