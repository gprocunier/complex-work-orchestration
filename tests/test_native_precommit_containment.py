from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt  # noqa: E402
from cwo_core.native_containment import (  # noqa: E402
    CONTAINMENT_ERROR,
    containment_error,
    native_operative_containment,
)
from cwo_core.proportional_execution import evaluate_proportional_execution  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.work_sizing import normalize_worker_commitment_response  # noqa: E402
from prepare_native_worker import (  # noqa: E402
    build_native_worker_packet,
    validate_native_worker_packet,
)
from scaffold_workgraph import planned_graph  # noqa: E402


def _draft(workdir: str) -> dict:
    return build_native_worker_packet(
        bead_id="containment-test",
        lane="implementation",
        workdir=workdir,
        allowed_paths=["tests"],
        acceptance_checks=["focused tests pass"],
    )


class NativePrecommitContainmentTests(unittest.TestCase):
    def test_policy_state_is_strict_and_requires_packet_bound_evidence(self) -> None:
        state = native_operative_containment()
        self.assertEqual(state["status"], "operative-authorized")
        self.assertTrue(state["canary_authorized"])
        self.assertTrue(state["dispatch_authorized"])
        self.assertTrue(state["evidence_required"])
        self.assertEqual(state["reason"], "fsh.3-operative-release-gate")
        self.assertEqual(state["release_requires"], "complex-work-orchestration-fsh.3.5")
        self.assertEqual(state["maximum_release_state"], "operative-authorized")
        self.assertIn("supervised-worker-fit-request", state["allowed_non_operative_operations"])
        self.assertIn("receipt-bound-candidate-packet-build", state["allowed_non_operative_operations"])
        self.assertIn(CONTAINMENT_ERROR, containment_error("native-dispatch"))

        policy = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
        malformed_cases = []
        missing = json.loads(json.dumps(policy))
        missing.pop("precommit_containment")
        malformed_cases.append(missing)
        disabled = json.loads(json.dumps(policy))
        disabled["precommit_containment"]["active"] = False
        malformed_cases.append(disabled)
        unknown = json.loads(json.dumps(policy))
        unknown["precommit_containment"]["unknown"] = True
        malformed_cases.append(unknown)
        for malformed in malformed_cases:
            with self.assertRaisesRegex(ValueError, "malformed policy"):
                native_operative_containment(malformed)

    def test_route_coach_and_scaffold_offer_native_lanes_after_release(self) -> None:
        prompt = "Use Sol as architect and Spark for implementation, tests, validation, docs, and reporting."
        route = classify_work(prompt)
        self.assertTrue(route["native_operative_dispatch"]["dispatch_authorized"])
        self.assertTrue(route["native_operative_dispatch"]["evidence_required"])
        coached = coach_orchestration_prompt(prompt)
        planned = coached["workerbee_planned_delegation"]
        self.assertEqual(planned["mode"], "review-only")
        self.assertEqual(planned["model"], "gpt-5.3-codex-spark")
        self.assertTrue(planned["lanes"])
        self.assertFalse(planned["hard_stop"])
        self.assertEqual(planned["hard_stop_reason"], "")
        self.assertEqual(planned["spark_dispatch"]["status"], "native-first")
        self.assertEqual(planned["spark_dispatch"]["failed_native_capability_check"], "")
        self.assertNotIn("native_precommit_containment", coached["route"]["hard_stops"])
        self.assertFalse(any("contained until fsh.3" in warning for warning in coached["warnings"]))
        graph = planned_graph("contained graph", coached["route"], "tight")
        self.assertTrue(graph)
        root_items = [item for item in graph if item.get("lane") is None]
        self.assertEqual(len(root_items), 1)
        for item in graph:
            metadata = item.get("metadata", {})
            if item.get("lane") is None:
                continue
            self.assertIn("workerbee_planned_mode", metadata)
            self.assertNotEqual(metadata.get("workerbee_planned_mode"), "blocked")
            self.assertEqual(metadata.get("workerbee_planned_model"), "gpt-5.3-codex-spark")
            self.assertEqual(metadata.get("workerbee_planned_lanes"), planned["lanes"])

    def test_planned_build_and_dispatchable_validation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            with self.assertRaisesRegex(SystemExit, "trusted precommit receipt"):
                build_native_worker_packet(
                    bead_id="containment-test",
                    lane="implementation",
                    workdir=workdir,
                    allowed_paths=["."],
                    acceptance_checks=["focused tests pass"],
                    work_plan={"route": "spark"},
                )
            packet = _draft(workdir)
            self.assertEqual(validate_native_worker_packet(packet), [])
            self.assertTrue(
                any(
                    CONTAINMENT_ERROR in error
                    for error in validate_native_worker_packet(packet, dispatchable=True)
                )
            )
            latent_errors = validate_native_worker_packet(packet, dispatchable=True)
            self.assertIn(
                "dispatchable packet requires work_plan and worker_commitment",
                latent_errors,
            )

    def test_commitment_normalization_does_not_assert_zero_activity(self) -> None:
        result = normalize_worker_commitment_response(
            {"decision": "accept", "estimates": {}},
            {},
            session_id="spark-session",
            attested_model="gpt-5.3-codex-spark",
        )
        self.assertEqual(result["outcome"], "pm-realignment")
        self.assertIsNone(result["normalized_commitment"])
        self.assertTrue(any(CONTAINMENT_ERROR in error for error in result["errors"]))
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("tool_calls_before_commitment", rendered)
        self.assertNotIn("context_compactions_before_commitment", rendered)

    def test_proportional_fast_path_cannot_become_dispatchable(self) -> None:
        result = evaluate_proportional_execution({})
        self.assertFalse(result["selected"])
        self.assertFalse(result["dispatchable"])
        self.assertFalse(result["dispatch_required"])
        self.assertTrue(any(CONTAINMENT_ERROR in reason for reason in result["reasons"]))

    def test_real_cli_render_and_supervisor_authority_paths_emit_no_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as workdir:
            packet_path = Path(workdir) / "packet.json"
            packet_path.write_text(json.dumps(_draft(workdir)), encoding="utf-8")
            rendered = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "prepare_native_worker.py"), "render", str(packet_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rendered.returncode, 0)
            self.assertEqual(rendered.stdout, "")
            self.assertIn(CONTAINMENT_ERROR, rendered.stderr)
            self.assertNotIn(str(ROOT), rendered.stderr)

            state_path = Path(workdir) / "state.json"
            commands = (
                ["start", "--packet", str(packet_path), "--session-id", "s", "--session-file", "missing", "--agent-id", "a"],
                ["arm", "--state-file", str(state_path), "--control-turn-id", "c"],
                ["mark-dispatched", "--state-file", str(state_path), "--control-turn-id", "c", "--submission-id", "s"],
                [
                    "authorize-retry",
                    "--state-file", str(state_path),
                    "--control-turn-id", "c",
                    "--retry-packet", "missing",
                    "--fresh-attestation", "missing",
                    "--workspace-report", "missing",
                    "--semantic-result", "missing",
                ],
            )
            for command in commands:
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "supervise_native_worker.py"), *command],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, command[0])
                self.assertIn(CONTAINMENT_ERROR, result.stderr, command[0])
                self.assertFalse(state_path.exists(), command[0])


if __name__ == "__main__":
    unittest.main()
