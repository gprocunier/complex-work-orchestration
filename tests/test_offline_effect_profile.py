"""EXAMPLE effects through the actual admitted host and original bound adapter."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_effect_profile as effects  # noqa: E402
import test_offline_admitted_n1 as admitted  # noqa: E402


def binding(case):
    return {
        "candidate": case.host._initial,
        "context": case.adapter._effective_boundary,
        "factory": json.loads(case.receipt.execution_bytes),
        "limits": {"allowance": json.loads(case.receipt.amounts_bytes),
                   "aggregate": json.loads(case.receipt.limits_bytes)},
        "request_sha256": admitted.admission.request_sha256(case.receipt.request_bytes),
        "scope_sha256": case.receipt.scope_sha256,
        "configuration_pins": case.pins, "control_contract": case.control, "max_steps": 128,
    }


class EffectServer(admitted.AdmittedFakeServer):
    """Original fake transport; useful output comes only from the effect runner."""

    def record_completed_write(self):
        self.runner.check_binding(self.current_binding())
        useful = self.runner.request(effects.COMMAND)
        if useful["status"] != "completed":
            raise RuntimeError("EXAMPLE useful command failed")
        self.record_tool(effects.COMMAND, useful, "EXAMPLE-useful")
        for command in self.followups:
            self.runner.check_binding(self.current_binding())
            result = self.runner.request(command)
            self.record_tool(command, result, "EXAMPLE-effect-" + str(result["sequence"]))

    def record_tool(self, command, result, call_id):
        code = 0 if result["status"] == "completed" else 1
        output = result["output"] or result["error"]
        formatted = ("Chunk ID: EXAMPLE_EFFECT\nWall time: 0.001 seconds\n"
                     f"Process exited with code {code}\nFinal output:\n{output}")
        event = {"turn_id": self.turn_id, "call_id": call_id,
                 "command": [command], "cwd": str(self.root), "source": "agent"}
        self.append_fake_record("response_item", {
            "type": "function_call", "name": "exec_command", "call_id": call_id,
            "arguments": json.dumps({"cmd": command, "workdir": str(self.root)}),
        })
        self.append_fake_record("event_msg", {"type": "exec_command_begin", **event})
        self.append_fake_record("event_msg", {
            "type": "exec_command_end", **event, "exit_code": code,
            "stdout": output, "stderr": "", "aggregated_output": output,
            "formatted_output": formatted, "status": "completed",
            "duration": {"secs": 0, "nanos": 1_000_000},
        })
        self.append_fake_record("response_item", {
            "type": "function_call_output", "call_id": call_id, "output": formatted,
        })

    def complete_turn(self):
        super().complete_turn()
        # Thread observation describes the actual productive call, not the old
        # CompletingFakeServer producer stub's command or acknowledgement.
        self.items[0].update(id="EXAMPLE-useful", command=effects.COMMAND,
                             aggregatedOutput=effects.ACK)


class OfflineEffectProfileTests(unittest.TestCase):
    def setUp(self):
        self.repositories = admitted.RepositoryFixture(self)

    def case(self, followups=()):
        # Compose the existing fixture constructor without inheriting its tests.
        harness = admitted.OfflineAdmittedN1Tests()
        harness.repositories = self.repositories
        # Select only the fixture server before construction; original host and
        # LiveThreadAdapter objects and their bound methods remain untouched.
        with patch.object(admitted, "AdmittedFakeServer", EffectServer):
            case = harness.case()
        server = case.server
        runner = effects.ExampleEffectRunner(case.host.worker, binding=binding(case))
        server.runner, server.current_binding = runner, lambda: binding(case)
        server.followups = followups
        return SimpleNamespace(case=case, runner=runner, harness=harness)

    def run_case(self, fixture):
        return fixture.harness.run_case(fixture.case)

    def test_same_runner_useful_output_then_forbidden_effects_failure_and_escalation(self):
        commands = (*effects.PROFILE["denied"], "EXAMPLE_ORDINARY_FAILURE",
                    "EXAMPLE_EXPLICIT_ESCALATION", "EXAMPLE_UNKNOWN")
        fixture = self.case(commands)
        case, runner = fixture.case, fixture.runner
        self.assertFalse((case.host.worker / "result.txt").exists())
        result = self.run_case(fixture)
        observed = runner.observations()
        records = observed["requests"]
        self.assertEqual([item["command"] for item in records], [effects.COMMAND, *commands])
        self.assertEqual([item["status"] for item in records],
                         ["completed", "denied", "denied", "denied", "denied",
                          "failed", "escalation-required", "unknown"])
        self.assertEqual(observed["effect_calls"], {
            effects.COMMAND: 1, "EXAMPLE_WRITE": 0, "EXAMPLE_NETWORK": 0,
            "EXAMPLE_PROCESS": 0, "EXAMPLE_READ": 0, "EXAMPLE_ORDINARY_FAILURE": 1,
        })
        self.assertEqual(observed["profile"], effects.PROFILE)
        runner.check_binding(binding(case))
        self.assertEqual(observed["binding"], json.loads(json.dumps(binding(case))))
        for item in records:
            self.assertFalse(item["ordinary_retry"] or item["fallback"] or item["unsandboxed"])
        self.assertEqual(case.server.sends, 1)
        self.assertTrue(result["offline_completed"])
        self.assertTrue(result["artifact_verification"]["valid"])
        self.assertEqual((case.host.worker / "result.txt").read_bytes(), effects.OUTPUT)
        self.assertEqual((case.host.state / "artifact/file-0000").read_bytes(), effects.OUTPUT)
        self.assertEqual(result["native_report"]["summary"]["completed_tool_calls"], 8)
        self.assertEqual(result["declared_execution"], observed["binding"]["factory"])
        self.assertEqual(result["declared_allowance"], observed["binding"]["limits"]["allowance"])
        self.assertEqual(result["attempt"]["charge"], result["declared_allowance"])
        self.assertIsNone(result["attempt"]["observed_usage"])
        self.assertEqual(result["native_report"]["binding"]["configuration_pins"], case.pins)
        for value in (result, observed):
            for name in effects.FALSE_FIELDS:
                self.assertIs(value[name], False)
        for value in (result["native_report"], result["artifact_verification"]):
            for name in admitted.native._FLAGS_FALSE:
                self.assertIs(value[name], False)
        self.assertIsNone(observed["effective_backend_metadata"])
        self.assertFalse(observed["actual_confinement_qualified"])
        # Actual session records retain every refusal and distinct failure class.
        raw = case.server.path.read_text()
        for item in records:
            self.assertIn(item["command"], raw)

    def test_ordinary_failure_before_output_keeps_original_host_unknown_without_retry(self):
        fixture = self.case()
        worker = fixture.case.host.worker
        (worker / "result.txt").write_bytes(b"EXAMPLE preexisting output\n")
        with self.assertRaises(admitted.client.OfflineAdmittedN1Error) as caught:
            self.run_case(fixture)
        self.assertEqual(fixture.case.server.sends, 1)
        self.assertEqual(fixture.runner.observations()["effect_calls"][effects.COMMAND], 1)
        self.assertEqual(fixture.runner.observations()["requests"][0]["status"], "failed")
        self.assertEqual(caught.exception.native_report["status"], "reconciliation-required")
        self.assertEqual(fixture.harness.attempt(fixture.case)["outcome"], "unknown")
        self.assertFalse((fixture.case.host.state / "artifact").exists())

    def test_unknown_binding_drift_and_request_bound_refuse_without_substitution(self):
        fixture = self.case()
        runner = fixture.runner
        for key in effects.BINDING_KEYS:
            changed = copy.deepcopy(binding(fixture.case))
            changed[key] = "EXAMPLE_CHANGED"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "binding changed"):
                runner.check_binding(changed)
        for _ in range(effects.PROFILE["max_requests"]):
            self.assertEqual(runner.request({"EXAMPLE": "untrusted"})["status"], "unknown")
        with self.assertRaisesRegex(ValueError, "bound exhausted"):
            runner.request(effects.COMMAND)
        self.assertEqual(sum(runner.observations()["effect_calls"].values()), 0)
        self.assertEqual(fixture.case.server.sends, 0)
        self.assertEqual(len(runner.observations()["requests"]), effects.PROFILE["max_requests"])

    def test_changed_binding_at_actual_send_retains_unknown_without_effects(self):
        fixture = self.case()
        current = binding(fixture.case)
        current["factory"] = "EXAMPLE_CHANGED_FACTORY"
        fixture.case.server.current_binding = lambda: current
        with self.assertRaises(admitted.client.OfflineAdmittedN1Error) as caught:
            self.run_case(fixture)
        self.assertEqual(sum(fixture.runner.observations()["effect_calls"].values()), 0)
        self.assertEqual(fixture.case.server.sends, 1)
        self.assertEqual(caught.exception.native_report["status"], "reconciliation-required")
        self.assertEqual(fixture.harness.attempt(fixture.case)["outcome"], "unknown")

    def test_backend_controls_can_observe_every_harmless_forbidden_effect(self):
        fixture = self.case()
        backend = effects.ExampleEffects(fixture.case.host.worker)
        for command in effects.PROFILE["denied"]:
            backend.apply(command)
        self.assertEqual(backend.memory["EXAMPLE_WRITE"], "EXAMPLE effect occurred")
        self.assertEqual(backend.memory["EXAMPLE_NETWORK"], "EXAMPLE effect occurred")
        self.assertEqual(backend.memory["EXAMPLE_PROCESS"], "EXAMPLE effect occurred")
        self.assertEqual([backend.calls[command] for command in effects.PROFILE["denied"]], [1] * 4)
        self.assertEqual(sum(fixture.runner.observations()["effect_calls"].values()), 0)


if __name__ == "__main__":
    unittest.main()
