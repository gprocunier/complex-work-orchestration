"""Current worker policy uses roles and historical exact identity remains readable."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

SPARK = "gpt-5.3-codex-spark"
FROZEN_VALIDATOR_CONTRACT_FILES = {
    "scripts/run_native_pool_live_canaries.py",
}


def string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]


class CentralModelIdentityTests(unittest.TestCase):
    def test_historical_identities_are_exact_and_unchanged(self) -> None:
        from cwo_core import model_identities

        self.assertEqual(model_identities.SPARK_MODEL, SPARK)
        self.assertEqual(model_identities.GPT55_MODEL, "gpt-5.5")
        self.assertEqual(model_identities.TERRA_MODEL, "gpt-5.6-terra")
        self.assertEqual(model_identities.LUNA_MODEL, "gpt-5.6-luna")

    def test_current_worker_consumes_the_configured_model_and_refuses_spark(self) -> None:
        from cwo_core.model_identities import resolve_model
        from prepare_native_worker import _policy_model

        self.assertEqual(_policy_model(), resolve_model("luna"))
        self.assertEqual(_policy_model(resolve_model("terra")), resolve_model("terra"))
        self.assertEqual(_policy_model(resolve_model("sol")), resolve_model("sol"))
        with self.assertRaisesRegex(SystemExit, "historical-nonoperative"):
            _policy_model(SPARK)

    def test_current_executor_metadata_projects_roles_from_policy(self) -> None:
        from cwo_core.model_identities import resolve_model
        from cwo_core.policy import executor_config, load_policy

        snapshot = load_policy("executor-registry")
        for executor, role in (("internal_worker_luna", "luna"), ("internal_worker_terra", "terra"),
                               ("internal_worker_sol", "sol"),
                               ("frontier_architect", "sol"), ("codex_architecture_critic", "sol")):
            with self.subTest(executor=executor):
                self.assertEqual(executor_config(executor)["model_label"], resolve_model(role))
                self.assertEqual(executor_config(executor, snapshot)["model_label"],
                                 snapshot["executors"][executor]["model_label"])

    def test_the_spark_literal_is_written_once_outside_historical_sources(self) -> None:
        holders = []
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative in FROZEN_VALIDATOR_CONTRACT_FILES:
                continue
            if relative == "scripts/cwo_core/supervision/transport/app_server.py":
                # The historical EXACT_MODEL declaration retains its exact bytes.
                # Permit exactly that declaration, not arbitrary new literals in
                # this module. The move-fidelity proof binds its historical source.
                tree = ast.parse(path.read_text(encoding="utf-8"))
                declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                                and any(isinstance(target, ast.Name) and target.id == "EXACT_MODEL"
                                        for target in node.targets)]
                self.assertEqual(len(declarations), 1)
                self.assertEqual(ast.literal_eval(declarations[0].value), SPARK)
                self.assertEqual([value for value in string_literals(path) if SPARK in value], [SPARK])
                continue
            if any(SPARK in value for value in string_literals(path)):
                holders.append(relative)
        self.assertEqual(holders, ["scripts/cwo_core/model_identities.py"])

class CentralPacketProvenanceTests(unittest.TestCase):
    """The production-packet rule is stated once and every consumer goes through it."""

    CONSUMER_CALLS = {
        "dispatch_work": "require_production_contractor_packet",
        "generate_manual_dispatch_prompt": "require_production_contractor_packet",
        "chatgpt_browser_review": "load_browser_packet_prompt",
        "browser_request": "require_production_contractor_packet",
        "normalize_contractor_return": "require_production_contractor_packet",
        "evaluate_return": "require_production_contractor_packet",
    }

    def test_every_packet_consumer_uses_the_central_rule(self) -> None:
        for name, expected_call in self.CONSUMER_CALLS.items():
            with self.subTest(consumer=name):
                tree = ast.parse((ROOT / "scripts" / f"{name}.py").read_text(encoding="utf-8"))
                called = {
                    node.func.id for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                }
                self.assertIn(expected_call, called)
                self.assertNotIn("require_valid_contractor_packet", called)


if __name__ == "__main__":
    unittest.main()
