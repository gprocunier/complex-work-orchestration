"""The exact model identities named by current runtime code are defined once.

Current model aliases and defaults are centralized while recording resolved exact
identities, without substituting a model for an exact request or renaming frozen literals.
``cwo_core.model_identities`` holds each exact identity once; current runtime modules import it
instead of repeating the literal. The values are unchanged, so no default, requirement or
refusal changes. Frozen validator-contract files (their blobs are bound into historical evidence)
keep their literals.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

SPARK = "gpt-5.3-codex-spark"
FROZEN_VALIDATOR_CONTRACT_FILES = {
    "scripts/cwo_core/native_live_campaign_contracts.py",
    "scripts/run_native_pool_live_canaries.py",
}
# Every current runtime name that used to hold its own copy of the Spark literal.
SPARK_NAMES = {
    "check_codex_worker_surface": "DEFAULT_MODEL",
    "check_native_worker_session": "DEFAULT_REQUESTED_MODEL",
    "prepare_native_worker": "REQUESTED_MODEL",
    "scaffold_workgraph": "SPARK_WORKER_MODEL",
    "cwo_core.coach": "SPARK_MODEL_ALIAS",
    "cwo_core.native_precommit": "REQUIRED_MODEL",
    "cwo_core.native_activation_preview": "MODEL",
    "cwo_core.operative_routing": "SPARK_MODEL",
}


def string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]


class CentralModelIdentityTests(unittest.TestCase):
    def test_identities_are_exact_and_unchanged(self) -> None:
        from cwo_core import model_identities

        self.assertEqual(model_identities.SPARK_MODEL, SPARK)
        self.assertEqual(model_identities.GPT55_MODEL, "gpt-5.5")
        self.assertEqual(model_identities.TERRA_MODEL, "gpt-5.6-terra")
        self.assertEqual(model_identities.LUNA_MODEL, "gpt-5.6-luna")

    def test_current_runtime_names_resolve_to_the_central_identity(self) -> None:
        import importlib

        from cwo_core import model_identities

        for module_name, attribute in SPARK_NAMES.items():
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                self.assertEqual(getattr(module, attribute), SPARK)
                self.assertIs(getattr(module, "SPARK_MODEL", None), model_identities.SPARK_MODEL)

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

    def test_central_module_imports_nothing(self) -> None:
        tree = ast.parse((ROOT / "scripts" / "cwo_core" / "model_identities.py").read_text(encoding="utf-8"))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([ast.unparse(node) for node in imports], ["from __future__ import annotations"])


class CentralPacketProvenanceTests(unittest.TestCase):
    """The production-packet rule is stated once and every consumer goes through it."""

    CONSUMERS = (
        "dispatch_work", "generate_manual_dispatch_prompt", "chatgpt_browser_review",
        "normalize_contractor_return", "evaluate_return",
    )

    def test_every_packet_consumer_uses_the_central_rule(self) -> None:
        for name in self.CONSUMERS:
            with self.subTest(consumer=name):
                tree = ast.parse((ROOT / "scripts" / f"{name}.py").read_text(encoding="utf-8"))
                called = {
                    node.func.id for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                }
                self.assertIn("require_production_contractor_packet", called)
                self.assertNotIn("require_valid_contractor_packet", called)


if __name__ == "__main__":
    unittest.main()
