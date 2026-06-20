from __future__ import annotations

import json
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.harness import (  # noqa: E402
    build_harness_dispatch,
    execution_environment_registry,
    harness_registry,
    validate_harness_dispatch_envelope,
    validate_execution_environment_registry,
)


class ExecutionEnvironmentTests(unittest.TestCase):
    def test_execution_environment_registry_is_consistent(self) -> None:
        self.assertEqual(validate_execution_environment_registry(), [])

    def test_sample_execution_environment_documents_airgap_boundary(self) -> None:
        sample = json.loads((ROOT / "examples" / "sample-execution-environment.json").read_text(encoding="utf-8"))
        self.assertEqual(sample["environment"], "airgapped-rhoai")
        self.assertEqual(sample["default_harness"], "opencode")
        self.assertIn("Codex CLI is not assumed available", sample["operator_note"])

    def test_opencode_dispatch_is_secret_free_and_not_executed(self) -> None:
        envelope = build_harness_dispatch(
            task="Review docs for execution environment wording.",
            dispatch_id="dispatch-test",
            environment_key="connected-opencode-exemplar",
            role="worker",
            harness_key="opencode",
            bead_id="cwo-test",
            epic_id="cwo-epic",
            agent="cwo-review",
            model="rhoai/local-model",
            variant="high",
        )
        self.assertEqual(envelope["envelope_type"], "harness-dispatch")
        self.assertEqual(envelope["envelope_version"], "1.0")
        self.assertEqual(envelope["lifecycle_state"], "rendered")
        self.assertFalse(envelope["execution_enabled"])
        self.assertIn("timeout_seconds", envelope)
        self.assertFalse(envelope["capability_requirements"]["supports_repo_write"])
        self.assertIn("opencode run", envelope["suggested_command"])
        self.assertIn("--format json", envelope["suggested_command"])
        self.assertIn("--agent cwo-review", envelope["suggested_command"])
        self.assertIn("rhoai/local-model", envelope["suggested_command"])
        self.assertNotIn("api_key", json.dumps(envelope).lower())
        self.assertNotIn("token", json.dumps(envelope).lower())
        self.assertEqual(validate_harness_dispatch_envelope(envelope), [])

    def test_capability_requirements_fail_closed(self) -> None:
        with self.assertRaises(SystemExit):
            build_harness_dispatch(
                task="Review docs.",
                dispatch_id="dispatch-test",
                environment_key="connected-opencode-exemplar",
                role="worker",
                harness_key="aider",
                capability_requirements={"supports_mcp": True},
            )

    def test_unknown_environment_and_harness_fail_closed(self) -> None:
        with self.assertRaises(SystemExit):
            build_harness_dispatch(
                task="Review docs.",
                dispatch_id="dispatch-test",
                environment_key="missing-env",
                role="worker",
            )
        with self.assertRaises(SystemExit):
            build_harness_dispatch(
                task="Review docs.",
                dispatch_id="dispatch-test",
                environment_key="connected-opencode-exemplar",
                role="worker",
                harness_key="missing-harness",
            )

    def test_unsupported_envelope_versions_fail_validation(self) -> None:
        envelope = build_harness_dispatch(
            task="Review docs.",
            dispatch_id="dispatch-test",
            environment_key="connected-opencode-exemplar",
            role="worker",
            harness_key="opencode",
        )
        envelope["envelope_version"] = "2.0"
        self.assertTrue(any("unsupported" in error for error in validate_harness_dispatch_envelope(envelope)))

    def test_airgapped_profile_has_no_codex_or_external_contracting(self) -> None:
        profile = execution_environment_registry()["profiles"]["airgapped-rhoai"]
        self.assertNotIn("codex_cli", profile["allowed_harnesses"])
        self.assertEqual(profile["constraints"]["external_contracting"], "disabled")
        self.assertEqual(profile["default_harness"], "opencode")
        self.assertEqual(profile["constraints"]["execution_lifecycle_owner"], "CWO")

    def test_opencode_is_exemplar_not_only_harness(self) -> None:
        harnesses = harness_registry()["harnesses"]
        self.assertEqual(harnesses["opencode"]["status"], "v2-exemplar")
        self.assertIn("manual_operator", harnesses)
        self.assertIn("codex_cli", harnesses)

    def test_render_path_has_no_execution_side_effect_imports(self) -> None:
        blocked_imports = {"subprocess", "urllib", "requests", "playwright"}
        for relative in ["scripts/render_harness_dispatch.py", "scripts/cwo_core/harness.py"]:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            imports: set[str] = set()
            calls: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".", 1)[0])
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        calls.add(node.func.attr)
                    elif isinstance(node.func, ast.Name):
                        calls.add(node.func.id)
            self.assertFalse(imports & blocked_imports, relative)
            self.assertFalse({"system", "popen", "run", "call"} & calls, relative)


if __name__ == "__main__":
    unittest.main()
