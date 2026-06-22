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
    model_profile_registry,
    validate_harness_dispatch_envelope,
    validate_execution_environment_registry,
    validate_model_profile_registry,
)


class ExecutionEnvironmentTests(unittest.TestCase):
    def test_execution_environment_registry_is_consistent(self) -> None:
        self.assertEqual(validate_execution_environment_registry(), [])

    def test_model_profile_registry_is_consistent(self) -> None:
        self.assertEqual(validate_model_profile_registry(), [])
        registry = model_profile_registry()
        self.assertIn("role_substitution_matrix", registry)
        self.assertIn("rhoai-architect-mistral-small-4-119b-nvfp4", registry["profiles"])
        self.assertIn("rhoai-architect-nemotron-3-ultra-550b-a55b-fp8", registry["profiles"])
        self.assertIn("rhoai-architect-glm-5-2-fp8", registry["profiles"])
        architect_row = next(row for row in registry["role_substitution_matrix"] if row["cwo_role"] == "architect")
        self.assertEqual(
            architect_row["enterprise_profiles"],
            ["rhoai-architect-nemotron-3-ultra-550b-a55b-fp8", "rhoai-architect-glm-5-2-fp8"],
        )
        self.assertIn("benchmark_gate", registry["profiles"]["rhoai-architect-nemotron-3-ultra-550b-a55b-fp8"])

    def test_role_model_profiles_resolve_to_allowed_local_providers(self) -> None:
        profiles = model_profile_registry()["profiles"]
        environments = execution_environment_registry()["profiles"]
        for env_key in [
            "connected-opencode-exemplar",
            "restricted-opencode-rhoai",
            "airgapped-rhoai",
            "airgapped-rhoai-h200-nemotron",
            "airgapped-rhoai-h200-glm",
        ]:
            environment = environments[env_key]
            for role in ["architect", "project_manager", "worker", "review_worker", "local_worker", "synthesis_input"]:
                with self.subTest(environment=env_key, role=role):
                    profile_key = environment["role_bindings"][role]["model_profile"]
                    profile = profiles[profile_key]
                    self.assertIn(profile["provider_key"], environment["allowed_providers"])
                    self.assertEqual(profile["provider_key"], "openshift_ai_vllm")

    def test_sample_execution_environment_documents_airgap_boundary(self) -> None:
        sample = json.loads((ROOT / "examples" / "sample-execution-environment.json").read_text(encoding="utf-8"))
        self.assertEqual(sample["environment"], "airgapped-rhoai")
        self.assertEqual(sample["default_harness"], "opencode")
        profiles = model_profile_registry()["profiles"]
        for binding in sample["role_bindings"].values():
            profile_key = binding.get("model_profile")
            if profile_key:
                self.assertIn(profile_key, profiles)
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
        self.assertIsNone(envelope["model_profile"])
        self.assertIsNone(envelope["model_profile_details"])
        self.assertNotIn("api_key", json.dumps(envelope).lower())
        self.assertNotIn("token", json.dumps(envelope).lower())
        self.assertEqual(validate_harness_dispatch_envelope(envelope), [])

    def test_opencode_dispatch_resolves_bound_model_profile(self) -> None:
        envelope = build_harness_dispatch(
            task="Review docs for execution environment wording.",
            dispatch_id="dispatch-test",
            environment_key="airgapped-rhoai",
            role="architect",
            bead_id="cwo-test",
            epic_id="cwo-epic",
        )
        self.assertEqual(envelope["harness"], "opencode")
        self.assertEqual(envelope["model_profile"], "rhoai-architect-mistral-small-4-119b-nvfp4")
        self.assertEqual(envelope["model"], "rhoai/architect")
        self.assertEqual(envelope["variant"], "reasoning-high")
        self.assertTrue(envelope["capability_requirements"]["supports_local_openai_compatible"])
        self.assertEqual(envelope["model_profile_details"]["provider_key"], "openshift_ai_vllm")
        self.assertIn("Model profile: rhoai-architect-mistral-small-4-119b-nvfp4", envelope["prompt"])
        self.assertIn("--model rhoai/architect", envelope["suggested_command"])
        self.assertIn("--variant reasoning-high", envelope["suggested_command"])
        self.assertEqual(validate_harness_dispatch_envelope(envelope), [])

    def test_h200_nemotron_environment_resolves_deep_reasoning_profile(self) -> None:
        envelope = build_harness_dispatch(
            task="Review the enterprise execution plan.",
            dispatch_id="dispatch-test",
            environment_key="airgapped-rhoai-h200-nemotron",
            role="architect",
            bead_id="cwo-test",
        )
        self.assertEqual(envelope["model_profile"], "rhoai-architect-nemotron-3-ultra-550b-a55b-fp8")
        self.assertEqual(envelope["model"], "rhoai/architect-nemotron-ultra")
        self.assertEqual(envelope["variant"], "reasoning-xhigh")
        self.assertEqual(envelope["model_profile_details"]["deployment_tier"], "h200-enterprise-candidate")
        self.assertEqual(envelope["model_profile_details"]["promotion_status"], "candidate")
        self.assertIn("NCCL all_reduce_perf 8-GPU and 16-GPU", envelope["model_profile_details"]["benchmark_gate"])
        self.assertEqual(validate_harness_dispatch_envelope(envelope), [])

    def test_h200_glm_environment_resolves_long_context_profile(self) -> None:
        envelope = build_harness_dispatch(
            task="Review a Beads-heavy architecture packet.",
            dispatch_id="dispatch-test",
            environment_key="airgapped-rhoai-h200-glm",
            role="synthesis_input",
            bead_id="cwo-test",
        )
        self.assertEqual(envelope["model_profile"], "rhoai-architect-glm-5-2-fp8")
        self.assertEqual(envelope["model"], "rhoai/architect-glm-5-2")
        self.assertEqual(envelope["variant"], "reasoning-long-context")
        self.assertEqual(envelope["model_profile_details"]["deployment_tier"], "h200-enterprise-candidate")
        self.assertIn("long-context Beads briefing packet", envelope["model_profile_details"]["benchmark_gate"])
        self.assertEqual(validate_harness_dispatch_envelope(envelope), [])

    def test_explicit_model_profile_can_select_workerbee_model(self) -> None:
        envelope = build_harness_dispatch(
            task="Review command examples.",
            dispatch_id="dispatch-test",
            environment_key="connected-opencode-exemplar",
            role="worker",
            model_profile_key="rhoai-worker-qwen2-5-coder-32b-fp8",
        )
        self.assertEqual(envelope["agent"], "cwo-review")
        self.assertEqual(envelope["model_profile"], "rhoai-worker-qwen2-5-coder-32b-fp8")
        self.assertEqual(envelope["model"], "rhoai/workerbee")
        self.assertIn("--agent cwo-review", envelope["suggested_command"])

    def test_explicit_model_overrides_bound_profile(self) -> None:
        envelope = build_harness_dispatch(
            task="Review command examples.",
            dispatch_id="dispatch-test",
            environment_key="connected-opencode-exemplar",
            role="worker",
            model="rhoai/custom-worker",
        )
        self.assertEqual(envelope["model"], "rhoai/custom-worker")
        self.assertIsNone(envelope["model_profile"])
        self.assertIsNone(envelope["model_profile_details"])

    def test_model_and_profile_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            build_harness_dispatch(
                task="Review command examples.",
                dispatch_id="dispatch-test",
                environment_key="connected-opencode-exemplar",
                role="worker",
                model="rhoai/custom-worker",
                model_profile_key="rhoai-worker-qwen2-5-coder-32b-fp8",
            )

    def test_unbound_role_fails_closed(self) -> None:
        with self.assertRaises(SystemExit):
            build_harness_dispatch(
                task="Review docs.",
                dispatch_id="dispatch-test",
                environment_key="airgapped-rhoai",
                role="master_review",
            )

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
