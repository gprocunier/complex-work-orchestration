from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.access_profiles import (  # noqa: E402
    access_profile_for_model_profile,
    access_profile_for_executor,
    access_profile_runtime_status,
    access_profiles,
    sanitized_access_profile,
    validate_access_profile_registry,
)
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402


class AccessProfileTests(unittest.TestCase):
    def test_access_profile_registry_is_consistent(self) -> None:
        self.assertEqual(validate_access_profile_registry(), [])
        profiles = access_profiles()
        self.assertIn("codex-connected-shell", profiles)
        self.assertIn("rhoai-glm-bf16", profiles)
        self.assertIn("rhoai-glm-bf16-256k", profiles)
        self.assertEqual(profiles["rhoai-glm-bf16"]["status"], "offline")
        self.assertEqual(profiles["rhoai-glm-bf16-256k"]["status"], "offline")

    def test_every_executor_resolves_to_known_access_profile(self) -> None:
        profiles = access_profiles()
        for key, executor in load_policy("executor-registry")["executors"].items():
            with self.subTest(executor=key):
                profile_key = access_profile_for_executor({**executor, "key": key})
                self.assertIn(profile_key, profiles)

    def test_route_result_carries_access_profile_for_codex_and_local_lanes(self) -> None:
        codex = classify_work("Implement a small repo patch.", requested_roles=["general-reasoning"])
        self.assertEqual(codex["access_profile"], "codex-connected-shell")
        self.assertEqual(codex["selected_executor"]["access_profile"], "codex-connected-shell")

        local = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        self.assertEqual(local["access_profile"], "rhoai-vllm")
        self.assertEqual(local["selected_executor"]["access_profile"], "rhoai-vllm")

    def test_glm_executor_resolves_to_offline_access_profile(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        self.assertEqual(route["recommended_executor"], "rhoai_glm_architecture_critic")
        self.assertEqual(route["access_profile"], "rhoai-glm-bf16")
        details = route["selected_executor"]["access_profile_details"]
        self.assertEqual(details["status"], "offline")

    def test_glm_bf16_matching_is_case_insensitive(self) -> None:
        profile_key = "rhoai-architect-GLM-5-2-BF16-thinking"
        self.assertEqual(
            access_profile_for_model_profile(profile_key, {"provider_key": "openshift_ai_vllm"}),
            "rhoai-glm-bf16",
        )
        self.assertEqual(
            access_profile_for_executor(
                {
                    "provider_key": "openshift_ai_vllm",
                    "dispatch_mode": "local_secure_review",
                    "model_profile": profile_key,
                    "external": False,
                }
            ),
            "rhoai-glm-bf16",
        )

    def test_glm_bf16_256k_matching_precedes_generic_bf16(self) -> None:
        profile_key = "rhoai-architect-GLM-5-2-BF16-256K-thinking"
        self.assertEqual(
            access_profile_for_model_profile(profile_key, {"provider_key": "openshift_ai_vllm"}),
            "rhoai-glm-bf16-256k",
        )
        self.assertEqual(
            access_profile_for_executor(
                {
                    "provider_key": "openshift_ai_vllm",
                    "dispatch_mode": "local_secure_review",
                    "model_profile": profile_key,
                    "external": False,
                }
            ),
            "rhoai-glm-bf16-256k",
        )

    def test_runtime_status_reports_env_names_without_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CWO_OPENSHIFT_AI_VLLM_BASE_URL": "https://vllm.internal.example",
                "CWO_OPENSHIFT_AI_VLLM_API_KEY": "secret-token",
            },
            clear=False,
        ):
            status = access_profile_runtime_status("rhoai-vllm")
        self.assertTrue(status["ready"])
        rendered = json.dumps(status, sort_keys=True)
        self.assertIn("CWO_OPENSHIFT_AI_VLLM_API_KEY", rendered)
        self.assertNotIn("secret-token", rendered)
        self.assertNotIn("vllm.internal.example", rendered)

    def test_status_script_redacts_secret_values(self) -> None:
        env = {
            **os.environ,
            "CWO_OPENSHIFT_AI_VLLM_BASE_URL": "https://vllm.internal.example",
            "CWO_OPENSHIFT_AI_VLLM_API_KEY": "secret-token",
        }
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_access_profile_status.py"),
                "--profile",
                "rhoai-vllm",
                "--json",
            ],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("CWO_OPENSHIFT_AI_VLLM_API_KEY", result.stdout)
        self.assertNotIn("secret-token", result.stdout)
        self.assertNotIn("vllm.internal.example", result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["profiles"][0]["access_profile"], "rhoai-vllm")

    def test_sanitized_profile_contains_policy_metadata_only(self) -> None:
        profile = sanitized_access_profile("browser-external-review")
        self.assertEqual(profile["key"], "browser-external-review")
        self.assertEqual(profile["disclosure"]["default_share_boundary"], "redacted-packet")
        self.assertIn("CWO_CHATGPT_BROWSER_CONFIG", profile["credential_sources"]["optional_env"])

    def test_unknown_profile_sanitizes_to_none(self) -> None:
        self.assertIsNone(sanitized_access_profile("missing-profile"))


if __name__ == "__main__":
    unittest.main()
