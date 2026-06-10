from __future__ import annotations

import os
import sys
import unittest
from argparse import Namespace
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dispatch_work import build_local_envelope, execute_local_envelope  # noqa: E402
from orchestration_lib import classify_work  # noqa: E402


class FakeResponse:
    status = 200

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"ok"}}]}'


class LocalDispatchTests(unittest.TestCase):
    def test_openshift_profile_routes_to_openshift_executor(self) -> None:
        route = classify_work(
            "Documentation review for public README examples.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        self.assertEqual(route["recommended_executor"], "openshift_ai_vllm_worker")
        self.assertEqual(route["selected_executor"]["provider_key"], "openshift_ai_vllm")

    def test_local_envelope_uses_environment_variable_names_not_secret_values(self) -> None:
        route = classify_work(
            "Documentation review for public README examples.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url=None,
            local_model=None,
            execute_local=False,
        )
        with patch.dict(
            os.environ,
            {"CWO_OPENSHIFT_AI_VLLM_API_KEY": "secret-token"},
            clear=False,
        ):
            envelope = build_local_envelope(
                task="Documentation review for public README examples.",
                route=route,
                dispatch_id="dispatch-local-test",
                bead_id="cwo-local",
                epic_id=None,
                args=args,
            )
        self.assertEqual(envelope["api_key_env"], "CWO_OPENSHIFT_AI_VLLM_API_KEY")
        self.assertNotIn("secret-token", str(envelope))
        self.assertFalse(envelope["execution_enabled"])

    def test_execute_local_posts_openai_compatible_payload(self) -> None:
        route = classify_work(
            "Documentation review for public README examples.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url=None,
            local_model=None,
            execute_local=True,
        )
        with patch.dict(
            os.environ,
            {
                "CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000",
                "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model",
            },
            clear=False,
        ):
            envelope = build_local_envelope(
                task="Documentation review for public README examples.",
                route=route,
                dispatch_id="dispatch-local-test",
                bead_id="cwo-local",
                epic_id=None,
                args=args,
            )
            with patch("dispatch_work.request.urlopen", return_value=FakeResponse()) as mocked:
                response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["status_code"], 200)
        self.assertTrue(mocked.called)


if __name__ == "__main__":
    unittest.main()
