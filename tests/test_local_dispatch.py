from __future__ import annotations

import os
import socket
import sys
import unittest
from argparse import Namespace
from io import BytesIO
from unittest.mock import patch
from pathlib import Path
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dispatch_work import build_local_envelope, execute_local_envelope, validate_local_endpoint_base_url  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402


class FakeResponse:
    status = 200

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"ok"}}]}'


class FakeOpener:
    def __init__(self) -> None:
        self.called = False

    def open(self, *args: object, **kwargs: object) -> FakeResponse:
        self.called = True
        return FakeResponse()


class FakeHTTPErrorOpener:
    def open(self, *args: object, **kwargs: object) -> FakeResponse:
        raise HTTPError(
            "http://127.0.0.1:8000/v1/chat/completions",
            500,
            "Internal Server Error",
            {},
            BytesIO(b"api_key=plain-secret\nStatus: injected"),
        )


class LocalDispatchTests(unittest.TestCase):
    def test_openshift_profile_routes_to_openshift_executor(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        self.assertEqual(route["recommended_executor"], "openshift_ai_vllm_worker")
        self.assertEqual(route["selected_executor"]["provider_key"], "openshift_ai_vllm")

    def test_local_envelope_uses_environment_variable_names_not_secret_values(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
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
                task="Documentation review for internal example notes.",
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
            "Documentation review for internal example notes.",
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
                task="Documentation review for internal example notes.",
                route=route,
                dispatch_id="dispatch-local-test",
                bead_id="cwo-local",
                epic_id=None,
                args=args,
            )
            opener = FakeOpener()
            with patch("dispatch_work.request.build_opener", return_value=opener):
                response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["status_code"], 200)
        self.assertTrue(opener.called)

    def test_execute_local_rejects_public_endpoint_before_post(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="https://example.com",
            local_model="test-model",
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Documentation review for internal example notes.",
            route=route,
            dispatch_id="dispatch-local-test",
            bead_id="cwo-local",
            epic_id=None,
            args=args,
        )
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            with self.assertRaises(SystemExit):
                execute_local_envelope(envelope, route["selected_executor"], args)

    def test_execute_local_rejects_url_credentials(self) -> None:
        with self.assertRaises(SystemExit) as context:
            validate_local_endpoint_base_url("http://user:pass@127.0.0.1:8000")
        self.assertIn("must not contain credentials", str(context.exception))

    def test_execute_local_rejects_private_hostname_to_avoid_dns_rebinding(self) -> None:
        fake_records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.25", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.10.8", 443)),
        ]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            with self.assertRaises(SystemExit) as context:
                validate_local_endpoint_base_url("https://vllm.internal.example:8443")
        self.assertIn("literal IP address or localhost", str(context.exception))

    def test_execute_local_rejects_public_hostname_resolution(self) -> None:
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            with self.assertRaises(SystemExit) as context:
                validate_local_endpoint_base_url("https://vllm.example.com")
        self.assertIn("literal IP address or localhost", str(context.exception))

    def test_execute_local_rejects_mixed_hostname_resolution(self) -> None:
        fake_records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.25", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            with self.assertRaises(SystemExit):
                validate_local_endpoint_base_url("https://mixed.example.com")

    def test_execute_local_rejects_private_http_non_loopback(self) -> None:
        with self.assertRaises(SystemExit) as context:
            validate_local_endpoint_base_url("http://10.0.0.25:8000")
        self.assertIn("http only for loopback", str(context.exception))

    def test_execute_local_rejects_unallowlisted_api_key_env(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        args = Namespace(
            local_api_key_env="AWS_SECRET_ACCESS_KEY",
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000",
            local_model="test-model",
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Documentation review for internal example notes.",
            route=route,
            dispatch_id="dispatch-local-test",
            bead_id="cwo-local",
            epic_id=None,
            args=args,
        )
        with self.assertRaises(SystemExit) as context:
            execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertIn("not allowlisted", str(context.exception))

    def test_execute_local_omits_raw_http_error_body(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000",
            local_model="test-model",
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Documentation review for internal example notes.",
            route=route,
            dispatch_id="dispatch-local-test",
            bead_id="cwo-local",
            epic_id=None,
            args=args,
        )
        with patch("dispatch_work.request.build_opener", return_value=FakeHTTPErrorOpener()):
            with self.assertRaises(SystemExit) as context:
                execute_local_envelope(envelope, route["selected_executor"], args)

        rendered = str(context.exception)
        self.assertIn("response body omitted", rendered)
        self.assertIn("sha256=", rendered)
        self.assertNotIn("plain-secret", rendered)
        self.assertNotIn("Status: injected", rendered)


if __name__ == "__main__":
    unittest.main()
