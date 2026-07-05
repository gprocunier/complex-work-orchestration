from __future__ import annotations

import os
import json
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

from dispatch_work import (  # noqa: E402
    build_local_envelope,
    execute_local_envelope,
    local_response_telemetry,
    pinned_local_endpoint_address,
    validate_local_endpoint_base_url,
)
from cwo_core.routing import classify_work  # noqa: E402


class FakeResponse:
    status = 200

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}'


class FakeThinkingResponse(FakeResponse):
    def read(self) -> bytes:
        return (
            b'{"choices":[{"message":{"content":"<think>private reasoning</think>GLM final"}}],'
            b'"usage":{"prompt_tokens":13,"completion_tokens":9,"total_tokens":22}}'
        )


class FakeTruncatedThinkingResponse(FakeResponse):
    def read(self) -> bytes:
        return (
            b'{"choices":[{"finish_reason":"length","message":{"content":"<think>private reasoning</think>partial"}}],'
            b'"usage":{"prompt_tokens":13,"completion_tokens":9}}'
        )


class FakeOpener:
    def __init__(self) -> None:
        self.called = False

    def open(self, *args: object, **kwargs: object) -> FakeResponse:
        self.called = True
        return FakeResponse()


class FakePayloadOpener:
    def __init__(self) -> None:
        self.payload: dict[str, object] | None = None

    def open(self, req: object, **kwargs: object) -> FakeThinkingResponse:
        self.payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        return FakeThinkingResponse()


class FakeTruncatedPayloadOpener(FakePayloadOpener):
    def open(self, req: object, **kwargs: object) -> FakeTruncatedThinkingResponse:
        self.payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        return FakeTruncatedThinkingResponse()


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
        self.assertIn("elapsed_seconds", response)
        self.assertTrue(opener.called)

        telemetry = local_response_telemetry(response)
        self.assertEqual(telemetry["input_tokens"], 11)
        self.assertEqual(telemetry["output_tokens"], 7)
        self.assertEqual(telemetry["total_tokens"], 18)
        self.assertEqual(telemetry["agent_model_calls"], 1)
        self.assertIn("local_response_sha256", telemetry)
        self.assertNotIn("response", telemetry)
        self.assertNotIn("\"content\"", json.dumps(telemetry))
        self.assertNotIn("\"message\"", json.dumps(telemetry))

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

    def test_execute_local_accepts_private_dns_when_profile_allows_it(self) -> None:
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.10.190", 443))]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            addresses = validate_local_endpoint_base_url("https://vllm.internal.example", allow_private_dns=True)
        self.assertEqual(addresses, ["172.16.10.190"])

    def test_private_dns_endpoint_returns_pinned_address_when_allowed(self) -> None:
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.10.190", 443))]
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            address = pinned_local_endpoint_address("https://vllm.internal.example", allow_private_dns=True)
        self.assertEqual(address, "172.16.10.190")

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

    def test_glm_envelope_carries_thinking_options_and_tls_metadata(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        self.assertEqual(route["recommended_executor"], "openshift_ai_vllm_glm_5_2_bf16_architecture_critic")
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url=None,
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=True,
            execute_local=False,
        )
        envelope = build_local_envelope(
            task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            route=route,
            dispatch_id="dispatch-glm-test",
            bead_id="cwo-glm",
            epic_id=None,
            args=args,
        )

        self.assertEqual(envelope["model"], "glm-5.2-bf16-128k")
        self.assertEqual(envelope["model_profile"], "rhoai-architect-glm-5-2-bf16-thinking")
        self.assertTrue(envelope["allow_private_dns"])
        self.assertFalse(envelope["tls_verify"])
        self.assertEqual(envelope["tls_verify_source"], "--local-insecure-tls")
        self.assertTrue(envelope["allow_insecure_tls"])
        self.assertEqual(envelope["request_options"], {"chat_template_kwargs": {"enable_thinking": True}})
        self.assertEqual(envelope["thinking_parser"], "glm-think-tags")
        self.assertEqual(envelope["response_sanitization"], "strip-raw-thinking")

    def test_glm_execute_posts_thinking_options_and_strips_reasoning(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000",
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=False,
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            route=route,
            dispatch_id="dispatch-glm-test",
            bead_id="cwo-glm",
            epic_id=None,
            args=args,
        )
        opener = FakePayloadOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(opener.payload["chat_template_kwargs"], {"enable_thinking": True})
        self.assertEqual(opener.payload["model"], "glm-5.2-bf16-128k")
        message = response["response"]["choices"][0]["message"]
        self.assertEqual(message["content"], "GLM final")
        self.assertTrue(response["reasoning_stripped"])
        self.assertIn("raw_response_sha256", response)
        self.assertNotIn("private reasoning", json.dumps(response))

        telemetry = local_response_telemetry(response)
        self.assertTrue(telemetry["reasoning_stripped"])
        self.assertEqual(telemetry["reasoning_chars"], len("private reasoning"))
        self.assertIn("raw_response_sha256", telemetry)
        self.assertNotIn("private reasoning", json.dumps(telemetry))

    def test_glm_execute_records_truncated_finish_reason(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000",
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=False,
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            route=route,
            dispatch_id="dispatch-glm-test",
            bead_id="cwo-glm",
            epic_id=None,
            args=args,
        )
        opener = FakeTruncatedPayloadOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertTrue(response["response_truncated"])
        self.assertEqual(response["finish_reasons"], ["length"])
        telemetry = local_response_telemetry(response)
        self.assertTrue(telemetry["response_truncated"])
        self.assertEqual(telemetry["finish_reasons"], ["length"])
        self.assertNotIn("private reasoning", json.dumps(telemetry))

    def test_glm_private_dns_execution_uses_pinned_https_handler(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="https://vllm.internal.example",
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=True,
            execute_local=True,
        )
        envelope = build_local_envelope(
            task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            route=route,
            dispatch_id="dispatch-glm-private-dns",
            bead_id="cwo-glm",
            epic_id=None,
            args=args,
        )
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.10.190", 443))]
        opener = FakePayloadOpener()
        with patch("dispatch_work.socket.getaddrinfo", return_value=fake_records):
            with patch("dispatch_work.request.build_opener", return_value=opener) as mocked_build_opener:
                response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(response["status_code"], 200)
        handler_names = [getattr(arg, "__name__", arg.__class__.__name__) for arg in mocked_build_opener.call_args.args]
        self.assertIn("PinnedHTTPSHandler", handler_names)


if __name__ == "__main__":
    unittest.main()
