from __future__ import annotations

import os
import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from argparse import Namespace
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from pathlib import Path
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dispatch_work import (  # noqa: E402
    build_local_envelope,
    compact_local_response,
    execute_local_envelope,
    local_response_telemetry,
    pinned_local_endpoint_address,
    sanitize_local_response_payload,
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


class FakeModelsResponse(FakeResponse):
    def read(self) -> bytes:
        return b'{"object":"list","data":[{"id":"glm-5.2-bf16-256k","object":"model"}]}'


class FakeWrongModelsResponse(FakeResponse):
    def read(self) -> bytes:
        return b'{"object":"list","data":[{"id":"glm-5.2-bf16-128k","object":"model"}]}'


class FakeHardenedThinkingResponse(FakeResponse):
    def read(self) -> bytes:
        return (
            b'{"model":"glm-5.2-bf16-256k","choices":[{"finish_reason":"stop",'
            b'"message":{"content":"useful final","reasoning_content":"private separate reasoning"}}],'
            b'"usage":{"prompt_tokens":31,"completion_tokens":17,"total_tokens":48}}'
        )


class FakeReasoningOnlyResponse(FakeResponse):
    def read(self) -> bytes:
        return (
            b'{"model":"glm-5.2-bf16-256k","choices":[{"finish_reason":"stop",'
            b'"message":{"content":null,"reasoning_content":"private reasoning only"}}],'
            b'"usage":{"prompt_tokens":31,"completion_tokens":8192,"total_tokens":8223}}'
        )


class FakeHardenedOpener:
    def __init__(self, *, wrong_model: bool = False, reasoning_only: bool = False) -> None:
        self.wrong_model = wrong_model
        self.reasoning_only = reasoning_only
        self.chat_called = False
        self.payload: dict[str, object] | None = None
        self.correlation_ids: list[str | None] = []

    def open(self, req: object, **kwargs: object) -> FakeResponse:
        headers = {str(key).lower(): str(value) for key, value in req.header_items()}  # type: ignore[attr-defined]
        self.correlation_ids.append(headers.get("x-cwo-dispatch-id"))
        url = str(getattr(req, "full_url", ""))
        if url.endswith("/v1/models"):
            return FakeWrongModelsResponse() if self.wrong_model else FakeModelsResponse()
        self.chat_called = True
        self.payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        return FakeReasoningOnlyResponse() if self.reasoning_only else FakeHardenedThinkingResponse()


class FakeHTTPErrorOpener:
    def open(self, *args: object, **kwargs: object) -> FakeResponse:
        raise HTTPError(
            "http://127.0.0.1:8000/v1/chat/completions",
            500,
            "Internal Server Error",
            {},
            BytesIO(b"api_key=plain-secret\nStatus: injected"),
        )


class FakeRedirectResponse(FakeResponse):
    status = 302

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"redirected content"}}]}'


class FakeRedirectOpener:
    def open(self, *args: object, **kwargs: object) -> FakeRedirectResponse:
        return FakeRedirectResponse()


class HardenedGLMHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return None

    def _send(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send({"object": "list", "data": [{"id": "glm-5.2-bf16-256k"}]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self._send(
            {
                "model": "glm-5.2-bf16-256k",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": "compact final",
                            "reasoning_content": "never retain this reasoning",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 7, "completion_tokens": 5, "total_tokens": 12},
            }
        )


class LocalDispatchTests(unittest.TestCase):
    def _hardened_glm_route(self) -> dict[str, object]:
        return classify_work(
            "Use exact GLM-5.2 BF16 256K thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-glm-256k",
            requested_roles=["architecture"],
        )

    def _hardened_glm_args(self) -> Namespace:
        return Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000",
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=False,
            local_max_tokens=None,
            local_thinking="default",
            allow_offline_access_profile=True,
            execute_local=True,
        )

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
        self.assertEqual(envelope["access_profile"], "rhoai-vllm")
        self.assertEqual(envelope["version"], 2)
        self.assertEqual(envelope["expected_return_language"], "en")
        self.assertEqual(envelope["expected_return_language_source"], "local-envelope-v2")
        self.assertIn("CWO_OPENSHIFT_AI_VLLM_API_KEY", str(envelope["access_profile_readiness"]))
        self.assertNotIn("secret-token", str(envelope))
        self.assertFalse(envelope["execution_enabled"])

    def test_local_envelope_fails_if_executor_has_no_access_profile(self) -> None:
        route = classify_work(
            "Documentation review for internal example notes.",
            local_ok=True,
            prefer_local=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["documentation"],
        )
        broken_route = dict(route)
        broken_executor = dict(route["selected_executor"])
        broken_executor.pop("access_profile", None)
        broken_executor["provider_key"] = "unknown_provider"
        broken_route["selected_executor"] = broken_executor
        args = Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url=None,
            local_model=None,
            execute_local=False,
        )
        with self.assertRaises(SystemExit) as context:
            build_local_envelope(
                task="Documentation review for internal example notes.",
                route=broken_route,
                dispatch_id="dispatch-local-test",
                bead_id="cwo-local",
                epic_id=None,
                args=args,
            )
        self.assertIn("known access profile", str(context.exception))

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

    def test_execute_local_rejects_non_200_response_without_body(self) -> None:
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
            dispatch_id="dispatch-local-redirect",
            bead_id="cwo-local",
            epic_id=None,
            args=args,
        )
        with patch("dispatch_work.request.build_opener", return_value=FakeRedirectOpener()):
            with self.assertRaises(SystemExit) as context:
                execute_local_envelope(envelope, route["selected_executor"], args)
        rendered = str(context.exception)
        self.assertIn("did not return HTTP 200", rendered)
        self.assertNotIn("redirected content", rendered)

    def test_glm_envelope_carries_thinking_options_and_tls_metadata(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        self.assertEqual(route["recommended_executor"], "rhoai_glm_architecture_critic")
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
        self.assertEqual(envelope["access_profile"], "rhoai-glm-bf16")
        self.assertEqual(envelope["access_profile_details"]["status"], "offline")
        self.assertTrue(envelope["allow_private_dns"])
        self.assertFalse(envelope["tls_verify"])
        self.assertEqual(envelope["tls_verify_source"], "--local-insecure-tls")
        self.assertTrue(envelope["allow_insecure_tls"])
        self.assertEqual(
            envelope["request_options"],
            {"chat_template_kwargs": {"enable_thinking": True}, "max_tokens": 4096},
        )
        self.assertEqual(envelope["thinking_parser"], "glm-think-tags")
        self.assertEqual(envelope["response_sanitization"], "strip-raw-thinking")

    def test_hardened_glm_profile_is_exact_and_bounded(self) -> None:
        route = self._hardened_glm_route()
        self.assertEqual(route["recommended_executor"], "rhoai_glm_hardened_architecture_critic")
        args = self._hardened_glm_args()
        args.execute_local = False
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )
        self.assertEqual(envelope["model"], "glm-5.2-bf16-256k")
        self.assertEqual(envelope["local_profile"], "openshift-ai-glm-256k")
        self.assertEqual(envelope["model_profile"], "rhoai-architect-glm-5-2-bf16-256k-thinking")
        self.assertEqual(envelope["access_profile"], "rhoai-glm-bf16-256k")
        self.assertEqual(envelope["access_profile_details"]["status"], "offline")
        self.assertEqual(
            envelope["base_url_env"],
            "CWO_OPENSHIFT_AI_GLM_5_2_BF16_256K_BASE_URL",
        )
        self.assertEqual(envelope["timeout_seconds"], 900)
        self.assertEqual(envelope["max_input_chars"], 24000)
        self.assertEqual(envelope["target_input_chars"], 14000)
        self.assertEqual(envelope["request_options"]["max_tokens"], 8192)
        self.assertTrue(envelope["model_preflight_required"])
        self.assertEqual(envelope["required_finish_reason"], "stop")
        self.assertTrue(envelope["response_model_required"])

    def test_hardened_glm_offline_profile_fails_closed_without_override(self) -> None:
        route = self._hardened_glm_route()
        args = self._hardened_glm_args()
        args.allow_offline_access_profile = False
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k-offline",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )

        with self.assertRaises(SystemExit) as context:
            execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertIn("marked offline", str(context.exception))

    def test_hardened_glm_preflight_strips_separate_reasoning_and_completes(self) -> None:
        route = self._hardened_glm_route()
        args = self._hardened_glm_args()
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )
        opener = FakeHardenedOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertTrue(opener.chat_called)
        self.assertEqual(opener.payload["model"], "glm-5.2-bf16-256k")
        self.assertEqual(opener.payload["max_tokens"], 8192)
        self.assertEqual(response["model_preflight"]["status"], "passed")
        self.assertLessEqual(response["model_preflight"]["to_post_ms"], 1000)
        self.assertEqual(opener.correlation_ids, ["dispatch-glm-256k", "dispatch-glm-256k"])
        self.assertEqual(response["response_model_status"], "matched")
        self.assertEqual(response["completion_status"], "completed")
        self.assertTrue(response["usable_final_content"])
        self.assertEqual(response["final_content"], "useful final")
        self.assertTrue(response["reasoning_stripped"])
        self.assertNotIn("reasoning_content", json.dumps(response))
        self.assertNotIn("private separate reasoning", json.dumps(response))

        telemetry = local_response_telemetry(response)
        self.assertEqual(telemetry["agent_model_calls"], 1)
        self.assertEqual(telemetry["attempted_model_calls"], 1)
        self.assertEqual(telemetry["incomplete_model_calls"], 0)
        self.assertEqual(telemetry["completion_status"], "completed")
        self.assertEqual(telemetry["preflight_attempts"], 1)
        self.assertEqual(telemetry["preflight_successes"], 1)
        self.assertEqual(telemetry["post_attempts"], 1)
        self.assertEqual(telemetry["usable_post_responses"], 1)
        self.assertEqual(telemetry["incomplete_post_responses"], 0)
        compact = compact_local_response(response)
        self.assertNotIn("response", compact)
        self.assertEqual(compact["final_content"], "useful final")

    def test_hardened_glm_reasoning_only_is_incomplete_and_not_counted(self) -> None:
        route = self._hardened_glm_route()
        args = self._hardened_glm_args()
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k-reasoning-only",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )
        opener = FakeHardenedOpener(reasoning_only=True)
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(response["completion_status"], "empty-final-content")
        self.assertFalse(response["usable_final_content"])
        self.assertEqual(response["final_content"], "")
        self.assertNotIn("private reasoning only", json.dumps(response))
        telemetry = local_response_telemetry(response)
        self.assertEqual(telemetry["agent_model_calls"], 0)
        self.assertEqual(telemetry["attempted_model_calls"], 1)
        self.assertEqual(telemetry["incomplete_model_calls"], 1)
        self.assertEqual(telemetry["telemetry_status"], "failed")

    def test_hardened_glm_reasoning_only_length_is_output_budget_exhausted(self) -> None:
        sanitized, metadata = sanitize_local_response_payload(
            {
                "model": "glm-5.2-bf16-256k",
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {
                            "content": None,
                            "reasoning_content": "private budget-exhausted reasoning",
                        },
                    }
                ],
            },
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertEqual(metadata["completion_status"], "output-budget-exhausted")
        self.assertFalse(metadata["usable_final_content"])
        self.assertTrue(metadata["response_truncated"])
        self.assertNotIn("private budget-exhausted reasoning", json.dumps(sanitized))

    def test_hardened_glm_preflight_model_mismatch_blocks_chat(self) -> None:
        route = self._hardened_glm_route()
        args = self._hardened_glm_args()
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k-wrong-model",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )
        opener = FakeHardenedOpener(wrong_model=True)
        with patch("dispatch_work.request.build_opener", return_value=opener):
            with self.assertRaises(SystemExit) as context:
                execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertIn("exact requested model", str(context.exception))
        self.assertFalse(opener.chat_called)

    def test_hardened_glm_expired_preflight_blocks_chat(self) -> None:
        route = self._hardened_glm_route()
        args = self._hardened_glm_args()
        envelope = build_local_envelope(
            task="Compact independent architecture review.",
            route=route,
            dispatch_id="dispatch-glm-256k-expired",
            bead_id="cwo-glm-256k",
            epic_id=None,
            args=args,
        )
        opener = FakeHardenedOpener()
        monotonic_values = [0.0, 0.1, 0.2, 0.2, 1.5]
        with patch("dispatch_work.request.build_opener", return_value=opener):
            with patch("dispatch_work.time.monotonic", side_effect=monotonic_values):
                with self.assertRaises(SystemExit) as context:
                    execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertIn("preflight expired", str(context.exception))
        self.assertFalse(opener.chat_called)

    def test_hardened_glm_malformed_think_tag_is_not_usable(self) -> None:
        payload = {
            "model": "glm-5.2-bf16-256k",
            "choices": [
                {"finish_reason": "stop", "message": {"content": "<think>private unfinished"}}
            ],
        }
        sanitized, metadata = sanitize_local_response_payload(
            payload,
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertEqual(metadata["completion_status"], "malformed-response")
        self.assertFalse(metadata["usable_final_content"])
        self.assertNotIn("private unfinished", json.dumps(sanitized))

    def test_hardened_glm_unicode_reasoning_key_is_removed(self) -> None:
        payload = {
            "model": "glm-5.2-bf16-256k",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": "useful final",
                        "ｒｅａｓｏｎｉｎｇ＿ｃｏｎｔｅｎｔ": "private unicode-key reasoning",
                    },
                }
            ],
        }
        sanitized, metadata = sanitize_local_response_payload(
            payload,
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertEqual(metadata["completion_status"], "completed")
        self.assertTrue(metadata["reasoning_stripped"])
        self.assertNotIn("private unicode-key reasoning", json.dumps(sanitized))

    def test_hardened_glm_tool_payload_is_removed_and_fails_closed(self) -> None:
        payload = {
            "model": "glm-5.2-bf16-256k",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": "apparently useful final",
                        "tool_calls": [
                            {"function": {"name": "x", "arguments": "private tool reasoning"}}
                        ],
                    },
                }
            ],
        }
        sanitized, metadata = sanitize_local_response_payload(
            payload,
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertEqual(metadata["completion_status"], "malformed-response")
        self.assertFalse(metadata["usable_final_content"])
        self.assertEqual(metadata["forbidden_response_fields"], ["tool_calls"])
        self.assertNotIn("private tool reasoning", json.dumps(sanitized))

    def test_hardened_glm_requires_exactly_one_choice(self) -> None:
        for choices in ([], [{"finish_reason": "stop", "message": {"content": "one"}}, {"finish_reason": "stop", "message": {"content": "two"}}]):
            with self.subTest(choice_count=len(choices)):
                _, metadata = sanitize_local_response_payload(
                    {"model": "glm-5.2-bf16-256k", "choices": choices},
                    "glm-think-tags",
                    required_finish_reason="stop",
                )
                self.assertEqual(metadata["completion_status"], "malformed-response")
                self.assertFalse(metadata["usable_final_content"])

    def test_hardened_glm_top_level_error_is_hashed_not_retained(self) -> None:
        sanitized, metadata = sanitize_local_response_payload(
            {
                "error": {"message": "private provider error detail"},
                "choices": [{"finish_reason": "stop", "message": {"content": "misleading final"}}],
            },
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertTrue(metadata["provider_error_present"])
        self.assertIsNotNone(metadata["provider_error_sha256"])
        self.assertEqual(metadata["completion_status"], "malformed-response")
        self.assertNotIn("private provider error detail", json.dumps(sanitized))

    def test_hardened_glm_compact_cli_emits_only_final_and_telemetry(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), HardenedGLMHTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8") as task_file:
                task_file.write(
                    "Use exact GLM-5.2 BF16 256K thinking as an independent architecture critic second opinion."
                )
                task_file.flush()
                result = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        str(ROOT / "scripts" / "dispatch_work.py"),
                        "--file",
                        task_file.name,
                        "--local-ok",
                        "--local-profile",
                        "openshift-ai-glm-256k",
                        "--local-base-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--execute-local",
                        "--allow-offline-access-profile",
                        "--no-audit",
                        "--waiver-reason",
                        "focused compact CLI test uses offline profile and no-audit",
                        "--rehearsal",
                        "--requested-role",
                        "architecture",
                        "--local-result-view",
                        "compact",
                        "--json",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=20,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = json.loads(result.stdout)
        self.assertEqual(artifact["local_response"]["final_content"], "compact final")
        self.assertNotIn("response", artifact["local_response"])
        self.assertNotIn("messages", artifact["local_envelope"])
        self.assertEqual(artifact["local_telemetry"]["completion_status"], "completed")
        rendered = json.dumps(artifact)
        self.assertNotIn("never retain this reasoning", rendered)
        self.assertNotIn("reasoning_content", rendered)

    def test_glm_offline_access_profile_fails_closed_without_override(self) -> None:
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
            local_max_tokens=None,
            local_thinking="default",
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
        with self.assertRaises(SystemExit) as context:
            execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertIn("marked offline", str(context.exception))

    def test_glm_envelope_and_payload_preserve_default_request_options(self) -> None:
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
            local_max_tokens=None,
            local_thinking="default",
            allow_offline_access_profile=True,
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
        self.assertEqual(
            envelope["request_options"],
            {"chat_template_kwargs": {"enable_thinking": True}, "max_tokens": 4096},
        )

        opener = FakePayloadOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(opener.payload["chat_template_kwargs"], {"enable_thinking": True})
        self.assertEqual(opener.payload.get("max_tokens"), 4096)
        self.assertEqual(response["status_code"], 200)

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
            allow_offline_access_profile=True,
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
            allow_offline_access_profile=True,
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

    def test_local_dispatch_respects_local_max_tokens_override(self) -> None:
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
            local_max_tokens=1234,
            local_thinking="default",
            allow_offline_access_profile=True,
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
        self.assertEqual(
            envelope["request_options"],
            {"chat_template_kwargs": {"enable_thinking": True}, "max_tokens": 1234},
        )
        opener = FakePayloadOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(opener.payload["max_tokens"], 1234)
        self.assertEqual(opener.payload["chat_template_kwargs"]["enable_thinking"], True)

    def test_local_dispatch_respects_local_thinking_on_and_off_overrides(self) -> None:
        route = classify_work(
            "Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-vllm",
            requested_roles=["architecture"],
        )
        with self.subTest("off"):
            args = Namespace(
                local_api_key_env=None,
                local_timeout=None,
                local_base_url="http://127.0.0.1:8000",
                local_model=None,
                local_allow_private_dns=False,
                local_ca_bundle=None,
                local_insecure_tls=False,
                local_max_tokens=None,
                local_thinking="off",
                allow_offline_access_profile=True,
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
            self.assertEqual(envelope["request_options"]["chat_template_kwargs"]["enable_thinking"], False)

            opener = FakePayloadOpener()
            with patch("dispatch_work.request.build_opener", return_value=opener):
                execute_local_envelope(envelope, route["selected_executor"], args)
            self.assertEqual(opener.payload["chat_template_kwargs"]["enable_thinking"], False)

        with self.subTest("on"):
            args = Namespace(
                local_api_key_env=None,
                local_timeout=None,
                local_base_url="http://127.0.0.1:8000",
                local_model=None,
                local_allow_private_dns=False,
                local_ca_bundle=None,
                local_insecure_tls=False,
                local_max_tokens=None,
                local_thinking="on",
                allow_offline_access_profile=True,
                execute_local=True,
            )
            envelope = build_local_envelope(
                task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
                route=route,
                dispatch_id="dispatch-glm-test-on",
                bead_id="cwo-glm",
                epic_id=None,
                args=args,
            )
            self.assertEqual(envelope["request_options"]["chat_template_kwargs"]["enable_thinking"], True)

            opener = FakePayloadOpener()
            with patch("dispatch_work.request.build_opener", return_value=opener):
                execute_local_envelope(envelope, route["selected_executor"], args)
            self.assertEqual(opener.payload["chat_template_kwargs"]["enable_thinking"], True)

    def test_local_dispatch_combined_max_tokens_and_thinking_override(self) -> None:
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
            local_max_tokens=4096,
            local_thinking="off",
            allow_offline_access_profile=True,
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
        self.assertEqual(
            envelope["request_options"],
            {"chat_template_kwargs": {"enable_thinking": False}, "max_tokens": 4096},
        )
        opener = FakePayloadOpener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(opener.payload["max_tokens"], 4096)
        self.assertEqual(opener.payload["chat_template_kwargs"]["enable_thinking"], False)

    def test_local_dispatch_rejects_non_positive_max_tokens(self) -> None:
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
            local_max_tokens=0,
            local_thinking="default",
            execute_local=True,
        )
        with self.assertRaises(SystemExit):
            build_local_envelope(
                task="Use GLM-5.2 BF16 thinking as an independent architecture critic second opinion.",
                route=route,
                dispatch_id="dispatch-glm-test",
                bead_id="cwo-glm",
                epic_id=None,
                args=args,
            )

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
            allow_offline_access_profile=True,
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
