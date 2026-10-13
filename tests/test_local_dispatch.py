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
    GLM_CRITIC_JSON_SCHEMA,
    GLM_CRITIC_V1_JSON_SCHEMA,
    build_local_envelope,
    compact_local_envelope,
    compact_local_response,
    compact_local_route,
    endpoint_url,
    execute_local_envelope,
    local_response_telemetry,
    local_execution_exit_code,
    local_response_contract_prompt,
    _read_local_http_response,
    pinned_local_endpoint_address,
    sanitize_local_response_payload,
    validate_local_response_contract,
    validate_local_endpoint_base_url,
)
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.return_sections import parse_return_sections  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402


def _bounded_bytes(data: bytes, size: int | None) -> bytes:
    return data if size is None else data[:size]


class FakeResponse:
    status = 200

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}', size)


class FakeThinkingResponse(FakeResponse):
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes((
            b'{"choices":[{"message":{"content":"<think>private reasoning</think>GLM final"}}],'
            b'"usage":{"prompt_tokens":13,"completion_tokens":9,"total_tokens":22}}'
        ), size)


class FakeTruncatedThinkingResponse(FakeResponse):
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes((
            b'{"choices":[{"finish_reason":"length","message":{"content":"<think>private reasoning</think>partial"}}],'
            b'"usage":{"prompt_tokens":13,"completion_tokens":9}}'
        ), size)


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
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(b'{"object":"list","data":[{"id":"glm-5.2-bf16-256k","object":"model"}]}', size)


class FakeWrongModelsResponse(FakeResponse):
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(b'{"object":"list","data":[{"id":"glm-5.2-bf16-128k","object":"model"}]}', size)


class FakeHardenedThinkingResponse(FakeResponse):
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes((
            b'{"model":"glm-5.2-bf16-256k","choices":[{"finish_reason":"stop",'
            b'"message":{"content":"useful final","reasoning_content":"private separate reasoning"}}],'
            b'"usage":{"prompt_tokens":31,"completion_tokens":17,"total_tokens":48}}'
        ), size)


class FakeReasoningOnlyResponse(FakeResponse):
    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes((
            b'{"model":"glm-5.2-bf16-256k","choices":[{"finish_reason":"stop",'
            b'"message":{"content":null,"reasoning_content":"private reasoning only"}}],'
            b'"usage":{"prompt_tokens":31,"completion_tokens":8192,"total_tokens":8223}}'
        ), size)


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


GLM53_VALID_REVIEW = {
    "verdict": "revise",
    "summary": "The plan needs one bounded correction.",
    "findings": [
        {
            "severity": "high",
            "claim": "The packet couples unrelated decisions.",
            "evidence": "The supplied packet assigns both transport and release changes to one step.",
            "repair": "Split transport readiness from release adjudication.",
        }
    ],
    "alternatives": ["Keep the monolith, rejected because one failure discards all evidence."],
    "risks": ["The smaller contract covers fewer secondary observations."],
    "confidence": "high",
    "recommended_next_action": "Create one bounded transport repair bead.",
    "escalation_needed": "none",
}


class FakeGLM53Response(FakeResponse):
    def __init__(
        self,
        content: str,
        *,
        finish_reason: str = "stop",
        model: str = "glm-5.3-bf16",
    ) -> None:
        self.content = content
        self.finish_reason = finish_reason
        self.model = model

    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(json.dumps(
            {
                "model": self.model,
                "choices": [
                    {
                        "finish_reason": self.finish_reason,
                        "message": {
                            "content": self.content,
                            "reasoning": "private reasoning must be stripped",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
            }
        ).encode("utf-8"), size)


class FakeRawResponse(FakeResponse):
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(self.raw, size)


class FakeGLM53Opener:
    def __init__(
        self,
        *,
        content: str | None = None,
        finish_reason: str = "stop",
        response_model: str = "glm-5.3-bf16",
        raw_chat_response: bytes | None = None,
    ) -> None:
        self.content = (
            content
            if content is not None
            else json.dumps(GLM53_VALID_REVIEW, separators=(",", ":"))
        )
        self.finish_reason = finish_reason
        self.response_model = response_model
        self.raw_chat_response = raw_chat_response
        self.urls: list[str] = []
        self.headers: list[dict[str, str]] = []
        self.payload: dict[str, object] | None = None

    def open(self, req: object, **kwargs: object) -> FakeResponse:
        url = str(getattr(req, "full_url", ""))
        self.urls.append(url)
        self.headers.append(
            {str(key).lower(): str(value) for key, value in req.header_items()}  # type: ignore[attr-defined]
        )
        if url.endswith("/v1/models"):
            return FakeRawResponse(b'{"object":"list","data":[{"id":"glm-5.3-bf16"}]}')
        self.payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
        if self.raw_chat_response is not None:
            return FakeRawResponse(self.raw_chat_response)
        return FakeGLM53Response(
            self.content,
            finish_reason=self.finish_reason,
            model=self.response_model,
        )


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

    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(b'{"choices":[{"message":{"content":"redirected content"}}]}', size)


class FakeRedirectOpener:
    def open(self, *args: object, **kwargs: object) -> FakeRedirectResponse:
        return FakeRedirectResponse()


class BoundedResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name) if self.headers is not None else None

    def read(self, size: int | None = None) -> bytes:
        return _bounded_bytes(self.body, size)


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


class InvalidGLM53HTTPHandler(BaseHTTPRequestHandler):
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
        self._send({"object": "list", "data": [{"id": "glm-5.3-bf16"}]})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self._send(
            {
                "model": "glm-5.3-bf16",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "not a JSON critic return"},
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

    def _glm53_route(self) -> dict[str, object]:
        return classify_work(
            "Use exact GLM-5.3 BF16 as an independent architecture critic second opinion.",
            local_ok=True,
            local_profile="openshift-ai-glm-5-3-direct",
            requested_roles=["architecture"],
        )

    def _glm53_args(self) -> Namespace:
        return Namespace(
            local_api_key_env=None,
            local_timeout=None,
            local_base_url="http://127.0.0.1:8000/v1",
            local_model=None,
            local_allow_private_dns=False,
            local_ca_bundle=None,
            local_insecure_tls=False,
            local_max_tokens=None,
            local_thinking="default",
            allow_offline_access_profile=False,
            execute_local=True,
        )

    def test_bounded_local_response_accepts_absent_getheader_headers(self) -> None:
        response = BoundedResponse(b"ok")
        response.headers = None
        self.assertEqual(
            _read_local_http_response(response, cap=8, phase="test"), b"ok"
        )

    def test_bounded_local_response_accepts_absent_mapping_headers(self) -> None:
        response = BoundedResponse(b"ok")
        response.getheader = None  # type: ignore[method-assign]
        response.headers = {}
        self.assertEqual(
            _read_local_http_response(response, cap=8, phase="test"), b"ok"
        )

    def test_bounded_local_response_accepts_valid_content_length(self) -> None:
        response = BoundedResponse(b"okay", {"Content-Length": "4"})
        self.assertEqual(
            _read_local_http_response(response, cap=8, phase="test"), b"okay"
        )

    def test_bounded_local_response_rejects_malformed_content_length(self) -> None:
        response = BoundedResponse(b"okay", {"Content-Length": "four"})
        with self.assertRaisesRegex(SystemExit, "malformed Content-Length"):
            _read_local_http_response(response, cap=8, phase="test")

    def test_bounded_local_response_rejects_conflicting_framing(self) -> None:
        response = BoundedResponse(
            b"okay", {"Content-Length": "4", "Transfer-Encoding": "chunked"}
        )
        with self.assertRaisesRegex(SystemExit, "conflicting framing"):
            _read_local_http_response(response, cap=8, phase="test")

    def test_bounded_local_response_rejects_unsupported_content_encoding(self) -> None:
        response = BoundedResponse(b"okay", {"Content-Encoding": "gzip"})
        with self.assertRaisesRegex(SystemExit, "unsupported content encoding"):
            _read_local_http_response(response, cap=8, phase="test")

    def test_bounded_local_response_rejects_premature_eof(self) -> None:
        response = BoundedResponse(b"ok", {"Content-Length": "4"})
        with self.assertRaisesRegex(SystemExit, "ended before Content-Length"):
            _read_local_http_response(response, cap=8, phase="test")

    def test_bounded_local_response_rejects_response_over_cap(self) -> None:
        response = BoundedResponse(b"12345")
        with self.assertRaisesRegex(SystemExit, "exceeded response cap"):
            _read_local_http_response(response, cap=4, phase="test")

    def test_endpoint_url_accepts_origin_or_v1_base_without_duplication(self) -> None:
        self.assertEqual(
            endpoint_url("https://example.invalid", "/v1/models"),
            "https://example.invalid/v1/models",
        )
        self.assertEqual(
            endpoint_url("https://example.invalid/v1", "/v1/models"),
            "https://example.invalid/v1/models",
        )

    def test_glm53_compact_contract_validation_is_exact(self) -> None:
        parsed, errors = validate_local_response_contract(
            json.dumps(GLM53_VALID_REVIEW, separators=(",", ":")),
            "cwo-glm-critic-v1",
        )
        self.assertEqual(errors, [])
        self.assertEqual(parsed, GLM53_VALID_REVIEW)
        parsed, errors = validate_local_response_contract(
            json.dumps(GLM53_VALID_REVIEW),
            "cwo-glm-critic-v1",
        )
        self.assertEqual(errors, [])
        self.assertEqual(parsed, GLM53_VALID_REVIEW)
        invalid = dict(GLM53_VALID_REVIEW)
        invalid["unexpected"] = True
        parsed, errors = validate_local_response_contract(
            json.dumps(invalid, separators=(",", ":")),
            "cwo-glm-critic-v1",
        )
        self.assertIsNone(parsed)
        self.assertIn("fields do not exactly match", " ".join(errors))

        too_many = json.loads(json.dumps(GLM53_VALID_REVIEW))
        too_many["findings"] = too_many["findings"] * 4
        parsed, errors = validate_local_response_contract(
            json.dumps(too_many, separators=(",", ":")),
            "cwo-glm-critic-v1",
        )
        self.assertIsNone(parsed)
        self.assertIn("one to 3", " ".join(errors))

        too_long = json.loads(json.dumps(GLM53_VALID_REVIEW))
        too_long["findings"][0]["claim"] = "x" * 301
        parsed, errors = validate_local_response_contract(
            json.dumps(too_long, separators=(",", ":")),
            "cwo-glm-critic-v1",
        )
        self.assertIsNone(parsed)
        self.assertIn("finding 0 claim", " ".join(errors))

    def test_glm53_v2_uses_one_aggregate_bound_without_reinterpreting_v1(self) -> None:
        review = json.loads(json.dumps(GLM53_VALID_REVIEW))
        review["findings"][0]["evidence"] = "e" * 600
        review["risks"] = ["r" * 241]
        rendered = json.dumps(review, ensure_ascii=False, separators=(",", ":"))

        parsed_v1, errors_v1 = validate_local_response_contract(
            rendered,
            "cwo-glm-critic-v1",
        )
        parsed_v2, errors_v2 = validate_local_response_contract(
            rendered,
            "cwo-glm-critic-v2",
        )
        self.assertIsNone(parsed_v1)
        self.assertTrue(errors_v1)
        self.assertEqual(errors_v2, [])
        self.assertEqual(parsed_v2, review)
        self.assertEqual(
            GLM_CRITIC_V1_JSON_SCHEMA["properties"]["findings"]["items"]["properties"]["evidence"]["maxLength"],
            300,
        )
        self.assertNotIn(
            "maxLength",
            GLM_CRITIC_JSON_SCHEMA["properties"]["findings"]["items"]["properties"]["evidence"],
        )

        exactly_at_bound = rendered + (" " * (6000 - len(rendered)))
        parsed, errors = validate_local_response_contract(
            exactly_at_bound,
            "cwo-glm-critic-v2",
        )
        self.assertEqual(len(exactly_at_bound), 6000)
        self.assertEqual(errors, [])
        self.assertEqual(parsed, review)
        parsed, errors = validate_local_response_contract(
            exactly_at_bound + " ",
            "cwo-glm-critic-v2",
        )
        self.assertIsNone(parsed)
        self.assertEqual(errors, ["final content exceeds max_final_chars=6000"])

    def test_glm53_contract_json_is_strict_total_and_unicode_safe(self) -> None:
        rendered = json.dumps(GLM53_VALID_REVIEW, ensure_ascii=False, separators=(",", ":"))
        duplicate_cases = [
            rendered.replace(
                '"verdict":"revise"',
                '"verdict":"approve","verdict":"revise"',
                1,
            ),
            rendered.replace(
                '"severity":"high"',
                '"severity":"low","severity":"high"',
                1,
            ),
            rendered.replace(
                '"verdict":"revise"',
                '"verdict":"approve","ver\\u0064ict":"revise"',
                1,
            ),
        ]
        for duplicate in duplicate_cases:
            with self.subTest(duplicate=duplicate[:80]):
                parsed, errors = validate_local_response_contract(
                    duplicate,
                    "cwo-glm-critic-v2",
                )
                self.assertIsNone(parsed)
                self.assertIn("duplicate JSON object key", " ".join(errors))

        for field, value in (("verdict", []), ("confidence", {})):
            with self.subTest(field=field):
                invalid = json.loads(json.dumps(GLM53_VALID_REVIEW))
                invalid[field] = value
                parsed, errors = validate_local_response_contract(
                    json.dumps(invalid),
                    "cwo-glm-critic-v2",
                )
                self.assertIsNone(parsed)
                self.assertTrue(errors)

        non_finite = rendered.replace(
            '"summary":"The plan needs one bounded correction."',
            '"summary":NaN',
        )
        parsed, errors = validate_local_response_contract(non_finite, "cwo-glm-critic-v2")
        self.assertIsNone(parsed)
        self.assertIn("non-finite", " ".join(errors))

        invalid_unicode = json.loads(json.dumps(GLM53_VALID_REVIEW))
        invalid_unicode["summary"] = "bad\ud800text"
        parsed, errors = validate_local_response_contract(
            json.dumps(invalid_unicode),
            "cwo-glm-critic-v2",
        )
        self.assertIsNone(parsed)
        self.assertIn("invalid Unicode", " ".join(errors))

        valid_unicode = json.loads(json.dumps(GLM53_VALID_REVIEW))
        valid_unicode["summary"] = "Café evidence remains valid 🧪."
        parsed, errors = validate_local_response_contract(
            json.dumps(valid_unicode, ensure_ascii=False),
            "cwo-glm-critic-v2",
        )
        self.assertEqual(errors, [])
        self.assertEqual(parsed, valid_unicode)

    def test_glm53_rejects_dangerous_controls_before_rendering(self) -> None:
        review = json.loads(json.dumps(GLM53_VALID_REVIEW))
        review["findings"][0]["evidence"] = "alpha\u202ebeta"
        content = json.dumps(review, separators=(",", ":"))
        parsed, errors = validate_local_response_contract(content, "cwo-glm-critic-v2")
        self.assertIsNone(parsed)
        self.assertEqual(errors, ["final content contains dangerous Unicode controls"])

        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-control",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(content=content)
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["completion_status"], "content-unsafe")
        self.assertFalse(response["usable_final_content"])
        self.assertEqual(response["final_content"], "")
        self.assertEqual(response["response"]["choices"][0]["message"]["content"], "")
        self.assertNotIn("alpha", json.dumps(response))

    def test_glm53_literal_reasoning_tags_inside_json_are_data(self) -> None:
        review = json.loads(json.dumps(GLM53_VALID_REVIEW))
        review["findings"][0]["evidence"] = (
            "The literal examples <think>draft</think> and </reasoning> occur in supplied text."
        )
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-tag-data",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(
            content=json.dumps(review, ensure_ascii=False, separators=(",", ":"))
        )
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertTrue(response["usable_final_content"])
        self.assertFalse(response["reasoning_malformed"])
        self.assertIn(r"<think>draft</think>", response["normalized_return"])

    def test_glm53_realistic_multiconcern_review_passes_v2_end_to_end(self) -> None:
        review = json.loads(json.dumps(GLM53_VALID_REVIEW))
        review["summary"] = "Causal repair is required across the bounded controller path. " * 8
        review["findings"][0]["claim"] = "The admission and final eligibility decisions diverge. " * 10
        review["findings"][0]["evidence"] = "Recorded evidence connects the producer, consumer, wrapper, and final decision. " * 18
        review["findings"][0]["repair"] = "Unify the decision and retain fail-closed rejection at every consumer. " * 12
        review["risks"] = ["A stale wrapper could still misclassify an unusable result. " * 8]
        review["recommended_next_action"] = "Run the complete deterministic validation transaction. " * 8
        content = json.dumps(review, ensure_ascii=False, separators=(",", ":"))
        self.assertGreater(len(content), 3000)
        self.assertLess(len(content), 6000)
        parsed_v1, _ = validate_local_response_contract(content, "cwo-glm-critic-v1")
        self.assertIsNone(parsed_v1)

        route = self._glm53_route()
        args = self._glm53_args()
        task = "Review a multi-concern architecture packet. " + ("Bound fact. " * 500)
        envelope = build_local_envelope(
            task=task,
            route=route,
            dispatch_id="dispatch-glm53-realistic",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(content=content)
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["response_contract"], "cwo-glm-critic-v2")
        self.assertEqual(response["response_contract_status"], "valid")
        self.assertTrue(response["usable_final_content"])
        self.assertIsNotNone(response["normalized_return"])

    def test_glm53_execution_revalidates_envelope_at_request_boundary(self) -> None:
        mutations = {
            "grammar": lambda envelope: envelope["request_options"].__setitem__("response_format", None),
            "reserved-model": lambda envelope: envelope["request_options"].__setitem__("model", "other"),
            "contract": lambda envelope: envelope.__setitem__("response_contract", "cwo-glm-critic-v1"),
            "messages": lambda envelope: envelope["messages"][1].__setitem__("content", "changed"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                route = self._glm53_route()
                args = self._glm53_args()
                envelope = build_local_envelope(
                    task="Review one bounded architecture concern.",
                    route=route,
                    dispatch_id=f"dispatch-glm53-binding-{name}",
                    bead_id="cwo-glm53",
                    epic_id=None,
                    args=args,
                )
                mutate(envelope)
                opener = FakeGLM53Opener()
                with patch("dispatch_work.request.build_opener", return_value=opener):
                    with self.assertRaises(SystemExit):
                        execute_local_envelope(envelope, route["selected_executor"], args)
                self.assertEqual(opener.urls, [])

    def test_glm53_execution_reloads_authoritative_executor_policy(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-policy-reload",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        selected = json.loads(json.dumps(route["selected_executor"]))
        selected["transport"].pop("forbidden_request_options")
        selected["transport"].pop("allowed_request_options")
        selected["transport"]["request_options"]["response_format"] = None
        envelope["forbidden_request_options"] = None
        envelope["allowed_request_options"] = None
        envelope["request_options"]["response_format"] = None
        opener = FakeGLM53Opener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(SystemExit, "changed after policy routing"):
                execute_local_envelope(envelope, selected, args)
        self.assertEqual(opener.urls, [])

    def test_glm53_execution_rejects_post_build_transport_or_tls_drift(self) -> None:
        for name, mutate, error in (
            (
                "endpoint",
                lambda args: setattr(args, "local_base_url", "http://127.0.0.1:9000"),
                "transport changed after construction",
            ),
            (
                "tls",
                lambda args: setattr(args, "local_insecure_tls", True),
                "TLS settings changed after construction",
            ),
        ):
            with self.subTest(name=name):
                route = self._glm53_route()
                args = self._glm53_args()
                envelope = build_local_envelope(
                    task="Review one bounded architecture concern.",
                    route=route,
                    dispatch_id=f"dispatch-glm53-drift-{name}",
                    bead_id="cwo-glm53",
                    epic_id=None,
                    args=args,
                )
                mutate(args)
                opener = FakeGLM53Opener()
                with patch("dispatch_work.request.build_opener", return_value=opener):
                    with self.assertRaisesRegex(SystemExit, error):
                        execute_local_envelope(envelope, route["selected_executor"], args)
                self.assertEqual(opener.urls, [])

    def test_glm53_noauth_profile_rejects_override_and_ignores_shared_key(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        args.local_api_key_env = "CWO_LOCAL_OPENAI_API_KEY"
        with self.assertRaisesRegex(SystemExit, "no-auth"):
            build_local_envelope(
                task="Review one bounded architecture concern.",
                route=route,
                dispatch_id="dispatch-glm53-auth-override",
                bead_id="cwo-glm53",
                epic_id=None,
                args=args,
            )

        args.local_api_key_env = None
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-auth-shared",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener()
        with patch.dict(os.environ, {"CWO_LOCAL_OPENAI_API_KEY": "must-not-be-sent"}):
            with patch("dispatch_work.request.build_opener", return_value=opener):
                execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertTrue(all("authorization" not in headers for headers in opener.headers))

    def test_glm53_duplicate_outer_keys_and_invalid_utf8_fail_closed(self) -> None:
        content = json.dumps(GLM53_VALID_REVIEW, separators=(",", ":"))
        duplicate_outer = (
            '{"model":"glm-5.3-bf16","choices":[{"finish_reason":"stop","message":'
            '{"tool_calls":[{"id":"hidden"}],"tool_calls":[],"content":'
            + json.dumps(content)
            + '}}]}'
        ).encode("utf-8")
        for name, raw in (("duplicate", duplicate_outer), ("utf8", b"\xff")):
            with self.subTest(name=name):
                route = self._glm53_route()
                args = self._glm53_args()
                envelope = build_local_envelope(
                    task="Review one bounded architecture concern.",
                    route=route,
                    dispatch_id=f"dispatch-glm53-outer-{name}",
                    bead_id="cwo-glm53",
                    epic_id=None,
                    args=args,
                )
                opener = FakeGLM53Opener(raw_chat_response=raw)
                with patch("dispatch_work.request.build_opener", return_value=opener):
                    response = execute_local_envelope(envelope, route["selected_executor"], args)
                self.assertFalse(response["usable_final_content"])
                self.assertIsNone(response["normalized_return"])
                self.assertEqual(response["final_content"], "")
                self.assertNotIn("hidden", json.dumps(response))

    def test_glm53_all_unusable_complete_content_is_quarantined(self) -> None:
        for name, finish_reason, response_model in (
            ("length", "length", "glm-5.3-bf16"),
            ("model", "stop", "unexpected-model"),
        ):
            with self.subTest(name=name):
                route = self._glm53_route()
                args = self._glm53_args()
                envelope = build_local_envelope(
                    task="Review one bounded architecture concern.",
                    route=route,
                    dispatch_id=f"dispatch-glm53-unusable-{name}",
                    bead_id="cwo-glm53",
                    epic_id=None,
                    args=args,
                )
                opener = FakeGLM53Opener(
                    finish_reason=finish_reason,
                    response_model=response_model,
                )
                with patch("dispatch_work.request.build_opener", return_value=opener):
                    response = execute_local_envelope(envelope, route["selected_executor"], args)
                self.assertFalse(response["usable_final_content"])
                self.assertEqual(response["final_content"], "")
                self.assertEqual(response["response"]["choices"][0]["message"]["content"], "")
                self.assertIsNone(response["normalized_return"])
                self.assertIsNotNone(response["quarantined_content_sha256"])
                self.assertEqual(local_execution_exit_code(response), 4)

    def test_glm53_excessive_nested_provider_data_is_classified(self) -> None:
        nested: object = "leaf"
        for _ in range(70):
            nested = [nested]
        sanitized, metadata = sanitize_local_response_payload(
            {"extension": nested},
            "glm-think-tags",
            required_finish_reason="stop",
        )
        self.assertEqual(sanitized, {})
        self.assertEqual(metadata["completion_status"], "malformed-response")
        self.assertFalse(metadata["usable_final_content"])
        self.assertIn("depth", metadata["payload_validation_error"])

    def test_glm53_input_hard_boundary_is_exact(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="x" * 16000,
            route=route,
            dispatch_id="dispatch-glm53-input-boundary",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        self.assertEqual(envelope["max_input_chars"], 16000)
        with self.assertRaisesRegex(SystemExit, "max_input_chars=16000"):
            build_local_envelope(
                task="x" * 16001,
                route=route,
                dispatch_id="dispatch-glm53-input-over",
                bead_id="cwo-glm53",
                epic_id=None,
                args=args,
            )
        with self.assertRaisesRegex(SystemExit, "valid UTF-8"):
            build_local_envelope(
                task="bad\ud800task",
                route=route,
                dispatch_id="dispatch-glm53-input-unicode",
                bead_id="cwo-glm53",
                epic_id=None,
                args=args,
            )

    def test_glm53_pipeline_counts_trailing_whitespace_in_final_bound(self) -> None:
        compact = json.dumps(GLM53_VALID_REVIEW, separators=(",", ":"))
        oversized = compact + (" " * (6001 - len(compact)))
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-final-over",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(content=oversized)
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["completion_status"], "contract-invalid")
        self.assertEqual(
            response["response_contract_errors"],
            ["final content exceeds max_final_chars=6000"],
        )
        self.assertEqual(response["quarantined_content_chars"], 6001)
        self.assertEqual(response["final_content"], "")

    def test_glm53_cli_emits_failure_artifact_then_exits_nonzero(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), InvalidGLM53HTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8") as task_file:
                task_file.write(
                    "Use exact GLM-5.3 BF16 as an independent architecture critic second opinion."
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
                        "openshift-ai-glm-5-3-direct",
                        "--local-base-url",
                        f"http://127.0.0.1:{server.server_port}",
                        "--execute-local",
                        "--no-audit",
                        "--waiver-reason",
                        "focused GLM failure-exit rehearsal",
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

        self.assertEqual(result.returncode, 4, result.stderr)
        artifact = json.loads(result.stdout)
        self.assertFalse(artifact["local_response"]["usable_final_content"])
        self.assertEqual(artifact["local_response"]["final_content"], "")
        self.assertIsNone(artifact["local_response"]["normalized_return"])

    def test_glm53_envelope_and_execution_are_compact_exact_and_no_auth(self) -> None:
        route = self._glm53_route()
        self.assertEqual(route["recommended_executor"], "rhoai_glm_compact_architecture_critic")
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review the supplied architecture plan and identify the highest-impact corrections.",
            route=route,
            dispatch_id="dispatch-glm53",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        self.assertEqual(envelope["model"], "glm-5.3-bf16")
        self.assertEqual(envelope["access_profile"], "rhoai-glm-5-3-direct")
        self.assertEqual(envelope["response_contract"], "cwo-glm-critic-v2")
        self.assertEqual(envelope["auth_mode"], "none")
        self.assertEqual(envelope["request_options"]["reasoning_effort"], "low")
        self.assertTrue(envelope["request_options"]["include_reasoning"])
        self.assertNotIn("chat_template_kwargs", envelope["request_options"])
        system_prompt = envelope["messages"][0]["content"]
        self.assertIn('"findings"', system_prompt)
        self.assertIn('"recommended_next_action"', system_prompt)
        self.assertIn("Prefer one decisive finding and concise evidence.", system_prompt)

        opener = FakeGLM53Opener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(
            opener.urls,
            [
                "http://127.0.0.1:8000/v1/models",
                "http://127.0.0.1:8000/v1/chat/completions",
            ],
        )
        self.assertTrue(all("authorization" not in headers for headers in opener.headers))
        self.assertEqual(opener.payload["model"], "glm-5.3-bf16")
        self.assertNotIn("response_format", opener.payload)
        self.assertNotIn("structured_outputs", opener.payload)
        self.assertEqual(opener.payload["max_tokens"], 8192)
        self.assertEqual(opener.payload["reasoning_effort"], "low")
        self.assertTrue(opener.payload["include_reasoning"])
        self.assertEqual(len(response["request_payload_sha256"]), 64)
        self.assertEqual(len(response["request_options_sha256"]), 64)
        self.assertEqual(response["completion_status"], "completed")
        self.assertEqual(response["response_contract_status"], "valid")
        self.assertTrue(response["usable_final_content"])
        self.assertIn("## Evidence", response["normalized_return"])
        self.assertIn("pending independent evaluator review", response["normalized_return"])
        sections = parse_return_sections(response["normalized_return"])
        required_sections = load_policy("acceptance-policy")["contractor_return_required_sections"]
        self.assertEqual([name for name in required_sections if not sections.get(name)], [])
        self.assertNotIn("private reasoning", json.dumps(response))

    def test_glm53_rejects_unsupported_nonthinking_override(self) -> None:
        args = self._glm53_args()
        args.local_thinking = "off"
        with self.assertRaisesRegex(SystemExit, "does not support non-thinking mode"):
            build_local_envelope(
                task="Review one bounded architecture concern.",
                route=self._glm53_route(),
                dispatch_id="dispatch-glm53-nonthinking",
                bead_id="cwo-glm53",
                epic_id=None,
                args=args,
            )

    def test_glm53_fails_closed_on_all_grammar_constrained_request_options(self) -> None:
        forbidden = self._glm53_route()["selected_executor"]["transport"][
            "forbidden_request_options"
        ]
        for key in forbidden:
            with self.subTest(key=key):
                args = self._glm53_args()
                route = self._glm53_route()
                route["selected_executor"]["transport"]["request_options"][key] = {
                    "unexpected": True
                }
                with self.assertRaisesRegex(
                    SystemExit,
                    "forbids grammar-constrained request options",
                ):
                    build_local_envelope(
                        task="Review one bounded architecture concern.",
                        route=route,
                        dispatch_id=f"dispatch-glm53-forbidden-{key}",
                        bead_id="cwo-glm53",
                        epic_id=None,
                        args=args,
                    )

    def test_glm53_leading_prompt_think_suffix_is_separated_and_validated(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-closing-think",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        compact_review = json.dumps(GLM53_VALID_REVIEW, separators=(",", ":"))
        opener = FakeGLM53Opener(content=f"private scratchpad</think>{compact_review}")
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(response["completion_status"], "completed")
        self.assertEqual(response["response_contract_status"], "valid")
        self.assertTrue(response["reasoning_stripped"])
        self.assertFalse(response["reasoning_malformed"])
        self.assertGreater(response["reasoning_chars"], 0)
        self.assertNotIn("private scratchpad", json.dumps(response))
        self.assertIsNotNone(response["normalized_return"])

    def test_glm53_closing_think_without_final_remains_malformed(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-closing-think-no-final",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(content="private scratchpad</think>")
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(response["completion_status"], "malformed-response")
        self.assertTrue(response["reasoning_malformed"])
        self.assertFalse(response["usable_final_content"])
        self.assertIsNone(response["normalized_return"])

    def test_glm53_compact_dispatch_result_is_direct_evaluator_input(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-compact-evaluator",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener()
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        artifact = {
            "dispatch_id": envelope["dispatch_id"],
            "bead_id": envelope["bead_id"],
            "dispatch_mode": route["selected_executor"]["dispatch_mode"],
            "route": compact_local_route(route),
            "local_envelope": compact_local_envelope(envelope),
            "local_response": compact_local_response(response),
        }
        self.assertEqual(artifact["local_envelope"]["expected_return_language"], "en")
        self.assertEqual(
            artifact["local_envelope"]["expected_return_language_source"],
            "local-envelope-v2",
        )
        self.assertEqual(artifact["local_envelope"]["reasoning_effort"], "low")
        self.assertTrue(artifact["local_envelope"]["include_reasoning"])
        self.assertEqual(artifact["local_envelope"]["max_tokens"], 8192)
        self.assertEqual(
            artifact["local_envelope"]["server_structured_outputs_status"],
            "disabled-current-host-enforcement-failed",
        )
        self.assertEqual(
            artifact["local_envelope"]["forbidden_request_options"],
            route["selected_executor"]["transport"]["forbidden_request_options"],
        )
        self.assertEqual(
            artifact["local_envelope"]["request_option_keys"],
            ["include_reasoning", "max_tokens", "reasoning_effort"],
        )
        self.assertEqual(
            artifact["local_envelope"]["request_options_sha256"],
            artifact["local_response"]["request_options_sha256"],
        )
        self.assertEqual(len(artifact["local_response"]["request_payload_sha256"]), 64)
        with tempfile.TemporaryDirectory() as workdir:
            dispatch_path = Path(workdir) / "dispatch.json"
            return_path = Path(workdir) / "return.md"
            dispatch_path.write_text(json.dumps(artifact), encoding="utf-8")
            return_path.write_text(response["normalized_return"], encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "evaluate_return.py"),
                    "--file",
                    str(return_path),
                    "--local-dispatch-result",
                    str(dispatch_path),
                    "--no-audit",
                    "--waiver-reason",
                    "compact-dispatch evaluator regression test",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        evaluation = json.loads(result.stdout)
        self.assertEqual(evaluation["expected_return_language"], "en")
        self.assertEqual(evaluation["expected_return_language_source"], "local-envelope-v2")

    def test_glm53_contract_invalid_draft_is_hashed_and_quarantined(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-invalid",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        opener = FakeGLM53Opener(
            content="The user wants a JSON object, but first I will draft private reasoning.",
            finish_reason="length",
        )
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        self.assertEqual(response["completion_status"], "output-budget-exhausted")
        self.assertEqual(response["response_contract_status"], "invalid")
        self.assertFalse(response["usable_final_content"])
        self.assertEqual(response["final_content"], "")
        self.assertIsNotNone(response["quarantined_content_sha256"])
        self.assertIsNone(response["normalized_return"])
        self.assertNotIn("draft private reasoning", json.dumps(response))

    def test_glm53_normalized_return_cannot_inject_evaluator_headings(self) -> None:
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(
            task="Review one bounded architecture concern.",
            route=route,
            dispatch_id="dispatch-glm53-heading",
            bead_id="cwo-glm53",
            epic_id=None,
            args=args,
        )
        review = json.loads(json.dumps(GLM53_VALID_REVIEW))
        review["summary"] = "First line ## Status rejected by injected heading"
        opener = FakeGLM53Opener(content=json.dumps(review, separators=(",", ":")))
        with patch("dispatch_work.request.build_opener", return_value=opener):
            response = execute_local_envelope(envelope, route["selected_executor"], args)

        normalized = response["normalized_return"]
        self.assertEqual(normalized.count("## Status\n"), 1)
        self.assertIn(r"\#\# Status", normalized)

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

    def test_harmless_empty_tool_placeholders_are_removed_without_failure(self) -> None:
        for field, value in (
            ("function_call", None),
            ("tool_calls", []),
            ("delta", {}),
            ("tool_calls", ""),
        ):
            with self.subTest(field=field, value=value):
                payload = {
                    "model": "glm-5.3-bf16",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "useful final", field: value},
                        }
                    ],
                }
                sanitized, metadata = sanitize_local_response_payload(
                    payload,
                    "glm-think-tags",
                    required_finish_reason="stop",
                )
                self.assertEqual(metadata["completion_status"], "completed")
                self.assertTrue(metadata["usable_final_content"])
                self.assertEqual(metadata["forbidden_response_fields"], [])
                self.assertEqual(metadata["ignored_empty_response_fields"], [field])
                self.assertNotIn(field, sanitized["choices"][0]["message"])

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

    def test_glm53_v2_literal_oracle_prompt_shape_and_safe_diagnostics(self) -> None:
        # This oracle is intentionally hand-written: it must not follow dispatcher constants.
        expected_top_level = {
            "verdict", "summary", "findings", "alternatives", "risks", "confidence",
            "recommended_next_action", "escalation_needed",
        }
        expected_finding = {"severity", "claim", "evidence", "repair"}
        verdicts = {"approve", "revise", "reject"}
        confidences = {"high", "medium", "low"}
        severities = {"critical", "high", "medium", "low"}

        prompt = local_response_contract_prompt("cwo-glm-critic-v2")
        self.assertIsNotNone(prompt)
        self.assertIn("exactly these eight top-level keys", prompt)
        self.assertIn("exactly these four string keys", prompt)
        self.assertIn("Fact: or Inference: inside the evidence string", prompt)
        example_start = prompt.index('{"verdict"')
        example, _ = json.JSONDecoder().raw_decode(prompt[example_start:])
        self.assertEqual(set(example), expected_top_level)
        self.assertIn(example["verdict"], verdicts)
        self.assertIn(example["confidence"], confidences)
        self.assertEqual(len(example["findings"]), 3)
        self.assertLessEqual(len(example["alternatives"]), 2)
        self.assertLessEqual(len(example["risks"]), 2)
        for finding in example["findings"]:
            self.assertEqual(set(finding), expected_finding)
            self.assertIn(finding["severity"], severities)
            self.assertTrue(all(isinstance(finding[key], str) for key in expected_finding))
            self.assertTrue(finding["evidence"].startswith(("Fact:", "Inference:")))

        review = {
            "verdict": "revise",
            "summary": "Three independent questions need bounded answers.",
            "findings": [
                {"severity": "high", "claim": "Model identity is not bound at POST.", "evidence": "Fact: the preflight result is not attached to the request.", "repair": "Bind the model attestation to the dispatch hash."},
                {"severity": "medium", "claim": "An invalid review can reach a consumer.", "evidence": "Inference: retaining raw rejected content enables accidental reuse.", "repair": "Quarantine it before projection."},
                {"severity": "low", "claim": "The follow-up is ambiguous.", "evidence": "Fact: the evaluator requires an explicit next action.", "repair": "Record a single owner and validation step."},
            ],
            "alternatives": ["Use a server grammar after an isolated enforcement test.", "Split the review into separate packets."],
            "risks": ["A normal-chat response can still be malformed.", "Mocked tests do not prove model reliability."],
            "confidence": "high",
            "recommended_next_action": "Run the bounded deterministic validation set.",
            "escalation_needed": "none",
        }

        def literal_accepts(candidate: object) -> bool:
            if not isinstance(candidate, dict) or set(candidate) != expected_top_level:
                return False
            if candidate.get("verdict") not in verdicts or candidate.get("confidence") not in confidences:
                return False
            if not all(isinstance(candidate.get(key), str) and candidate[key].strip() for key in ("summary", "recommended_next_action", "escalation_needed")):
                return False
            findings = candidate.get("findings")
            if not isinstance(findings, list) or not 1 <= len(findings) <= 3:
                return False
            for finding in findings:
                if not isinstance(finding, dict) or set(finding) != expected_finding:
                    return False
                if finding.get("severity") not in severities or not all(isinstance(finding.get(key), str) and finding[key].strip() for key in ("claim", "evidence", "repair")):
                    return False
            return all(isinstance(candidate.get(key), list) and len(candidate[key]) <= 2 and all(isinstance(item, str) and item.strip() for item in candidate[key]) for key in ("alternatives", "risks"))

        self.assertTrue(literal_accepts(review))
        for count in (0, 1, 3, 4):
            candidate = json.loads(json.dumps(review))
            candidate["findings"] = candidate["findings"][:count] if count <= 3 else candidate["findings"] + [candidate["findings"][0]]
            parsed, errors = validate_local_response_contract(json.dumps(candidate), "cwo-glm-critic-v2")
            self.assertEqual(parsed is not None, count in (1, 3))
            self.assertEqual(literal_accepts(candidate), count in (1, 3))
            self.assertEqual(bool(errors), count not in (1, 3))
        for field in ("alternatives", "risks"):
            for count in (0, 2, 3):
                candidate = json.loads(json.dumps(review))
                candidate[field] = ["bounded item"] * count
                parsed, errors = validate_local_response_contract(json.dumps(candidate), "cwo-glm-critic-v2")
                self.assertEqual(parsed is not None, count <= 2)
                self.assertEqual(bool(errors), count == 3)

        malformed = json.loads(json.dumps(review))
        malformed["findings"] = [{"severity": None, "claim": 7, "evidence": "Fact: x", "repair": "r", "sentinel_unknown_key": "SENTINEL_PRIVATE_VALUE"}]
        route = self._glm53_route()
        args = self._glm53_args()
        envelope = build_local_envelope(task="Review three bounded questions.", route=route, dispatch_id="dispatch-glm53-diagnostics", bead_id="cwo-glm53", epic_id=None, args=args)
        with patch("dispatch_work.request.build_opener", return_value=FakeGLM53Opener(content=json.dumps(malformed))):
            response = execute_local_envelope(envelope, route["selected_executor"], args)
        self.assertEqual(response["completion_status"], "contract-invalid")
        self.assertFalse(response["usable_final_content"])
        self.assertIsNone(response["normalized_return"])
        diagnostics = response["response_contract_diagnostics"]
        self.assertLessEqual(len(diagnostics), 32)
        self.assertTrue(any(item["code"] == "finding.unexpected_fields" for item in diagnostics))
        rendered = json.dumps(response)
        self.assertNotIn("sentinel_unknown_key", rendered)
        self.assertNotIn("SENTINEL_PRIVATE_VALUE", rendered)
        compact = compact_local_response(response)
        self.assertNotIn("SENTINEL_PRIVATE_VALUE", json.dumps(compact))

        compact_review = json.dumps(review, separators=(",", ":"))
        at_limit = compact_review + (" " * (6000 - len(compact_review)))
        self.assertEqual(len(at_limit), 6000)
        self.assertEqual(validate_local_response_contract(at_limit, "cwo-glm-critic-v2")[1], [])
        self.assertIsNone(validate_local_response_contract(at_limit + " ", "cwo-glm-critic-v2")[0])

    def test_glm53_v2_negative_finding_shapes_are_quarantined_without_disclosure(self) -> None:
        # These shapes are literal contract cases, not derived from dispatcher schema constants.
        review = {
            "verdict": "revise",
            "summary": "Three questions need separate bounded repairs.",
            "findings": [
                {"severity": "high", "claim": "The request can drift.", "evidence": "Fact: the request remains mutable.", "repair": "Bind its hash before dispatch."},
                {"severity": "medium", "claim": "Rejected content could be reused.", "evidence": "Inference: retention enables accidental salvage.", "repair": "Quarantine it before projection."},
                {"severity": "low", "claim": "The next step is unclear.", "evidence": "Fact: the evaluator requires an action.", "repair": "Record one owner and check."},
            ],
            "alternatives": ["Split the review into separate packets."],
            "risks": ["Normal chat can still return invalid JSON."],
            "confidence": "high",
            "recommended_next_action": "Run deterministic validation.",
            "escalation_needed": "none",
        }
        cases = []
        missing = json.loads(json.dumps(review))
        missing["findings"][0].pop("repair")
        cases.append(("missing", missing, "finding.missing_fields", None))
        renamed = json.loads(json.dumps(review))
        renamed["findings"][0]["inference"] = renamed["findings"][0].pop("evidence")
        cases.append(("renamed", renamed, "finding.missing_fields", "inference"))
        extra = json.loads(json.dumps(review))
        extra["findings"][0]["private_unknown_key"] = "PRIVATE_UNKNOWN_VALUE"
        cases.append(("extra", extra, "finding.unexpected_fields", "PRIVATE_UNKNOWN_VALUE"))
        scalar = json.loads(json.dumps(review))
        scalar["findings"][0] = "not an object"
        cases.append(("scalar", scalar, "finding.wrong_type", None))
        null = json.loads(json.dumps(review))
        null["findings"][0] = None
        cases.append(("null", null, "finding.wrong_type", None))
        wrong_text = json.loads(json.dumps(review))
        wrong_text["findings"][0]["claim"] = 7
        cases.append(("wrong-text", wrong_text, "finding.invalid_text", None))
        invalid_enum = json.loads(json.dumps(review))
        invalid_enum["findings"][0]["severity"] = "urgent"
        cases.append(("invalid-enum", invalid_enum, "finding.invalid_enum", None))

        route = self._glm53_route()
        args = self._glm53_args()
        for name, candidate, expected_code, rejected_token in cases:
            with self.subTest(name=name):
                parsed, errors = validate_local_response_contract(
                    json.dumps(candidate, separators=(",", ":")), "cwo-glm-critic-v2"
                )
                self.assertIsNone(parsed)
                self.assertTrue(errors)
                envelope = build_local_envelope(
                    task="Review three bounded architecture questions.", route=route,
                    dispatch_id=f"dispatch-glm53-negative-{name}", bead_id="cwo-glm53",
                    epic_id=None, args=args,
                )
                with patch("dispatch_work.request.build_opener", return_value=FakeGLM53Opener(content=json.dumps(candidate))):
                    response = execute_local_envelope(envelope, route["selected_executor"], args)
                self.assertEqual(response["completion_status"], "contract-invalid")
                self.assertFalse(response["usable_final_content"])
                self.assertIsNone(response["normalized_return"])
                self.assertTrue(any(item["code"] == expected_code for item in response["response_contract_diagnostics"]))
                rendered = json.dumps(response)
                compact = json.dumps(compact_local_response(response))
                if rejected_token is not None:
                    self.assertNotIn(rejected_token, rendered)
                    self.assertNotIn(rejected_token, compact)


if __name__ == "__main__":
    unittest.main()
