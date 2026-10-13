#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt
from cwo_core.routing import current_authority_file_arguments

from cwo_core.errors import CWOError
from cwo_core.routing import classify_work
from cwo_core.audit import (
    enforce_contracting_quota,
    record_audit_event,
    require_packet_build_audit,
)
from cwo_core.telemetry import telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields
from cwo_core.access_profiles import (
    access_profile_for_executor,
    access_profile_runtime_status,
    sanitized_access_profile,
)
from cwo_core.policy import executor_config
from cwo_core.return_language import analyze_return_language, default_expected_return_language
from cwo_core.util import (
    artifact_hash,
    make_dispatch_id,
    read_text_arg,
)
from cwo_core.packets import contractor_packet_language_metadata, redact_text, require_valid_contractor_packet


LOCAL_ENDPOINT_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)
ALLOWED_LOCAL_API_KEY_ENV_NAMES = {
    "CWO_LOCAL_OPENAI_API_KEY",
    "CWO_OPENSHIFT_AI_VLLM_API_KEY",
    "LOCAL_OPENAI_API_KEY",
    "LOCAL_VLLM_API_KEY",
    "VLLM_API_KEY",
}
LOCAL_COMPLETION_STATUSES = {
    "completed",
    "content-unsafe",
    "contract-invalid",
    "output-budget-exhausted",
    "empty-final-content",
    "malformed-response",
}
RAW_REASONING_FIELDS = {
    "chain_of_thought",
    "internal_reasoning",
    "reasoning",
    "reasoning_content",
    "reasoning_text",
    "reflection",
    "thinking_content",
    "thought",
    "thoughts",
    "tool_reasoning",
}
FORBIDDEN_LOCAL_RESPONSE_FIELDS = {"delta", "function_call", "tool_calls"}

LOCAL_PREFLIGHT_RESPONSE_CAP = 262144
LOCAL_COMPLETION_RESPONSE_CAP = 1048576
LOCAL_HTTP_ERROR_RESPONSE_CAP = 65536

GLM_CRITIC_CONTRACT_V1 = "cwo-glm-critic-v1"
GLM_CRITIC_CONTRACT = "cwo-glm-critic-v2"
GLM_CRITIC_CONTRACTS = {GLM_CRITIC_CONTRACT_V1, GLM_CRITIC_CONTRACT}
GLM_CRITIC_FIELDS = {
    "verdict",
    "summary",
    "findings",
    "alternatives",
    "risks",
    "confidence",
    "recommended_next_action",
    "escalation_needed",
}
GLM_CRITIC_FINDING_FIELDS = {"severity", "claim", "evidence", "repair"}
GLM_CRITIC_MAX_FINDINGS = 3
GLM_CRITIC_MAX_ALTERNATIVES = 2
GLM_CRITIC_MAX_RISKS = 2
GLM_CRITIC_MAX_SUMMARY_CHARS = 320
GLM_CRITIC_MAX_FINDING_TEXT_CHARS = 300
GLM_CRITIC_MAX_LIST_ITEM_CHARS = 240
GLM_CRITIC_MAX_ACTION_CHARS = 320
GLM_CRITIC_MAX_ESCALATION_CHARS = 240
GLM_CRITIC_MAX_FINAL_CHARS = 6000
GLM_CRITIC_V1_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "revise", "reject"]},
        "summary": {
            "type": "string",
            "minLength": 1,
            "maxLength": GLM_CRITIC_MAX_SUMMARY_CHARS,
        },
        "findings": {
            "type": "array",
            "minItems": 1,
            "maxItems": GLM_CRITIC_MAX_FINDINGS,
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "claim": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": GLM_CRITIC_MAX_FINDING_TEXT_CHARS,
                    },
                    "evidence": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": GLM_CRITIC_MAX_FINDING_TEXT_CHARS,
                    },
                    "repair": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": GLM_CRITIC_MAX_FINDING_TEXT_CHARS,
                    },
                },
                "required": ["severity", "claim", "evidence", "repair"],
                "additionalProperties": False,
            },
        },
        "alternatives": {
            "type": "array",
            "maxItems": GLM_CRITIC_MAX_ALTERNATIVES,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": GLM_CRITIC_MAX_LIST_ITEM_CHARS,
            },
        },
        "risks": {
            "type": "array",
            "maxItems": GLM_CRITIC_MAX_RISKS,
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": GLM_CRITIC_MAX_LIST_ITEM_CHARS,
            },
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "recommended_next_action": {
            "type": "string",
            "minLength": 1,
            "maxLength": GLM_CRITIC_MAX_ACTION_CHARS,
        },
        "escalation_needed": {
            "type": "string",
            "minLength": 1,
            "maxLength": GLM_CRITIC_MAX_ESCALATION_CHARS,
        },
    },
    "required": [
        "verdict",
        "summary",
        "findings",
        "alternatives",
        "risks",
        "confidence",
        "recommended_next_action",
        "escalation_needed",
    ],
    "additionalProperties": False,
}
GLM_CRITIC_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "revise", "reject"]},
        "summary": {"type": "string", "minLength": 1},
        "findings": {
            "type": "array",
            "minItems": 1,
            "maxItems": GLM_CRITIC_MAX_FINDINGS,
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "claim": {"type": "string", "minLength": 1},
                    "evidence": {"type": "string", "minLength": 1},
                    "repair": {"type": "string", "minLength": 1},
                },
                "required": ["severity", "claim", "evidence", "repair"],
                "additionalProperties": False,
            },
        },
        "alternatives": {
            "type": "array",
            "maxItems": GLM_CRITIC_MAX_ALTERNATIVES,
            "items": {"type": "string", "minLength": 1},
        },
        "risks": {
            "type": "array",
            "maxItems": GLM_CRITIC_MAX_RISKS,
            "items": {"type": "string", "minLength": 1},
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "recommended_next_action": {"type": "string", "minLength": 1},
        "escalation_needed": {"type": "string", "minLength": 1},
    },
    "required": [
        "verdict",
        "summary",
        "findings",
        "alternatives",
        "risks",
        "confidence",
        "recommended_next_action",
        "escalation_needed",
    ],
    "additionalProperties": False,
}

LOCAL_RESERVED_REQUEST_OPTIONS = {
    "function_call",
    "functions",
    "messages",
    "model",
    "stream",
    "temperature",
    "tool_choice",
    "tools",
}
MAX_LOCAL_JSON_DEPTH = 64
LOCAL_UNUSABLE_RESPONSE_EXIT_CODE = 4


class StrictJSONError(ValueError):
    """A bounded, content-free classification for untrusted JSON."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictJSONError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_non_finite_json_constant(_value: str) -> None:
    raise StrictJSONError("non-finite JSON number")


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_LOCAL_JSON_DEPTH:
        raise StrictJSONError("JSON nesting exceeds the supported depth")
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise StrictJSONError("JSON contains invalid Unicode") from exc
        return
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StrictJSONError("JSON contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_json_value(key, depth=depth + 1)
            _validate_json_value(item, depth=depth + 1)
        return
    raise StrictJSONError("JSON contains an unsupported runtime value")


def strict_json_loads(content: str) -> tuple[Any | None, str | None]:
    if not isinstance(content, str):
        return None, "JSON input must be text"
    try:
        content.encode("utf-8", errors="strict")
        value = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_non_finite_json_constant,
        )
        _validate_json_value(value)
    except json.JSONDecodeError:
        return None, "malformed JSON"
    except StrictJSONError as exc:
        return None, str(exc)
    except (RecursionError, UnicodeEncodeError, ValueError, TypeError):
        return None, "JSON could not be decoded safely"
    return value, None


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _falsey(value: Any) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "off"}


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive integer")
    return parsed


class NoRedirectHandler(request.HTTPRedirectHandler):
    """Reject redirects so a validated local endpoint cannot shift targets."""

    def redirect_request(self, req: request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, pinned_address: str, **kwargs: Any) -> None:
        self._cwo_pinned_address = pinned_address
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self._cwo_pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, pinned_address: str, **kwargs: Any) -> None:
        self._cwo_pinned_address = pinned_address
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        sock = self._create_connection(
            (self._cwo_pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedHTTPHandler(request.HTTPHandler):
    def __init__(self, pinned_address: str) -> None:
        self._cwo_pinned_address = pinned_address
        super().__init__()

    def http_open(self, req: request.Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPConnection(host, pinned_address=self._cwo_pinned_address, **kwargs),
            req,
        )


class PinnedHTTPSHandler(request.HTTPSHandler):
    def __init__(self, pinned_address: str, context: ssl.SSLContext | None = None) -> None:
        self._cwo_pinned_address = pinned_address
        super().__init__(context=context)

    def https_open(self, req: request.Request) -> Any:
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPSConnection(
                host,
                pinned_address=self._cwo_pinned_address,
                context=self._context,
                **kwargs,
            ),
            req,
        )


def local_executor_fallback(executor_key: str) -> dict[str, Any]:
    try:
        return executor_config(executor_key)
    except SystemExit:
        return {}


def endpoint_url(base_url: str, endpoint_path: str) -> str:
    base = base_url.rstrip("/")
    path = "/" + endpoint_path.strip("/")
    if base.endswith("/v1") and (path == "/v1" or path.startswith("/v1/")):
        path = path[3:] or "/"
    return f"{base}{path}"


def local_response_contract_prompt(contract: str | None) -> str | None:
    if contract not in GLM_CRITIC_CONTRACTS:
        return None
    common = (
        "Return exactly one compact UTF-8 JSON object and nothing else. Do not use Markdown fences. "
        "Prefer one line. The model-visible contract is: "
        '{"verdict":"approve|revise|reject","summary":"short conclusion",'
        '"findings":[{"severity":"critical|high|medium|low","claim":"specific issue",'
        '"evidence":"fact from the supplied packet or explicitly labeled inference",'
        '"repair":"smallest effective correction"}],'
        '"alternatives":["rejected alternative and why"],"risks":["residual risk"],'
        '"confidence":"high|medium|low","recommended_next_action":"one bounded next action",'
        '"escalation_needed":"none or the genuine boundary"}. '
        "Provide one to three findings and at most two alternatives and two risks. Prefer one decisive "
        "finding and concise evidence. Keep the entire object at most 6,000 characters. Keep private "
        "reasoning before the final answer; after reasoning, "
        "emit only the JSON object. Do not claim tool use or repeat the input."
    )
    if contract == GLM_CRITIC_CONTRACT_V1:
        return (
            common
            + " Historical v1 also requires summary and recommended_next_action at most 320 "
            "characters; each finding text at most 300 characters; and each alternative, risk, "
            "and escalation_needed at most 240 characters."
        )
    return (
        "Return exactly one compact UTF-8 JSON object and nothing else. Do not use Markdown fences. "
        "Use exactly these eight top-level keys, with no others: verdict, summary, findings, alternatives, "
        "risks, confidence, recommended_next_action, escalation_needed. verdict is one of approve, revise, "
        "reject; confidence is one of high, medium, low. summary, recommended_next_action, and "
        "escalation_needed are non-empty strings. findings is an array containing one to three objects; every "
        "finding has exactly these four string keys, with no others: severity, claim, evidence, repair. severity "
        "is one of critical, high, medium, low. Put Fact: or Inference: inside the evidence string; never add "
        "an inference key. alternatives and risks are arrays of zero to two non-empty strings. Prefer one decisive "
        "finding and concise evidence. Keep the whole "
        "object at most 6,000 characters. Example of a valid three-finding normal-chat response: "
        '{"verdict":"revise","summary":"Three bounded corrections are needed.","findings":['
        '{"severity":"high","claim":"The request can drift after review.","evidence":"Fact: the request is mutable after construction.","repair":"Bind and revalidate its hash before dispatch."},'
        '{"severity":"medium","claim":"A failed response could be reused.","evidence":"Inference: retaining rejected content invites later salvage.","repair":"Quarantine invalid final content."},'
        '{"severity":"low","claim":"Operators need a clear next step.","evidence":"Fact: the route has an evaluator gate.","repair":"Record the gate before promotion."}],'
        '"alternatives":["Use a server grammar only after isolated validation."],"risks":["Mocked tests do not prove model compliance."],'
        '"confidence":"high","recommended_next_action":"Run deterministic validation.","escalation_needed":"none"}. '
        "Keep private reasoning before the final answer; after reasoning, emit only the JSON object. Do not claim "
        "tool use or repeat the input."
    )


def _bounded_nonempty_string(value: Any, *, maximum: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _local_json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (int, float)):
        return "number"
    return "unknown"


def _contract_key_digest(keys: set[str]) -> str:
    return hashlib.sha256(json.dumps(sorted(keys), separators=(",", ":")).encode("utf-8")).hexdigest()


def _validate_local_response_contract_detailed(
    content: str,
    contract: str | None,
    *,
    max_final_chars: int | None = None,
) -> tuple[dict[str, Any] | None, list[str], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []

    def diagnostic(code: str, path: str, **details: Any) -> None:
        if len(diagnostics) < 32:
            diagnostics.append({"code": code, "path": path, **details})

    if not contract:
        return None, [], diagnostics
    if contract not in GLM_CRITIC_CONTRACTS:
        return None, [f"unsupported local response contract: {contract}"], diagnostics
    maximum = GLM_CRITIC_MAX_FINAL_CHARS if max_final_chars is None else max_final_chars
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
        return None, ["local response contract requires a positive max_final_chars"], diagnostics
    if not isinstance(content, str):
        return None, ["final content must be UTF-8 text"], diagnostics
    if len(content) > maximum:
        diagnostic("final.overlong", "final", observed_count=len(content), maximum=maximum)
        return None, [f"final content exceeds max_final_chars={maximum}"], diagnostics
    language = analyze_return_language(
        content,
        expected_language="en",
        expected_language_source="local-response-contract",
    )
    if any(
        item.get("category") == "unicode_control_evasion"
        for item in language.get("return_language_findings", [])
        if isinstance(item, dict)
    ):
        diagnostic("final.unsafe_unicode", "final")
        return None, ["final content contains dangerous Unicode controls"], diagnostics
    value, decode_error = strict_json_loads(content)
    if decode_error:
        diagnostic("final.invalid_json", "final")
        return None, [f"final content is not one safe JSON object: {decode_error}"], diagnostics
    decoded_language = analyze_return_language(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        expected_language="en",
        expected_language_source="local-response-contract-decoded",
    )
    if any(
        item.get("category") == "unicode_control_evasion"
        for item in decoded_language.get("return_language_findings", [])
        if isinstance(item, dict)
    ):
        diagnostic("final.unsafe_unicode", "final")
        return None, ["final content contains dangerous Unicode controls"], diagnostics
    errors: list[str] = []
    if not isinstance(value, dict):
        diagnostic("final.wrong_type", "final", observed_type=_local_json_type(value))
        return None, ["final content must be a JSON object"], diagnostics
    keys = set(value)
    if keys != GLM_CRITIC_FIELDS:
        errors.append(f"final object fields do not exactly match {contract}")
        missing = sorted(GLM_CRITIC_FIELDS - keys)
        extra = keys - GLM_CRITIC_FIELDS
        if missing:
            diagnostic("final.missing_fields", "final", fields=missing)
        if extra:
            diagnostic("final.unexpected_fields", "final", count=len(extra), digest=_contract_key_digest(extra))
    verdict = value.get("verdict")
    if not isinstance(verdict, str) or verdict not in {"approve", "revise", "reject"}:
        errors.append("verdict must be approve, revise, or reject")
        diagnostic("verdict.invalid_enum", "verdict", observed_type=_local_json_type(verdict))
    confidence = value.get("confidence")
    if not isinstance(confidence, str) or confidence not in {"high", "medium", "low"}:
        errors.append("confidence must be high, medium, or low")
        diagnostic("confidence.invalid_enum", "confidence", observed_type=_local_json_type(confidence))
    if contract == GLM_CRITIC_CONTRACT_V1:
        string_limits = {
            "summary": GLM_CRITIC_MAX_SUMMARY_CHARS,
            "recommended_next_action": GLM_CRITIC_MAX_ACTION_CHARS,
            "escalation_needed": GLM_CRITIC_MAX_ESCALATION_CHARS,
        }
        for field, field_maximum in string_limits.items():
            if not _bounded_nonempty_string(value.get(field), maximum=field_maximum):
                errors.append(
                    f"{field} must be a non-empty string no longer than {field_maximum} characters"
                )
                diagnostic("field.invalid_text", field, observed_type=_local_json_type(value.get(field)))
    else:
        for field in ("summary", "recommended_next_action", "escalation_needed"):
            if not _nonempty_string(value.get(field)):
                errors.append(f"{field} must be a non-empty string")
                diagnostic("field.invalid_text", field, observed_type=_local_json_type(value.get(field)))
    findings = value.get("findings")
    if not isinstance(findings, list) or not 1 <= len(findings) <= GLM_CRITIC_MAX_FINDINGS:
        errors.append(f"findings must contain one to {GLM_CRITIC_MAX_FINDINGS} items")
        diagnostic("findings.invalid_bounds", "findings", observed_type=_local_json_type(findings), observed_count=len(findings) if isinstance(findings, list) else None, minimum=1, maximum=GLM_CRITIC_MAX_FINDINGS)
    else:
        for index, finding in enumerate(findings):
            path = f"findings[{index}]"
            if not isinstance(finding, dict):
                errors.append(f"finding {index} fields do not exactly match the contract")
                diagnostic("finding.wrong_type", path, observed_type=_local_json_type(finding))
                continue
            finding_keys = set(finding)
            if finding_keys != GLM_CRITIC_FINDING_FIELDS:
                errors.append(f"finding {index} fields do not exactly match the contract")
                missing = sorted(GLM_CRITIC_FINDING_FIELDS - finding_keys)
                extra = finding_keys - GLM_CRITIC_FINDING_FIELDS
                if missing:
                    diagnostic("finding.missing_fields", path, fields=missing)
                if extra:
                    diagnostic("finding.unexpected_fields", path, count=len(extra), digest=_contract_key_digest(extra))
                if contract == GLM_CRITIC_CONTRACT_V1:
                    continue
            severity = finding.get("severity")
            if not isinstance(severity, str) or severity not in {"critical", "high", "medium", "low"}:
                errors.append(f"finding {index} severity is invalid")
                diagnostic("finding.invalid_enum", f"{path}.severity", observed_type=_local_json_type(severity))
            for field in ("claim", "evidence", "repair"):
                item = finding.get(field)
                if contract == GLM_CRITIC_CONTRACT_V1:
                    valid = _bounded_nonempty_string(
                        item,
                        maximum=GLM_CRITIC_MAX_FINDING_TEXT_CHARS,
                    )
                else:
                    valid = _nonempty_string(item)
                if not valid:
                    qualifier = "bounded " if contract == GLM_CRITIC_CONTRACT_V1 else ""
                    errors.append(f"finding {index} {field} must be a {qualifier}non-empty string")
                    diagnostic("finding.invalid_text", f"{path}.{field}", observed_type=_local_json_type(item))
    list_limits = {
        "alternatives": GLM_CRITIC_MAX_ALTERNATIVES,
        "risks": GLM_CRITIC_MAX_RISKS,
    }
    for field, maximum_items in list_limits.items():
        items = value.get(field)
        if not isinstance(items, list) or len(items) > maximum_items:
            errors.append(f"{field} must be a list of at most {maximum_items} items")
            diagnostic("list.invalid_bounds", field, observed_type=_local_json_type(items), observed_count=len(items) if isinstance(items, list) else None, minimum=0, maximum=maximum_items)
        elif contract == GLM_CRITIC_CONTRACT_V1 and any(
            not _bounded_nonempty_string(item, maximum=GLM_CRITIC_MAX_LIST_ITEM_CHARS)
            for item in items
        ):
            errors.append(f"{field} items must be bounded non-empty strings")
            diagnostic("list.invalid_text", field)
        elif contract == GLM_CRITIC_CONTRACT and any(
            not _nonempty_string(item) for item in items
        ):
            errors.append(f"{field} items must be non-empty strings")
            diagnostic("list.invalid_text", field)
    return (value if not errors else None), errors, diagnostics


def validate_local_response_contract(
    content: str,
    contract: str | None,
    *,
    max_final_chars: int | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    review, errors, _ = _validate_local_response_contract_detailed(
        content, contract, max_final_chars=max_final_chars
    )
    return review, errors


def _render_model_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    printable = "".join(character if character.isprintable() else " " for character in normalized)
    return " ".join(printable.split()).replace("#", r"\#")


def render_local_critic_return(
    review: dict[str, Any],
    *,
    envelope: dict[str, Any],
    response_metadata: dict[str, Any],
) -> str:
    findings = "\n".join(
        f"- [{item['severity']}] {_render_model_text(item['claim'])} "
        f"Evidence: {_render_model_text(item['evidence'])} "
        f"Repair: {_render_model_text(item['repair'])}"
        for item in review["findings"]
    )
    alternatives = "\n".join(f"- {_render_model_text(item)}" for item in review["alternatives"]) or "- none supplied"
    risks = "\n".join(f"- {_render_model_text(item)}" for item in review["risks"]) or "- none supplied"
    preflight = response_metadata.get("model_preflight")
    preflight_data = preflight if isinstance(preflight, dict) else {}
    requested_model = str(envelope.get("model") or "unknown")
    job_description = str(envelope.get("job_description_label") or "contract-jd-architecture-reasoning")
    return (
        "## Status\ncompleted\n\n"
        f"## Contractor job description\n{_render_model_text(job_description)}\n\n"
        f"## Summary\n{review['verdict']}: {_render_model_text(review['summary'])}\n\n"
        "## Validation result\nThe compact GLM critic return contract passed.\n\n"
        f"## Evidence\n{findings}\n\n"
        "## Evidence provenance\n"
        f"Exact requested model: {requested_model}; preflight: {preflight_data.get('status', 'not-recorded')}; "
        f"final-content SHA-256: {response_metadata.get('final_content_sha256')}.\n\n"
        "## Attestation or reproducibility note\n"
        "The shared dispatcher performed the configured exact-model preflight immediately before the POST; "
        "the response model and stop finish reason remain mandatory.\n\n"
        "## Share-boundary conformance\n"
        f"{envelope.get('share_boundary') or 'no-outside-sharing'}; no tools, shell, web, or repo-write authority.\n\n"
        "## Peer-review disposition\npending independent evaluator review and architect adjudication\n\n"
        f"## Alternatives considered\n{alternatives}\n\n"
        f"## Confidence\n{review['confidence']}\n\n"
        f"## Risks or gaps\n{risks}\n\n"
        f"## Recommended next bead\n{_render_model_text(review['recommended_next_action'])}\n\n"
        f"## Escalation needed\n{_render_model_text(review['escalation_needed'])}\n"
    )


def quarantine_local_response_content(payload: Any) -> None:
    if not isinstance(payload, dict):
        return
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            message["content"] = ""


def _local_endpoint_ip_allowed(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in network for network in LOCAL_ENDPOINT_NETWORKS)


def _resolve_local_endpoint_addresses(host: str, port: int | None) -> list[ipaddress._BaseAddress]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [literal]
    try:
        records = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SystemExit(f"local endpoint host could not be resolved: {host}") from exc
    addresses: list[ipaddress._BaseAddress] = []
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        try:
            addresses.append(ipaddress.ip_address(str(sockaddr[0])))
        except ValueError as exc:
            raise SystemExit(f"local endpoint resolved to an invalid address: {sockaddr[0]}") from exc
    unique = sorted(set(addresses), key=str)
    if not unique:
        raise SystemExit(f"local endpoint host resolved no usable addresses: {host}")
    return unique


def validate_local_endpoint_base_url(base_url: str, *, allow_private_dns: bool = False) -> list[str]:
    try:
        parsed = urlparse(base_url)
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"local endpoint URL is invalid: {base_url}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit(f"local endpoint must use http or https, got: {parsed.scheme or 'missing'}")
    if parsed.username or parsed.password:
        raise SystemExit("local endpoint URL must not contain credentials")
    if not parsed.hostname:
        raise SystemExit(f"local endpoint URL must include a host: {base_url}")
    hostname = parsed.hostname.lower()
    literal_host = True
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        literal_host = False
    if not literal_host and hostname not in {"localhost"} and not allow_private_dns:
        raise SystemExit(
            "local endpoint host must be a literal IP address or localhost so validation and dispatch use the same target"
        )
    addresses = _resolve_local_endpoint_addresses(parsed.hostname, port)
    disallowed = [str(ip) for ip in addresses if not _local_endpoint_ip_allowed(ip)]
    if disallowed:
        raise SystemExit(
            "local endpoint must resolve only to loopback, RFC1918, or RFC4193 addresses; "
            f"got {', '.join(disallowed)}"
        )
    if parsed.scheme == "http" and not all(ip.is_loopback for ip in addresses):
        raise SystemExit("local endpoint may use http only for loopback addresses; use https for private network endpoints")
    return [str(ip) for ip in addresses]


def pinned_local_endpoint_address(base_url: str, *, allow_private_dns: bool = False) -> str | None:
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").lower()
    try:
        ipaddress.ip_address(hostname)
        literal_host = True
    except ValueError:
        literal_host = False
    addresses = validate_local_endpoint_base_url(base_url, allow_private_dns=allow_private_dns)
    if literal_host or hostname == "localhost":
        return None
    return addresses[0]


def local_tls_settings(transport: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    ca_bundle_env = str(transport.get("tls_ca_bundle_env") or "")
    ca_bundle = getattr(args, "local_ca_bundle", None) or (os.environ.get(ca_bundle_env) if ca_bundle_env else None)
    tls_verify_env = str(transport.get("tls_verify_env") or "")
    tls_verify_value = os.environ.get(tls_verify_env) if tls_verify_env else None
    allow_insecure = bool(transport.get("allow_insecure_tls"))
    tls_verify = True
    source = "default"

    if tls_verify_value is not None:
        if _falsey(tls_verify_value):
            tls_verify = False
            source = tls_verify_env
        elif _truthy(tls_verify_value):
            tls_verify = True
            source = tls_verify_env
        else:
            raise SystemExit(f"{tls_verify_env} must be true/false style value")
    if getattr(args, "local_insecure_tls", False):
        tls_verify = False
        source = "--local-insecure-tls"
    if not tls_verify and not allow_insecure:
        raise SystemExit("insecure TLS is not allowed for this local executor profile")
    return {
        "tls_verify": tls_verify,
        "tls_verify_source": source,
        "tls_ca_bundle_env": ca_bundle_env or None,
        "tls_ca_bundle_configured": bool(ca_bundle),
        "tls_ca_bundle": ca_bundle,
        "allow_insecure_tls": allow_insecure,
    }


def local_ssl_context(base_url: str, transport: dict[str, Any], args: argparse.Namespace) -> ssl.SSLContext | None:
    if urlparse(base_url).scheme != "https":
        return None
    tls = local_tls_settings(transport, args)
    if not tls["tls_verify"]:
        return ssl._create_unverified_context()
    ca_bundle = tls.get("tls_ca_bundle")
    if ca_bundle:
        return ssl.create_default_context(cafile=str(ca_bundle))
    return None


def validate_local_api_key_env_name(name: str | None) -> None:
    if not name:
        return
    normalized = str(name).strip()
    if normalized not in ALLOWED_LOCAL_API_KEY_ENV_NAMES:
        raise SystemExit(
            "local API key environment variable is not allowlisted; "
            "use one of: " + ", ".join(sorted(ALLOWED_LOCAL_API_KEY_ENV_NAMES))
        )


def local_transport(selected_executor: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    transport = dict(selected_executor.get("transport") or {})
    fallback = local_executor_fallback(str(selected_executor.get("key") or ""))
    transport.update({key: value for key, value in dict(fallback.get("transport") or {}).items() if key not in transport})
    transport.setdefault("kind", "openai-chat-completions")
    transport.setdefault("endpoint_path", "/v1/chat/completions")
    transport.setdefault("base_url_env", "CWO_LOCAL_OPENAI_BASE_URL")
    transport.setdefault("api_key_env", "CWO_LOCAL_OPENAI_API_KEY")
    transport.setdefault("model_env", "CWO_LOCAL_OPENAI_MODEL")
    transport.setdefault("default_model", "local-model")
    transport.setdefault("timeout_seconds", 120)
    transport.setdefault("max_input_chars", 24000)
    transport.setdefault(
        "auth_mode",
        "bearer-env" if str(transport.get("api_key_env") or "").strip() else "none",
    )
    if getattr(args, "local_api_key_env", None):
        if transport.get("auth_mode") == "none" or not str(transport.get("api_key_env") or "").strip():
            raise SystemExit("selected local executor is no-auth and forbids --local-api-key-env")
        transport["api_key_env"] = args.local_api_key_env
    if getattr(args, "local_timeout", None):
        maximum_timeout = transport.get("max_timeout_seconds")
        if isinstance(maximum_timeout, int) and args.local_timeout > maximum_timeout:
            raise SystemExit(f"--local-timeout must not exceed profile maximum {maximum_timeout}")
        transport["timeout_seconds"] = args.local_timeout
    if getattr(args, "local_allow_private_dns", False):
        transport["allow_private_dns"] = True
    base_url = (
        getattr(args, "local_base_url", None)
        or os.environ.get(str(transport.get("base_url_env")))
        or transport.get("default_base_url")
    )
    model = getattr(args, "local_model", None) or os.environ.get(str(transport.get("model_env"))) or transport.get("default_model")
    return {
        **transport,
        "base_url": base_url,
        "model": model,
        "timeout_seconds": int(transport.get("timeout_seconds", 120)),
        "max_input_chars": int(transport.get("max_input_chars", 24000)),
    }


def local_request_options(transport: dict[str, Any]) -> dict[str, Any]:
    options = transport.get("request_options")
    if not isinstance(options, dict):
        return {}
    return json.loads(json.dumps(options))


def local_request_options_override(transport: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    request_options = local_request_options(transport)
    local_max_tokens = getattr(args, "local_max_tokens", None)
    if local_max_tokens is not None:
        if not isinstance(local_max_tokens, int) or local_max_tokens <= 0:
            raise SystemExit("--local-max-tokens must be a positive integer")
        maximum = transport.get("max_output_tokens")
        if isinstance(maximum, int) and local_max_tokens > maximum:
            raise SystemExit(f"--local-max-tokens must not exceed profile maximum {maximum}")
        request_options["max_tokens"] = local_max_tokens
    local_thinking = str(getattr(args, "local_thinking", "default")).strip().lower()
    response_contract = str(transport.get("response_contract") or "")
    if response_contract in GLM_CRITIC_CONTRACTS and local_thinking == "off":
        raise SystemExit(
            "GLM-5.3 does not support non-thinking mode; use its bounded reasoning_effort profile"
        )
    if response_contract not in GLM_CRITIC_CONTRACTS and local_thinking in {"on", "off"}:
        existing = request_options.get("chat_template_kwargs")
        if existing is None:
            chat_template_kwargs = {}
        elif isinstance(existing, dict):
            chat_template_kwargs = dict(existing)
        else:
            raise SystemExit("--local-thinking requires chat_template_kwargs to be an object in request options")
        chat_template_kwargs["enable_thinking"] = local_thinking == "on"
        request_options["chat_template_kwargs"] = chat_template_kwargs
    if transport.get("thinking_required") is True:
        thinking = request_options.get("chat_template_kwargs")
        if not isinstance(thinking, dict) or thinking.get("enable_thinking") is not True:
            raise SystemExit("selected local executor requires thinking to remain enabled")
    required_reasoning_effort = transport.get("required_reasoning_effort")
    if (
        isinstance(required_reasoning_effort, str)
        and request_options.get("reasoning_effort") != required_reasoning_effort
    ):
        raise SystemExit(
            "selected local executor requires reasoning_effort="
            f"{required_reasoning_effort!r}"
        )
    forbidden_request_options = transport.get("forbidden_request_options")
    if forbidden_request_options is not None:
        if not isinstance(forbidden_request_options, list) or not all(
            isinstance(key, str) and key for key in forbidden_request_options
        ):
            raise SystemExit(
                "selected local executor forbidden_request_options must be a list of non-empty strings"
            )
        present = sorted(
            key for key in forbidden_request_options if key in request_options
        )
        if present:
            raise SystemExit(
                "selected local executor forbids grammar-constrained request options: "
                + ", ".join(present)
            )
    reserved = sorted(key for key in LOCAL_RESERVED_REQUEST_OPTIONS if key in request_options)
    if reserved:
        raise SystemExit(
            "selected local executor request options contain controller-reserved fields: "
            + ", ".join(reserved)
        )
    allowed_request_options = transport.get("allowed_request_options")
    if allowed_request_options is not None:
        if not isinstance(allowed_request_options, list) or not all(
            isinstance(key, str) and key for key in allowed_request_options
        ):
            raise SystemExit(
                "selected local executor allowed_request_options must be a list of non-empty strings"
            )
        unexpected = sorted(set(request_options) - set(allowed_request_options))
        if unexpected:
            raise SystemExit(
                "selected local executor request options are not allowlisted: "
                + ", ".join(unexpected)
            )
    max_tokens = request_options.get("max_tokens")
    if max_tokens is not None and (
        not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0
    ):
        raise SystemExit("selected local executor max_tokens must be a positive integer")
    maximum_output = transport.get("max_output_tokens")
    if (
        isinstance(maximum_output, int)
        and isinstance(max_tokens, int)
        and not isinstance(max_tokens, bool)
        and max_tokens > maximum_output
    ):
        raise SystemExit(
            f"selected local executor max_tokens must not exceed profile maximum {maximum_output}"
        )
    if response_contract in GLM_CRITIC_CONTRACTS:
        expected_keys = {"reasoning_effort", "include_reasoning", "max_tokens"}
        if set(request_options) != expected_keys:
            raise SystemExit(
                "GLM-5.3 critic request options must exactly contain reasoning_effort, "
                "include_reasoning, and max_tokens"
            )
        if request_options.get("include_reasoning") is not True:
            raise SystemExit("GLM-5.3 critic requires include_reasoning=true")
    return request_options


def _canonical_json_hash(value: Any) -> str:
    return artifact_hash(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )


def validate_local_execution_binding(
    envelope: dict[str, Any],
    selected_executor: dict[str, Any],
    transport: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    if not isinstance(envelope, dict) or envelope.get("envelope_type") != "local-openai-compatible-dispatch":
        raise SystemExit("local execution requires a supported local dispatch envelope")
    if envelope.get("version") != 2:
        raise SystemExit("local execution requires envelope version 2")
    access_profile_key = str(selected_executor.get("access_profile") or "")
    expected_access_profile = sanitized_access_profile(access_profile_key)
    if envelope.get("access_profile_details") != expected_access_profile:
        raise SystemExit("local dispatch access profile changed after construction")
    if envelope.get("transport_binding_sha256") != _canonical_json_hash(transport):
        raise SystemExit("local dispatch transport changed after construction")
    tls = local_tls_settings(transport, args)
    if envelope.get("tls_binding_sha256") != _canonical_json_hash(tls):
        raise SystemExit("local dispatch TLS settings changed after construction")
    expected_fields = {
        "executor_key": selected_executor.get("key"),
        "provider_key": selected_executor.get("provider_key"),
        "access_profile": selected_executor.get("access_profile"),
        "local_profile": selected_executor.get("local_profile"),
        "model_profile": selected_executor.get("model_profile"),
        "model": transport.get("model"),
        "required_model": transport.get("required_model"),
        "endpoint_path": transport.get("endpoint_path"),
        "timeout_seconds": transport.get("timeout_seconds"),
        "max_input_chars": transport.get("max_input_chars"),
        "model_preflight_required": bool(transport.get("model_preflight_required")),
        "model_preflight_endpoint_path": transport.get("model_preflight_endpoint_path"),
        "response_model_required": bool(transport.get("response_model_required")),
        "required_finish_reason": transport.get("required_finish_reason"),
        "response_contract": str(transport.get("response_contract") or "") or None,
        "thinking_parser": transport.get("thinking_parser"),
        "max_final_chars": transport.get("max_final_chars"),
        "api_key_env": transport.get("api_key_env"),
        "auth_mode": transport.get("auth_mode"),
        "forbidden_request_options": transport.get("forbidden_request_options"),
        "allowed_request_options": transport.get("allowed_request_options"),
        "allow_private_dns": bool(transport.get("allow_private_dns")),
    }
    mismatched = sorted(
        field for field, expected in expected_fields.items() if envelope.get(field) != expected
    )
    if mismatched:
        raise SystemExit(
            "local dispatch envelope no longer matches the selected executor profile: "
            + ", ".join(mismatched)
        )
    messages = envelope.get("messages")
    if (
        not isinstance(messages, list)
        or len(messages) != 2
        or [item.get("role") if isinstance(item, dict) else None for item in messages]
        != ["system", "user"]
        or any(
            not isinstance(item, dict)
            or set(item) != {"role", "content"}
            or not isinstance(item.get("content"), str)
            or not item["content"].strip()
            for item in messages
        )
    ):
        raise SystemExit("local dispatch envelope messages are malformed")
    if envelope.get("messages_sha256") != _canonical_json_hash(messages):
        raise SystemExit("local dispatch envelope messages changed after construction")
    expected_options = local_request_options_override(transport, args)
    if envelope.get("request_options") != expected_options:
        raise SystemExit("local dispatch request options changed after construction")
    return expected_options


def _split_thinking_content(content: str) -> dict[str, Any]:
    if content.lstrip().startswith(("{", "[")):
        return {
            "content": content,
            "reasoning_stripped": False,
            "reasoning_chars": 0,
            "reasoning_sha256": None,
            "reasoning_malformed": False,
        }
    opening = re.match(r"(?is)^\s*<(think|analysis|reasoning)>", content)
    if opening:
        tag = opening.group(1)
        closing = re.search(rf"(?is)</{re.escape(tag)}>", content[opening.end():])
        if closing:
            reasoning_start = opening.end()
            reasoning_end = reasoning_start + closing.start()
            final_start = reasoning_start + closing.end()
            reasoning = content[reasoning_start:reasoning_end].strip()
            final = content[final_start:]
        else:
            return {
                "content": "",
                "reasoning_stripped": True,
                "reasoning_chars": len(content),
                "reasoning_sha256": artifact_hash(content),
                "reasoning_malformed": True,
            }
        return {
            "content": final.strip(),
            "reasoning_stripped": True,
            "reasoning_chars": len(reasoning),
            "reasoning_sha256": artifact_hash(reasoning),
            "reasoning_malformed": False,
        }
    tags = list(re.finditer(r"(?is)</?(think|analysis|reasoning)>", content))
    if len(tags) == 1 and tags[0].group(0).startswith("</"):
        reasoning = content[: tags[0].start()].strip()
        final = content[tags[0].end() :].strip()
        if reasoning and final:
            return {
                "content": final,
                "reasoning_stripped": True,
                "reasoning_chars": len(reasoning),
                "reasoning_sha256": artifact_hash(reasoning),
                "reasoning_malformed": False,
            }
    if tags:
        return {
            "content": "",
            "reasoning_stripped": True,
            "reasoning_chars": len(content),
            "reasoning_sha256": artifact_hash(content),
            "reasoning_malformed": True,
        }
    return {
        "content": content,
        "reasoning_stripped": False,
        "reasoning_chars": 0,
        "reasoning_sha256": None,
        "reasoning_malformed": False,
    }


def _record_reasoning_digest(metadata: dict[str, Any], digest: str, chars: int) -> None:
    previous = metadata.get("reasoning_sha256")
    metadata["reasoning_sha256"] = digest if not previous else artifact_hash(f"{previous}:{digest}")
    metadata["reasoning_chars"] = int(metadata.get("reasoning_chars") or 0) + chars
    metadata["reasoning_stripped"] = True


def _record_reasoning_fragment(metadata: dict[str, Any], value: Any) -> None:
    if value is None:
        return
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    _record_reasoning_digest(metadata, artifact_hash(rendered), len(rendered))


def _strip_raw_reasoning_fields(value: Any, metadata: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key in list(value):
            normalized_key = unicodedata.normalize("NFKC", str(key)).strip().casefold()
            if normalized_key in RAW_REASONING_FIELDS:
                _record_reasoning_fragment(metadata, value.pop(key))
                continue
            if normalized_key in FORBIDDEN_LOCAL_RESPONSE_FIELDS:
                removed = value.pop(key)
                if (
                    removed is None
                    or (isinstance(removed, str) and not removed.strip())
                    or (isinstance(removed, (dict, list)) and not removed)
                ):
                    metadata["ignored_empty_response_fields"].append(normalized_key)
                    continue
                rendered = json.dumps(removed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                metadata["forbidden_response_fields"].append(normalized_key)
                metadata["forbidden_response_sha256"] = artifact_hash(rendered)
                metadata["reasoning_malformed"] = True
                continue
            _strip_raw_reasoning_fields(value[key], metadata)
    elif isinstance(value, list):
        for item in value:
            _strip_raw_reasoning_fields(item, metadata)


def sanitize_local_response_payload(
    payload: Any,
    thinking_parser: str | None,
    *,
    required_finish_reason: str | None = None,
) -> tuple[Any, dict[str, Any]]:
    metadata = {
        "thinking_parser": thinking_parser,
        "reasoning_stripped": False,
        "reasoning_malformed": False,
        "reasoning_chars": 0,
        "reasoning_sha256": None,
        "response_truncated": False,
        "finish_reasons": [],
        "completion_status": "malformed-response",
        "usable_final_content": False,
        "final_content": "",
        "final_content_sha256": artifact_hash(""),
        "final_content_chars": 0,
        "forbidden_response_fields": [],
        "forbidden_response_sha256": None,
        "ignored_empty_response_fields": [],
        "provider_error_present": False,
        "provider_error_sha256": None,
        "payload_validation_error": None,
        "content_security_status": "not-checked",
    }
    try:
        _validate_json_value(payload)
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        sanitized, clone_error = strict_json_loads(serialized)
        if clone_error:
            raise StrictJSONError(clone_error)
    except (StrictJSONError, RecursionError, UnicodeEncodeError, ValueError, TypeError) as exc:
        metadata["payload_validation_error"] = str(exc) or "unsafe JSON payload"
        metadata["content_security_status"] = "rejected"
        return {}, metadata
    if isinstance(payload, dict):
        choices = payload.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                finish_reason = choice.get("finish_reason")
                if isinstance(finish_reason, str) and finish_reason.strip():
                    reason = finish_reason.strip()
                    metadata["finish_reasons"].append(reason)
                    if reason == "length":
                        metadata["response_truncated"] = True
    if isinstance(sanitized, dict) and "error" in sanitized:
        provider_error = sanitized.pop("error")
        rendered_error = json.dumps(provider_error, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        metadata["provider_error_present"] = True
        metadata["provider_error_sha256"] = artifact_hash(rendered_error)
        metadata["reasoning_malformed"] = True
    _strip_raw_reasoning_fields(sanitized, metadata)
    if not isinstance(sanitized, dict):
        return sanitized, metadata
    choices = sanitized.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        metadata["reasoning_malformed"] = True
    final_contents: list[str] = []
    for choice in choices if isinstance(choices, list) else []:
        if not isinstance(choice, dict) or (
            required_finish_reason and not isinstance(choice.get("finish_reason"), str)
        ):
            metadata["reasoning_malformed"] = True
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            metadata["reasoning_malformed"] = True
            continue
        content = message.get("content")
        if content is None:
            message["content"] = ""
            content = ""
        if not isinstance(content, str):
            metadata["reasoning_malformed"] = True
            message["content"] = ""
            content = ""
        if thinking_parser == "glm-think-tags":
            split = _split_thinking_content(content)
            if split["reasoning_stripped"]:
                message["content"] = split["content"]
                if split["reasoning_sha256"] is not None:
                    _record_reasoning_digest(
                        metadata,
                        str(split["reasoning_sha256"]),
                        int(split["reasoning_chars"]),
                    )
                metadata["reasoning_malformed"] = bool(
                    metadata["reasoning_malformed"] or split["reasoning_malformed"]
                )
                content = split["content"]
        clean = str(message.get("content") or "")
        if clean.strip():
            final_contents.append(clean)
    final_content = final_contents[0] if final_contents else ""
    metadata["final_content"] = final_content
    metadata["final_content_sha256"] = artifact_hash(final_content)
    metadata["final_content_chars"] = len(final_content)
    finish_reasons = [str(item).strip().lower() for item in metadata["finish_reasons"]]
    language = analyze_return_language(
        final_content,
        expected_language="en",
        expected_language_source="local-response-sanitizer",
    )
    dangerous_controls = any(
        item.get("category") == "unicode_control_evasion"
        for item in language.get("return_language_findings", [])
        if isinstance(item, dict)
    )
    metadata["content_security_status"] = "rejected" if dangerous_controls else "passed"
    if dangerous_controls:
        completion_status = "content-unsafe"
    elif metadata["reasoning_malformed"]:
        completion_status = "malformed-response"
    elif metadata["response_truncated"] or any(item in {"length", "max_tokens"} for item in finish_reasons):
        completion_status = "output-budget-exhausted"
    elif not final_content:
        completion_status = "empty-final-content"
    elif required_finish_reason and (
        not finish_reasons or any(item != required_finish_reason.strip().lower() for item in finish_reasons)
    ):
        completion_status = "malformed-response"
    else:
        completion_status = "completed"
    metadata["completion_status"] = completion_status
    metadata["usable_final_content"] = completion_status == "completed"
    return sanitized, metadata


def project_local_response_payload(payload: Any) -> dict[str, Any]:
    """Retain only response fields used by telemetry and final-content consumers."""
    if not isinstance(payload, dict):
        return {}
    projected: dict[str, Any] = {}
    model = payload.get("model")
    if isinstance(model, str):
        projected["model"] = model
    choices = payload.get("choices")
    projected_choices: list[dict[str, Any]] = []
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            projected_choice: dict[str, Any] = {}
            finish_reason = choice.get("finish_reason")
            if finish_reason is None or isinstance(finish_reason, str):
                projected_choice["finish_reason"] = finish_reason
            message = choice.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                projected_choice["message"] = {
                    "content": content if isinstance(content, str) else ""
                }
            projected_choices.append(projected_choice)
    projected["choices"] = projected_choices
    usage = payload.get("usage")
    if isinstance(usage, dict):
        projected_usage = {
            key: value
            for key in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "input_tokens",
                "output_tokens",
            )
            if isinstance((value := usage.get(key)), int)
            and not isinstance(value, bool)
            and value >= 0
        }
        if projected_usage:
            projected["usage"] = projected_usage
    return projected


def build_local_envelope(
    *,
    task: str,
    route: dict[str, Any],
    dispatch_id: str,
    bead_id: str | None,
    epic_id: str | None,
    args: argparse.Namespace,
) -> dict[str, Any]:
    selected = dict(route["selected_executor"])
    access_profile_key = str(selected.get("access_profile") or access_profile_for_executor(selected) or "")
    access_profile_details = sanitized_access_profile(access_profile_key)
    if not access_profile_key or not access_profile_details:
        raise SystemExit("selected local executor does not resolve to a known access profile")
    transport = local_transport(selected, args)
    tls = local_tls_settings(transport, args)
    max_input_chars = int(transport["max_input_chars"])
    model = str(transport.get("model") or "")
    required_model = transport.get("required_model")
    if isinstance(required_model, str) and required_model and model != required_model:
        raise SystemExit(
            f"selected local executor requires exact model {required_model!r}; got {model!r}"
        )
    try:
        task.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise SystemExit("local dispatch task must be valid UTF-8 text") from exc
    if len(task) > max_input_chars:
        raise SystemExit(f"local dispatch task exceeds max_input_chars={max_input_chars}")
    request_options = local_request_options_override(transport, args)
    response_contract = str(transport.get("response_contract") or "") or None
    contract_prompt = local_response_contract_prompt(response_contract)
    constraints = (
        "local-only, evaluator review required, architect adjudication required, "
        "no web, no shell, no repo write; repo read only when executor policy explicitly allows it"
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You are a bounded local worker for complex-work-orchestration. "
                "Return evidence-focused findings only. Do not claim repo mutation, "
                "web access, shell execution, or policy approval."
                + (f" {contract_prompt}" if contract_prompt else "")
            ),
        },
        {
            "role": "user",
            "content": (
                f"Dispatch ID: {dispatch_id}\n"
                f"Share boundary: {route.get('share_boundary')}\n"
                f"Task class: {route.get('task_class')}\n"
                f"Risk: {route.get('risk_level')}\n"
                f"Job label: {(route.get('ranked_experts') or [{}])[0].get('job_description_label')}\n\n"
                f"Task:\n{task}"
            ),
        },
    ]
    return {
        "envelope_type": "local-openai-compatible-dispatch",
        "version": 2,
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "epic_id": epic_id,
        "executor_key": route["recommended_executor"],
        "provider_key": selected.get("provider_key"),
        "provider_trust_tier": selected.get("provider_trust_tier"),
        "access_profile": access_profile_key or None,
        "access_profile_details": access_profile_details,
        "access_profile_readiness": access_profile_runtime_status(access_profile_key),
        "share_boundary": route.get("share_boundary"),
        "job_description_label": (route.get("ranked_experts") or [{}])[0].get("job_description_label"),
        "local_profile": selected.get("local_profile"),
        "model_profile": selected.get("model_profile"),
        "expected_return_language": default_expected_return_language(),
        "expected_return_language_source": "local-envelope-v2",
        "transport_kind": transport.get("kind"),
        "base_url_env": transport.get("base_url_env"),
        "base_url_configured": bool(transport.get("base_url")),
        "transport_binding_sha256": _canonical_json_hash(transport),
        "api_key_env": transport.get("api_key_env"),
        "auth_mode": transport.get("auth_mode"),
        "model_env": transport.get("model_env"),
        "model": model,
        "endpoint_path": transport.get("endpoint_path"),
        "timeout_seconds": transport.get("timeout_seconds"),
        "max_input_chars": max_input_chars,
        "target_input_chars": transport.get("target_input_chars"),
        "model_preflight_required": bool(transport.get("model_preflight_required")),
        "model_preflight_endpoint_path": transport.get("model_preflight_endpoint_path"),
        "required_model": required_model,
        "required_finish_reason": transport.get("required_finish_reason"),
        "response_model_required": bool(transport.get("response_model_required")),
        "allow_private_dns": bool(transport.get("allow_private_dns")),
        "tls_verify": bool(tls["tls_verify"]),
        "tls_verify_source": tls["tls_verify_source"],
        "tls_ca_bundle_env": tls["tls_ca_bundle_env"],
        "tls_ca_bundle_configured": bool(tls["tls_ca_bundle_configured"]),
        "allow_insecure_tls": bool(tls["allow_insecure_tls"]),
        "tls_binding_sha256": _canonical_json_hash(tls),
        "request_options": request_options,
        "messages_sha256": _canonical_json_hash(messages),
        "response_contract": response_contract,
        "server_structured_outputs_status": transport.get(
            "server_structured_outputs_status"
        ),
        "forbidden_request_options": transport.get("forbidden_request_options"),
        "allowed_request_options": transport.get("allowed_request_options"),
        "max_final_chars": transport.get("max_final_chars"),
        "quarantine_contract_invalid_content": bool(
            transport.get("quarantine_contract_invalid_content")
        ),
        "quarantine_unusable_content": bool(
            transport.get("quarantine_unusable_content")
        ),
        "thinking_parser": transport.get("thinking_parser"),
        "response_sanitization": transport.get("response_sanitization"),
        "constraints": constraints,
        "messages": messages,
        "execution_enabled": bool(args.execute_local),
    }


def require_access_profile_online_for_execution(envelope: dict[str, Any], args: argparse.Namespace) -> None:
    profile_key = str(envelope.get("access_profile") or "")
    details = envelope.get("access_profile_details") if isinstance(envelope.get("access_profile_details"), dict) else {}
    status = str(details.get("status") or "").strip().lower()
    if status != "offline":
        return
    if getattr(args, "allow_offline_access_profile", False):
        return
    raise SystemExit(
        f"access profile {profile_key!r} is marked offline; "
        "pass --allow-offline-access-profile with --waiver-reason only after the operator confirms the endpoint is restored"
    )


def _build_local_opener(
    base_url: str,
    transport: dict[str, Any],
    args: argparse.Namespace,
    pinned_address: str | None,
) -> Any:
    opener_handlers: list[Any] = [NoRedirectHandler, request.ProxyHandler({})]
    context = local_ssl_context(base_url, transport, args)
    scheme = urlparse(base_url).scheme
    if pinned_address and scheme == "https":
        opener_handlers.append(PinnedHTTPSHandler(pinned_address, context=context))
    elif pinned_address and scheme == "http":
        opener_handlers.append(PinnedHTTPHandler(pinned_address))
    elif context is not None:
        opener_handlers.append(request.HTTPSHandler(context=context))
    return request.build_opener(*opener_handlers)


def _local_response_header(response: Any, name: str) -> str | None:
    getheader = getattr(response, "getheader", None)
    value = getheader(name) if callable(getheader) else None
    if value is None:
        headers = getattr(response, "headers", None)
        getter = getattr(headers, "get", None)
        value = getter(name) if callable(getter) else None
    return None if value is None else str(value).strip()


def _read_local_http_response(response: Any, *, cap: int, phase: str) -> bytes:
    content_length = _local_response_header(response, "Content-Length")
    transfer_encoding = _local_response_header(response, "Transfer-Encoding")
    content_encoding = _local_response_header(response, "Content-Encoding")
    if content_encoding is not None and content_encoding.lower() not in {"", "identity"}:
        raise SystemExit(f"local {phase} response used unsupported content encoding")
    if transfer_encoding is not None and transfer_encoding.lower() not in {"", "chunked"}:
        raise SystemExit(f"local {phase} response used unsupported transfer encoding")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            raise SystemExit(f"local {phase} response had malformed Content-Length")
        declared = int(content_length)
        if transfer_encoding is not None:
            raise SystemExit(f"local {phase} response had conflicting framing")
        if declared > cap:
            raise SystemExit(f"local {phase} response exceeded response cap")
    else:
        declared = None
    raw_bytes = response.read(cap + 1)
    if len(raw_bytes) > cap:
        raise SystemExit(f"local {phase} response exceeded response cap")
    if declared is not None and len(raw_bytes) != declared:
        raise SystemExit(f"local {phase} response ended before Content-Length")
    return raw_bytes


def _preflight_local_model(
    opener: Any,
    *,
    base_url: str,
    transport: dict[str, Any],
    headers: dict[str, str],
    model: str,
) -> dict[str, Any]:
    endpoint_path = str(transport.get("model_preflight_endpoint_path", "/v1/models"))
    req = request.Request(endpoint_url(base_url, endpoint_path), headers=headers, method="GET")
    started = time.monotonic()
    with opener.open(req, timeout=int(transport.get("timeout_seconds", 120))) as response:
        raw_bytes = _read_local_http_response(
            response, cap=LOCAL_PREFLIGHT_RESPONSE_CAP, phase="model preflight"
        )
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        try:
            raw = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SystemExit(
                "local model preflight returned invalid UTF-8; body omitted "
                f"(sha256={raw_sha256}, bytes={len(raw_bytes)})"
            ) from exc
        payload, decode_error = strict_json_loads(raw)
        if decode_error:
            raise SystemExit(
                "local model preflight returned unsafe or malformed JSON; body omitted "
                f"(sha256={raw_sha256}, chars={len(raw)}, classification={decode_error})"
            )
        data = payload.get("data") if isinstance(payload, dict) else None
        model_ids = [
            str(item.get("id"))
            for item in data or []
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("id")
        ] if isinstance(data, list) else []
        if getattr(response, "status", None) != 200 or model not in model_ids:
            raise SystemExit(
                "local model preflight did not attest the exact requested model; "
                f"status={getattr(response, 'status', None)!r}, model={model!r}, "
                f"response_sha256={raw_sha256}"
            )
        return {
            "status": "passed",
            "status_code": 200,
            "required_model": model,
            "observed_model_count": len(model_ids),
            "response_sha256": raw_sha256,
            "response_chars": len(raw),
            "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
            "_completed_monotonic": time.monotonic(),
        }


def execute_local_envelope(envelope: dict[str, Any], selected_executor: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    require_access_profile_online_for_execution(envelope, args)
    executor_key = str(envelope.get("executor_key") or "")
    authoritative_executor = executor_config(executor_key)
    binding_fields = (
        "key",
        "provider_key",
        "access_profile",
        "local_profile",
        "model_profile",
        "transport",
    )
    if any(
        selected_executor.get(field) != authoritative_executor.get(field)
        for field in binding_fields
    ):
        raise SystemExit(
            "selected local executor changed after policy routing; rebuild the dispatch envelope"
        )
    transport = local_transport(authoritative_executor, args)
    request_options = validate_local_execution_binding(
        envelope,
        authoritative_executor,
        transport,
        args,
    )
    base_url = transport.get("base_url")
    if not base_url:
        raise SystemExit(
            f"--execute-local requires --local-base-url or ${transport.get('base_url_env')} for the local endpoint"
        )
    model = transport.get("model")
    if not model:
        raise SystemExit(f"--execute-local requires --local-model or ${transport.get('model_env')}")
    required_model = transport.get("required_model")
    if isinstance(required_model, str) and required_model and model != required_model:
        raise SystemExit(
            f"selected local executor requires exact model {required_model!r}; got {model!r}"
        )
    pinned_address = pinned_local_endpoint_address(str(base_url), allow_private_dns=bool(transport.get("allow_private_dns")))
    api_key_env = str(transport.get("api_key_env") or "")
    auth_mode = str(transport.get("auth_mode") or "")
    if auth_mode == "none":
        if api_key_env:
            raise SystemExit("no-auth local executor must not configure an API-key environment variable")
    elif auth_mode == "bearer-env":
        if not api_key_env:
            raise SystemExit("authenticated local executor requires an API-key environment variable")
        validate_local_api_key_env_name(api_key_env)
    else:
        raise SystemExit(f"unsupported local executor auth_mode: {auth_mode or 'missing'}")
    payload = {
        "model": model,
        "messages": envelope["messages"],
        "temperature": 0,
    }
    payload.update(request_options)
    body = json.dumps(payload).encode("utf-8")
    request_payload_sha256 = artifact_hash(body.decode("utf-8"))
    request_options_sha256 = artifact_hash(
        json.dumps(
            request_options,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    headers = {"Content-Type": "application/json"}
    headers["X-CWO-Dispatch-ID"] = str(envelope.get("dispatch_id") or uuid.uuid4())
    if auth_mode == "bearer-env":
        api_key = os.environ.get(api_key_env)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
    req = request.Request(
        endpoint_url(str(base_url), str(transport.get("endpoint_path", "/v1/chat/completions"))),
        data=body,
        headers=headers,
        method="POST",
    )
    started = time.monotonic()
    try:
        opener = _build_local_opener(str(base_url), transport, args, pinned_address)
        model_preflight = None
        if transport.get("model_preflight_required") is True:
            model_preflight = _preflight_local_model(
                opener,
                base_url=str(base_url),
                transport=transport,
                headers=headers,
                model=str(model),
            )
            completed_monotonic = float(model_preflight.pop("_completed_monotonic"))
            preflight_to_post_ms = max(0, int((time.monotonic() - completed_monotonic) * 1000))
            model_preflight["to_post_ms"] = preflight_to_post_ms
            maximum_gap = int(transport.get("max_preflight_to_post_ms", 1000))
            if preflight_to_post_ms > maximum_gap:
                raise SystemExit(
                    "local model preflight expired before POST; "
                    f"gap_ms={preflight_to_post_ms}, maximum_ms={maximum_gap}"
                )
        with opener.open(req, timeout=int(transport.get("timeout_seconds", 120))) as response:
            raw_bytes = _read_local_http_response(
                response, cap=LOCAL_COMPLETION_RESPONSE_CAP, phase="completion"
            )
            raw_response_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            try:
                raw = raw_bytes.decode("utf-8", errors="strict")
                raw_decode_error = None
            except UnicodeDecodeError:
                raw = ""
                raw_decode_error = "invalid UTF-8"
            if getattr(response, "status", None) != 200:
                raise SystemExit(
                    "local endpoint did not return HTTP 200; response body omitted "
                    f"(status={getattr(response, 'status', None)!r}, "
                    f"sha256={raw_response_sha256}, bytes={len(raw_bytes)})"
                )
            parsed: Any = None
            parse_error = raw_decode_error
            if parse_error is None:
                parsed, parse_error = strict_json_loads(raw)
            if parse_error:
                parsed = {
                    "malformed_response_sha256": raw_response_sha256,
                    "malformed_response_bytes": len(raw_bytes),
                    "malformed_response_classification": parse_error,
                }
            response_model = parsed.get("model") if isinstance(parsed, dict) else None
            sanitized, response_metadata = sanitize_local_response_payload(
                parsed,
                transport.get("thinking_parser"),
                required_finish_reason=(
                    str(transport.get("required_finish_reason"))
                    if transport.get("required_finish_reason")
                    else None
                ),
            )
            if parse_error:
                response_metadata["payload_validation_error"] = parse_error
                response_metadata["completion_status"] = "malformed-response"
                response_metadata["usable_final_content"] = False
            response_model_status = "not-required"
            if transport.get("response_model_required") is True:
                response_model_status = "matched" if response_model == model else "mismatch"
                if response_model_status != "matched":
                    response_metadata["completion_status"] = "malformed-response"
                    response_metadata["usable_final_content"] = False
            response_contract = str(transport.get("response_contract") or "") or None
            normalized_return = None
            review = None
            contract_errors: list[str] = []
            contract_diagnostics: list[dict[str, Any]] = []
            if response_contract:
                content = str(response_metadata.get("final_content") or "")
                max_final_chars = int(transport.get("max_final_chars") or 0)
                review, contract_errors, contract_diagnostics = _validate_local_response_contract_detailed(
                    content,
                    response_contract,
                    max_final_chars=max_final_chars,
                )
                response_metadata["response_contract"] = response_contract
                response_metadata["response_contract_status"] = (
                    "valid" if review is not None and not contract_errors else "invalid"
                )
                response_metadata["response_contract_errors"] = contract_errors
                response_metadata["response_contract_diagnostics"] = contract_diagnostics
                if (review is None or contract_errors) and response_metadata.get("completion_status") == "completed":
                    if any("dangerous Unicode controls" in error for error in contract_errors):
                        response_metadata["content_security_status"] = "rejected"
                        response_metadata["completion_status"] = "content-unsafe"
                    else:
                        response_metadata["completion_status"] = "contract-invalid"
            content = str(response_metadata.get("final_content") or "")
            eligible = (
                response_metadata.get("completion_status") == "completed"
                and response_model_status in {"matched", "not-required"}
                and (not response_contract or (review is not None and not contract_errors))
            )
            response_metadata["usable_final_content"] = eligible
            if eligible and response_contract and review is not None:
                render_metadata = {**response_metadata, "model_preflight": model_preflight}
                normalized_return = render_local_critic_return(
                    review,
                    envelope=envelope,
                    response_metadata=render_metadata,
                )
                response_metadata["normalized_return_sha256"] = artifact_hash(normalized_return)
                response_metadata["normalized_return_chars"] = len(normalized_return)
            elif content and (
                transport.get("quarantine_unusable_content") is True
                or (
                    response_contract
                    and transport.get("quarantine_contract_invalid_content") is True
                )
            ):
                response_metadata["quarantined_content_sha256"] = artifact_hash(content)
                response_metadata["quarantined_content_chars"] = len(content)
                quarantine_local_response_content(sanitized)
                response_metadata["final_content"] = ""
                response_metadata["final_content_sha256"] = artifact_hash("")
                response_metadata["final_content_chars"] = 0
            sanitized = project_local_response_payload(sanitized)
            return {
                "status_code": response.status,
                "response": sanitized,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "raw_response_sha256": raw_response_sha256,
                "raw_response_chars": len(raw),
                "raw_response_bytes": len(raw_bytes),
                "request_payload_sha256": request_payload_sha256,
                "request_options_sha256": request_options_sha256,
                "server_structured_outputs_status": envelope.get(
                    "server_structured_outputs_status"
                ),
                "model_preflight": model_preflight,
                "response_model_status": response_model_status,
                "normalized_return": normalized_return,
                **response_metadata,
            }
    except HTTPError as exc:
        try:
            body = _read_local_http_response(
                exc, cap=LOCAL_HTTP_ERROR_RESPONSE_CAP, phase="HTTP error"
            )
            raise SystemExit(
                f"local endpoint returned HTTP {exc.code}; response body omitted "
                f"(sha256={hashlib.sha256(body).hexdigest()}, bytes={len(body)})"
                + _debug_local_http_excerpt("")
            ) from exc
        finally:
            exc.close()
    except URLError as exc:
        raise SystemExit(f"local endpoint request failed: {exc}") from exc


def _debug_local_http_excerpt(body: str) -> str:
    _ = body
    return ""


def local_response_telemetry(local_response: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(local_response, dict):
        return {}
    response_payload = local_response.get("response")
    rendered = json.dumps(response_payload, sort_keys=True) if isinstance(response_payload, (dict, list)) else str(response_payload or "")
    usage = response_payload.get("usage") if isinstance(response_payload, dict) and isinstance(response_payload.get("usage"), dict) else {}
    completion_status = str(local_response.get("completion_status") or "malformed-response")
    if completion_status not in LOCAL_COMPLETION_STATUSES:
        completion_status = "malformed-response"
    usable = completion_status == "completed" and local_response.get("usable_final_content") is True
    preflight = local_response.get("model_preflight") if isinstance(local_response.get("model_preflight"), dict) else {}
    return telemetry_fields(
        telemetry_status="completed" if usable else "failed",
        telemetry_missing_reason=None if usable else f"local-response-{completion_status}",
        completion_status=completion_status,
        agent_model_calls=1 if usable else 0,
        attempted_model_calls=1,
        usable_model_calls=1 if usable else 0,
        incomplete_model_calls=0 if usable else 1,
        retry_count=0,
        input_tokens=usage.get("prompt_tokens") or usage.get("input_tokens"),
        output_tokens=usage.get("completion_tokens") or usage.get("output_tokens"),
        total_tokens=usage.get("total_tokens"),
        elapsed_seconds=local_response.get("elapsed_seconds"),
        local_status_code=local_response.get("status_code"),
        local_response_sha256=artifact_hash(rendered),
        local_response_chars=len(rendered),
        raw_response_sha256=local_response.get("raw_response_sha256"),
        raw_response_chars=local_response.get("raw_response_chars"),
        thinking_parser=local_response.get("thinking_parser"),
        reasoning_stripped=local_response.get("reasoning_stripped"),
        reasoning_malformed=local_response.get("reasoning_malformed"),
        reasoning_chars=local_response.get("reasoning_chars"),
        reasoning_sha256=local_response.get("reasoning_sha256"),
        response_truncated=local_response.get("response_truncated"),
        finish_reasons=local_response.get("finish_reasons"),
        usable_final_content=local_response.get("usable_final_content"),
        final_content_sha256=local_response.get("final_content_sha256"),
        final_content_chars=local_response.get("final_content_chars"),
        response_model_status=local_response.get("response_model_status"),
        model_preflight_status=preflight.get("status"),
        model_preflight_required_model=preflight.get("required_model"),
        model_preflight_response_sha256=preflight.get("response_sha256"),
        model_preflight_response_chars=preflight.get("response_chars"),
        model_preflight_observed_model_count=preflight.get("observed_model_count"),
        model_preflight_elapsed_ms=preflight.get("elapsed_ms"),
        preflight_to_post_ms=preflight.get("to_post_ms"),
        preflight_attempts=1 if preflight else 0,
        preflight_successes=1 if preflight.get("status") == "passed" else 0,
        post_attempts=1,
        usable_post_responses=1 if usable else 0,
        incomplete_post_responses=0 if usable else 1,
        forbidden_response_fields=local_response.get("forbidden_response_fields"),
        forbidden_response_sha256=local_response.get("forbidden_response_sha256"),
        provider_error_present=local_response.get("provider_error_present"),
        provider_error_sha256=local_response.get("provider_error_sha256"),
        payload_validation_error=local_response.get("payload_validation_error"),
        content_security_status=local_response.get("content_security_status"),
    )


def compact_local_response(local_response: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(local_response, dict):
        return None
    fields = (
        "status_code",
        "completion_status",
        "usable_final_content",
        "final_content",
        "final_content_sha256",
        "final_content_chars",
        "elapsed_seconds",
        "raw_response_sha256",
        "raw_response_chars",
        "raw_response_bytes",
        "request_payload_sha256",
        "request_options_sha256",
        "thinking_parser",
        "reasoning_stripped",
        "reasoning_malformed",
        "reasoning_chars",
        "reasoning_sha256",
        "response_truncated",
        "finish_reasons",
        "response_model_status",
        "model_preflight",
        "forbidden_response_fields",
        "forbidden_response_sha256",
        "ignored_empty_response_fields",
        "provider_error_present",
        "provider_error_sha256",
        "payload_validation_error",
        "content_security_status",
        "response_contract",
        "server_structured_outputs_status",
        "response_contract_status",
        "response_contract_errors",
        "response_contract_diagnostics",
        "quarantined_content_sha256",
        "quarantined_content_chars",
        "normalized_return",
        "normalized_return_sha256",
        "normalized_return_chars",
    )
    return {key: local_response.get(key) for key in fields if key in local_response}


def compact_local_envelope(envelope: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(envelope, dict):
        return None
    fields = (
        "envelope_type",
        "version",
        "dispatch_id",
        "bead_id",
        "epic_id",
        "executor_key",
        "provider_key",
        "provider_trust_tier",
        "access_profile",
        "local_profile",
        "model_profile",
        "model",
        "auth_mode",
        "expected_return_language",
        "expected_return_language_source",
        "share_boundary",
        "job_description_label",
        "endpoint_path",
        "transport_binding_sha256",
        "timeout_seconds",
        "max_input_chars",
        "thinking_parser",
        "response_sanitization",
        "response_contract",
        "server_structured_outputs_status",
        "forbidden_request_options",
        "allowed_request_options",
        "max_final_chars",
        "quarantine_contract_invalid_content",
        "quarantine_unusable_content",
        "tls_verify",
        "tls_verify_source",
        "tls_binding_sha256",
        "execution_enabled",
    )
    compact = {key: envelope.get(key) for key in fields if key in envelope}
    options = envelope.get("request_options")
    if isinstance(options, dict):
        compact["request_options_sha256"] = artifact_hash(
            json.dumps(options, sort_keys=True, separators=(",", ":"))
        )
        compact["request_option_keys"] = sorted(options)
        for key in ("max_tokens", "reasoning_effort", "include_reasoning"):
            if key in options:
                compact[key] = options[key]
        structured_outputs = options.get("structured_outputs")
        if isinstance(structured_outputs, dict):
            compact["structured_outputs_kind"] = next(
                (
                    key
                    for key in ("json", "regex", "choice", "grammar")
                    if structured_outputs.get(key) is not None
                ),
                None,
            )
            compact["structured_outputs_sha256"] = artifact_hash(
                json.dumps(structured_outputs, sort_keys=True, separators=(",", ":"))
            )
    return compact


def compact_local_route(route: dict[str, Any]) -> dict[str, Any]:
    selected = route.get("selected_executor") if isinstance(route.get("selected_executor"), dict) else {}
    return {
        "route": route.get("route"),
        "task_class": route.get("task_class"),
        "risk_level": route.get("risk_level"),
        "share_boundary": route.get("share_boundary"),
        "recommended_executor": route.get("recommended_executor"),
        "selected_executor": {
            key: selected.get(key)
            for key in (
                "key",
                "display_name",
                "provider_key",
                "provider_trust_tier",
                "dispatch_mode",
                "access_profile",
                "local_profile",
                "model_profile",
            )
            if key in selected
        },
    }


def local_execution_exit_code(local_response: dict[str, Any] | None) -> int:
    if not isinstance(local_response, dict):
        return LOCAL_UNUSABLE_RESPONSE_EXIT_CODE
    if (
        local_response.get("completion_status") == "completed"
        and local_response.get("usable_final_content") is True
    ):
        return 0
    return LOCAL_UNUSABLE_RESPONSE_EXIT_CODE


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a manual dispatch artifact from a route result or packet.")
    parser.add_argument("text", nargs="*")
    parser.add_argument("--file")
    parser.add_argument("--packet", help="Boundary-gated JSON contractor packet from build_contractor_packet.py.")
    parser.add_argument(
        "--allow-degraded-packet",
        action="store_true",
        help="Allow dispatch of a packet that omits the expert profile after validation.",
    )
    parser.add_argument(
        "--allow-unlinked-packet",
        action="store_true",
        help="Operator-only escape hatch: allow a valid packet without a matching packet_built audit event.",
    )
    parser.add_argument(
        "--allow-raw-manual-prompt",
        action="store_true",
        help="Operator-only degraded path: render an external manual prompt without a validated packet.",
    )
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="Permit degraded/no-audit dispatch preparation only as a local rehearsal.",
    )
    parser.add_argument("--mode", choices=["manual"], default="manual")
    parser.add_argument("--external-ok", action="store_true")
    parser.add_argument(
        "--allow-disclosure-escalation",
        action="store_true",
        help="Explicitly approve repo-readonly or patch-branch disclosure routing.",
    )
    parser.add_argument("--local-ok", action="store_true", help="Permit low-risk local worker dispatch.")
    parser.add_argument("--prefer-local", action="store_true", help="Prefer local worker routing when policy permits it.")
    parser.add_argument(
        "--local-profile",
        help="Require a named local executor profile, for example openshift-ai-vllm.",
    )
    parser.add_argument("--local-base-url", help="OpenAI-compatible local endpoint base URL.")
    parser.add_argument("--local-model", help="Model name for local OpenAI-compatible dispatch.")
    parser.add_argument("--local-api-key-env", help="Environment variable containing the local endpoint API key.")
    parser.add_argument("--local-timeout", type=int, help="Timeout in seconds for --execute-local.")
    parser.add_argument(
        "--local-max-tokens",
        type=_positive_int,
        help="Override the OpenAI max_tokens request option for local dispatch.",
    )
    parser.add_argument(
        "--local-thinking",
        choices=["default", "on", "off"],
        default="default",
        help="Override local request chat_template_kwargs.enable_thinking.",
    )
    parser.add_argument(
        "--local-allow-private-dns",
        action="store_true",
        help="Allow private DNS route hostnames that resolve only to local/private addresses.",
    )
    parser.add_argument("--local-ca-bundle", help="CA bundle path for HTTPS local endpoint verification.")
    parser.add_argument(
        "--local-insecure-tls",
        action="store_true",
        help="Lab-only: disable TLS verification when the selected local executor profile explicitly allows it.",
    )
    parser.add_argument("--execute-local", action="store_true", help="Actually POST a local-worker envelope to the endpoint.")
    parser.add_argument(
        "--local-result-view",
        choices=["full", "compact"],
        default="full",
        help="Emit the historical full sanitized local result or a compact final-content and telemetry view.",
    )
    parser.add_argument(
        "--allow-offline-access-profile",
        action="store_true",
        help="Permit execution when the selected access profile is marked offline. Requires --waiver-reason.",
    )
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument(
        "--data-sensitivity",
        choices=["public", "redacted", "internal", "restricted"],
        help="Declare known input data sensitivity; overrides the advisory text heuristic.",
    )
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--bead")
    parser.add_argument("--epic")
    parser.add_argument("--dispatch-id")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    parser.add_argument("--json", action="store_true")
    add_waiver_reason_argument(parser)
    parser.add_argument("--current-authority", help="Current v3 routing evidence JSON; not a dispatch grant.")
    args = parser.parse_args()
    if not args.audit and not args.rehearsal:
        raise SystemExit("--no-audit is allowed only with --rehearsal for local tests or rehearsals")
    require_waiver_reason(
        args,
        [
            "allow_degraded_packet",
            "allow_unlinked_packet",
            "allow_raw_manual_prompt",
            "allow_disclosure_escalation",
            "local_allow_private_dns",
            "local_insecure_tls",
            "allow_offline_access_profile",
            "audit",
        ],
    )

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        expected_language, expected_language_source = contractor_packet_language_metadata(packet)
        if not args.allow_unlinked_packet:
            require_packet_build_audit(
                dispatch_id=str(packet.get("dispatch_id") or ""),
                bead_id=packet.get("bead_id"),
                packet_sha256=str(packet.get("packet_sha256") or ""),
            )
        quota_info = enforce_contracting_quota(
            packet.get("epic_id") or args.epic,
            packet["executor"],
            "external-contract",
            dispatch_id=packet.get("dispatch_id"),
            packet_sha256=packet.get("packet_sha256"),
        )
        artifact = {
            "dispatch_id": packet.get("dispatch_id"),
            "bead_id": packet.get("bead_id"),
            "epic_id": packet.get("epic_id") or args.epic,
            "executor_key": packet.get("executor"),
            "provider_key": packet.get("provider_key"),
            "provider_trust_tier": packet.get("provider_trust_tier"),
            "dispatch_mode": "manual_ui",
            "share_boundary": packet.get("share_boundary"),
            "disclosure_stage": packet.get("disclosure_stage"),
            "packet_sha256": packet.get("packet_sha256"),
            "packet_version": packet.get("packet_version"),
            "expected_return_language": expected_language,
            "expected_return_language_source": expected_language_source,
            "manual_prompt": render_packet_prompt(packet),
            **quota_info,
        }
        if args.audit:
            profile = packet.get("expert_profile") if isinstance(packet.get("expert_profile"), dict) else {}
            transport = packet.get("executor_transport") if isinstance(packet.get("executor_transport"), dict) else {}
            record_audit_event(
                {
                    "event_type": "dispatch_prepared",
                    "quota_event_type": quota_info.get("quota_event_type"),
                    "quota_stage": "consumed",
                    "dispatch_id": artifact["dispatch_id"],
                    "bead_id": artifact["bead_id"],
                    "epic_id": artifact["epic_id"],
                    "executor_key": artifact["executor_key"],
                    "provider_key": artifact["provider_key"],
                    "provider_trust_tier": artifact["provider_trust_tier"],
                    "access_profile": packet.get("access_profile"),
                    "executor_external": quota_info.get("executor_external"),
                    "dispatch_mode": artifact["dispatch_mode"],
                    "share_boundary": artifact["share_boundary"],
                    "disclosure_stage": artifact["disclosure_stage"],
                    "quota_remaining": quota_info.get("quota_remaining"),
                    "packet_sha256": artifact["packet_sha256"],
                    **waiver_audit_fields(args, ["allow_degraded_packet", "allow_unlinked_packet", "audit"]),
                    **telemetry_fields(
                        telemetry_kind="manual_dispatch",
                        telemetry_status="prepared",
                        telemetry_missing_reason="manual-dispatch-usage-unavailable",
                        agent_model_calls=1,
                        retry_count=0,
                        model=transport.get("model") or transport.get("default_model_label"),
                        model_label=transport.get("default_model_label"),
                        provider_family=packet.get("provider_family"),
                        provider_retention_class=packet.get("provider_retention_class"),
                        job_description_label=packet.get("job_description_label"),
                        expert_profile=profile.get("path"),
                        expert_profile_path=profile.get("path"),
                        expected_return_language=expected_language,
                        expected_return_language_source=expected_language_source,
                    ),
                }
            )
        if args.json:
            print(json.dumps(artifact, indent=2, sort_keys=True))
        else:
            print(artifact["manual_prompt"])
        return

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    try:
        route = classify_work(
            task,
            external_ok=args.external_ok,
            allow_disclosure_escalation=args.allow_disclosure_escalation,
            local_ok=args.local_ok,
            prefer_local=args.prefer_local,
            local_profile=args.local_profile,
            share_boundary=args.share_boundary,
            data_sensitivity=args.data_sensitivity,
            requested_roles=args.requested_role,
            **current_authority_file_arguments(args.current_authority),
        )
    except CWOError as exc:
        raise SystemExit(str(exc))
    if route.get("route") == "external-contract" and not args.allow_raw_manual_prompt:
        raise SystemExit(
            "external manual dispatch requires --packet; pass --allow-raw-manual-prompt only for an operator-only degraded dispatch"
        )
    if route.get("route") == "external-contract" and args.allow_raw_manual_prompt and not args.rehearsal:
        raise SystemExit("--allow-raw-manual-prompt requires --rehearsal and must not be used as production dispatch evidence")
    if args.allow_raw_manual_prompt:
        task = redact_text(task)
    dispatch_id = args.dispatch_id or make_dispatch_id(args.bead or "unassigned")
    quota_info = enforce_contracting_quota(
        args.epic,
        route["recommended_executor"],
        route["route"],
        dispatch_id=dispatch_id,
    )
    local_envelope = (
        build_local_envelope(
            task=task,
            route=route,
            dispatch_id=dispatch_id,
            bead_id=args.bead,
            epic_id=args.epic,
            args=args,
        )
        if route["selected_executor"]["dispatch_mode"] in {"local_openai_compatible", "local_secure_review"}
        else None
    )
    local_response = None
    if args.execute_local:
        if not local_envelope:
            raise SystemExit("--execute-local is only valid for local worker dispatch routes")
        local_response = execute_local_envelope(local_envelope, route["selected_executor"], args)

    artifact = {
        "dispatch_id": dispatch_id,
        "bead_id": args.bead,
        "epic_id": args.epic,
        "route": route,
        "dispatch_mode": route["selected_executor"]["dispatch_mode"],
        "manual_prompt": render_prompt(task, route) if route["selected_executor"]["dispatch_mode"] == "manual_ui" else None,
        "local_envelope": local_envelope,
        "local_response": local_response,
        **quota_info,
    }
    if args.audit:
        selected_executor = route["selected_executor"]
        dispatch_mode = artifact["dispatch_mode"]
        job_label = ((route.get("ranked_experts") or [{}])[0] or {}).get("job_description_label")
        is_local_dispatch = dispatch_mode in {"local_openai_compatible", "local_secure_review"}
        base_telemetry = telemetry_fields(
            telemetry_kind="local_dispatch" if is_local_dispatch else ("manual_dispatch" if dispatch_mode == "manual_ui" else "dispatch"),
            telemetry_status="completed" if local_response else "prepared",
            telemetry_missing_reason=None if local_response else "dispatch-usage-unavailable-until-execution",
            agent_model_calls=1 if (local_response or dispatch_mode == "manual_ui") else 0,
            retry_count=0,
            model=(local_envelope or {}).get("model"),
            provider_family=selected_executor.get("provider_family"),
            provider_retention_class=selected_executor.get("provider_retention_class"),
            access_profile=selected_executor.get("access_profile"),
            job_description_label=job_label,
            local_status_code=(local_response or {}).get("status_code") if local_response else None,
            execution_enabled=bool(args.execute_local),
            endpoint_path=(local_envelope or {}).get("endpoint_path"),
            timeout_seconds=(local_envelope or {}).get("timeout_seconds"),
            max_input_chars=(local_envelope or {}).get("max_input_chars"),
            allow_private_dns=(local_envelope or {}).get("allow_private_dns"),
            allow_insecure_tls=(local_envelope or {}).get("allow_insecure_tls"),
            tls_verify=(local_envelope or {}).get("tls_verify"),
            tls_verify_source=(local_envelope or {}).get("tls_verify_source"),
            tls_ca_bundle_env=(local_envelope or {}).get("tls_ca_bundle_env"),
            tls_ca_bundle_configured=(local_envelope or {}).get("tls_ca_bundle_configured"),
            thinking_parser=(local_envelope or {}).get("thinking_parser"),
            response_sanitization=(local_envelope or {}).get("response_sanitization"),
            expected_return_language=(local_envelope or {}).get("expected_return_language"),
            expected_return_language_source=(local_envelope or {}).get("expected_return_language_source"),
        )
        base_telemetry.update(local_response_telemetry(local_response))
        record_audit_event(
            {
                "event_type": "dispatch_prepared",
                "quota_event_type": quota_info.get("quota_event_type"),
                "quota_stage": "consumed",
                "dispatch_id": dispatch_id,
                "bead_id": args.bead,
                **waiver_audit_fields(
                    args,
                    [
                        "allow_raw_manual_prompt",
                        "allow_disclosure_escalation",
                        "local_allow_private_dns",
                        "local_insecure_tls",
                        "allow_offline_access_profile",
                        "audit",
                    ],
                ),
                "epic_id": args.epic,
                "executor_key": route["recommended_executor"],
                "provider_key": route["selected_executor"].get("provider_key"),
                "provider_trust_tier": route["selected_executor"].get("provider_trust_tier"),
                "access_profile": route["selected_executor"].get("access_profile"),
                "executor_external": quota_info.get("executor_external"),
                "dispatch_mode": artifact["dispatch_mode"],
                "share_boundary": args.share_boundary,
                "local_profile": args.local_profile,
                "quota_remaining": quota_info.get("quota_remaining"),
                **base_telemetry,
            }
        )
    rendered_artifact = artifact
    if args.local_result_view == "compact" and local_envelope is not None:
        rendered_artifact = {
            "dispatch_id": dispatch_id,
            "bead_id": args.bead,
            "epic_id": args.epic,
            "dispatch_mode": artifact["dispatch_mode"],
            "route": compact_local_route(route),
            "local_envelope": compact_local_envelope(local_envelope),
            "local_response": compact_local_response(local_response),
            "local_telemetry": local_response_telemetry(local_response),
            **quota_info,
        }
    if args.json:
        print(json.dumps(rendered_artifact, indent=2, sort_keys=True))
    else:
        print(
            rendered_artifact.get("manual_prompt")
            or json.dumps(rendered_artifact.get("local_envelope") or rendered_artifact.get("route"), indent=2, sort_keys=True)
        )
    if args.execute_local:
        exit_code = local_execution_exit_code(local_response)
        if exit_code:
            raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
