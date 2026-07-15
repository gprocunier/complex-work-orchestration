#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
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
from cwo_core.return_language import default_expected_return_language
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
    return f"{base}{path}"


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
    if getattr(args, "local_api_key_env", None):
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
    if local_thinking in {"on", "off"}:
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
    return request_options


def _split_thinking_content(content: str) -> dict[str, Any]:
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
    if re.search(r"(?is)</?(think|analysis|reasoning)>", content):
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
        "provider_error_present": False,
        "provider_error_sha256": None,
    }
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
    sanitized = json.loads(json.dumps(payload))
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
        clean = str(message.get("content") or "").strip()
        if clean:
            final_contents.append(clean)
    final_content = final_contents[0] if final_contents else ""
    metadata["final_content"] = final_content
    metadata["final_content_sha256"] = artifact_hash(final_content)
    metadata["final_content_chars"] = len(final_content)
    finish_reasons = [str(item).strip().lower() for item in metadata["finish_reasons"]]
    if metadata["reasoning_malformed"]:
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
    if len(task) > max_input_chars:
        raise SystemExit(f"local dispatch task exceeds max_input_chars={max_input_chars}")
    request_options = local_request_options_override(transport, args)
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
        "local_profile": selected.get("local_profile"),
        "model_profile": selected.get("model_profile"),
        "expected_return_language": default_expected_return_language(),
        "expected_return_language_source": "local-envelope-v2",
        "transport_kind": transport.get("kind"),
        "base_url_env": transport.get("base_url_env"),
        "base_url_configured": bool(transport.get("base_url")),
        "api_key_env": transport.get("api_key_env"),
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
        "request_options": request_options,
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
        raw = response.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                "local model preflight returned malformed JSON; body omitted "
                f"(sha256={artifact_hash(raw)}, chars={len(raw)})"
            ) from exc
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
                f"response_sha256={artifact_hash(raw)}"
            )
        return {
            "status": "passed",
            "status_code": 200,
            "required_model": model,
            "observed_model_count": len(model_ids),
            "response_sha256": artifact_hash(raw),
            "response_chars": len(raw),
            "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
            "_completed_monotonic": time.monotonic(),
        }


def execute_local_envelope(envelope: dict[str, Any], selected_executor: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    require_access_profile_online_for_execution(envelope, args)
    transport = local_transport(selected_executor, args)
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
    validate_local_api_key_env_name(api_key_env)
    payload = {
        "model": model,
        "messages": envelope["messages"],
        "temperature": 0,
    }
    request_options = envelope.get("request_options")
    if isinstance(request_options, dict):
        payload.update(request_options)
    else:
        payload.update(local_request_options_override(transport, args))
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    headers["X-CWO-Dispatch-ID"] = str(envelope.get("dispatch_id") or uuid.uuid4())
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
            raw = response.read().decode("utf-8")
            if getattr(response, "status", None) != 200:
                raise SystemExit(
                    "local endpoint did not return HTTP 200; response body omitted "
                    f"(status={getattr(response, 'status', None)!r}, "
                    f"sha256={artifact_hash(raw)}, chars={len(raw)})"
                )
            try:
                parsed: Any = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {
                    "malformed_response_sha256": artifact_hash(raw),
                    "malformed_response_chars": len(raw),
                }
            sanitized, response_metadata = sanitize_local_response_payload(
                parsed,
                transport.get("thinking_parser"),
                required_finish_reason=(
                    str(transport.get("required_finish_reason"))
                    if transport.get("required_finish_reason")
                    else None
                ),
            )
            response_model = parsed.get("model") if isinstance(parsed, dict) else None
            response_model_status = "not-required"
            if transport.get("response_model_required") is True:
                response_model_status = "matched" if response_model == model else "mismatch"
                if response_model_status != "matched":
                    response_metadata["completion_status"] = "malformed-response"
                    response_metadata["usable_final_content"] = False
            return {
                "status_code": response.status,
                "response": sanitized,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "raw_response_sha256": artifact_hash(raw),
                "raw_response_chars": len(raw),
                "model_preflight": model_preflight,
                "response_model_status": response_model_status,
                **response_metadata,
            }
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"local endpoint returned HTTP {exc.code}; response body omitted "
            f"(sha256={artifact_hash(body)}, chars={len(body)})"
            + _debug_local_http_excerpt(body)
        ) from exc
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
        "provider_error_present",
        "provider_error_sha256",
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
        "endpoint_path",
        "timeout_seconds",
        "max_input_chars",
        "thinking_parser",
        "response_sanitization",
        "tls_verify",
        "tls_verify_source",
        "execution_enabled",
    )
    return {key: envelope.get(key) for key in fields if key in envelope}


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


if __name__ == "__main__":
    main()
