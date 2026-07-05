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
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt
from cwo_core.routing import classify_work
from cwo_core.audit import (
    enforce_contracting_quota,
    record_audit_event,
    require_packet_build_audit,
)
from cwo_core.telemetry import telemetry_fields
from cwo_core.policy import load_policy
from cwo_core.util import (
    artifact_hash,
    make_dispatch_id,
    read_text_arg,
)
from cwo_core.packets import redact_text, require_valid_contractor_packet


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


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _falsey(value: Any) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "off"}


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
    executor = load_policy("executor-registry").get("executors", {}).get(executor_key, {})
    return dict(executor) if isinstance(executor, dict) else {}


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


def _split_thinking_content(content: str) -> dict[str, Any]:
    if "</think>" in content.lower():
        parts = re.split(r"(?is)</think>", content, maxsplit=1)
        reasoning = parts[0]
        final = parts[1] if len(parts) > 1 else ""
        reasoning = re.sub(r"(?is)^.*?<think>", "", reasoning, count=1).strip()
        return {
            "content": final.strip(),
            "reasoning_stripped": True,
            "reasoning_chars": len(reasoning),
            "reasoning_sha256": artifact_hash(reasoning),
            "reasoning_malformed": False,
        }
    if re.search(r"(?is)<think>", content):
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


def sanitize_local_response_payload(payload: Any, thinking_parser: str | None) -> tuple[Any, dict[str, Any]]:
    metadata = {
        "thinking_parser": thinking_parser,
        "reasoning_stripped": False,
        "reasoning_malformed": False,
        "reasoning_chars": 0,
        "reasoning_sha256": None,
        "response_truncated": False,
        "finish_reasons": [],
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
    if thinking_parser != "glm-think-tags" or not isinstance(payload, dict):
        return payload, metadata

    sanitized = json.loads(json.dumps(payload))
    for choice in sanitized.get("choices", []) if isinstance(sanitized.get("choices"), list) else []:
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            continue
        split = _split_thinking_content(message["content"])
        if not split["reasoning_stripped"]:
            continue
        message["content"] = split["content"]
        message["reasoning_content_stripped"] = True
        message["reasoning_content_sha256"] = split["reasoning_sha256"]
        message["reasoning_content_chars"] = split["reasoning_chars"]
        if split["reasoning_malformed"]:
            message["reasoning_content_malformed"] = True
        metadata["reasoning_stripped"] = True
        metadata["reasoning_malformed"] = bool(metadata["reasoning_malformed"] or split["reasoning_malformed"])
        metadata["reasoning_chars"] = int(metadata["reasoning_chars"]) + int(split["reasoning_chars"])
        metadata["reasoning_sha256"] = split["reasoning_sha256"]
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
    transport = local_transport(selected, args)
    tls = local_tls_settings(transport, args)
    max_input_chars = int(transport["max_input_chars"])
    if len(task) > max_input_chars:
        raise SystemExit(f"local dispatch task exceeds max_input_chars={max_input_chars}")
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
        "version": 1,
        "dispatch_id": dispatch_id,
        "bead_id": bead_id,
        "epic_id": epic_id,
        "executor_key": route["recommended_executor"],
        "provider_key": selected.get("provider_key"),
        "provider_trust_tier": selected.get("provider_trust_tier"),
        "local_profile": selected.get("local_profile"),
        "model_profile": selected.get("model_profile"),
        "transport_kind": transport.get("kind"),
        "base_url_env": transport.get("base_url_env"),
        "base_url_configured": bool(transport.get("base_url")),
        "api_key_env": transport.get("api_key_env"),
        "model_env": transport.get("model_env"),
        "model": transport.get("model"),
        "endpoint_path": transport.get("endpoint_path"),
        "timeout_seconds": transport.get("timeout_seconds"),
        "max_input_chars": max_input_chars,
        "allow_private_dns": bool(transport.get("allow_private_dns")),
        "tls_verify": bool(tls["tls_verify"]),
        "tls_verify_source": tls["tls_verify_source"],
        "tls_ca_bundle_env": tls["tls_ca_bundle_env"],
        "tls_ca_bundle_configured": bool(tls["tls_ca_bundle_configured"]),
        "allow_insecure_tls": bool(tls["allow_insecure_tls"]),
        "request_options": local_request_options(transport),
        "thinking_parser": transport.get("thinking_parser"),
        "response_sanitization": transport.get("response_sanitization"),
        "constraints": constraints,
        "messages": messages,
        "execution_enabled": bool(args.execute_local),
    }


def execute_local_envelope(envelope: dict[str, Any], selected_executor: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    transport = local_transport(selected_executor, args)
    base_url = transport.get("base_url")
    if not base_url:
        raise SystemExit(
            f"--execute-local requires --local-base-url or ${transport.get('base_url_env')} for the local endpoint"
        )
    model = transport.get("model")
    if not model:
        raise SystemExit(f"--execute-local requires --local-model or ${transport.get('model_env')}")
    pinned_address = pinned_local_endpoint_address(str(base_url), allow_private_dns=bool(transport.get("allow_private_dns")))
    api_key_env = str(transport.get("api_key_env") or "")
    validate_local_api_key_env_name(api_key_env)
    payload = {
        "model": model,
        "messages": envelope["messages"],
        "temperature": 0,
    }
    payload.update(local_request_options(transport))
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
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
        opener_handlers: list[Any] = [NoRedirectHandler, request.ProxyHandler({})]
        context = local_ssl_context(str(base_url), transport, args)
        scheme = urlparse(str(base_url)).scheme
        if pinned_address and scheme == "https":
            opener_handlers.append(PinnedHTTPSHandler(pinned_address, context=context))
        elif pinned_address and scheme == "http":
            opener_handlers.append(PinnedHTTPHandler(pinned_address))
        elif context is not None:
            opener_handlers.append(request.HTTPSHandler(context=context))
        opener = request.build_opener(*opener_handlers)
        with opener.open(req, timeout=int(transport.get("timeout_seconds", 120))) as response:
            raw = response.read().decode("utf-8")
            try:
                parsed: Any = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            sanitized, response_metadata = sanitize_local_response_payload(parsed, transport.get("thinking_parser"))
            return {
                "status_code": response.status,
                "response": sanitized,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "raw_response_sha256": artifact_hash(raw),
                "raw_response_chars": len(raw),
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
    if os.environ.get("CWO_DEBUG_LOCAL_HTTP_BODY", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return ""
    safe = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "?", body)
    if len(safe) > 240:
        safe = safe[:240] + "...[truncated]"
    return f"; sanitized excerpt={safe!r}"


def local_response_telemetry(local_response: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(local_response, dict):
        return {}
    response_payload = local_response.get("response")
    rendered = json.dumps(response_payload, sort_keys=True) if isinstance(response_payload, (dict, list)) else str(response_payload or "")
    usage = response_payload.get("usage") if isinstance(response_payload, dict) and isinstance(response_payload.get("usage"), dict) else {}
    return telemetry_fields(
        telemetry_status="completed",
        agent_model_calls=1,
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
    )


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
    parser.add_argument("--share-boundary", default="no-outside-sharing")
    parser.add_argument("--requested-role", action="append", default=[])
    parser.add_argument("--bead")
    parser.add_argument("--epic")
    parser.add_argument("--dispatch-id")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.audit and not args.rehearsal:
        raise SystemExit("--no-audit is allowed only with --rehearsal for local tests or rehearsals")

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
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
                    "executor_external": quota_info.get("executor_external"),
                    "dispatch_mode": artifact["dispatch_mode"],
                    "share_boundary": artifact["share_boundary"],
                    "disclosure_stage": artifact["disclosure_stage"],
                    "quota_remaining": quota_info.get("quota_remaining"),
                    "packet_sha256": artifact["packet_sha256"],
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
                    ),
                }
            )
        if args.json:
            print(json.dumps(artifact, indent=2, sort_keys=True))
        else:
            print(artifact["manual_prompt"])
        return

    task = read_text_arg(" ".join(args.text).strip() or None, args.file)
    route = classify_work(
        task,
        external_ok=args.external_ok,
        allow_disclosure_escalation=args.allow_disclosure_escalation,
        local_ok=args.local_ok,
        prefer_local=args.prefer_local,
        local_profile=args.local_profile,
        share_boundary=args.share_boundary,
        requested_roles=args.requested_role,
    )
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
        )
        base_telemetry.update(local_response_telemetry(local_response))
        record_audit_event(
            {
                "event_type": "dispatch_prepared",
                "quota_event_type": quota_info.get("quota_event_type"),
                "quota_stage": "consumed",
                "dispatch_id": dispatch_id,
                "bead_id": args.bead,
                "epic_id": args.epic,
                "executor_key": route["recommended_executor"],
                "provider_key": route["selected_executor"].get("provider_key"),
                "provider_trust_tier": route["selected_executor"].get("provider_trust_tier"),
                "executor_external": quota_info.get("executor_external"),
                "dispatch_mode": artifact["dispatch_mode"],
                "share_boundary": args.share_boundary,
                "local_profile": args.local_profile,
                "quota_remaining": quota_info.get("quota_remaining"),
                **base_telemetry,
            }
        )
    if args.json:
        print(json.dumps(artifact, indent=2, sort_keys=True))
    else:
        print(artifact["manual_prompt"] or json.dumps(artifact["local_envelope"] or artifact["route"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
