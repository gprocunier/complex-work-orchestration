#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt
from orchestration_lib import (
    classify_work,
    enforce_contracting_quota,
    load_policy,
    make_dispatch_id,
    read_text_arg,
    record_audit_event,
    require_valid_contractor_packet,
)


def local_executor_fallback(executor_key: str) -> dict[str, Any]:
    executor = load_policy("executor-registry").get("executors", {}).get(executor_key, {})
    return dict(executor) if isinstance(executor, dict) else {}


def endpoint_url(base_url: str, endpoint_path: str) -> str:
    base = base_url.rstrip("/")
    path = "/" + endpoint_path.strip("/")
    return f"{base}{path}"


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
    if args.local_api_key_env:
        transport["api_key_env"] = args.local_api_key_env
    if args.local_timeout:
        transport["timeout_seconds"] = args.local_timeout
    base_url = args.local_base_url or os.environ.get(str(transport.get("base_url_env"))) or transport.get("default_base_url")
    model = args.local_model or os.environ.get(str(transport.get("model_env"))) or transport.get("default_model")
    return {
        **transport,
        "base_url": base_url,
        "model": model,
        "timeout_seconds": int(transport.get("timeout_seconds", 120)),
        "max_input_chars": int(transport.get("max_input_chars", 24000)),
    }


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
        "transport_kind": transport.get("kind"),
        "base_url_env": transport.get("base_url_env"),
        "base_url_configured": bool(transport.get("base_url")),
        "api_key_env": transport.get("api_key_env"),
        "model_env": transport.get("model_env"),
        "model": transport.get("model"),
        "endpoint_path": transport.get("endpoint_path"),
        "timeout_seconds": transport.get("timeout_seconds"),
        "max_input_chars": max_input_chars,
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
    payload = {
        "model": model,
        "messages": envelope["messages"],
        "temperature": 0,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get(str(transport.get("api_key_env") or ""))
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = request.Request(
        endpoint_url(str(base_url), str(transport.get("endpoint_path", "/v1/chat/completions"))),
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=int(transport.get("timeout_seconds", 120))) as response:
            raw = response.read().decode("utf-8")
            try:
                parsed: Any = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            return {"status_code": response.status, "response": parsed}
    except HTTPError as exc:
        raise SystemExit(f"local endpoint returned HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')}") from exc
    except URLError as exc:
        raise SystemExit(f"local endpoint request failed: {exc}") from exc


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

    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        quota_info = enforce_contracting_quota(
            packet.get("epic_id") or args.epic,
            packet["executor"],
            "external-contract",
            dispatch_id=packet.get("dispatch_id"),
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
            record_audit_event(
                {
                    "event_type": "dispatch_prepared",
                    "quota_event_type": quota_info.get("quota_event_type"),
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
        record_audit_event(
            {
                "event_type": "dispatch_prepared",
                "quota_event_type": quota_info.get("quota_event_type"),
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
            }
        )
    if args.json:
        print(json.dumps(artifact, indent=2, sort_keys=True))
    else:
        print(artifact["manual_prompt"] or json.dumps(artifact["local_envelope"] or artifact["route"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
