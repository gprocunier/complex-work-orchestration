#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import stat
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cwo_core.chatgpt_urls import approved_chatgpt_origin
from cwo_core.util import artifact_hash, atomic_write_text
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields

DEFAULT_CONFIG_ENV = "CWO_CHATGPT_BROWSER_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/cwo/chatgpt-browser.json"


DEFAULT_MAX_PROMPT_CHARS = 50000
LOCAL_CDP_HOSTS = {"127.0.0.1", "localhost", "::1"}
SHARE_UNAVAILABLE_REASON = "share-consent-contract-unavailable"
FORBIDDEN_CONFIG_KEYS = {
    "google_email",
    "google_password",
    "google_password_file",
    "password",
    "password_file",
    "cookie",
    "cookies",
    "session",
    "session_token",
    "token",
    "token_file",
}

BROWSER_DISPATCH_UNAVAILABLE = (
    "live browser dispatch is unavailable: CWO cannot yet bind workload-derived sizing to the exact prompt and "
    "hold an atomic one-use reservation within an aggregate budget before Send (issue #41). Nothing was sent. "
    "--dry-run and manual export remain available; --confirm-only is unavailable too, because confirming the "
    "model clicks configured page controls."
)


def browser_attestation_default(field: str) -> str:
    from browser_request import EXECUTOR_KEY
    from cwo_core.policy import load_policy

    defaults = load_policy("model-profiles").get("browser_attestation_defaults", {})
    profile = defaults.get(EXECUTOR_KEY, {}) if isinstance(defaults, dict) else {}
    value = profile.get(field) if isinstance(profile, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"policy/model-profiles.yaml browser_attestation_defaults.{EXECUTOR_KEY}.{field} is required")
    return value


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_config_path(raw: str | None) -> Path:
    value = raw or os.environ.get(DEFAULT_CONFIG_ENV) or DEFAULT_CONFIG_PATH
    return Path(value).expanduser().resolve()


def ensure_config_file_safe(path: Path) -> None:
    from cwo_core.paths import REPO_ROOT

    if not path.is_file():
        raise SystemExit(f"ChatGPT browser config not found: {path}")
    if path.is_relative_to(REPO_ROOT):
        raise SystemExit("ChatGPT browser config must live outside the repository")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(f"ChatGPT browser config must not be group/world accessible: {path} mode={mode:o}")


def load_browser_config(path: Path) -> dict[str, Any]:
    ensure_config_file_safe(path)
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ChatGPT browser config is not valid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("ChatGPT browser config must be a JSON object")
    forbidden = sorted(FORBIDDEN_CONFIG_KEYS.intersection(config))
    if forbidden:
        raise SystemExit(
            "ChatGPT browser config must not contain credentials or session material: " + ", ".join(forbidden)
        )
    config.setdefault("chatgpt_url", "https://chatgpt.com/")
    if approved_chatgpt_origin(str(config["chatgpt_url"])) is None:
        raise SystemExit("ChatGPT browser config chatgpt_url must be an https URL on a ChatGPT host")
    if config.get("model_label") in {None, ""}:
        config["model_label"] = browser_attestation_default("model_label")
    if config.get("reasoning_label") in {None, ""}:
        config["reasoning_label"] = browser_attestation_default("reasoning_label")
    config.setdefault("response_timeout_seconds", 1800)
    config.setdefault("stable_wait_seconds", 8)
    config.setdefault("headless", False)
    config.setdefault("share_link_required", False)
    config.setdefault("require_model_confirmation", True)
    config.setdefault("selectors", {})
    cdp_url = config.get("connect_over_cdp_url") or config.get("cdp_url")
    if cdp_url:
        parsed = urlparse(str(cdp_url))
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise SystemExit("ChatGPT browser CDP URL must be an unauthenticated local HTTP(S) URL")
        if (parsed.hostname or "").lower() not in LOCAL_CDP_HOSTS:
            raise SystemExit("ChatGPT browser CDP URL must point at localhost")
        config["connect_over_cdp_url"] = str(cdp_url)
    profile_dir = config.get("chrome_user_data_dir") or config.get("user_data_dir")
    if not profile_dir and not cdp_url:
        raise SystemExit("ChatGPT browser config must set chrome_user_data_dir")
    if profile_dir:
        config["chrome_user_data_dir"] = str(Path(str(profile_dir)).expanduser().resolve())
    return config


def config_summary(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    from cwo_core.paths import REPO_ROOT

    missing_confirmation = missing_confirmation_selectors(config)
    confirmation_configured = not missing_confirmation
    return {
        "config_present": config_path.is_file(),
        "config_external_to_repo": not config_path.is_relative_to(REPO_ROOT),
        "chrome_user_data_dir_configured": bool(config.get("chrome_user_data_dir")),
        "connect_over_cdp_configured": bool(config.get("connect_over_cdp_url")),
        "model_label": config.get("model_label"),
        "reasoning_label": config.get("reasoning_label"),
        "response_timeout_seconds": int(config.get("response_timeout_seconds", 1800)),
        "share_link_required": bool(config.get("share_link_required", False)),
        "share_creation": "unavailable",
        "clipboard_fallback": "removed",
        "require_model_confirmation": bool(config.get("require_model_confirmation", True)),
        "model_confirmation_configured": confirmation_configured,
        "model_confirmation_missing_selectors": missing_confirmation,
        "headless": bool(config.get("headless", False)),
    }


def missing_confirmation_selectors(config: dict[str, Any]) -> list[str]:
    selectors = dict(config.get("selectors") or {})
    return [
        f"{key}_confirmation_selector"
        for key in ["model_label", "reasoning_label"]
        if not (selectors.get(f"{key}_confirmation_selector") or config.get(f"{key}_confirmation_selector"))
    ]


def require_confirmation_selectors(config: dict[str, Any]) -> None:
    if not config.get("require_model_confirmation", True):
        return
    missing = missing_confirmation_selectors(config)
    if missing:
        raise SystemExit(
            "ChatGPT browser config requires model confirmation but is missing confirmation selectors: "
            + ", ".join(missing)
        )


def max_prompt_chars(config: dict[str, Any]) -> int:
    raw = config.get("max_prompt_chars", DEFAULT_MAX_PROMPT_CHARS)
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise SystemExit("ChatGPT browser config max_prompt_chars must be an integer") from exc


def enforce_prompt_size(prompt: str, config: dict[str, Any]) -> None:
    """Refuse a prompt whose submitted text, request id included, exceeds the limit."""
    from browser_request import bound_request

    limit = max_prompt_chars(config)
    if limit <= 0:
        return
    prompt_chars = len(bound_request(prompt, "0" * 32))
    if prompt_chars > limit:
        raise SystemExit(
            f"ChatGPT browser prompt is {prompt_chars} characters, above max_prompt_chars={limit}. "
            "Build a compact packet or selected-snippet prompt before launching the browser."
        )


def load_prompt_from_args(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    from browser_request import EXECUTOR_KEY, load_browser_packet_prompt

    if bool(args.packet) == bool(args.prompt_file):
        raise SystemExit("Provide exactly one of --packet or --prompt-file")
    if args.packet:
        prompt, metadata, _, _ = load_browser_packet_prompt(
            args.packet, vars(args), allow_degraded_packet=args.allow_degraded_packet,
            allow_unlinked_packet=args.allow_unlinked_packet,
        )
        return prompt, metadata
    if not args.allow_degraded_packet:
        raise SystemExit("ChatGPT prompt-file dispatch bypasses packet validation; use --packet or pass --allow-degraded-packet for an operator-only degraded dispatch")
    if not getattr(args, "rehearsal", False):
        raise SystemExit("ChatGPT prompt-file dispatch is rehearsal-only; use --packet for live ChatGPT Pro review")
    from cwo_core.audit import require_packet_build_audit
    from cwo_core.packets import find_residual_private_context
    from cwo_core.paths import assert_repo_safe_path
    from cwo_core.prepared_outbound import PreparedSource
    from generate_manual_dispatch_prompt import read_input_file

    prompt_path = assert_repo_safe_path(Path(args.prompt_file))
    files = []
    prompt = read_input_file(str(prompt_path), "prompt file", captures=files)
    source = {"prompt": prompt, "options": vars(args)}
    capture = PreparedSource.capture(source, files)
    if not args.dispatch_id or not args.bead or not args.packet_sha256:
        raise SystemExit("prompt-file dispatch requires --dispatch-id, --bead, and --packet-sha256")
    if not getattr(args, "allow_unlinked_packet", False):
        require_packet_build_audit(
            dispatch_id=str(args.dispatch_id),
            bead_id=args.bead,
            packet_sha256=str(args.packet_sha256),
        )
    residual_hits = find_residual_private_context(prompt)
    if residual_hits:
        raise SystemExit(
            "prompt-file dispatch contains residual private or secret-like context at: "
            + ", ".join(residual_hits)
        )
    capture.require_unchanged(source)
    return prompt, {
        "dispatch_id": args.dispatch_id,
        "bead_id": args.bead,
        "epic_id": args.epic,
        "packet_sha256": args.packet_sha256,
        "executor": EXECUTOR_KEY,
        "provider_key": "openai_manual",
        "provider_family": "openai",
        "provider_retention_class": "external-manual",
        "share_boundary": args.share_boundary,
    }


def share_status(config: dict[str, Any]) -> dict[str, Any]:
    """Report the legacy config request and the availability of sharing."""
    return {
        "created": False,
        "available": False,
        "reason": SHARE_UNAVAILABLE_REASON,
        "requested_by_config": bool(config.get("share_link_required", False)),
    }


def build_result(
    *,
    prompt: str,
    metadata: dict[str, Any],
    config: dict[str, Any],
    config_path: Path,
) -> dict[str, Any]:
    return {
        "dispatch_result_type": "chatgpt-browser-review-dispatch",
        "version": 1,
        "status": "dry-run",
        "error": None,
        "failure_stage": None,
        "failure_reason": None,
        "generated_at": now_utc(),
        "dispatch_id": metadata.get("dispatch_id"),
        "bead_id": metadata.get("bead_id"),
        "epic_id": metadata.get("epic_id"),
        "executor": metadata["executor"],
        "provider_key": metadata.get("provider_key") or "openai_manual",
        "provider_family": metadata.get("provider_family") or "openai",
        "provider_retention_class": metadata.get("provider_retention_class") or "external-manual",
        "job_description_label": metadata.get("job_description_label"),
        "expert_profile": metadata.get("expert_profile"),
        "model": config.get("model_label"),
        "model_label": config.get("model_label"),
        "reasoning_label": config.get("reasoning_label"),
        "share_boundary": metadata.get("share_boundary"),
        "packet_sha256": metadata.get("packet_sha256"),
        "packet_source_sha256": metadata.get("packet_source_sha256"),
        "expected_return_language": metadata.get("expected_return_language"),
        "expected_return_language_source": metadata.get("expected_return_language_source"),
        "prompt_sha256": artifact_hash(prompt),
        "prompt_chars": len(prompt),
        "config": config_summary(config, config_path),
        "share_url": None,
        "share_link_method": None,
        "response_chars": None,
        "model_attestation": None,
        "conversation_id": None,
        "response_extraction": None,
        "response_artifact": None,
        "share": share_status(config),
    }


def record_browser_rehearsal(result: dict[str, Any], args: argparse.Namespace) -> None:
    from cwo_core.audit import record_audit_event
    from cwo_core.telemetry import telemetry_fields

    waivers = waiver_audit_fields(args, ["allow_degraded_packet", "allow_unlinked_packet", "audit"])
    record_audit_event({
        "event_type": "chatgpt_browser_dispatch",
        "quota_event_type": None,
        "quota_stage": None,
        "dispatch_id": result["dispatch_id"],
        "bead_id": result["bead_id"],
        "epic_id": result["epic_id"],
        "executor_key": result["executor"],
        **waivers,
        "provider_key": result["provider_key"],
        "executor_external": True,
        "dispatch_mode": "browser_automation",
        "share_boundary": result["share_boundary"],
        "packet_sha256": result["packet_sha256"],
        "prompt_sha256": result["prompt_sha256"],
        "quota_remaining": None,
        "share_url_present": False,
        "response_artifact_present": False,
        "response_sha256": None,
        "share_link_method": None,
        "model_attestation_present": False,
        "status": result["status"],
        "failure_stage": None,
        **telemetry_fields(
            telemetry_kind="browser_rehearsal",
            telemetry_status=result["status"],
            agent_model_calls=0,
            retry_count=0,
            model=result["model"],
            model_label=result["model_label"],
            reasoning_label=result["reasoning_label"],
            provider_family=result["provider_family"],
            provider_retention_class=result["provider_retention_class"],
            job_description_label=result["job_description_label"],
            expert_profile=result["expert_profile"],
            prompt_chars=result["prompt_chars"],
            expected_return_language=result["expected_return_language"],
            expected_return_language_source=result["expected_return_language_source"],
        ),
    })


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a redacted browser review plan locally.")
    parser.add_argument("--packet", help="Boundary-gated contractor packet JSON.")
    parser.add_argument("--prompt-file", help="Rendered prompt file for advanced/operator use.")
    parser.add_argument("--config", help=f"Local browser config path. Defaults to ${DEFAULT_CONFIG_ENV} or {DEFAULT_CONFIG_PATH}.")
    parser.add_argument("--output", help="Write dispatch result JSON.")
    parser.add_argument(
        "--response-dir",
        help="Legacy compatibility argument.",
    )
    parser.add_argument("--bead")
    parser.add_argument("--epic")
    parser.add_argument("--dispatch-id")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--share-boundary", default="redacted-packet")
    parser.add_argument("--allow-degraded-packet", action="store_true")
    parser.add_argument(
        "--allow-unlinked-packet",
        action="store_true",
        help="Operator-only escape hatch: allow a valid packet without a matching packet_built audit event.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate prompt/config and print the redacted dispatch plan.")
    parser.add_argument("--confirm-only", action="store_true", help="Retired browser confirmation mode.")
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="Permit degraded prompt-file checks as a local rehearsal.",
    )
    parser.add_argument("--json", action="store_true", help="Compatibility flag; output is always JSON.")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    if not args.dry_run:
        raise SystemExit(BROWSER_DISPATCH_UNAVAILABLE)
    require_waiver_reason(args, ["allow_degraded_packet", "allow_unlinked_packet", "audit"])

    config_path = resolve_config_path(args.config)
    config = load_browser_config(config_path)
    prompt, metadata = load_prompt_from_args(args)
    enforce_prompt_size(prompt, config)
    require_confirmation_selectors(config)
    if args.confirm_only:
        raise SystemExit("--dry-run and --confirm-only are mutually exclusive")

    started = time.monotonic()
    result = build_result(prompt=prompt, metadata=metadata, config=config, config_path=config_path)
    result.update(
        elapsed_seconds=round(time.monotonic() - started, 3),
        quota_checked=False, quota_event_type=None, quota_remaining=None, executor_external=True,
    )
    if args.audit:
        record_browser_rehearsal(result, args)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        from cwo_core.paths import assert_safe_output_path

        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered + "\n")
    else:
        print(rendered, flush=True)


if __name__ == "__main__":
    main()
