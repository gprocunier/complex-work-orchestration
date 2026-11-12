#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from generate_manual_dispatch_prompt import render_packet_prompt
from cwo_core.chatgpt_urls import CHATGPT_SHARE_URL_RE, approved_chatgpt_origin, valid_chatgpt_share_url
from cwo_core.paths import REPO_ROOT, assert_repo_safe_path, assert_safe_output_path, cwo_temp_dir
from cwo_core.private_artifact import (
    PrivateArtifactError,
    PrivateDirectory,
    artifact_path,
    note_present_artifacts,
    note_retained_by_name,
    sha256_bytes,
)
from cwo_core.util import (
    atomic_write_text,
    artifact_hash,
    make_dispatch_id,
)
from cwo_core.audit import enforce_contracting_quota, record_audit_event, require_packet_build_audit
from cwo_core.packet_provenance import require_production_contractor_packet
from cwo_core.packets import contractor_packet_language_metadata, find_residual_private_context
from cwo_core.outbound_screen import require_clean
from cwo_core.policy import load_policy
from cwo_core.telemetry import safe_text_hash, telemetry_fields
from cwo_core.waivers import add_waiver_reason_argument, require_waiver_reason, waiver_audit_fields

EXECUTOR_KEY = "chatgpt_pro_browser_master_reviewer"
DEFAULT_CONFIG_ENV = "CWO_CHATGPT_BROWSER_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/cwo/chatgpt-browser.json"


def browser_attestation_default(field: str) -> str:
    defaults = load_policy("model-profiles").get("browser_attestation_defaults", {})
    profile = defaults.get(EXECUTOR_KEY, {}) if isinstance(defaults, dict) else {}
    value = profile.get(field) if isinstance(profile, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"policy/model-profiles.yaml browser_attestation_defaults.{EXECUTOR_KEY}.{field} is required")
    return value


DEFAULT_MODEL_LABEL = browser_attestation_default("model_label")
DEFAULT_REASONING_LABEL = browser_attestation_default("reasoning_label")
DEFAULT_SCROLL_TO_BOTTOM_SELECTOR = (
    "[data-testid='scroll-to-bottom-button'], "
    "button[aria-label*='Scroll to bottom'], "
    "button[aria-label*='Jump to bottom'], "
    "button[aria-label*='Jump to latest'], "
    "button[aria-label*='Go to bottom'], "
    "button[aria-label*='Go to latest'], "
    "button[aria-hidden='true'][tabindex='-1'].btn-secondary"
)
DEFAULT_SHARE_BUTTON_SELECTOR = "[data-testid='share-chat-button'], button[aria-label*='Share']"
DEFAULT_ASSISTANT_MESSAGE_SELECTOR = "[data-message-author-role='assistant']"
DEFAULT_USER_MESSAGE_SELECTOR = "[data-message-author-role='user']"
PRIVATE_RESPONSE_ARTIFACT_TYPE = "chatgpt-browser-private-response"
PRIVATE_RESPONSE_VERSION = 4
DEFAULT_COMPLETION_MARKER_SELECTOR = "[data-testid='copy-turn-action-button']"
# Every check must pass before a capture is a complete return.
CAPTURE_CHECKS = (
    "request_turn",
    "response_turn",
    "completion_confirmed",
    "content_stable",
    "conversation_stable",
    "assistant_extraction",
)
# Whether any control on the page offers to stop a generation. Waiting and
# capture use this same expression.
_GENERATING_JS = r"""[...document.querySelectorAll('button,[role="button"]')].some(el =>
    /stop[- ]button|stop answering|stop generating|stop response|stop streaming/i.test(
      [el.getAttribute('aria-label') || '', el.getAttribute('data-testid') || '', el.innerText || ''].join(' ')))"""
# One synchronous read of everything a capture depends on: the conversation
# URL, the submission stamp left on the document, whether any generation is
# running, and each message's role, id, text and completion marker. A marker
# counts only inside a recognized turn container holding that one message.
# Two such snapshots are compared.
_SNAPSHOT_SCRIPT = r"""([markerSelector]) => {
  const stopping = """ + _GENERATING_JS + r""";
  const messages = [...document.querySelectorAll('[data-message-author-role]')].map(el => {
    const turn = el.closest('article, [data-testid^="conversation-turn"]');
    const sole = !!turn && turn.querySelectorAll('[data-message-author-role]').length === 1;
    return {
      role: el.getAttribute('data-message-author-role'),
      id: el.getAttribute('data-message-id'),
      text: el.innerText,
      marked: sole && !!turn.querySelector(markerSelector)
    };
  });
  return {url: location.href, stamp: window.__cwoSubmission || null, stopping: stopping, messages: messages};
}"""
# The scripts below run only in a document whose origin was already checked
# from outside the page (see _submit_prompt), and each takes one primitive
# argument, so no page-defined iterator or array method ever handles it.
# Stamp the document with this submission's request id.
_STAMP_SCRIPT = r"""(box, requestId) => { window.__cwoSubmission = requestId; return box.isConnected; }"""
# Insert the text into the composer the handle names.
_FILL_SCRIPT = r"""(box, text) => {
  if (!box.isConnected) return false;
  box.focus();
  if (box instanceof HTMLTextAreaElement || box instanceof HTMLInputElement) {
    Object.getOwnPropertyDescriptor(Object.getPrototypeOf(box), 'value').set.call(box, text);
    box.dispatchEvent(new Event('input', {bubbles: true}));
  } else {
    const range = document.createRange();
    range.selectNodeContents(box);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    document.execCommand('insertText', false, text);
  }
  return true;
}"""
# The send control of the same document as the composer.
_SEND_BUTTON_SCRIPT = r"""(box, selector) => {
  const all = box.ownerDocument.querySelectorAll(selector);
  return all.length ? all[all.length - 1] : null;
}"""
# Press the send control from inside its document if it carries this
# submission's stamp; "waiting" while the control is disabled.
_SEND_SCRIPT = r"""(button, requestId) => {
  if (window.__cwoSubmission !== requestId || !button.isConnected) return 'refused';
  if (button.disabled || button.getAttribute('aria-disabled') === 'true') return 'waiting';
  button.click();
  return 'pressed';
}"""
CONVERSATION_ID_RE = re.compile(r"/c/([A-Za-z0-9-]{8,})")
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DEFAULT_MAX_PROMPT_CHARS = 50000
LOCAL_CDP_HOSTS = {"127.0.0.1", "localhost", "::1"}
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


class ChatGPTBrowserReviewError(RuntimeError):
    def __init__(self, stage: str, reason: str, browser_result: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.browser_result = browser_result or {}


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def resolve_config_path(raw: str | None) -> Path:
    value = raw or os.environ.get(DEFAULT_CONFIG_ENV) or DEFAULT_CONFIG_PATH
    return Path(value).expanduser().resolve()


def ensure_config_file_safe(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"ChatGPT browser config not found: {path}")
    if is_relative_to(path, REPO_ROOT):
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
        config["model_label"] = DEFAULT_MODEL_LABEL
    if config.get("reasoning_label") in {None, ""}:
        config["reasoning_label"] = DEFAULT_REASONING_LABEL
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
    missing_confirmation = missing_confirmation_selectors(config)
    confirmation_configured = not missing_confirmation
    return {
        "config_present": config_path.is_file(),
        "config_external_to_repo": not is_relative_to(config_path, REPO_ROOT),
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
    limit = max_prompt_chars(config)
    if limit <= 0:
        return
    prompt_chars = len(bound_request(prompt, "0" * 32))
    if prompt_chars > limit:
        raise SystemExit(
            f"ChatGPT browser prompt is {prompt_chars} characters, above max_prompt_chars={limit}. "
            "Build a compact packet or selected-snippet prompt before launching the browser."
        )


def bound_request(prompt: str, request_id: str) -> str:
    """Return the exact text submitted: the prompt and a fresh per-submission request id.

    The id ties the observed user turn to this submission. A conversation that
    only contains the same prompt does not carry it.
    """
    if not REQUEST_ID_RE.match(request_id):
        raise ValueError("request id must be 32 lowercase hexadecimal characters")
    return f"{prompt.rstrip()}\n\nCWO request id: {request_id}"


def load_prompt_from_args(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    if bool(args.packet) == bool(args.prompt_file):
        raise SystemExit("Provide exactly one of --packet or --prompt-file")
    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_production_contractor_packet(
            packet, allow_degraded_packet=args.allow_degraded_packet, allow_unlinked_packet=args.allow_unlinked_packet
        )
        expected_language, expected_language_source = contractor_packet_language_metadata(packet)
        if packet.get("executor") != EXECUTOR_KEY:
            raise SystemExit(f"packet executor must be {EXECUTOR_KEY}")
        profile = packet.get("expert_profile") if isinstance(packet.get("expert_profile"), dict) else {}
        return render_packet_prompt(packet), {
            "dispatch_id": packet.get("dispatch_id"),
            "bead_id": packet.get("bead_id"),
            "epic_id": packet.get("epic_id"),
            "packet_sha256": packet.get("packet_sha256"),
            "executor": packet.get("executor"),
            "provider_key": packet.get("provider_key"),
            "provider_family": packet.get("provider_family"),
            "provider_retention_class": packet.get("provider_retention_class"),
            "job_description_label": packet.get("job_description_label"),
            "expert_profile": profile.get("path"),
            "share_boundary": packet.get("share_boundary"),
            "expected_return_language": expected_language,
            "expected_return_language_source": expected_language_source,
        }
    if not args.allow_degraded_packet:
        raise SystemExit("ChatGPT prompt-file dispatch bypasses packet validation; use --packet or pass --allow-degraded-packet for an operator-only degraded dispatch")
    if not getattr(args, "rehearsal", False):
        raise SystemExit("ChatGPT prompt-file dispatch is rehearsal-only; use --packet for live ChatGPT Pro review")
    prompt_path = assert_repo_safe_path(Path(args.prompt_file))
    prompt = prompt_path.read_text(encoding="utf-8")
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
    return prompt, {
        "dispatch_id": args.dispatch_id or make_dispatch_id("chatgpt-browser"),
        "bead_id": args.bead,
        "epic_id": args.epic,
        "packet_sha256": args.packet_sha256,
        "executor": EXECUTOR_KEY,
        "provider_key": "openai_manual",
        "provider_family": "openai",
        "provider_retention_class": "external-manual",
        "share_boundary": args.share_boundary,
    }


def extract_chatgpt_share_url(value: str) -> str:
    pending = [value.strip()]
    seen: set[str] = set()
    while pending:
        candidate = pending.pop(0).strip().strip(".,;()[]<>")
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if valid_chatgpt_share_url(candidate):
            return candidate

        decoded = unquote(candidate)
        if decoded != candidate:
            pending.append(decoded)

        parsed = urlparse(candidate)
        for values in parse_qs(parsed.query).values():
            pending.extend(values)

        for match in CHATGPT_SHARE_URL_RE.findall(candidate):
            pending.append(match)
    return ""


# Live browser dispatch (Send) and model confirmation, which clicks configured
# page controls, are unavailable until CWO binds workload-derived sizing to the
# exact prompt and holds an atomic one-use reservation within an aggregate
# budget before Send (issue #41). Dry runs and manual export stay available.
# Only tests of that future path change this.
BROWSER_DISPATCH_AVAILABLE = False
BROWSER_DISPATCH_UNAVAILABLE = (
    "live browser dispatch is unavailable: CWO cannot yet bind workload-derived sizing to the exact prompt and "
    "hold an atomic one-use reservation within an aggregate budget before Send (issue #41). Nothing was sent. "
    "--dry-run and manual export remain available; --confirm-only is unavailable too, because confirming the "
    "model clicks configured page controls."
)


class PlaywrightChatGPTRunner:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.selectors = dict(config.get("selectors") or {})
        self.last_share_link_method: str | None = None
        self.completion_confirmed = False
        # "not-sent", "may-have-been-submitted" (set before Send is pressed)
        # or "submitted". Set before the effect, so any failure after it, from
        # any instruction, can say the prompt may have gone out.
        self.send_state = "not-sent"

    def submission_note(self) -> str | None:
        """What a failure report must say about Send, or None if nothing was sent."""
        if self.send_state == "may-have-been-submitted":
            return "the prompt may have been submitted: Send was being pressed when this happened"
        if self.send_state == "submitted":
            return "the prompt was submitted: Send had been pressed"
        return None

    def note_submission(self, exc: BaseException) -> None:
        """Note on ``exc`` that the prompt was, or may have been, submitted."""
        note = self.submission_note()
        if note is not None and note not in getattr(exc, "__notes__", []):
            exc.add_note(note)

    def selector(self, key: str, default: str) -> str:
        return str(self.selectors.get(key) or default)

    def _stop_playwright(self, playwright: Any) -> None:
        try:
            playwright.stop()
        except RuntimeError as exc:
            # Python 3.14 can report this after successful CDP work while
            # Playwright is cleaning up. Do not let cleanup discard the review
            # result, but keep other RuntimeErrors visible.
            if "event loop is already running" not in str(exc):
                raise

    def confirm_model_only(self) -> dict[str, Any]:
        # Confirmation clicks configurable controls, which could resolve to Send.
        if not BROWSER_DISPATCH_AVAILABLE:
            raise SystemExit(BROWSER_DISPATCH_UNAVAILABLE)
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on host install
            raise SystemExit("Playwright is required for ChatGPT browser dispatch") from exc

        timeout_ms = int(self.config.get("page_timeout_seconds", 30)) * 1000
        manager = sync_playwright()
        playwright = manager.start()
        context = None
        attached = False
        try:
            if self.config.get("connect_over_cdp_url"):
                attached = True
                browser = playwright.chromium.connect_over_cdp(str(self.config["connect_over_cdp_url"]))
                context = browser.contexts[0] if browser.contexts else browser.new_context()
            else:
                context = playwright.chromium.launch_persistent_context(
                    self.config["chrome_user_data_dir"],
                    executable_path=self.config.get("chrome_executable_path"),
                    headless=bool(self.config.get("headless", False)),
                )
            page = self._select_page(context)
            page.goto(str(self.config.get("chatgpt_url")), wait_until="domcontentloaded", timeout=timeout_ms)
            self._wait_for_prompt(page, timeout_ms)
            self._select_configured_labels(page, timeout_ms, PlaywrightTimeoutError)
            model_attestation = self._confirm_configured_labels(page, timeout_ms)
        finally:
            if context is not None and not attached:
                context.close()
            self._stop_playwright(playwright)
        return {"model_attestation": model_attestation}

    def run(self, prompt: str) -> dict[str, Any]:
        if not BROWSER_DISPATCH_AVAILABLE:
            raise SystemExit(BROWSER_DISPATCH_UNAVAILABLE)
        self.send_state = "not-sent"
        try:
            return self._run(prompt)
        except BaseException as exc:
            # Whatever failed, and wherever (including browser teardown), a
            # failure after Send says so.
            self.note_submission(exc)
            raise

    def _run(self, prompt: str) -> dict[str, Any]:
        if not BROWSER_DISPATCH_AVAILABLE:
            raise SystemExit(BROWSER_DISPATCH_UNAVAILABLE)
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on host install
            raise SystemExit("Playwright is required for ChatGPT browser dispatch") from exc

        request_id = secrets.token_hex(16)
        submitted = bound_request(prompt, request_id)
        timeout_ms = int(self.config.get("page_timeout_seconds", 30)) * 1000
        response_timeout = int(self.config.get("response_timeout_seconds", 1800))
        stable_wait = int(self.config.get("stable_wait_seconds", 8))
        stage = "browser-start"
        model_attestation: dict[str, Any] | None = None
        share_url = ""
        response_text = ""
        manager = sync_playwright()
        playwright = manager.start()
        context = None
        attached = False
        try:
            if self.config.get("connect_over_cdp_url"):
                attached = True
                browser = playwright.chromium.connect_over_cdp(str(self.config["connect_over_cdp_url"]))
                context = browser.contexts[0] if browser.contexts else browser.new_context()
            else:
                context = playwright.chromium.launch_persistent_context(
                    self.config["chrome_user_data_dir"],
                    executable_path=self.config.get("chrome_executable_path"),
                    headless=bool(self.config.get("headless", False)),
                )
            try:
                stage = "page-load"
                page = self._select_page(context)
                page.goto(str(self.config.get("chatgpt_url")), wait_until="domcontentloaded", timeout=timeout_ms)
                stage = "prompt-ready"
                self._wait_for_prompt(page, timeout_ms)
                stage = "model-selection"
                self._select_configured_labels(page, timeout_ms, PlaywrightTimeoutError)
                stage = "model-confirmation"
                model_attestation = self._confirm_configured_labels(page, timeout_ms)
                before_text = self._conversation_text(page)
                before_messages = self._message_snapshot(page)
                before_url = before_messages.get("url") or str(getattr(page, "url", "") or "")
                stage = "prompt-submit"
                # Nothing is typed unless the page is on a ChatGPT origin and the
                # conversation could be read, so the reply can be bound to it.
                if approved_chatgpt_origin(before_url) is None:
                    raise SystemExit("the page is not on a ChatGPT origin; the prompt was not sent")
                if not before_messages.get("available"):
                    raise SystemExit("the conversation could not be read before submission; the prompt was not sent")
                require_clean(submitted, surface="ChatGPT browser Send")
                self._submit_prompt(page, submitted, timeout_ms, request_id)
                stage = "response-wait"
                pinned = self._pin_conversation(page, request_id, before_url, timeout_ms)
                response_text = self._wait_for_stable_response(
                    page, before_text, response_timeout, stable_wait, request_id=request_id
                )
                captured = self._capture_assistant_response(
                    page,
                    before_text,
                    response_text,
                    before_messages=before_messages,
                    prompt=submitted,
                    request_id=request_id,
                    before_url=before_url,
                    pinned_conversation_id=pinned,
                )
                # Public share creation is unavailable until share consent binds the
                # exact conversation and content at the moment of sharing.
            except ChatGPTBrowserReviewError:
                raise
            except SystemExit as exc:
                raise ChatGPTBrowserReviewError(
                    stage,
                    str(exc),
                    {
                        "share_url": share_url,
                        "response_chars": len(response_text),
                        "model_attestation": model_attestation,
                        "share_link_method": self.last_share_link_method,
                    },
                ) from exc
            except Exception as exc:
                raise ChatGPTBrowserReviewError(
                    stage,
                    str(exc),
                    {
                        "share_url": share_url,
                        "response_chars": len(response_text),
                        "model_attestation": model_attestation,
                        "share_link_method": self.last_share_link_method,
                    },
                ) from exc
            finally:
                if context is not None and not attached:
                    context.close()
        finally:
            self._stop_playwright(playwright)
        return {
            "share_url": share_url,
            "response_chars": len(captured["text"]),
            "model_attestation": model_attestation,
            "share_link_method": self.last_share_link_method,
            "response_text": captured["text"],
            "response_extraction": captured["extraction"],
            "assistant_message_id": captured["message_id"],
            "user_message_id": captured.get("user_message_id"),
            "conversation_url": captured["conversation_url"],
            "conversation_id": captured["conversation_id"],
            "conversation_text_sha256": artifact_hash(response_text),
            "request_id": request_id,
            "submitted_sha256": artifact_hash(submitted),
            "capture_complete": captured.get("capture_complete") is True,
            "capture_checks": captured.get("checks", {}),
            "capture_incomplete_reasons": captured.get("incomplete_reasons", ["capture-checks-missing"]),
            "share": share_status(self.config),
        }

    def _page_snapshot(self, page: Any) -> dict[str, Any] | None:
        """One synchronous read of URL, generation state and every message; None if unreadable."""
        marker = self.selector("completion_marker", DEFAULT_COMPLETION_MARKER_SELECTOR)
        try:
            value = page.evaluate(_SNAPSHOT_SCRIPT, [marker])
        except Exception:
            return None
        if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
            return None
        messages = []
        for item in value["messages"]:
            if not isinstance(item, dict):
                return None
            messages.append({
                "role": item.get("role"),
                "id": item.get("id") or None,
                "text": item.get("text") if isinstance(item.get("text"), str) else None,
                "marked": item.get("marked") is True,
            })
        stamp = value.get("stamp") if isinstance(value.get("stamp"), str) else None
        return {"url": str(value.get("url") or ""), "stamp": stamp, "stopping": value.get("stopping") is True, "messages": messages}

    def _message_snapshot(self, page: Any) -> dict[str, Any]:
        """The conversation before submission."""
        snapshot = self._page_snapshot(page)
        return {"available": snapshot is not None, "messages": (snapshot or {}).get("messages", []), "url": (snapshot or {}).get("url", "")}

    @staticmethod
    def _request_text(value: str) -> str:
        """Compare requests exactly, ignoring only line-ending style and surrounding whitespace."""
        return value.replace("\r\n", "\n").strip()

    def _capture_assistant_response(
        self,
        page: Any,
        before_text: str,
        conversation_text: str,
        *,
        before_messages: dict[str, Any] | None = None,
        prompt: str | None = None,
        request_id: str | None = None,
        before_url: str = "",
        pinned_conversation_id: str | None = None,
    ) -> dict[str, Any]:
        """Return the reply to this submission and whether it is a verified complete return.

        Two snapshots are taken, each one synchronous read of the URL, the
        generation state and every message's role, id, text and completion
        marker; they must be identical. In them, the submitted turn must be the
        only new user message, carry an id, be the only user message carrying
        this submission's request id and match the submitted text exactly (only
        line-ending style and surrounding whitespace are ignored); its reply
        must be the single new assistant message after it, with an id and its
        completion marker, nothing may follow, and no generation may be
        running. Both snapshots must come from the document stamped at
        submission and show the conversation pinned right after Send, on the
        ChatGPT origin the request was sent from (and the conversation it was
        sent in when that was already known). Without a request id or a pinned
        conversation there is no binding and the capture is incomplete.
        Anything else, including the conversation-delta fallback, is kept only
        as incomplete diagnostic text.
        """
        before = before_messages or {"available": False, "messages": []}
        before_ids = {item.get("id") for item in before.get("messages") or [] if item.get("id")}
        checks = {name: False for name in CAPTURE_CHECKS}
        user_id = assistant_id = None
        text = ""
        first = self._page_snapshot(page)
        second = self._page_snapshot(page) if first is not None else None
        url = (first or {}).get("url") or str(getattr(page, "url", "") or "")
        match = CONVERSATION_ID_RE.search(urlparse(url).path) if url else None
        conversation_id = match.group(1) if match else None
        if first is not None and before.get("available") and request_id and REQUEST_ID_RE.match(request_id):
            messages = first["messages"]
            new_users = [index for index, item in enumerate(messages)
                         if item["role"] == "user" and item["id"] and item["id"] not in before_ids]
            carriers = [index for index, item in enumerate(messages)
                        if item["role"] == "user" and request_id in (item["text"] or "")]
            if len(new_users) == 1 and carriers == new_users:
                index = new_users[0]
                user_id = messages[index]["id"]
                user_text = messages[index]["text"]
                checks["request_turn"] = (
                    prompt is not None and user_text is not None and self._request_text(user_text) == self._request_text(prompt)
                )
                following = messages[index + 1:]
                if (
                    len(following) == 1
                    and following[0]["role"] == "assistant"
                    and following[0]["id"]
                    and following[0]["id"] not in before_ids
                ):
                    assistant_id = following[0]["id"]
                    checks["response_turn"] = True
                    checks["completion_confirmed"] = following[0]["marked"] and not first["stopping"]
                    # The reply is kept exactly as read; surrounding whitespace can be meaningful.
                    text = following[0]["text"] or ""
                    checks["assistant_extraction"] = bool(text.strip())
            checks["content_stable"] = second is not None and second == first
        extraction = "assistant-message"
        if not text.strip():
            extraction = "conversation-delta"
            text = conversation_text[len(before_text):] if conversation_text.startswith(before_text) else conversation_text
            text = text.strip()
            assistant_id = None
        before_match = CONVERSATION_ID_RE.search(urlparse(before_url).path) if before_url else None
        origin = approved_chatgpt_origin(url) if url else None
        second_url = (second or {}).get("url", "")
        checks["conversation_stable"] = (
            bool(conversation_id)
            and conversation_id == pinned_conversation_id
            and first is not None
            and bool(request_id)
            and first.get("stamp") == request_id
            and origin is not None
            and origin == (approved_chatgpt_origin(before_url) if before_url else None)
            and second_url == url
            and (before_match is None or before_match.group(1) == conversation_id)
        )
        reasons = [name for name in CAPTURE_CHECKS if not checks[name]]
        return {
            "text": text,
            "extraction": extraction,
            "message_id": assistant_id,
            "user_message_id": user_id,
            "conversation_url": url,
            "conversation_id": conversation_id,
            "checks": checks,
            "capture_complete": not reasons and bool(text.strip()),
            "incomplete_reasons": reasons if text.strip() else reasons + ["empty-response"],
        }

    def _select_page(self, context: Any) -> Any:
        for page in context.pages:
            try:
                if approved_chatgpt_origin(page.url):
                    return page
            except Exception:
                continue
        return context.pages[0] if context.pages else context.new_page()

    def _wait_for_prompt(self, page: Any, timeout_ms: int) -> None:
        prompt_selector = self.selector("prompt_box", "textarea, [contenteditable='true']")
        page.locator(prompt_selector).last.wait_for(timeout=timeout_ms)

    def _select_configured_labels(self, page: Any, timeout_ms: int, timeout_type: type[Exception]) -> None:
        for label_key in ["model_label", "reasoning_label"]:
            label = self.config.get(label_key)
            if not label:
                continue
            selector_key = f"{label_key}_selector"
            selector = self.selectors.get(selector_key)
            open_selector = self.selectors.get(f"{label_key}_open_selector") or self.config.get(
                f"{label_key}_open_selector"
            )
            try:
                if selector:
                    self._open_target_if_needed(page, str(selector), open_selector, timeout_ms)
                    page.locator(str(selector)).first.click(timeout=timeout_ms)
                elif self.config.get("require_model_confirmation", True):
                    # Do not click loose page text for expensive ChatGPT Pro
                    # work; the same label often appears inside the prompt or
                    # conversation transcript. Confirmation below must prove
                    # the preselected state before submission.
                    continue
                else:
                    page.get_by_text(str(label), exact=False).first.click(timeout=timeout_ms)
            except timeout_type as exc:
                raise SystemExit(f"Could not select ChatGPT option {label!r}; update selectors in the local config") from exc

    def _open_target_if_needed(self, page: Any, target_selector: str, open_selector: Any, timeout_ms: int) -> None:
        try:
            page.locator(target_selector).first.wait_for(state="visible", timeout=500)
            return
        except Exception:
            pass
        if not open_selector:
            return
        page.locator(str(open_selector)).first.click(timeout=timeout_ms)
        page.locator(target_selector).first.wait_for(state="visible", timeout=timeout_ms)

    def _confirm_configured_labels(self, page: Any, timeout_ms: int) -> dict[str, Any]:
        if not self.config.get("require_model_confirmation", True):
            return {"required": False, "status": "skipped"}
        attestation: dict[str, Any] = {"required": True, "status": "confirmed", "labels": {}}
        for label_key in ["model_label", "reasoning_label"]:
            label = str(self.config.get(label_key) or "").strip()
            if not label:
                raise SystemExit(f"ChatGPT browser config must set {label_key} when model confirmation is required")
            selector_key = f"{label_key}_confirmation_selector"
            selector = self.selectors.get(selector_key) or self.config.get(selector_key)
            if not selector:
                raise SystemExit(
                    "ChatGPT browser dispatch refused to submit without "
                    f"{selector_key}. Configure a stable UI selector that proves {label_key}={label!r}, "
                    "or explicitly set require_model_confirmation=false for non-Pro test runs."
                )
            confirmation_text = str(
                self.config.get(f"{label_key}_confirmation_text")
                or self.selectors.get(f"{label_key}_confirmation_text")
                or label
            ).strip()
            open_selector = self.selectors.get(f"{label_key}_confirmation_open_selector") or self.config.get(
                f"{label_key}_confirmation_open_selector"
            )
            self._open_target_if_needed(page, str(selector), open_selector, timeout_ms)
            locator = page.locator(str(selector)).first
            try:
                locator.wait_for(timeout=timeout_ms)
                observed_parts = [
                    locator.inner_text(timeout=timeout_ms),
                    locator.get_attribute("aria-label", timeout=timeout_ms) or "",
                    locator.get_attribute("title", timeout=timeout_ms) or "",
                ]
            except Exception as exc:
                raise SystemExit(
                    f"ChatGPT browser dispatch refused to submit because {selector_key} did not resolve"
                ) from exc
            observed = " ".join(part.strip() for part in observed_parts if part and part.strip())
            if confirmation_text.lower() not in observed.lower():
                raise SystemExit(
                    "ChatGPT browser dispatch refused to submit because "
                    f"{selector_key} observed {observed!r}, expected text containing {confirmation_text!r}"
                )
            attribute_name = self.config.get(f"{label_key}_confirmation_attribute") or self.selectors.get(
                f"{label_key}_confirmation_attribute"
            )
            attribute_value = self.config.get(f"{label_key}_confirmation_attribute_value") or self.selectors.get(
                f"{label_key}_confirmation_attribute_value"
            )
            observed_attribute = None
            if attribute_name:
                observed_attribute = locator.get_attribute(str(attribute_name), timeout=timeout_ms)
                if attribute_value is not None and str(observed_attribute) != str(attribute_value):
                    raise SystemExit(
                        "ChatGPT browser dispatch refused to submit because "
                        f"{selector_key} had {attribute_name}={observed_attribute!r}, expected {attribute_value!r}"
                    )
            attestation["labels"][label_key] = {
                "expected": label,
                "confirmation_text": confirmation_text,
                "selector": str(selector),
                "attribute": str(attribute_name) if attribute_name else None,
                "attribute_value": str(observed_attribute) if observed_attribute is not None else None,
            }
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
        return attestation

    @staticmethod
    def _frame_origin(handle: Any) -> str | None:
        """The ChatGPT origin of the frame holding ``handle``, read without running page script.

        Playwright tracks frame URLs from the browser's navigation events, so a
        page cannot forge this value the way it can tamper with its own
        prototypes. A handle whose document has since been replaced cannot run
        anything, so a later script on it runs in the document checked here
        or fails.
        """
        frame = handle.owner_frame()
        return approved_chatgpt_origin(str(frame.url)) if frame is not None else None

    def _submit_prompt(self, page: Any, prompt: str, timeout_ms: int, request_id: str) -> str:
        """Insert ``prompt`` and press Send inside one document on a ChatGPT origin.

        The composer's frame origin is checked from outside the page before
        any script receives the prompt. The document is then stamped with the
        request id, the text inserted and Send pressed by scripts running on
        handles from that document; the send control is looked up in the
        composer's own document and its frame origin checked again. A handle
        from a replaced document cannot run, so nothing is inserted or pressed
        anywhere else. There is no keyboard or mouse fallback: page-level input
        goes to whichever document is current when it arrives.
        """
        boxes = page.query_selector_all(self.selector("prompt_box", "textarea, [contenteditable='true']"))
        if not boxes:
            raise SystemExit("the prompt box was not found; the prompt was not sent")
        box = boxes[-1]
        try:
            origin = self._frame_origin(box)
        except Exception as exc:
            raise SystemExit("the page changed before the prompt was inserted; the prompt was not sent") from exc
        if origin is None:
            raise SystemExit("the page is not on a ChatGPT origin; the prompt was not sent")
        try:
            inserted = box.evaluate(_STAMP_SCRIPT, request_id) is True and box.evaluate(_FILL_SCRIPT, prompt) is True
        except Exception as exc:
            raise SystemExit("the page changed before the prompt was inserted; the prompt was not sent") from exc
        if not inserted:
            raise SystemExit("the prompt box left the page before insertion; the prompt was not sent")
        selector = self.selector("submit_button", "[data-testid='send-button'], button[aria-label*='Send']")
        deadline = time.monotonic() + timeout_ms / 1000
        while True:
            try:
                button = box.evaluate_handle(_SEND_BUTTON_SCRIPT, selector).as_element()
                if button is None:
                    state = "waiting"
                elif self._frame_origin(button) != origin:
                    state = "refused"
                else:
                    state = None
            except Exception as exc:
                raise SystemExit("the page changed before Send was pressed; the prompt was not sent") from exc
            if state is None:
                self.send_state = "may-have-been-submitted"
                try:
                    state = button.evaluate(_SEND_SCRIPT, request_id)
                except Exception as exc:
                    # The script presses Send before it answers, so a failure
                    # here does not show that nothing was submitted.
                    raise SystemExit("the page changed while Send was being pressed; the prompt may have been submitted") from exc
                except BaseException as exc:
                    # An interruption keeps its type and says the same.
                    self.note_submission(exc)
                    raise
                self.send_state = "submitted" if state == "pressed" else "not-sent"
            if state == "pressed":
                return state
            if state != "waiting" or time.monotonic() >= deadline:
                raise SystemExit("Send could not be pressed in the checked document; the prompt was not sent")
            time.sleep(0.2)

    def _pin_conversation(self, page: Any, request_id: str, before_url: str, timeout_ms: int) -> str | None:
        """The conversation the submission landed in, read as soon as it is known.

        Polls the stamped document until the submitted turn (the only user
        message carrying the request id) is visible with a conversation id in
        the URL, on the origin the request was sent from. A conversation that
        was already open when the request was sent must be that one. Returns
        None when this cannot be established (for example after the stamped
        document was replaced), which leaves the capture incomplete.
        """
        before_match = CONVERSATION_ID_RE.search(urlparse(before_url).path) if before_url else None
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            snapshot = self._page_snapshot(page)
            if snapshot is not None:
                if snapshot.get("stamp") != request_id:
                    return None
                carriers = [item for item in snapshot["messages"] if item["role"] == "user" and request_id in (item["text"] or "")]
                match = CONVERSATION_ID_RE.search(urlparse(snapshot["url"]).path)
                same_origin = approved_chatgpt_origin(snapshot["url"]) == approved_chatgpt_origin(before_url)
                if len(carriers) == 1 and match and same_origin:
                    if before_match is not None and before_match.group(1) != match.group(1):
                        return None
                    return match.group(1)
            time.sleep(0.5)
        return None

    def _conversation_text(self, page: Any) -> str:
        selector = self.selector("conversation_container", "main")
        try:
            return str(page.locator(selector).inner_text(timeout=5000))
        except Exception:
            return ""

    def _wait_for_stable_response(
        self,
        page: Any,
        before_text: str,
        response_timeout: int,
        stable_wait: int,
        *,
        request_id: str | None = None,
    ) -> str:
        deadline = time.monotonic() + response_timeout
        last_text = ""
        last_change = time.monotonic()
        saw_growth = False
        self.completion_confirmed = False
        while time.monotonic() < deadline:
            text = self._conversation_text(page)
            if len(text) > len(before_text) + 20:
                saw_growth = True
            if text != last_text:
                last_text = text
                last_change = time.monotonic()
            if saw_growth and time.monotonic() - last_change >= stable_wait:
                in_progress = self._response_in_progress(page)
                if in_progress is False and (request_id is None or self._bound_reply_terminal(page, request_id)):
                    self.completion_confirmed = True
                    return text
                if in_progress is False and time.monotonic() - last_change >= 2 * stable_wait:
                    # The page shows no generation, but the bound reply never
                    # reached its terminal state; the capture will say so.
                    return text
                if in_progress is None and time.monotonic() - last_change >= 2 * stable_wait:
                    # The probe cannot confirm completion; the text is returned
                    # but the capture will not be complete.
                    return text
            time.sleep(2)
        raise SystemExit("Timed out waiting for ChatGPT response to finish")

    def _bound_reply_terminal(self, page: Any, request_id: str) -> bool:
        """Whether the reply after the submitted turn shows its own completion marker."""
        snapshot = self._page_snapshot(page)
        if snapshot is None or snapshot["stopping"]:
            return False
        messages = snapshot["messages"]
        carriers = [index for index, item in enumerate(messages) if item["role"] == "user" and request_id in (item["text"] or "")]
        if len(carriers) != 1:
            return False
        following = messages[carriers[0] + 1:]
        return len(following) == 1 and following[0]["role"] == "assistant" and following[0]["marked"]

    def _response_in_progress(self, page: Any) -> bool | None:
        """True or False from the page; None when the probe itself failed."""
        try:
            return bool(page.evaluate("() => " + _GENERATING_JS))
        except Exception:
            return None

    def _wait_for_share_ready(self, page: Any, timeout_ms: int) -> None:
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            self._click_scroll_to_bottom_if_present(page)
            try:
                for candidate in self._share_button_candidates(page):
                    if self._locator_disabled(candidate):
                        continue
                    return
            except Exception:
                pass
            time.sleep(1)
        raise SystemExit("ChatGPT share button did not become ready before timeout")

    def _click_scroll_to_bottom_if_present(self, page: Any) -> None:
        selector = self.selector("scroll_to_bottom_button", DEFAULT_SCROLL_TO_BOTTOM_SELECTOR)
        try:
            locator = page.locator(selector)
            for candidate in self._visible_candidates(locator):
                try:
                    candidate.click(timeout=750)
                    time.sleep(0.5)
                    return
                except Exception:
                    continue
            time.sleep(0.5)
        except Exception:
            pass

    def _create_share_link(self, page: Any, timeout_ms: int, timeout_type: type[Exception]) -> str:
        self.last_share_link_method = None
        self._click_scroll_to_bottom_if_present(page)
        self._wait_for_share_ready(page, timeout_ms)
        self._click_scroll_to_bottom_if_present(page)
        self._click_share_button(page, timeout_ms, timeout_type)
        create_selector = self.selectors.get("create_link_button")
        if create_selector:
            try:
                page.locator(str(create_selector)).first.click(timeout=timeout_ms)
            except timeout_type:
                pass
        copy_selector = self.selectors.get("copy_link_button")
        if copy_selector:
            try:
                page.locator(str(copy_selector)).first.click(timeout=timeout_ms)
            except timeout_type:
                pass
        share_url = self._extract_share_url_from_page(page)
        if share_url:
            return share_url
        share_url = self._try_social_share_url(page, timeout_ms, timeout_type)
        if share_url:
            return share_url
        return ""

    def _click_share_button(self, page: Any, timeout_ms: int, timeout_type: type[Exception]) -> None:
        candidates = self._share_button_candidates(page)
        for candidate in candidates:
            try:
                candidate.click(timeout=timeout_ms)
                return
            except timeout_type:
                try:
                    candidate.click(timeout=timeout_ms, force=True)
                    return
                except Exception:
                    continue
            except Exception:
                continue
        raise ChatGPTBrowserReviewError("share-link", "ChatGPT share button could not be clicked")

    def _share_button_candidates(self, page: Any) -> list[Any]:
        selector = self.selector("share_button", DEFAULT_SHARE_BUTTON_SELECTOR)
        locator = page.locator(selector)
        candidates = self._locator_candidates(locator)
        ranked: list[tuple[int, int, Any]] = []
        seen: set[int] = set()
        for index, candidate in enumerate(candidates):
            marker = id(candidate)
            if marker in seen:
                continue
            seen.add(marker)
            if self._locator_disabled(candidate) or not self._locator_visible(candidate):
                continue
            aria_label = (self._locator_attribute(candidate, "aria-label") or "").lower()
            data_testid = (self._locator_attribute(candidate, "data-testid") or "").lower()
            in_viewport = self._locator_in_viewport(candidate)
            is_response_share = "share" in aria_label and data_testid != "share-chat-button"
            if is_response_share and in_viewport:
                rank = 0
            elif data_testid == "share-chat-button":
                rank = 1
            elif is_response_share:
                rank = 2
            else:
                rank = 3
            ranked.append((rank, index, candidate))
        ranked.sort(key=lambda item: (item[0], item[1]))
        return [candidate for _, _, candidate in ranked]

    def _locator_candidates(self, locator: Any) -> list[Any]:
        candidates: list[Any] = []
        try:
            count = int(locator.count())
            if count > 0:
                for index in range(count):
                    candidates.append(locator.nth(index))
                return candidates
        except Exception:
            pass
        try:
            candidates.append(locator.first)
        except Exception:
            pass
        if candidates:
            return candidates
        return [locator]

    def _locator_attribute(self, locator: Any, name: str) -> str:
        try:
            return str(locator.get_attribute(name, timeout=250) or "")
        except Exception:
            return ""

    def _locator_visible(self, locator: Any) -> bool:
        try:
            return bool(locator.is_visible())
        except Exception:
            pass
        try:
            box = locator.bounding_box()
            if not box:
                return False
            width = float(box.get("width", 0))
            height = float(box.get("height", 0))
            if width <= 0 or height <= 0:
                return False
            return True
        except Exception:
            pass
        return True

    def _locator_in_viewport(self, locator: Any) -> bool:
        try:
            return bool(
                locator.evaluate(
                    """el => {
  const rect = el.getBoundingClientRect();
  if (!rect || rect.width <= 0 || rect.height <= 0) {
    return false;
  }
  const viewport = {
    width: window.innerWidth || document.documentElement.clientWidth,
    height: window.innerHeight || document.documentElement.clientHeight,
  };
  return rect.right >= 0 && rect.bottom >= 0 && rect.left <= viewport.width && rect.top <= viewport.height;
}"""
                )
            )
        except Exception:
            pass
        try:
            box = locator.bounding_box()
            if not box:
                return True
            width = float(box.get("width", 0))
            height = float(box.get("height", 0))
            if width <= 0 or height <= 0:
                return False
            return True
        except Exception:
            pass
        return True

    def _locator_disabled(self, locator: Any) -> bool:
        try:
            if locator.is_disabled():
                return True
        except Exception:
            pass
        if self._locator_attribute(locator, "disabled").lower() in {"true", "disabled"}:
            return True
        if self._locator_attribute(locator, "aria-disabled").lower() in {"true", "disabled"}:
            return True
        if self._locator_attribute(locator, "data-disabled").lower() in {"true", "disabled"}:
            return True
        if self._locator_attribute(locator, "data-visually-disabled").lower() in {"true", "disabled"}:
            return True
        return False

    def _visible_candidates(self, locator: Any) -> list[Any]:
        return [
            candidate
            for candidate in self._locator_candidates(locator)
            if self._locator_visible(candidate) and not self._locator_disabled(candidate)
        ]

    def _extract_share_url_from_page(self, page: Any) -> str:
        for selector, method in [
            (self.selector("share_url", "input[value*='chatgpt.com'], textarea"), "dom-input"),
            ("a[href*='chatgpt.com/s/'], a[href*='chatgpt.com/share/']", "dom-anchor"),
        ]:
            try:
                locator = page.locator(selector).first
                value = locator.input_value(timeout=3000)
                if valid_chatgpt_share_url(value):
                    self.last_share_link_method = method
                    return value
            except Exception:
                try:
                    href = locator.get_attribute("href", timeout=3000)
                    if href and valid_chatgpt_share_url(href):
                        self.last_share_link_method = method
                        return href
                except Exception:
                    continue
        return ""

    def _try_social_share_url(self, page: Any, timeout_ms: int, timeout_type: type[Exception]) -> str:
        selector = self.selector(
            "social_share_button",
            "a[href*='twitter.com/intent'], a[href*='x.com/intent'], button:has-text('X'), a:has-text('X')",
        )
        context = getattr(page, "context", None)
        if context is None or not hasattr(context, "expect_page"):
            return ""
        locator = page.locator(selector)
        candidates: list[Any] = []
        try:
            count = int(locator.count())
            if count > 1:
                candidates.append(locator.nth(count - 1))
        except Exception:
            pass
        try:
            candidates.append(locator.first)
        except Exception:
            pass
        candidates.append(locator)
        for candidate in candidates:
            try:
                with context.expect_page(timeout=min(timeout_ms, 5000)) as popup_info:
                    candidate.click(timeout=min(timeout_ms, 5000))
                popup = popup_info.value
                share_url = self._share_url_from_social_intent(str(getattr(popup, "url", "") or ""))
                try:
                    popup.close()
                except Exception:
                    pass
                if share_url:
                    self.last_share_link_method = "social-intent"
                    return share_url
            except timeout_type:
                continue
            except Exception:
                continue
        return ""

    def _share_url_from_social_intent(self, value: str) -> str:
        return extract_chatgpt_share_url(value)


SHARE_UNAVAILABLE_REASON = "share-consent-contract-unavailable"


def share_status(config: dict[str, Any]) -> dict[str, Any]:
    """Report public sharing as unavailable; legacy config requests are not honored."""
    return {
        "created": False,
        "available": False,
        "reason": SHARE_UNAVAILABLE_REASON,
        "requested_by_config": bool(config.get("share_link_required", False)),
    }


def resolve_response_dir(raw: str | None) -> Path:
    """Return the owner-only directory for private responses (outside the repository).

    The path is read the way the artifact writer reads it: absolute, with no
    ``..`` component to normalize away. It must lie outside the repository both
    as written and with symlinks resolved; the writer then refuses any
    symlinked component.
    """
    if not raw:
        return cwo_temp_dir(purpose="chatgpt-browser-returns")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise SystemExit("--response-dir must be an absolute path")
    try:
        path = artifact_path(path)
    except PrivateArtifactError as exc:
        raise SystemExit("--response-dir must not contain a '..' component") from exc
    if is_relative_to(path, REPO_ROOT) or is_relative_to(path.resolve(), REPO_ROOT):
        raise SystemExit("--response-dir must live outside the repository")
    return path


def private_response_names(metadata: dict[str, Any]) -> tuple[str, str]:
    """Fresh ``(provenance, response)`` file names for one capture.

    A caller fixes them before anything is written, so that a failure at any
    point afterwards can be checked against these names.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", str(metadata.get("dispatch_id") or "dispatch")).strip(".-") or "dispatch"
    run_id = f"{stem}-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    return f"{run_id}.provenance.json", f"{run_id}.response.txt"


def note_present_response_files(exc: BaseException, response_dir: Path, names: tuple[str, ...],
                                published: list[str] | tuple[str, ...] = ()) -> None:
    """Note on ``exc`` each planned private response file that exists (or cannot be checked), and each one known to
    have been published (``published``) even if it is no longer found by name."""
    present = []
    for name in names:
        path = response_dir / name
        try:
            os.lstat(path)
        except FileNotFoundError:
            if any(Path(known).name == name for known in published):
                present.append(f"{path} (published, but no longer at that path)")
            continue
        except OSError:
            present.append(f"{path} (could not be checked)")
            continue
        present.append(str(path))
    if present:
        note = "private response files present after the failure: " + ", ".join(present)
        if note not in getattr(exc, "__notes__", []):
            exc.add_note(note)


def write_private_response(
    response_dir: Path,
    *,
    metadata: dict[str, Any],
    prompt: str,
    browser_result: dict[str, Any],
    retained: list[str] | None = None,
    names: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Persist the response privately and return a digest reference.

    The response text never enters the dispatch result, stdout or the audit log.
    An unverified capture is still stored, marked incomplete, as diagnostic
    material that ingestion refuses as a return. Both files are written through
    one pinned directory descriptor, provenance first: it holds identities and
    the response digest but no response text, and ingest refuses it while the
    response file it names is missing. Nothing is deleted on failure; the error
    (or, for an interruption, an exception note) names any file that was
    published, and every published path is appended to ``retained`` as soon
    as it is known, so a caller can still report it after a later failure.
    """
    text = browser_result.get("response_text")
    if not isinstance(text, str) or not text.strip():
        raise SystemExit("browser response capture is empty; no private response artifact was written")
    response_bytes = text.encode("utf-8")
    provenance_name, response_name = names or private_response_names(metadata)
    response_sha256 = sha256_bytes(response_bytes)
    checks = browser_result.get("capture_checks") if isinstance(browser_result.get("capture_checks"), dict) else {}
    bound = isinstance(browser_result.get("request_id"), str) and bool(REQUEST_ID_RE.match(browser_result["request_id"]))
    complete = bound and browser_result.get("capture_complete") is True and all(checks.get(name) is True for name in CAPTURE_CHECKS)
    reasons = list(browser_result.get("capture_incomplete_reasons") or [])
    if not bound:
        reasons.append("request-binding-missing")
    reasons = reasons or ["capture-checks-missing"]
    provenance = {
        "artifact_type": PRIVATE_RESPONSE_ARTIFACT_TYPE,
        "version": PRIVATE_RESPONSE_VERSION,
        "captured_at": now_utc(),
        "capture_complete": complete,
        "capture_checks": {name: checks.get(name) is True for name in CAPTURE_CHECKS},
        "capture_incomplete_reasons": [] if complete else reasons,
        "dispatch_id": metadata.get("dispatch_id"),
        "bead_id": metadata.get("bead_id"),
        "epic_id": metadata.get("epic_id"),
        "executor": metadata.get("executor") or EXECUTOR_KEY,
        "provider_key": metadata.get("provider_key") or "openai_manual",
        "packet_sha256": metadata.get("packet_sha256"),
        "prompt_sha256": artifact_hash(prompt),
        "request_id": browser_result.get("request_id"),
        "submitted_sha256": browser_result.get("submitted_sha256"),
        "share_boundary": metadata.get("share_boundary"),
        "conversation_url": browser_result.get("conversation_url"),
        "conversation_id": browser_result.get("conversation_id"),
        "assistant_message_id": browser_result.get("assistant_message_id"),
        "user_message_id": browser_result.get("user_message_id"),
        "response_extraction": browser_result.get("response_extraction"),
        "conversation_text_sha256": browser_result.get("conversation_text_sha256"),
        "response_file": response_name,
        "response_sha256": response_sha256,
        "response_chars": len(text),
        "model_attestation": browser_result.get("model_attestation"),
        "share": {"created": bool(browser_result.get("share_url"))},
    }
    provenance_bytes = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        directory = PrivateDirectory.open(response_dir, create=True)
    except PrivateArtifactError as exc:
        raise SystemExit(f"could not open the private response directory: {exc}") from exc
    published = retained if retained is not None else []
    try:
        try:
            try:
                provenance_path = directory.write(provenance_name, provenance_bytes)
            except BaseException as exc:
                if getattr(exc, "retained_artifact", None) is not None:
                    published.append(str(exc.retained_artifact))  # type: ignore[attr-defined]
                if isinstance(exc, PrivateArtifactError):
                    raise SystemExit(f"could not write private response provenance: {exc}") from exc
                raise
            published.append(str(provenance_path))
            try:
                response_path = directory.write(response_name, response_bytes)
                published.append(str(response_path))
            except BaseException as exc:
                if getattr(exc, "retained_artifact", None) is not None and str(exc.retained_artifact) not in published:
                    published.append(str(exc.retained_artifact))  # type: ignore[attr-defined]
                present = directory.contains(response_name)
                if present:
                    retained = (f"the provenance {provenance_path} and the response {directory.path / response_name} are both "
                                "retained; ingest accepts the pair only if the response matches its recorded digest")
                elif present is False:
                    retained = f"the provenance {provenance_path} is retained without its response file, and ingest refuses it"
                else:
                    retained = f"the provenance {provenance_path} is retained; whether the response file exists could not be checked"
                if isinstance(exc, PrivateArtifactError):
                    raise SystemExit(f"could not write private response artifact ({exc}); {retained}") from exc
                exc.add_note(retained)
                raise
            reference = {
                "provenance_path": str(provenance_path),
                "response_path": str(response_path),
                "response_sha256": response_sha256,
                "provenance_sha256": sha256_bytes(provenance_bytes),
                "response_chars": len(text),
                "capture_complete": complete,
                "capture_incomplete_reasons": provenance["capture_incomplete_reasons"],
            }
            # The return stays inside the try with the finally, so CPython keeps the
            # closing code it runs on the way out inside the outer handler.
            return reference
        except BaseException as exc:
            # Covers the whole transaction, including the instructions between a
            # publication and its bookkeeping: whatever exists is named.
            for path in note_present_artifacts(exc, directory, [provenance_name, response_name]):
                if path not in published:
                    published.append(path)
            raise
        finally:
            directory.close()
    except BaseException as exc:
        # Also covers closing the directory and the way into that cleanup, after
        # which the descriptor may be gone: check by name.
        for path in note_retained_by_name(exc, [directory.path / provenance_name, directory.path / response_name],
                                          published + directory.published_paths):
            if path not in published:
                published.append(path)
        raise


def build_result(
    *,
    prompt: str,
    metadata: dict[str, Any],
    config: dict[str, Any],
    config_path: Path,
    browser_result: dict[str, Any] | None,
    status: str,
    error: str | None = None,
    failure_stage: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "dispatch_result_type": "chatgpt-browser-review-dispatch",
        "version": 1,
        "status": status,
        "error": error,
        "failure_stage": failure_stage or (browser_result or {}).get("failure_stage"),
        "failure_reason": failure_reason or (browser_result or {}).get("failure_reason"),
        "generated_at": now_utc(),
        "dispatch_id": metadata.get("dispatch_id"),
        "bead_id": metadata.get("bead_id"),
        "epic_id": metadata.get("epic_id"),
        "executor": metadata.get("executor") or EXECUTOR_KEY,
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
        "expected_return_language": metadata.get("expected_return_language"),
        "expected_return_language_source": metadata.get("expected_return_language_source"),
        "prompt_sha256": artifact_hash(prompt),
        "prompt_chars": len(prompt),
        "config": config_summary(config, config_path),
        "share_url": (browser_result or {}).get("share_url"),
        "share_link_method": (browser_result or {}).get("share_link_method"),
        "response_chars": (browser_result or {}).get("response_chars"),
        "model_attestation": (browser_result or {}).get("model_attestation"),
        "conversation_id": (browser_result or {}).get("conversation_id"),
        "response_extraction": (browser_result or {}).get("response_extraction"),
        "response_artifact": None,
        "share": (browser_result or {}).get("share") or share_status(config),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Drive a local ChatGPT Pro browser review and capture a share link.")
    parser.add_argument("--packet", help="Boundary-gated contractor packet JSON.")
    parser.add_argument("--prompt-file", help="Rendered prompt file for advanced/operator use.")
    parser.add_argument("--config", help=f"Local browser config path. Defaults to ${DEFAULT_CONFIG_ENV} or {DEFAULT_CONFIG_PATH}.")
    parser.add_argument("--output", help="Write dispatch result JSON.")
    parser.add_argument(
        "--response-dir",
        help="Owner-only directory for the private response artifact. Defaults to a private CWO temp directory.",
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
    parser.add_argument("--confirm-only", action="store_true", help="Open ChatGPT and confirm configured model/effort without submitting the prompt.")
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="Permit degraded prompt-file checks only as a local rehearsal; live ChatGPT review must use --packet.",
    )
    parser.add_argument("--json", action="store_true", help="Compatibility flag; output is always JSON.")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    add_waiver_reason_argument(parser)
    args = parser.parse_args()
    if not args.dry_run and not BROWSER_DISPATCH_AVAILABLE:
        raise SystemExit(BROWSER_DISPATCH_UNAVAILABLE)
    if not args.audit and not (args.dry_run or args.confirm_only or args.rehearsal):
        raise SystemExit("--no-audit is allowed only for --dry-run, --confirm-only, or --rehearsal")
    require_waiver_reason(args, ["allow_degraded_packet", "allow_unlinked_packet", "audit"])
    if args.prompt_file and args.rehearsal and not (args.dry_run or args.confirm_only):
        raise SystemExit("prompt-file rehearsal cannot submit a live ChatGPT review; use --packet for live dispatch")

    config_path = resolve_config_path(args.config)
    config = load_browser_config(config_path)
    prompt, metadata = load_prompt_from_args(args)
    enforce_prompt_size(prompt, config)
    require_confirmation_selectors(config)
    exit_message = ""
    if args.dry_run and args.confirm_only:
        raise SystemExit("--dry-run and --confirm-only are mutually exclusive")
    quota_info = {
        "quota_checked": False,
        "quota_event_type": None,
        "quota_remaining": None,
        "executor_external": True,
    }
    if not args.dry_run and not args.confirm_only:
        quota_info = enforce_contracting_quota(
            metadata.get("epic_id"),
            EXECUTOR_KEY,
            "external-contract",
            dispatch_id=metadata.get("dispatch_id"),
            packet_sha256=metadata.get("packet_sha256"),
        )
    dispatch_started = time.monotonic()
    runner: PlaywrightChatGPTRunner | None = None
    response_dir: Path | None = None
    planned_names: tuple[str, str] | None = None
    # Paths the writer reports as published, kept for the handler below even if a name lookup later fails.
    retained_artifacts: list[str] = []
    try:
        if args.dry_run:
            result = build_result(prompt=prompt, metadata=metadata, config=config, config_path=config_path, browser_result=None, status="dry-run")
        elif args.confirm_only:
            browser_result = PlaywrightChatGPTRunner(config).confirm_model_only()
            result = build_result(
                prompt=prompt,
                metadata=metadata,
                config=config,
                config_path=config_path,
                browser_result=browser_result,
                status="model-confirmed",
            )
        else:
            response_dir = resolve_response_dir(args.response_dir)
            # Fixed before anything is sent or written; see the handler below.
            planned_names = private_response_names(metadata)
            runner = PlaywrightChatGPTRunner(config)
            try:
                browser_result = runner.run(prompt)
                result = build_result(
                    prompt=prompt,
                    metadata=metadata,
                    config=config,
                    config_path=config_path,
                    browser_result=browser_result,
                    status="completed",
                )
                try:
                    result["response_artifact"] = write_private_response(
                        response_dir, metadata=metadata, prompt=prompt, browser_result=browser_result,
                        retained=retained_artifacts, names=planned_names,
                    )
                except (SystemExit, PrivateArtifactError, OSError) as exc:
                    result["retained_artifacts"] = list(retained_artifacts)
                    result["status"] = "failed"
                    result["error"] = str(exc)
                    result["failure_stage"] = "response-capture"
                    result["failure_reason"] = str(exc)
                    exit_message = "; ".join([f"response-capture: {exc}", *getattr(exc, "__notes__", [])])
                else:
                    if not result["response_artifact"]["capture_complete"]:
                        reasons = ", ".join(result["response_artifact"]["capture_incomplete_reasons"])
                        result["status"] = "failed"
                        result["failure_stage"] = "response-capture"
                        result["failure_reason"] = f"capture-incomplete: {reasons}"
                        result["error"] = result["failure_reason"]
                        exit_message = f"response-capture: capture-incomplete: {reasons}"
            except ChatGPTBrowserReviewError as exc:
                browser_result = dict(exc.browser_result)
                browser_result["failure_stage"] = exc.stage
                browser_result["failure_reason"] = exc.reason
                result = build_result(
                    prompt=prompt,
                    metadata=metadata,
                    config=config,
                    config_path=config_path,
                    browser_result=browser_result,
                    status="failed",
                    error=exc.reason,
                    failure_stage=exc.stage,
                    failure_reason=exc.reason,
                )
                exit_message = f"{exc.stage}: {exc.reason}"
            # Whether the prompt went out, for completed and failed results alike.
            result["send_state"] = runner.send_state
        result["elapsed_seconds"] = round(time.monotonic() - dispatch_started, 3)
        result.update(quota_info)
        if args.audit:
            attestation = result.get("model_attestation") if isinstance(result.get("model_attestation"), dict) else {}
            telemetry_kind = "browser_dispatch"
            if args.dry_run:
                telemetry_kind = "browser_rehearsal"
            elif args.confirm_only:
                telemetry_kind = "browser_confirmation"
            live_submission = telemetry_kind == "browser_dispatch"
            record_audit_event(
                {
                    "event_type": "chatgpt_browser_dispatch",
                    "quota_event_type": quota_info.get("quota_event_type"),
                    "quota_stage": "consumed" if quota_info.get("quota_checked") else None,
                    "dispatch_id": result["dispatch_id"],
                    "bead_id": result["bead_id"],
                    "epic_id": result["epic_id"],
                    "executor_key": result["executor"],
                    **waiver_audit_fields(args, ["allow_degraded_packet", "allow_unlinked_packet", "audit"]),
                    "provider_key": result["provider_key"],
                    "executor_external": True,
                    "dispatch_mode": "browser_automation",
                    "share_boundary": result["share_boundary"],
                    "packet_sha256": result["packet_sha256"],
                    "prompt_sha256": result["prompt_sha256"],
                    "quota_remaining": quota_info.get("quota_remaining"),
                    "share_url_present": bool(result.get("share_url")),
                    "response_artifact_present": bool(result.get("response_artifact")),
                    "response_sha256": (result.get("response_artifact") or {}).get("response_sha256"),
                    "share_link_method": result.get("share_link_method"),
                    "model_attestation_present": bool(result.get("model_attestation")),
                    "status": result["status"],
                    "failure_stage": result.get("failure_stage"),
                    **telemetry_fields(
                        telemetry_kind=telemetry_kind,
                        telemetry_status=result["status"],
                        telemetry_missing_reason="browser-ui-token-usage-unavailable" if live_submission else None,
                        agent_model_calls=1 if live_submission else 0,
                        retry_count=0,
                        model=result.get("model"),
                        model_label=result.get("model_label"),
                        reasoning_label=result.get("reasoning_label"),
                        provider_family=result.get("provider_family"),
                        provider_retention_class=result.get("provider_retention_class"),
                        job_description_label=result.get("job_description_label"),
                        expert_profile=result.get("expert_profile"),
                        elapsed_seconds=result.get("elapsed_seconds") if live_submission else None,
                        prompt_chars=result.get("prompt_chars"),
                        response_chars=result.get("response_chars"),
                        share_url_sha256=safe_text_hash(result.get("share_url")),
                        share_url_chars=len(str(result.get("share_url") or "")) if result.get("share_url") else None,
                        failure_reason_sha256=safe_text_hash(result.get("failure_reason")),
                        failure_reason_chars=len(str(result.get("failure_reason") or "")) if result.get("failure_reason") else None,
                        model_attestation_status=attestation.get("status"),
                        model_attestation_required=attestation.get("required"),
                        expected_return_language=result.get("expected_return_language"),
                        expected_return_language_source=result.get("expected_return_language_source"),
                    ),
                }
            )
        rendered = json.dumps(result, indent=2, sort_keys=True)
        if args.output:
            atomic_write_text(assert_safe_output_path(Path(args.output)), rendered + "\n")
        else:
            print(rendered)
            # Written through now, so a closed pipe fails here, where the handler below reports the
            # effects, rather than at interpreter exit.
            sys.stdout.flush()
        if exit_message:
            # Handled failures end through the handler too, which adds the Send state and the files.
            raise SystemExit(exit_message)
        # Nothing follows: once the result is written and flushed it carries the Send state and the files.
    except BaseException as exc:
        # The file names and the Send state are fixed before the effects they
        # describe, so this holds wherever the failure happened, including
        # between an effect and the code that records it.
        if runner is not None:
            runner.note_submission(exc)
        if response_dir is not None and planned_names is not None:
            note_present_response_files(exc, response_dir, planned_names, retained_artifacts)
        notes = list(getattr(exc, "__notes__", []))
        if isinstance(exc, SystemExit) and notes:
            # Python prints only a SystemExit's code, which would hide these notes.
            if isinstance(exc.code, str):
                raise SystemExit("; ".join([exc.code, *notes])) from exc
            print("\n".join(notes), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
