#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from generate_manual_dispatch_prompt import render_packet_prompt
from cwo_core.chatgpt_urls import CHATGPT_SHARE_URL_RE, valid_chatgpt_share_url
from cwo_core.paths import REPO_ROOT, assert_repo_safe_path, assert_safe_output_path
from cwo_core.util import (
    atomic_write_text,
    artifact_hash,
    make_dispatch_id,
)
from cwo_core.audit import enforce_contracting_quota, record_audit_event, require_packet_build_audit
from cwo_core.packets import find_residual_private_context, require_valid_contractor_packet
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
    if config.get("model_label") in {None, ""}:
        config["model_label"] = DEFAULT_MODEL_LABEL
    if config.get("reasoning_label") in {None, ""}:
        config["reasoning_label"] = DEFAULT_REASONING_LABEL
    config.setdefault("response_timeout_seconds", 1800)
    config.setdefault("stable_wait_seconds", 8)
    config.setdefault("headless", False)
    config.setdefault("share_link_required", True)
    config.setdefault("local_clipboard_fallback", True)
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
        "share_link_required": bool(config.get("share_link_required", True)),
        "local_clipboard_fallback": bool(config.get("local_clipboard_fallback", True)),
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
    limit = max_prompt_chars(config)
    if limit <= 0:
        return
    prompt_chars = len(prompt)
    if prompt_chars > limit:
        raise SystemExit(
            f"ChatGPT browser prompt is {prompt_chars} characters, above max_prompt_chars={limit}. "
            "Build a compact packet or selected-snippet prompt before launching the browser."
        )


def load_prompt_from_args(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    if bool(args.packet) == bool(args.prompt_file):
        raise SystemExit("Provide exactly one of --packet or --prompt-file")
    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        if packet.get("executor") != EXECUTOR_KEY:
            raise SystemExit(f"packet executor must be {EXECUTOR_KEY}")
        if not args.allow_unlinked_packet:
            require_packet_build_audit(
                dispatch_id=str(packet.get("dispatch_id") or ""),
                bead_id=packet.get("bead_id"),
                packet_sha256=str(packet.get("packet_sha256") or ""),
            )
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


def read_local_clipboard_share_url() -> str:
    commands = [
        ["wl-paste", "--no-newline"],
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["qdbus", "org.kde.klipper", "/klipper", "org.kde.klipper.klipper.getClipboardContents"],
    ]
    for command in commands:
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2)
        except Exception:
            continue
        value = extract_chatgpt_share_url(result.stdout)
        if value:
            return value
    return ""


class PlaywrightChatGPTRunner:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.selectors = dict(config.get("selectors") or {})
        self.last_share_link_method: str | None = None

    def selector(self, key: str, default: str) -> str:
        return str(self.selectors.get(key) or default)

    def confirm_model_only(self) -> dict[str, Any]:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on host install
            raise SystemExit("Playwright is required for ChatGPT browser dispatch") from exc

        timeout_ms = int(self.config.get("page_timeout_seconds", 30)) * 1000
        with sync_playwright() as playwright:
            browser = None
            attached = False
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
            if not attached:
                context.close()
        return {"model_attestation": model_attestation}

    def run(self, prompt: str) -> dict[str, Any]:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on host install
            raise SystemExit("Playwright is required for ChatGPT browser dispatch") from exc

        timeout_ms = int(self.config.get("page_timeout_seconds", 30)) * 1000
        response_timeout = int(self.config.get("response_timeout_seconds", 1800))
        stable_wait = int(self.config.get("stable_wait_seconds", 8))
        stage = "browser-start"
        model_attestation: dict[str, Any] | None = None
        share_url = ""
        response_text = ""
        with sync_playwright() as playwright:
            browser = None
            attached = False
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
                stage = "prompt-submit"
                self._submit_prompt(page, prompt, timeout_ms)
                stage = "response-wait"
                response_text = self._wait_for_stable_response(page, before_text, response_timeout, stable_wait)
                stage = "share-link"
                share_url = self._create_share_link(page, timeout_ms, PlaywrightTimeoutError)
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
                if not attached:
                    context.close()
        if self.config.get("share_link_required", True) and not valid_chatgpt_share_url(share_url):
            raise ChatGPTBrowserReviewError(
                "share-link",
                "ChatGPT share-link creation failed or returned a non-ChatGPT share URL",
                {
                    "share_url": share_url,
                    "response_chars": len(response_text),
                    "model_attestation": model_attestation,
                    "share_link_method": self.last_share_link_method,
                },
            )
        return {
            "share_url": share_url,
            "response_chars": len(response_text),
            "model_attestation": model_attestation,
            "share_link_method": self.last_share_link_method,
        }

    def _select_page(self, context: Any) -> Any:
        for page in context.pages:
            try:
                if "chatgpt.com" in page.url or "chat.openai.com" in page.url:
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

    def _submit_prompt(self, page: Any, prompt: str, timeout_ms: int) -> None:
        prompt_box = page.locator(self.selector("prompt_box", "textarea, [contenteditable='true']")).last
        try:
            prompt_box.fill(prompt, timeout=timeout_ms)
        except Exception:
            prompt_box.click(timeout=timeout_ms)
            page.keyboard.insert_text(prompt)
        page.locator(self.selector("submit_button", "[data-testid='send-button'], button[aria-label*='Send']")).last.click(
            timeout=timeout_ms
        )

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
    ) -> str:
        deadline = time.monotonic() + response_timeout
        last_text = ""
        last_change = time.monotonic()
        saw_growth = False
        while time.monotonic() < deadline:
            text = self._conversation_text(page)
            if len(text) > len(before_text) + 20:
                saw_growth = True
            if text != last_text:
                last_text = text
                last_change = time.monotonic()
            if saw_growth and time.monotonic() - last_change >= stable_wait and not self._response_in_progress(page):
                return text
            time.sleep(2)
        raise SystemExit("Timed out waiting for ChatGPT response to finish")

    def _response_in_progress(self, page: Any) -> bool:
        try:
            return bool(
                page.evaluate(
                    r"""() => [...document.querySelectorAll('button,[role="button"]')]
                      .some(el => /stop answering|stop generating|stop response/i.test(
                        [el.getAttribute('aria-label') || '', el.innerText || el.textContent || ''].join(' ')
                      ))"""
                )
            )
        except Exception:
            return False

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
        clipboard_before = read_local_clipboard_share_url() if self.config.get("local_clipboard_fallback", True) else ""
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
        if self.config.get("local_clipboard_fallback", True):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                value = read_local_clipboard_share_url()
                if value:
                    body_text = ""
                    try:
                        body_text = str(page.locator("body").inner_text(timeout=1000)).lower()
                    except Exception:
                        pass
                    copy_confirmed = "link copied" in body_text or "public link copied" in body_text
                    if value != clipboard_before and (clipboard_before or copy_confirmed):
                        self.last_share_link_method = "clipboard"
                        return value
                time.sleep(1)
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
        "prompt_sha256": artifact_hash(prompt),
        "prompt_chars": len(prompt),
        "config": config_summary(config, config_path),
        "share_url": (browser_result or {}).get("share_url"),
        "share_link_method": (browser_result or {}).get("share_link_method"),
        "response_chars": (browser_result or {}).get("response_chars"),
        "model_attestation": (browser_result or {}).get("model_attestation"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Drive a local ChatGPT Pro browser review and capture a share link.")
    parser.add_argument("--packet", help="Boundary-gated contractor packet JSON.")
    parser.add_argument("--prompt-file", help="Rendered prompt file for advanced/operator use.")
    parser.add_argument("--config", help=f"Local browser config path. Defaults to ${DEFAULT_CONFIG_ENV} or {DEFAULT_CONFIG_PATH}.")
    parser.add_argument("--output", help="Write dispatch result JSON.")
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
        try:
            browser_result = PlaywrightChatGPTRunner(config).run(prompt)
            result = build_result(
                prompt=prompt,
                metadata=metadata,
                config=config,
                config_path=config_path,
                browser_result=browser_result,
                status="completed",
            )
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
                ),
            }
        )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        atomic_write_text(assert_safe_output_path(Path(args.output)), rendered + "\n")
    else:
        print(rendered)
    if exit_message:
        raise SystemExit(exit_message)


if __name__ == "__main__":
    main()
