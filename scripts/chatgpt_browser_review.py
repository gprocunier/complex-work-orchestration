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

from generate_manual_dispatch_prompt import render_packet_prompt
from orchestration_lib import (
    REPO_ROOT,
    artifact_hash,
    make_dispatch_id,
    record_audit_event,
    require_valid_contractor_packet,
)

EXECUTOR_KEY = "chatgpt_pro_5_5_extended_reasoning_browser"
DEFAULT_CONFIG_ENV = "CWO_CHATGPT_BROWSER_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/cwo/chatgpt-browser.json"
CHATGPT_HOSTS = {"chatgpt.com", "www.chatgpt.com", "chat.openai.com"}
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
    config.setdefault("model_label", "ChatGPT Pro 5.5")
    config.setdefault("reasoning_label", "Extended Reasoning")
    config.setdefault("response_timeout_seconds", 1800)
    config.setdefault("stable_wait_seconds", 8)
    config.setdefault("headless", False)
    config.setdefault("share_link_required", True)
    config.setdefault("selectors", {})
    profile_dir = config.get("chrome_user_data_dir") or config.get("user_data_dir")
    if not profile_dir:
        raise SystemExit("ChatGPT browser config must set chrome_user_data_dir")
    config["chrome_user_data_dir"] = str(Path(str(profile_dir)).expanduser().resolve())
    return config


def config_summary(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    return {
        "config_path": str(config_path),
        "chrome_user_data_dir_configured": bool(config.get("chrome_user_data_dir")),
        "model_label": config.get("model_label"),
        "reasoning_label": config.get("reasoning_label"),
        "response_timeout_seconds": int(config.get("response_timeout_seconds", 1800)),
        "share_link_required": bool(config.get("share_link_required", True)),
        "headless": bool(config.get("headless", False)),
    }


def load_prompt_from_args(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    if bool(args.packet) == bool(args.prompt_file):
        raise SystemExit("Provide exactly one of --packet or --prompt-file")
    if args.packet:
        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        require_valid_contractor_packet(packet, allow_degraded_packet=args.allow_degraded_packet)
        if packet.get("executor") != EXECUTOR_KEY:
            raise SystemExit(f"packet executor must be {EXECUTOR_KEY}")
        return render_packet_prompt(packet), {
            "dispatch_id": packet.get("dispatch_id"),
            "bead_id": packet.get("bead_id"),
            "epic_id": packet.get("epic_id"),
            "packet_sha256": packet.get("packet_sha256"),
            "executor": packet.get("executor"),
            "provider_key": packet.get("provider_key"),
            "share_boundary": packet.get("share_boundary"),
        }
    prompt = Path(args.prompt_file).read_text(encoding="utf-8")
    return prompt, {
        "dispatch_id": args.dispatch_id or make_dispatch_id("chatgpt-browser"),
        "bead_id": args.bead,
        "epic_id": args.epic,
        "packet_sha256": args.packet_sha256,
        "executor": EXECUTOR_KEY,
        "provider_key": "openai_manual",
        "share_boundary": args.share_boundary,
    }


def valid_chatgpt_share_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and (parsed.hostname or "").lower() in CHATGPT_HOSTS and (
        parsed.path.startswith("/s/") or parsed.path.startswith("/share/")
    )


class PlaywrightChatGPTRunner:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.selectors = dict(config.get("selectors") or {})

    def selector(self, key: str, default: str) -> str:
        return str(self.selectors.get(key) or default)

    def run(self, prompt: str) -> dict[str, Any]:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - depends on host install
            raise SystemExit("Playwright is required for ChatGPT browser dispatch") from exc

        timeout_ms = int(self.config.get("page_timeout_seconds", 30)) * 1000
        response_timeout = int(self.config.get("response_timeout_seconds", 1800))
        stable_wait = int(self.config.get("stable_wait_seconds", 8))
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                self.config["chrome_user_data_dir"],
                executable_path=self.config.get("chrome_executable_path"),
                headless=bool(self.config.get("headless", False)),
            )
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(str(self.config.get("chatgpt_url")), wait_until="domcontentloaded", timeout=timeout_ms)
            self._wait_for_prompt(page, timeout_ms)
            self._select_configured_labels(page, timeout_ms, PlaywrightTimeoutError)
            before_text = self._conversation_text(page)
            self._submit_prompt(page, prompt, timeout_ms)
            response_text = self._wait_for_stable_response(page, before_text, response_timeout, stable_wait)
            share_url = self._create_share_link(page, timeout_ms, PlaywrightTimeoutError)
            context.close()
        if self.config.get("share_link_required", True) and not valid_chatgpt_share_url(share_url):
            raise SystemExit("ChatGPT share-link creation failed or returned a non-ChatGPT share URL")
        return {"share_url": share_url, "response_chars": len(response_text)}

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
            try:
                if selector:
                    page.locator(str(selector)).first.click(timeout=timeout_ms)
                else:
                    page.get_by_text(str(label), exact=False).first.click(timeout=timeout_ms)
            except timeout_type as exc:
                raise SystemExit(f"Could not select ChatGPT option {label!r}; update selectors in the local config") from exc

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
            if saw_growth and time.monotonic() - last_change >= stable_wait:
                return text
            time.sleep(2)
        raise SystemExit("Timed out waiting for ChatGPT response to finish")

    def _create_share_link(self, page: Any, timeout_ms: int, timeout_type: type[Exception]) -> str:
        page.locator(self.selector("share_button", "button[aria-label*='Share']")).first.click(timeout=timeout_ms)
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
        for selector in [
            self.selector("share_url", "input[value*='chatgpt.com'], textarea"),
            "a[href*='chatgpt.com/s/'], a[href*='chatgpt.com/share/']",
        ]:
            try:
                locator = page.locator(selector).first
                value = locator.input_value(timeout=3000)
                if valid_chatgpt_share_url(value):
                    return value
            except Exception:
                try:
                    href = locator.get_attribute("href", timeout=3000)
                    if href and valid_chatgpt_share_url(href):
                        return href
                except Exception:
                    continue
        try:
            value = page.evaluate("navigator.clipboard.readText()")
            if isinstance(value, str) and valid_chatgpt_share_url(value):
                return value
        except Exception:
            pass
        return ""


def build_result(
    *,
    prompt: str,
    metadata: dict[str, Any],
    config: dict[str, Any],
    config_path: Path,
    browser_result: dict[str, Any] | None,
    status: str,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "dispatch_result_type": "chatgpt-browser-review-dispatch",
        "version": 1,
        "status": status,
        "error": error,
        "generated_at": now_utc(),
        "dispatch_id": metadata.get("dispatch_id"),
        "bead_id": metadata.get("bead_id"),
        "epic_id": metadata.get("epic_id"),
        "executor": metadata.get("executor") or EXECUTOR_KEY,
        "provider_key": metadata.get("provider_key") or "openai_manual",
        "share_boundary": metadata.get("share_boundary"),
        "packet_sha256": metadata.get("packet_sha256"),
        "prompt_sha256": artifact_hash(prompt),
        "config": config_summary(config, config_path),
        "share_url": (browser_result or {}).get("share_url"),
        "response_chars": (browser_result or {}).get("response_chars"),
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
    parser.add_argument("--dry-run", action="store_true", help="Validate prompt/config and print the redacted dispatch plan.")
    parser.set_defaults(audit=True)
    parser.add_argument("--audit", dest="audit", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-audit", dest="audit", action="store_false", help="Do not append the default audit event.")
    args = parser.parse_args()

    config_path = resolve_config_path(args.config)
    config = load_browser_config(config_path)
    prompt, metadata = load_prompt_from_args(args)
    if args.dry_run:
        result = build_result(prompt=prompt, metadata=metadata, config=config, config_path=config_path, browser_result=None, status="dry-run")
    else:
        browser_result = PlaywrightChatGPTRunner(config).run(prompt)
        result = build_result(
            prompt=prompt,
            metadata=metadata,
            config=config,
            config_path=config_path,
            browser_result=browser_result,
            status="completed",
        )
    if args.audit:
        record_audit_event(
            {
                "event_type": "chatgpt_browser_dispatch",
                "dispatch_id": result["dispatch_id"],
                "bead_id": result["bead_id"],
                "epic_id": result["epic_id"],
                "executor_key": result["executor"],
                "provider_key": result["provider_key"],
                "executor_external": True,
                "dispatch_mode": "browser_automation",
                "share_boundary": result["share_boundary"],
                "packet_sha256": result["packet_sha256"],
                "prompt_sha256": result["prompt_sha256"],
                "share_url_present": bool(result.get("share_url")),
                "status": result["status"],
            }
        )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
