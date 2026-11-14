"""Offline browser edges; Send, capture and private consumers stay real."""
from __future__ import annotations

from types import ModuleType, SimpleNamespace
from argparse import Namespace
import json
import contextlib
import tempfile
from pathlib import Path

import chatgpt_browser_review as browser
from build_contractor_packet import build_packet
from cwo_core import audit
from unittest.mock import patch

REPLY = "  Résultat café — review complete.\n\nKeep trailing space.  \n"
URL = "https://chatgpt.com/c/0123abcd-4567"


class Handle:
    def __init__(self, page, button=False):
        self.page, self.button = page, button

    def owner_frame(self):
        self.page.callback("button-origin" if self.button else "origin")
        return SimpleNamespace(url=self.page.url)

    def as_element(self):
        return self

    def evaluate_handle(self, script, value):
        assert script == browser._SEND_BUTTON_SCRIPT
        self.page.callback("button")
        return self.page.button

    def evaluate(self, script, value):
        page = self.page
        if script == browser._STAMP_SCRIPT:
            page.stamp = value
            page.callback("stamp")
            return True
        if script == browser._FILL_SCRIPT:
            page.filled.append(value)
            page.callback("fill")
            return True
        assert script == browser._SEND_SCRIPT
        page.callback("effect")
        request, text = value.split("\n", 1)
        assert request == page.stamp and text == page.filled[-1]
        assert not page.sent
        page.sent.append(text.encode("utf-8"))
        return "pressed"


class Page:
    def __init__(self, callback=lambda stage: None, reply=REPLY):
        self.url, self.stamp = URL, None
        self.callback = callback
        self.reply = reply
        self.filled, self.sent, self.snapshots = [], [], []
        self.box, self.button = Handle(self), Handle(self, True)
        self.last = self.first = self

    def goto(self, *args, **kwargs):
        self.callback("goto")

    def locator(self, selector):
        return self

    def wait_for(self, **kwargs):
        return None

    def inner_text(self, **kwargs):
        return "" if not self.sent else self.sent[0].decode("utf-8") + "\n" + self.reply

    def query_selector_all(self, selector):
        self.callback("query")
        return [self.box]

    def evaluate(self, script, value=None):
        if script != browser._SNAPSHOT_SCRIPT:
            return False
        self.callback("snapshot")
        messages = []
        if self.sent:
            messages = [
                {"role": "user", "id": "user-1", "text": self.sent[0].decode("utf-8"), "marked": False},
                {"role": "assistant", "id": "assistant-1", "text": self.reply, "marked": True},
            ]
        snapshot = {"url": self.url, "stamp": self.stamp, "stopping": False, "messages": messages}
        self.snapshots.append(snapshot)
        return snapshot


def runtime_modules(page):
    context = SimpleNamespace(pages=[page], close=lambda: None)
    chromium = SimpleNamespace(launch_persistent_context=lambda *a, **k: context)
    runtime = SimpleNamespace(chromium=chromium, stop=lambda: None)
    api = ModuleType("playwright.sync_api")
    api.TimeoutError = type("OfflineTimeout", (Exception,), {})
    api.sync_playwright = lambda: SimpleNamespace(start=lambda: runtime)
    return {"playwright": ModuleType("playwright"), "playwright.sync_api": api}


def packet_input(directory, *, candidate_record=None, candidate_root=None):
    bead_id = candidate_record["bead_id"] if candidate_record is not None else "cwo-1"
    packet = build_packet(
        bead_id=bead_id, bead_json={"id": bead_id, "title": "Plan review", "labels": [
            "contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]},
        executor=browser.EXECUTOR_KEY, share_boundary="redacted-packet",
        job_description_label="contract-jd-master-plan-review", allowed_files=[],
        inline_snippets=["Review café.\nPreserve exact bytes."], dispatch_id="connected-review",
        external_opt_in=True, opt_in_basis="cli-flag",
        candidate_record=candidate_record, candidate_root=candidate_root,
    )
    path, log = directory / "packet.json", directory / "audit.jsonl"
    path.write_text(json.dumps(packet), encoding="utf-8")
    audit.record_audit_event({"event_type": "packet_built", "dispatch_id": packet["dispatch_id"],
                             "bead_id": packet["bead_id"], "packet_sha256": packet["packet_sha256"]}, log)
    args = Namespace(packet=str(path), prompt_file=None, allow_degraded_packet=False, allow_unlinked_packet=False)
    return packet, args, log


@contextlib.contextmanager
def admitted_runner(runner, prompt, *, request_id="0" * 32, timeout_ms=1000, lifecycle=False,
                    observers=(), share=None, create_share=None, capacity=None, model_observation=None,
                    conversation_url=URL, action_limits=None):
    """Trusted offline bootstrap, never a dispatch/config grant."""
    from browser_action_dispatch import RegisteredBrowserParent
    from cwo_core.invocation_ledger import InvocationLedger
    from cwo_core.outbound_screen import require_clean
    from tests.test_invocation_ledger import FakeClock, FakeOwners

    with tempfile.TemporaryDirectory() as tmp:
        clock = FakeClock()
        ledger = InvocationLedger(Path(tmp) / "ledger", clock=clock, owner_probe=FakeOwners())
        if not runner.packet_metadata:
            runner.packet_metadata = {"packet_sha256": "a" * 64, "dispatch_id": "direct-send",
                                      "subject": {"kind": "packet-input", "source_sha256": "b" * 64}}
        source, capture = runner._capture_submission_source(prompt)
        submitted = browser.bound_request(prompt, request_id) if lifecycle else prompt
        prepared = capture.bind(source, require_clean(submitted, surface="ChatGPT browser Send"))
        runner._action_submission = prepared, source, submitted, request_id, timeout_ms
        if lifecycle:
            runner._model_observation = model_observation or {"required": False, "status": "skipped"}
            runner._observed_conversation_url = conversation_url
        runner._action_limits = action_limits or {"timeout_seconds": 3600, "max_output_bytes": 4 * 1024 * 1024, "max_send_probes": 4}
        runner._share_selection = share
        adapter = browser.BrowserRunnerAdapter(runner, create_share=create_share)
        limits = capacity or {"effect_calls": 8, "payload_bytes": 100_000_000, "output_bytes": 100_000_000,
                              "runtime_milliseconds": 100_000_000}
        parent = RegisteredBrowserParent(prepared, ledger=ledger,
            aggregate_scope={"aggregate_id": "offline-connected", "purpose": "browser-review"},
            aggregate_limits=limits, adapter=adapter, observers=observers)
        runner._action_parent = adapter.parent = parent
        runner._send_ticket = parent.issue_send(expires_at=clock() + 10000)
        adapter.ticket = runner._send_ticket
        yield SimpleNamespace(parent=parent, adapter=adapter, prepared=prepared, source=source, ledger=ledger, clock=clock)


def connected_capture(directory, *, reply=REPLY, candidate_record=None, candidate_root=None):
    """Real packet → Send → observation → publication → persisted audit → intake."""
    from cwo_core.browser_provenance import select_private_capture
    from ingest_chatgpt_share_return import load_private_response
    import sys

    page = Page(reply=reply)
    packet, args, log = packet_input(directory, candidate_record=candidate_record, candidate_root=candidate_root)
    sources = []
    with patch.object(audit, "AUDIT_LOG", log):
        prompt, metadata = browser.load_prompt_from_args(args, prepared_sources=sources)
    config = {"selectors": {}, "require_model_confirmation": False, "chrome_user_data_dir": "offline-profile",
              "stable_wait_seconds": 0, "share_link_required": True}
    runner = browser.PlaywrightChatGPTRunner(config)
    runner.prepared_sources, runner.packet_metadata = tuple(sources), metadata
    with admitted_runner(runner, prompt, lifecycle=True, timeout_ms=30000) as admission, \
            patch.object(browser.secrets, "token_hex", return_value="0" * 32), \
            patch.object(browser, "BROWSER_DISPATCH_AVAILABLE", True), patch.dict(sys.modules, runtime_modules(page)):
        captured = runner.run(prompt)
        accounting = json.loads((admission.ledger.root / "ledger.json").read_bytes())
    artifact = browser.write_private_response(directory / "returns", metadata=metadata, prompt=prompt, browser_result=captured)
    result = browser.build_result(prompt=prompt, metadata=metadata, config=config, config_path=directory / "config.json",
                                  browser_result=captured, status="completed")
    result["response_artifact"] = artifact
    options = Namespace(dry_run=False, confirm_only=False, allow_degraded_packet=False, allow_unlinked_packet=False, audit=True)
    with patch.object(audit, "AUDIT_LOG", log):
        event = browser.record_browser_dispatch(result, options, {"quota_checked": True, "quota_remaining": 3})
    expected = select_private_capture(packet, packet_source_sha256=metadata["packet_source_sha256"],
                                      capture_event_hash=event["event_hash"], audit_file=log,
                                      candidate_record=candidate_record, candidate_root=candidate_root)
    text, provenance, _ = load_private_response(Path(artifact["provenance_path"]), expected=expected)
    return SimpleNamespace(page=page, packet=packet, args=args, log=log, metadata=metadata, prompt=prompt,
                           captured=captured, artifact=artifact, result=result, event=event, expected=expected,
                           text=text, provenance=provenance, accounting=accounting)


def captured_result(runner, prompt, result):
    """Upgrade writer-focused fixtures through real guarded Send and capture."""
    request_id = result.get("request_id") or "0" * 32
    if not browser.REQUEST_ID_RE.fullmatch(request_id):
        request_id = "0" * 32
    page = Page(reply=result["response_text"])
    with admitted_runner(runner, prompt, request_id=request_id, lifecycle=True) as admission:
        submitted = admission.prepared.payload.text()
        runner._submit_prompt(page, submitted, 1000, request_id, prepared=admission.prepared, source=admission.source)
        observed = runner._capture_assistant_response(page, "", page.inner_text(),
            before_messages={"available": True, "messages": []}, prompt=submitted, request_id=request_id,
            before_url=URL, pinned_conversation_id="0123abcd-4567")
    fields = {key: observed[key] for key in ("pinned_conversation_id", "observed_document_request_id",
              "observed_user_sha256", "submitted_user_sha256", "user_text_normalization")}
    return {**result, **admission.prepared.metadata(), **fields,
            "submitted_sha256": browser.sha256_bytes(submitted.encode("utf-8")),
            "send_admission_sha256": runner.send_admission_sha256}
