from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import chatgpt_browser_review  # noqa: E402
import dispatch_work  # noqa: E402

import cwo_core.audit as audit_lib  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402

LOCAL_ENV = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
LOCAL_ARGV = ["dispatch_work.py", "Documentation review for internal example notes.", "--local-ok", "--prefer-local",
              "--local-profile", "openshift-ai-vllm", "--requested-role", "documentation", "--json"]


def fake_playwright() -> tuple[dict[str, types.ModuleType], list[str]]:
    """Stand-in Playwright modules that record any browser start."""
    started: list[str] = []
    api = types.ModuleType("playwright.sync_api")
    api.sync_playwright = lambda: started.append("sync_playwright")  # type: ignore[attr-defined]
    api.TimeoutError = TimeoutError  # type: ignore[attr-defined]
    return {"playwright": types.ModuleType("playwright"), "playwright.sync_api": api}, started


class ShippedRoutesAreDisabledTests(unittest.TestCase):
    """Controlled invocation stays unavailable until issue #41's admission contract exists."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(using_test_store(HostRecordStore.for_tests(Path(directory.name) / 'host')))

    def test_the_shipped_switches_are_off(self) -> None:
        self.assertIs(dispatch_work.LOCAL_INVOCATION_AVAILABLE, False)
        self.assertIs(chatgpt_browser_review.BROWSER_DISPATCH_AVAILABLE, False)

    def test_local_invocation_refuses_before_quota_audit_or_request(self) -> None:
        stdout = io.StringIO()
        with patch.dict(os.environ, LOCAL_ENV, clear=False), patch.object(sys, "argv", [*LOCAL_ARGV, "--execute-local"]), \
                contextlib.redirect_stdout(stdout), \
                patch.object(dispatch_work, "enforce_contracting_quota") as quota, \
                patch.object(dispatch_work, "record_audit_event") as audit, \
                patch("dispatch_work.request.build_opener") as opener, \
                patch("dispatch_work.socket.getaddrinfo") as resolver:
            with self.assertRaises(SystemExit) as raised:
                dispatch_work.main()
        self.assertEqual(str(raised.exception), dispatch_work.LOCAL_INVOCATION_UNAVAILABLE)
        self.assertIn("Nothing was sent", str(raised.exception))
        self.assertEqual((quota.call_count, audit.call_count, opener.call_count, resolver.call_count, stdout.getvalue()),
                         (0, 0, 0, 0, ""))

    def test_the_local_effect_function_refuses_any_caller(self) -> None:
        with patch("dispatch_work.request.build_opener") as opener, self.assertRaises(SystemExit) as raised:
            dispatch_work.execute_local_envelope({"executor_key": "x"}, {}, None)  # type: ignore[arg-type]
        self.assertEqual(str(raised.exception), dispatch_work.LOCAL_INVOCATION_UNAVAILABLE)
        opener.assert_not_called()


    def _browser_argv(self, *mode: str) -> list[str]:
        prompt = Path(tempfile.mkdtemp(dir=ROOT)) / "prompt.md"
        prompt.write_text("Review this final plan.\n", encoding="utf-8")
        self.addCleanup(lambda: (prompt.unlink(), prompt.parent.rmdir()))
        return ["chatgpt_browser_review.py", "--prompt-file", str(prompt), "--dispatch-id", "dispatch-containment", "--bead",
                "cwo-browser", "--packet-sha256", "abc123", "--allow-degraded-packet", "--allow-unlinked-packet", "--rehearsal",
                "--no-audit", "--waiver-reason", "containment test", "--json", *mode]

    def _live_packet_argv(self, directory: Path, *mode: str) -> list[str]:
        """An otherwise valid live request: a built packet, a confirmation config and auditing on."""
        from build_contractor_packet import build_packet
        from tests.test_chatgpt_browser_review import ChatGPTBrowserReviewTests

        helper = ChatGPTBrowserReviewTests("test_config_summary_does_not_include_profile_path")
        config = helper.write_confirmation_config(directory)
        packet = build_packet(
            bead_id="cwo-1", bead_json={"id": "cwo-1", "title": "Plan review", "labels": ["contractor-only", "no-codex-exec",
                                                                                           "contract-jd-master-plan-review"]},
            executor=chatgpt_browser_review.EXECUTOR_KEY, share_boundary="redacted-packet",
            job_description_label="contract-jd-master-plan-review", allowed_files=[], inline_snippets=["Review this final plan."],
            dispatch_id="dispatch-chatgpt", external_opt_in=True, opt_in_basis="cli-flag",
        )
        packet_path = Path(tempfile.mkdtemp(dir=ROOT)) / "packet.json"
        packet_path.write_text(json.dumps(packet), encoding="utf-8")
        self.addCleanup(lambda: (packet_path.unlink(), packet_path.parent.rmdir()))
        return ["chatgpt_browser_review.py", "--packet", str(packet_path), "--allow-unlinked-packet", "--config", str(config),
                "--response-dir", str(directory / "returns"), "--waiver-reason", "containment test", "--json", *mode]

    def test_live_browser_dispatch_and_confirmation_refuse_before_any_effect(self) -> None:
        """With the switch off, nothing happens; the same request with the switch on reaches the effect and the
        audit log, so the refusal, not the fixture, is what stops it."""
        from tests.test_chatgpt_browser_review import ChatGPTBrowserReviewTests

        modules, started = fake_playwright()
        attested = {"model_attestation": {"required": True, "status": "confirmed", "labels": {}}}
        # A complete, verified capture, so the enabled control finishes the way a real Send would.
        captured = ChatGPTBrowserReviewTests("test_config_summary_does_not_include_profile_path")._browser_result()
        for mode, effect, quota_calls in (((), "run", 1), (("--confirm-only",), "confirm_model_only", 0)):
            for available in (False, True):
                with self.subTest(mode=mode, available=available), tempfile.TemporaryDirectory() as tmpdir:
                    directory = Path(tmpdir)
                    stdout = io.StringIO()
                    with patch.object(sys, "argv", self._live_packet_argv(directory, *mode)), \
                            contextlib.redirect_stdout(stdout), \
                            patch.dict(sys.modules, modules), \
                            patch.object(audit_lib, "AUDIT_LOG", directory / "audit.jsonl"), \
                            patch.object(chatgpt_browser_review, "BROWSER_DISPATCH_AVAILABLE", available), \
                            patch.object(chatgpt_browser_review, "enforce_contracting_quota", return_value={}) as quota, \
                            patch.object(chatgpt_browser_review.PlaywrightChatGPTRunner, effect,
                                         return_value=captured if effect == "run" else attested) as reached:
                        if available:
                            chatgpt_browser_review.main()
                        else:
                            with self.assertRaises(SystemExit) as raised:
                                chatgpt_browser_review.main()
                            self.assertEqual(str(raised.exception), chatgpt_browser_review.BROWSER_DISPATCH_UNAVAILABLE)
                    audited = (directory / "audit.jsonl").exists()
                    if available:
                        self.assertEqual((quota.call_count, reached.call_count, audited), (quota_calls, 1, True))
                    else:
                        self.assertEqual((quota.call_count, reached.call_count, audited, stdout.getvalue()), (0, 0, False, ""))
                    self.assertEqual(started, [])

    def test_the_browser_effects_refuse_any_caller_before_starting_a_browser(self) -> None:
        for effect, args in (("run", ("Prompt",)), ("confirm_model_only", ())):
            with self.subTest(effect=effect):
                modules, started = fake_playwright()
                runner = chatgpt_browser_review.PlaywrightChatGPTRunner({"selectors": {}})
                with patch.dict(sys.modules, modules), patch.object(runner, "_select_page") as page, \
                        self.assertRaises(SystemExit) as raised:
                    getattr(runner, effect)(*args)
                self.assertEqual(str(raised.exception), chatgpt_browser_review.BROWSER_DISPATCH_UNAVAILABLE)
                self.assertEqual((started, page.call_count), ([], 0))

    def test_browser_dry_run_still_works(self) -> None:
        from tests.test_chatgpt_browser_review import ChatGPTBrowserReviewTests

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        helper = ChatGPTBrowserReviewTests("test_config_summary_does_not_include_profile_path")
        written = helper.write_confirmation_config(Path(directory.name))
        stdout = io.StringIO()
        with patch.object(sys, "argv", [*self._browser_argv("--dry-run"), "--config", str(written)]), \
                contextlib.redirect_stdout(stdout):
            try:
                chatgpt_browser_review.main()
            except SystemExit as exc:
                self.assertIn(exc.code, (0, None))
        self.assertEqual(json.loads(stdout.getvalue())["status"], "dry-run")

    def test_static_scan_finds_no_other_reference_to_the_effects(self) -> None:
        """Supporting evidence, not proof of complete effect coverage: names, attributes and import
        aliases of the two effect entry points appear only in their own modules and dispatch_work's CLI."""
        effects = {"execute_local_envelope": "dispatch_work.py", "PlaywrightChatGPTRunner": "chatgpt_browser_review.py"}
        found: set[tuple[str, str]] = set()
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Name):
                    names = [node.id]
                elif isinstance(node, ast.Attribute):
                    names = [node.attr]
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [alias.name.rsplit(".", 1)[-1] for alias in node.names]
                elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    names = [node.name]
                found.update((name, path.name) for name in names if name in effects)
        self.assertEqual({name: sorted({where for found_name, where in found if found_name == name}) for name in effects},
                         {"execute_local_envelope": ["dispatch_work.py", "qualified_review_dispatch.py"],
                          "PlaywrightChatGPTRunner": ["chatgpt_browser_review.py"]})

    def test_planning_without_execute_local_still_writes_the_envelope(self) -> None:
        stdout = io.StringIO()
        with patch.dict(os.environ, LOCAL_ENV, clear=False), patch.object(sys, "argv", LOCAL_ARGV), \
                contextlib.redirect_stdout(stdout), \
                patch.object(dispatch_work, "enforce_contracting_quota", return_value={"quota_checked": True}), \
                patch.object(dispatch_work, "record_audit_event"), \
                patch("dispatch_work.request.build_opener") as opener:
            try:
                dispatch_work.main()
            except SystemExit as exc:
                self.assertIn(exc.code, (0, None))
        artifact = json.loads(stdout.getvalue())
        self.assertIsNotNone(artifact["local_envelope"])
        self.assertIsNone(artifact.get("local_response"))
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
