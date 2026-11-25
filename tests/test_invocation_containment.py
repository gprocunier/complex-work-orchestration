from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import chatgpt_browser_review  # noqa: E402
import dispatch_work  # noqa: E402
from cwo_core import audit as audit_lib  # noqa: E402

from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402

LOCAL_ENV = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
LOCAL_ARGV = ["dispatch_work.py", "Documentation review for internal example notes.", "--local-ok", "--prefer-local",
              "--local-profile", "openshift-ai-vllm", "--requested-role", "documentation", "--json"]


class ShippedRoutesAreDisabledTests(unittest.TestCase):
    """Controlled invocation stays unavailable until issue #41's admission contract exists."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(using_test_store(HostRecordStore.for_tests(Path(directory.name) / 'host')))

    def test_the_shipped_switches_are_off(self) -> None:
        self.assertIs(dispatch_work.LOCAL_INVOCATION_AVAILABLE, False)

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


    def test_live_browser_dispatch_and_confirmation_refuse_before_any_effect(self) -> None:
        refusal = (
            "live browser dispatch is unavailable: CWO cannot yet bind workload-derived sizing to the exact prompt and "
            "hold an atomic one-use reservation within an aggregate budget before Send (issue #41). Nothing was sent. "
            "--dry-run and manual export remain available; --confirm-only is unavailable too, because confirming the "
            "model clicks configured page controls."
        )
        missing = "/missing/browser-input"
        for mode in ([], ["--confirm-only"]):
            for source in ([], ["--packet", missing], ["--prompt-file", missing, "--rehearsal"]):
                stdout = io.StringIO()
                with self.subTest(mode=mode, source=source), contextlib.redirect_stdout(stdout), \
                        patch.dict(os.environ, {"CWO_CHATGPT_BROWSER_CONFIG": missing, "BROWSER_DISPATCH_AVAILABLE": "1"}), \
                        patch.object(chatgpt_browser_review, "load_browser_config") as config, \
                        patch.object(chatgpt_browser_review, "load_prompt_from_args") as prompt, \
                        patch.object(chatgpt_browser_review, "require_waiver_reason") as waiver, \
                        patch.object(audit_lib, "record_audit_event") as audit, \
                        patch.object(chatgpt_browser_review, "atomic_write_text") as write:
                    argv = ["chatgpt_browser_review.py", "--no-audit", "--allow-unlinked-packet", "--output", missing,
                            "--response-dir", missing, *mode, *source]
                    with patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as raised:
                        chatgpt_browser_review.main()
                    self.assertEqual(str(raised.exception), refusal)
                    self.assertEqual(stdout.getvalue(), "")
                    for effect in (config, prompt, waiver, audit, write):
                        effect.assert_not_called()

    def test_cold_browser_refusals_do_not_read_local_configuration(self) -> None:
        code = """
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
from cwo import main
with patch.object(Path, "read_text", side_effect=AssertionError("unexpected file read")):
    main(sys.argv[2:])
"""
        cases = [
            (["browser-review"], chatgpt_browser_review.BROWSER_DISPATCH_UNAVAILABLE),
            (["browser-review", "--confirm-only"], chatgpt_browser_review.BROWSER_DISPATCH_UNAVAILABLE),
            (["ingest-share", "https://chatgpt.com/share/example"],
             "share URL and HTML intake is retired; use --private-artifact for browser returns"),
        ]
        for argv, refusal in cases:
            with self.subTest(argv=argv):
                completed = subprocess.run(
                    [sys.executable, "-I", "-c", code, str(ROOT / "scripts"), *argv],
                    capture_output=True, text=True, check=False, timeout=30,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(completed.stderr, refusal + "\n")

    def test_static_scan_finds_no_other_reference_to_the_effects(self) -> None:
        """Supporting evidence, not proof of complete effect coverage: names, attributes and import
        aliases of the local effect entry point appear only in its public and qualified dispatch modules."""
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
                          "PlaywrightChatGPTRunner": []})

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
