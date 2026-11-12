from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from argparse import Namespace
from functools import cache
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import outbound_screen  # noqa: E402
from cwo_core.outbound_screen import OutboundRefused, require_clean, screen_outbound, screen_request  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "outbound_screening"
# enforce_contracting_quota only reads the audit log; the audit event that
# follows a dispatch is what records consumption.
QUOTA_INFO = {"quota_checked": True, "quota_event_type": "external_manual_dispatch", "quota_limit": 5, "quota_remaining": 4,
              "executor_external": True}


@cache
def _corpus_text(name: str) -> str:
    """Share immutable fixture text; each caller parses its own mutable objects."""
    return (FIXTURES / name).read_text(encoding="utf-8")


def cases(name: str) -> list[dict]:
    return json.loads(_corpus_text(name))["cases"]


def raw_occurrences(text: str, span: str) -> list[tuple[int, int]]:
    """Raw offsets of every occurrence of ``span``, found literally or once escapes are decoded."""
    raw = outbound_screen._View("raw", text)
    found = []
    for view in (raw, outbound_screen._unescaped_view(raw, "unescaped")):
        if view is None:
            continue
        start = view.text.find(span)
        while start >= 0:
            found.append(view.raw_span(start, start + len(span)))
            start = view.text.find(span, start + 1)
    return found


def uncovered(text: str, spans: list[str], findings: tuple) -> list[str]:
    """Sensitive spans with an occurrence that no finding's raw span overlaps."""
    missing = []
    for span in spans:
        occurrences = raw_occurrences(text, span)
        if not occurrences or any(not any(f.start < end and f.end > start for f in findings) for start, end in occurrences):
            missing.append(span)
    return missing


def packet_with(snippet: str) -> dict:
    from build_contractor_packet import build_packet

    return build_packet(
        bead_id="cwo-1",
        bead_json={"id": "cwo-1", "title": "Plan review", "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]},
        executor="chatgpt_pro_browser_master_reviewer",
        share_boundary="redacted-packet",
        job_description_label="contract-jd-master-plan-review",
        allowed_files=[],
        inline_snippets=[snippet],
        dispatch_id="dispatch-1",
        external_opt_in=True,
        opt_in_basis="cli-flag",
    )


@contextlib.contextmanager
def with_provenance(packet: dict):
    """Give ``packet`` production provenance: its packet_built event in a temporary audit log.

    The manual export requires it (cwo_core.packet_provenance), as the packet builder would record.
    """
    from cwo_core import audit

    with tempfile.TemporaryDirectory() as tmpdir:
        log = Path(tmpdir) / "audit.jsonl"
        audit.record_audit_event({"event_type": "packet_built", "dispatch_id": packet["dispatch_id"],
                                  "bead_id": packet["bead_id"], "packet_sha256": packet["packet_sha256"]}, log)
        with patch.object(audit, "AUDIT_LOG", log):
            yield


def setUpModule() -> None:
    # These tests exercise the local HTTP send path with screening; that route
    # itself is disabled in shipped code until issue #41 is resolved. The flag
    # is enabled only while this module runs and restored when it finishes, so
    # no later module in the same interpreter inherits an enabled gate.
    # ProductionGuardTests check the shipped default in fresh interpreters.
    import dispatch_work
    from tests.local_invocation_fixtures import isolate_local_invocation_ledgers

    unittest.addModuleCleanup(_corpus_text.cache_clear)
    enabled = patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True)
    enabled.start()
    unittest.addModuleCleanup(enabled.stop)
    # Each send reserves against its own temporary ledger, never one in the source tree.
    isolate_local_invocation_ledgers()


class CorpusTests(unittest.TestCase):
    def test_seed_and_review_corpus_sensitive_spans_and_controls(self) -> None:
        variants = (
            ('test_seed_corpus_sensitive_spans_are_found_and_controls_pass', 'seed-corpus.json'),
            # Cases from the fourth review and their benign pairs. They shaped the rules, so they are regressions.
            ('test_review_cases_are_found_and_their_benign_pairs_pass', 'review-cases.json'),
        )
        for original, corpus in variants:
            with self.subTest(original=original):
                for case in cases(corpus):
                    with self.subTest(case=case["id"]):
                        screened = screen_outbound(case["text"], surface="test")
                        if case["sensitive"]:
                            self.assertEqual(uncovered(case["text"], case["sensitive"], screened.findings), [])
                        else:
                            self.assertEqual(screened.findings, (), [f.describe() for f in screened.findings])


    def test_refusals_never_repeat_the_values(self) -> None:
        for case in cases("seed-corpus.json") + cases("held-out.json") + cases("review-cases.json"):
            if not case["sensitive"]:
                continue
            with self.subTest(case=case["id"]):
                with self.assertRaises(OutboundRefused) as raised:
                    require_clean(case["text"], surface="test")
                message = str(raised.exception)
                for span in case["sensitive"]:
                    self.assertNotIn(span, message)
                    if len(span) >= 12:
                        self.assertNotIn(span[:12], message)

    def test_held_out_cases_by_category(self) -> None:
        """Held-out cases were written before the rules, by the same author, so they are not independent.

        They are reported per category and kept as regressions; they did not
        shape the rules.
        """
        report: dict[str, dict[str, int]] = {}
        for case in cases("held-out.json"):
            flagged = bool(screen_outbound(case["text"], surface="test").findings)
            row = report.setdefault(case["category"], {"true_positive": 0, "false_negative": 0, "true_negative": 0, "false_positive": 0})
            if case["sensitive"]:
                row["true_positive" if flagged else "false_negative"] += 1
            else:
                row["false_positive" if flagged else "true_negative"] += 1
        misses = {category: row for category, row in report.items() if row["false_negative"] or row["false_positive"]}
        # Opaque encoded content is refused by policy (round 2), so this
        # benign image now counts as a false positive; it is reported, not hidden.
        self.assertEqual(misses, {"benign-encoded": {"true_positive": 0, "false_negative": 0, "true_negative": 0, "false_positive": 1}},
                         json.dumps(report, sort_keys=True))

class ViewTests(unittest.TestCase):
    TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

    def test_normalized_view_maps_findings_to_raw_offsets(self) -> None:
        for label, disguised in (
            ("confusable letter", "ghр_" + self.TOKEN[4:]),  # Cyrillic er
            ("zero-width space", "gh​p_" + self.TOKEN[4:]),
            ("fullwidth forms", "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in self.TOKEN)),
        ):
            with self.subTest(case=label):
                text = "ä😀 see " + disguised + " end"
                screened = screen_outbound(text, surface="test")
                normalized = [f for f in screened.findings if f.view == "normalized"]
                self.assertTrue(normalized, [f.describe() for f in screened.findings])
                finding = normalized[0]
                self.assertEqual(text[finding.start:finding.end], disguised)

    def test_screening_is_idempotent(self) -> None:
        text = "AKIA" + "Z" * 16 + " and the password is Pr0b4bly-s3cret"
        self.assertEqual(screen_outbound(text, surface="test").findings, screen_outbound(text, surface="test").findings)


    def test_json_escapes_are_decoded(self) -> None:
        escaped = '{"note": "use \\u0067hp_' + self.TOKEN[4:] + '"}'
        screened = screen_outbound(escaped, surface="test", content_type="application/json")
        token = hashlib.sha256(self.TOKEN.encode()).hexdigest()
        located = [f for f in screened.findings if f.fingerprint == token]
        self.assertTrue(located, [f.describe() for f in screened.findings])
        self.assertEqual(escaped[located[0].start:located[0].end], "\\u0067hp_" + self.TOKEN[4:])

    def test_json_nested_inside_strings_is_inspected(self) -> None:
        # The token is escaped inside JSON that is itself a string value, so it
        # appears only after decoding both levels.
        inner = '{"note": "use \\u0067hp_' + self.TOKEN[4:] + '"}'
        outer = json.dumps({"data": inner})
        self.assertNotIn("ghp_", outer)
        screened = screen_outbound(outer, surface="test", content_type="application/json")
        fingerprints = {f.fingerprint for f in screened.findings}
        self.assertIn(hashlib.sha256(self.TOKEN.encode()).hexdigest(), fingerprints, [f.describe() for f in screened.findings])

class BoundaryTests(unittest.TestCase):
    def test_incomplete_scans_refuse(self) -> None:
        rules = dict(outbound_screen._rules())
        with patch.object(outbound_screen, "_rules", return_value={**rules, "limits": {"max_input_bytes": 16, "max_json_depth": 3}}):
            with self.assertRaisesRegex(OutboundRefused, "screening limit"):
                screen_outbound("x" * 17, surface="test")
            with self.assertRaisesRegex(OutboundRefused, "depth"):
                screen_outbound('[[[["x"]]]]', surface="test", content_type="application/json")
        with self.assertRaisesRegex(OutboundRefused, "not UTF-8"):
            screen_outbound(b"\xff\xfe review", surface="test")
        with self.assertRaisesRegex(OutboundRefused, "does not parse"):
            screen_outbound("{not json", surface="test", content_type="application/json")
        with self.assertRaisesRegex(OutboundRefused, "screening depth"):
            screen_outbound("[" * 100_000 + "]" * 100_000, surface="test", content_type="application/json")


    def test_screened_payload_is_bound_to_its_bytes(self) -> None:
        screened = require_clean("plain review text\n", surface="test")
        self.assertEqual(screened.sha256, hashlib.sha256(b"plain review text\n").hexdigest())
        self.assertEqual(screened.require_unchanged("plain review text\n"), b"plain review text\n")
        self.assertEqual(screened.require_unchanged(b"plain review text\n"), b"plain review text\n")
        for changed in ("plain review text", "plain review text\n ", b"plain review text\r\n"):
            with self.subTest(changed=changed), self.assertRaises(OutboundRefused):
                screened.require_unchanged(changed)


class ManualExportTests(unittest.TestCase):
    def run_export(self, argv: list[str]) -> tuple[str, BaseException | None]:
        import generate_manual_dispatch_prompt

        stdout = io.StringIO()
        raised = None
        with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", *argv]), contextlib.redirect_stdout(stdout):
            try:
                generate_manual_dispatch_prompt.main()
            except SystemExit as exc:
                raised = exc
        return stdout.getvalue(), raised

    def test_corpus_material_never_leaves_through_manual_export(self) -> None:
        """Every sensitive seed case, plain and as JSON, either exports with none of its sensitive content
        or is refused by the screen for content of that case. Any other exit fails the test, and so does a
        refusal with a finding outside the case's own snippet."""
        import generate_manual_dispatch_prompt

        outcomes = {"exported": 0, "refused": 0}
        for case in cases("seed-corpus.json"):
            if not case["sensitive"]:
                continue
            packet = packet_with(case["text"])
            snippet = packet["selected_snippets"][0]["content"]
            for extra in ([], ["--json"]):
                with self.subTest(case=case["id"], json=bool(extra)), tempfile.TemporaryDirectory() as tmpdir:
                    path = Path(tmpdir) / "packet.json"
                    path.write_text(json.dumps(packet), encoding="utf-8")
                    record: list[tuple[str, tuple]] = []
                    stdout = io.StringIO()
                    refusal = None
                    with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", "--packet", str(path), *extra]), \
                            contextlib.redirect_stdout(stdout), with_provenance(packet), \
                            patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
                        try:
                            generate_manual_dispatch_prompt.main()
                        except OutboundRefused as exc:  # any other exit propagates and fails
                            refusal = exc
                    text, findings = record[-1]
                    surviving = [span for span in case["sensitive"] if raw_occurrences(text, span)]
                    if refusal is None:
                        self.assertEqual(surviving, [], "an export carries none of the case's sensitive content")
                        outcomes["exported"] += 1
                        continue
                    self.assertEqual(stdout.getvalue(), "", "a refusal prints nothing")
                    self.assertTrue(surviving, "a refusal rests on sensitive content that reached the output")
                    self.assertEqual(uncovered(text, surviving, findings), [])
                    regions = raw_occurrences(text, snippet)
                    self.assertTrue(regions, "the case's snippet is found in the screened text")
                    for finding in findings:
                        self.assertTrue(any(finding.start < end and finding.end > start for start, end in regions),
                                        f"{finding.rule} at {finding.start}-{finding.end} lies outside the case's snippet")
                    outcomes["refused"] += 1
        self.assertGreater(outcomes["refused"], 0)
        self.assertGreater(outcomes["exported"], 0)

    def test_export_prints_exactly_the_screened_bytes(self) -> None:
        from generate_manual_dispatch_prompt import render_packet_prompt

        packet = packet_with("Review the retry plan for duplicate jobs.")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            with with_provenance(packet):
                printed, raised = self.run_export(["--packet", str(path)])
        self.assertIsNone(raised)
        self.assertEqual(printed, render_packet_prompt(packet) + "\n")

    def test_dispatch_refuses_before_audit_or_output(self) -> None:
        import dispatch_work

        survivor = next(case for case in cases("seed-corpus.json") if case["id"] == "seed-a/ghp_prose")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            path.write_text(json.dumps(packet_with(survivor["text"])), encoding="utf-8")
            argv = ["dispatch_work.py", "--packet", str(path), "--allow-unlinked-packet", "--waiver-reason", "outbound screening test"]
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event") as audit:
                with self.assertRaises(OutboundRefused):
                    dispatch_work.main()
        self.assertEqual((audit.call_count, stdout.getvalue()), (0, ""))


class _OutboundHelpers:
    """Shared drivers only; unittest collects the concrete regression classes below."""

    def _envelope(self, task: str) -> tuple[dict, dict, Namespace]:
        from cwo_core.routing import classify_work
        from dispatch_work import build_local_envelope

        route = classify_work("Documentation review for internal example notes.", local_ok=True, prefer_local=True,
                              local_profile="openshift-ai-vllm", requested_roles=["documentation"])
        args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None, local_model=None, execute_local=True)
        envelope = build_local_envelope(task=task, route=route, dispatch_id="dispatch-local-test", bead_id="cwo-local",
                                        epic_id=None, args=args)
        return envelope, route, args

    def _execute(self, task: str, opener: object, request_class: object | None = None) -> object:
        import dispatch_work

        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        with patch.dict(os.environ, env, clear=False):
            envelope, route, args = self._envelope(task)
            with patch("dispatch_work.request.build_opener", return_value=opener), contextlib.ExitStack() as stack:
                if request_class is not None:
                    stack.enter_context(patch("dispatch_work.request.Request", request_class))
                return dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)

    class Opener:
        def __init__(self) -> None:
            self.bodies: list[bytes] = []

        def open(self, req: object, **kwargs: object) -> object:
            self.bodies.append(req.data)  # type: ignore[attr-defined]
            from tests.test_local_dispatch import FakeResponse

            return FakeResponse()

    def export(self, argv: list[str]) -> tuple[str, list[tuple[str, tuple]]]:
        """Run the manual export command, expecting a refusal; return its output and what it screened."""
        import generate_manual_dispatch_prompt

        record: list[tuple[str, tuple]] = []
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", *argv]), contextlib.redirect_stdout(stdout), \
                patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
            with self.assertRaises(OutboundRefused):
                generate_manual_dispatch_prompt.main()
        return stdout.getvalue(), record

    def refused_everywhere(self, text: str, injected: list[str]) -> None:
        """Refused by the screen, by manual export (plain and JSON, findings on the injected value) and
        through a mocked request that is never sent."""
        from cwo_core.routing import classify_work
        from generate_manual_dispatch_prompt import render_prompt

        findings = screen_outbound(text, surface="test").findings
        self.assertTrue(findings, text)
        task = "Review the retry plan. " + text
        self.assertTrue(all(value in render_prompt(task, classify_work(task)) for value in injected))
        for extra in ([], ["--json"]):
            printed, record = self.export([task, *extra])
            self.assertEqual(printed, "")
            only_injected(self, record[-1][0], record[-1][1], injected)
        opener = self.Opener()
        with self.assertRaises(OutboundRefused):
            self._execute("Documentation review for internal example notes. " + text, opener)
        self.assertEqual(opener.bodies, [], "the request is never sent")

    def rules(self, text: str, content_type: str = "text/plain") -> set[str]:
        return {finding.rule for finding in screen_outbound(text, surface="test", content_type=content_type).findings}

    def views(self, text: str) -> set[tuple[str, str]]:
        return {(finding.rule, finding.view) for finding in screen_outbound(text, surface="test").findings}

    def refused_on(self, text: str, injected: list[str]) -> None:
        findings = screen_outbound(text, surface="test").findings
        self.assertTrue(findings, text)
        only_injected(self, text, findings, injected)


class LocalHttpTests(_OutboundHelpers, unittest.TestCase):


    def test_refused_content_is_never_sent(self) -> None:
        survivor = next(case for case in cases("seed-corpus.json") if case["id"] == "seed-b/github_token_prose")
        opener = self.Opener()
        with self.assertRaises(OutboundRefused) as raised:
            self._execute(survivor["text"], opener)
        self.assertEqual(opener.bodies, [])
        for span in survivor["sensitive"]:
            self.assertNotIn(span, str(raised.exception))

    def test_a_body_changed_after_screening_is_not_sent(self) -> None:
        from urllib import request

        class Tampered(request.Request):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)
                self.data = (self.data or b"") + b" "

        opener = self.Opener()
        with self.assertRaisesRegex(OutboundRefused, "changed after it was screened"):
            self._execute("Documentation review for internal example notes.", opener, request_class=Tampered)
        self.assertEqual(opener.bodies, [])


    def test_the_screened_bytes_are_the_bytes_sent(self) -> None:
        opener = self.Opener()
        self._execute("Documentation review for internal example notes.", opener)
        self.assertEqual(len(opener.bodies), 1)
        require_clean(opener.bodies[0], surface="test", content_type="application/json")


class RoundTwoTests(unittest.TestCase):
    """Structured credentials, decoding bounds and screened export integrity."""

    TOKEN = "ghp_" + "Zq8sV3nL0pX7rT2wY5uBa1Kc9Dd4Ee6Ff0Gg"

    def assertRefused(self, payload: str, *, content_type: str = "text/plain") -> str:
        with self.assertRaises(OutboundRefused) as raised:
            require_clean(payload, surface="test", content_type=content_type)
        message = str(raised.exception)
        for secret in (self.TOKEN, "hunter2", "VelvetSunset42!", "getenvSecret42!"):
            self.assertNotIn(secret, message)
        return message

    def test_decoded_keys_are_scanned_and_normalized(self) -> None:
        key = "".join(f"\\u{ord(character):04x}" for character in self.TOKEN)
        self.assertRefused('{"' + key + '": "x"}', content_type="application/json")
        self.assertRefused('{"p\\u0430ssword": "hunter2"}', content_type="application/json")  # Cyrillic a
        self.assertRefused('{"p\u0430ssword": "hunter2"}', content_type="application/json")

    def test_code_references_must_be_complete_code(self) -> None:
        self.assertRefused('{"password": "getenvSecret42!"}', content_type="application/json")
        self.assertRefused('{"password": "os.getenv(\'DB_PASSWORD\')"}', content_type="application/json")
        self.assertRefused("password = getenvSecret42!")
        self.assertRefused('password = "get_secret()"')
        for reference in ('password = os.getenv("DB_PASSWORD")', "password = load_password(config)",
                          'password = request.form["password"]', "password = settings.database.password"):
            with self.subTest(reference=reference):
                self.assertEqual(screen_outbound(reference, surface="test").findings, ())

    def test_combining_marks_cannot_split_a_token(self) -> None:
        self.assertRefused("g\u0301hp_" + self.TOKEN[4:])

    def test_manual_export_writes_exactly_the_screened_bytes(self) -> None:
        import generate_manual_dispatch_prompt

        text = "Review: café plan\u0301 with combining marks"
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="ignore", newline="\r\n")
        with patch.object(sys, "stdout", stream):
            generate_manual_dispatch_prompt.export_screened(text, as_json=False)
        stream.flush()
        self.assertEqual(stream.buffer.getvalue(), (text + "\n").encode("utf-8"))

    def test_final_json_export_is_screened_before_audit_or_output(self) -> None:
        import dispatch_work

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            path.write_text(json.dumps(packet_with("Review the retry plan for duplicate jobs.")), encoding="utf-8")
            argv = ["dispatch_work.py", "--packet", str(path), "--allow-unlinked-packet", "--json",
                    "--epic", self.TOKEN, "--waiver-reason", "outbound screening test"]
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event") as audit:
                with self.assertRaises(OutboundRefused) as raised:
                    dispatch_work.main()
        self.assertEqual((audit.call_count, stdout.getvalue()), (0, ""))
        self.assertNotIn(self.TOKEN, str(raised.exception))

    def test_data_uris_are_decoded_or_refused(self) -> None:
        import base64

        encoded = base64.b64encode(b"password=VelvetSunset42!").decode()
        for label in ("text/plain", "image/png", "application/octet-stream"):
            with self.subTest(label=label):
                self.assertRefused(f"see data:{label};base64,{encoded} for details")
        opaque = base64.b64encode(bytes(range(256))).decode()
        message = self.assertRefused(f"icon: data:image/png;base64,{opaque}")
        self.assertIn("encoded-content", message)

    def test_json_escapes_embedded_in_text_are_decoded(self) -> None:
        self.assertRefused('Here is the config:\n```json\n{"\\u0070assword":"hunter2"}\n```\n')
        self.assertRefused('Task: compare these settings {"\\u0070assword":"hunter2"} with the docs')
        self.assertRefused("note: \\\\u0067hp_" + self.TOKEN[4:])  # escaped twice

    def test_refusals_never_echo_input_derived_names(self) -> None:
        message = self.assertRefused(f"password {self.TOKEN} = {self.TOKEN}")
        self.assertNotIn(self.TOKEN[:12], message)
        message = self.assertRefused(json.dumps({f"password {self.TOKEN}": self.TOKEN}), content_type="application/json")
        self.assertNotIn(self.TOKEN[:12], message)

    def test_repeated_keys_are_all_inspected(self) -> None:
        escaped = "\\u0067hp_" + self.TOKEN[4:]
        self.assertRefused('{"note": "' + escaped + '", "note": "public"}', content_type="application/json")
        self.assertRefused('{"outer": "{\\"note\\": \\"' + escaped.replace("\\", "\\\\") + '\\", \\"note\\": \\"public\\"}"}',
                           content_type="application/json")


class RoundTwoHttpTests(_OutboundHelpers, unittest.TestCase):
    """HTTP headers, endpoint queries and drift are checked before requests."""

    TOKEN = RoundTwoTests.TOKEN

    def test_dispatch_header_is_screened(self) -> None:
        import dispatch_work

        real_build = dispatch_work.build_local_envelope

        def tainted(*args: object, **kwargs: object) -> dict:
            envelope = real_build(*args, **kwargs)
            envelope["dispatch_id"] = self.TOKEN
            return envelope

        opener = self.Opener()
        with patch.object(dispatch_work, "build_local_envelope", side_effect=tainted), self.assertRaises(OutboundRefused) as raised:
            self._execute("Documentation review for internal example notes.", opener)
        self.assertEqual(opener.bodies, [])
        self.assertIn("line and headers", str(raised.exception))

    def test_endpoint_query_is_screened(self) -> None:
        import dispatch_work

        real_endpoint = dispatch_work.endpoint_url
        opener = self.Opener()
        with patch.object(dispatch_work, "endpoint_url", side_effect=lambda base, path: real_endpoint(base, path) + "?key=" + self.TOKEN), \
                self.assertRaises(OutboundRefused):
            self._execute("Documentation review for internal example notes.", opener)
        self.assertEqual(opener.bodies, [])

    def test_drift_is_refused_before_the_preflight(self) -> None:
        from urllib import request

        import dispatch_work

        class Tampered(request.Request):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)
                self.data = (self.data or b"") + b" "

        real_transport = dispatch_work.local_transport
        opener = self.Opener()
        with patch.object(dispatch_work, "local_transport",
                          side_effect=lambda *a, **k: {**real_transport(*a, **k), "model_preflight_required": True}), \
                self.assertRaisesRegex(OutboundRefused, "changed after it was screened"):
            self._execute("Documentation review for internal example notes.", opener, request_class=Tampered)
        self.assertEqual(opener.bodies, [], "neither the preflight nor the POST was sent")

class RoundThreeTests(unittest.TestCase):
    """Reference exemptions, authentication headers and nested decoding bounds."""

    TOKEN = RoundTwoTests.TOKEN

    def refused(self, payload: str, *, content_type: str = "text/plain") -> str:
        with self.assertRaises(OutboundRefused) as raised:
            require_clean(payload, surface="test", content_type=content_type)
        for secret in (self.TOKEN, "hunter2", "SuperSecret42!", "YWRtaW46aHVudGVyMg=="):
            self.assertNotIn(secret, str(raised.exception))
        return str(raised.exception)

    def test_only_recognized_references_are_exempt(self) -> None:
        for literal in ("password = str('hunter2') ;", "password = decode('aHVudGVyMg==')", "password = os.getenv('X', 'hunter2')",
                        "password = getpass(default='hunter2')"):
            with self.subTest(literal=literal):
                self.refused(literal)
        self.refused(json.dumps({"messages": [{"role": "user", "content": "password = str('hunter2') ;"}]}),
                     content_type="application/json")

    def test_authentication_headers_are_bound_but_not_screened(self) -> None:
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + self.TOKEN}
        screened = screen_request("POST", "http://127.0.0.1:8000/v1/chat", headers, b"{}", surface="test")
        screened.require_unchanged("POST", "http://127.0.0.1:8000/v1/chat", headers, b"{}")
        for changed in ({**headers, "Authorization": "Bearer other"}, {**headers, "Proxy-Authorization": "Basic x"},
                        {"Content-Type": "application/json"}):
            with self.subTest(changed=sorted(changed)), self.assertRaises(OutboundRefused):
                screened.require_unchanged("POST", "http://127.0.0.1:8000/v1/chat", changed, b"{}")

    def test_quota_check_only_reads_the_audit_log(self) -> None:
        import cwo_core.audit as audit

        executor = "chatgpt_pro_browser_master_reviewer"
        event = {"event_type": "chatgpt_browser_dispatch", "quota_event_type": "external_manual_dispatch", "epic_id": "epic-1",
                 "executor_external": True, "status": "completed"}

        def events(count: int) -> str:
            return "".join(json.dumps({**event, "dispatch_id": f"d{i}", "event_hash": f"h{i}"}) + "\n" for i in range(count))

        with tempfile.TemporaryDirectory() as tmpdir:
            log = Path(tmpdir) / "audit.jsonl"
            with patch.object(audit, "AUDIT_LOG", log):
                info = audit.enforce_contracting_quota("epic-1", executor, "external-contract")
                self.assertEqual((info["quota_checked"], info["quota_limit"], info["quota_remaining"]), (True, 5, 4))
                self.assertFalse(log.exists(), "a missing log is not created")
                for count in (0, 2, 4):
                    with self.subTest(used=count):
                        log.write_text(events(count), encoding="utf-8")
                        before = log.read_bytes()
                        info = audit.enforce_contracting_quota("epic-1", executor, "external-contract")
                        self.assertEqual(info["quota_remaining"], 5 - count - 1)
                        self.assertEqual(log.read_bytes(), before, "the quota check wrote nothing")
                log.write_text(events(5), encoding="utf-8")
                before = log.read_bytes()
                digest = hashlib.sha256(b"epic-1").hexdigest()[:12]
                with self.assertRaisesRegex(SystemExit, f"exhausted for epic sha256:{digest}: used 5 of 5"):
                    audit.enforce_contracting_quota("epic-1", executor, "external-contract")
                self.assertEqual(log.read_bytes(), before, "an exhausted quota writes nothing either")
                log.write_text("not json\n", encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "invalid audit JSON"):
                    audit.enforce_contracting_quota("epic-1", executor, "external-contract")
                self.assertEqual(log.read_text(encoding="utf-8"), "not json\n")

    def test_credential_headers_written_as_json_members_are_found(self) -> None:
        message = self.refused('{"Authorization": "Basic YWRtaW46aHVudGVyMg=="}', content_type="application/json")
        self.assertIn("header:authorization", message)
        self.refused(json.dumps({"headers": json.dumps({"X-Api-Key": "Zq8sV3nL0pX7rT2wY5uB"})}), content_type="application/json")

    def test_decoded_findings_cover_the_whole_encoded_source(self) -> None:
        import base64

        escaped = "".join(f"\\u{ord(character):04x}" for character in self.TOKEN)
        text = "key: " + escaped + " end"
        finding = next(f for f in screen_outbound(text, surface="test").findings if f.rule == "token-prefix")
        self.assertEqual((finding.start, finding.end), (5, 5 + len(escaped)))
        encoded = base64.b64encode(b"password=hunter2").decode()
        text = f"see data:text/plain;base64,{encoded} ok"
        start = text.index(encoded)
        findings = [f for f in screen_outbound(text, surface="test").findings if f.view.startswith("data-uri")]
        self.assertTrue(findings)
        # Each covers the whole encoded run (a lenient join with the text after it covers more).
        self.assertTrue(all(f.start == start and f.end >= start + len(encoded) for f in findings))
        self.assertIn((start, start + len(encoded)), {(f.start, f.end) for f in findings})

    def test_encoding_left_after_the_last_decoding_level_refuses(self) -> None:
        payload = "Note: \\u005cu005cu005cu0070assword=hunter2"
        self.refused(payload)
        self.refused(json.dumps({"messages": [{"role": "user", "content": payload}]}), content_type="application/json")
        self.refused("query=%25252570assword%25253Dhunter2")

    def test_placeholders_are_narrow(self) -> None:
        self.refused("Authorization: Bearer my_SuperSecret42!")
        self.refused('{"password": "my_SuperSecret42!"}', content_type="application/json")
        self.refused("password = <SuperSecret42!>")
        for placeholder in ("password = my_password", "password = <your password>", "password: ${DB_PASSWORD}",
                            "token = {{ api_token }}"):
            with self.subTest(placeholder=placeholder):
                self.assertEqual(screen_outbound(placeholder, surface="test").findings, ())

    def test_uri_encodings_are_decoded(self) -> None:
        import base64

        encoded = base64.b64encode(b"password=hunter2").decode()
        self.refused(f"see data:;base64,{encoded}")
        self.refused("see data:text/plain,password%3Dhunter2 for details")
        self.refused("see data:,password%3Dhunter2")
        quoted = "".join(f"%{byte:02X}" for byte in self.TOKEN.encode())
        with self.assertRaises(OutboundRefused):
            screen_request("GET", f"http://127.0.0.1:8000/v1/models?key={quoted}", {"Content-Type": "application/json"}, b"",
                           surface="test")


class RoundThreeCommandTests(_OutboundHelpers, unittest.TestCase):
    """Screening refusals precede requests and audit writes."""

    TOKEN = RoundTwoTests.TOKEN

    def test_preflight_request_is_screened_before_any_request(self) -> None:
        import dispatch_work

        real_transport = dispatch_work.local_transport
        opener = self.Opener()
        tainted = lambda *a, **k: {**real_transport(*a, **k), "model_preflight_required": True,  # noqa: E731
                                   "model_preflight_endpoint_path": "/v1/models?key=" + self.TOKEN}
        with patch.object(dispatch_work, "local_transport", side_effect=tainted), self.assertRaises(OutboundRefused) as raised:
            self._execute("Documentation review for internal example notes.", opener)
        self.assertEqual(opener.bodies, [], "neither the preflight nor the POST was sent")
        self.assertIn("model preflight", str(raised.exception))

    def test_final_output_over_the_limit_refuses_before_audit(self) -> None:
        import dispatch_work

        rules = dict(outbound_screen._rules())
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            path.write_text(json.dumps(packet_with("Review the retry plan for duplicate jobs.")), encoding="utf-8")
            argv = ["dispatch_work.py", "--packet", str(path), "--allow-unlinked-packet", "--json",
                    "--waiver-reason", "outbound screening test"]
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event") as audit, \
                    patch.object(outbound_screen, "_rules", return_value={**rules, "limits": {"max_input_bytes": 1024, "max_json_depth": 64}}):
                with self.assertRaisesRegex(OutboundRefused, "screening limit"):
                    dispatch_work.main()
        self.assertEqual((audit.call_count, stdout.getvalue()), (0, ""))

    def test_sensitive_local_task_refuses_before_audit_or_request(self) -> None:
        import dispatch_work

        survivor = next(case for case in cases("seed-corpus.json") if case["id"] == "seed-b/github_token_prose")
        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        argv = ["dispatch_work.py", "Documentation review for internal example notes. " + survivor["text"], "--local-ok",
                "--prefer-local", "--local-profile", "openshift-ai-vllm", "--requested-role", "documentation", "--execute-local",
                "--json"]
        opener = self.Opener()
        stdout = io.StringIO()
        with patch.dict(os.environ, env, clear=False), patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                patch.object(dispatch_work, "record_audit_event") as audit, \
                patch("dispatch_work.request.build_opener", return_value=opener):
            with self.assertRaises(OutboundRefused):
                dispatch_work.main()
        self.assertEqual((audit.call_count, opener.bodies, stdout.getvalue()), (0, [], ""))

    def test_the_same_command_with_a_clean_task_reaches_the_request(self) -> None:
        import dispatch_work

        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        argv = ["dispatch_work.py", "Documentation review for internal example notes.", "--local-ok", "--prefer-local",
                "--local-profile", "openshift-ai-vllm", "--requested-role", "documentation", "--execute-local", "--json"]
        opener = self.Opener()
        stdout = io.StringIO()
        with patch.dict(os.environ, env, clear=False), patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                patch.object(dispatch_work, "record_audit_event"), \
                patch("dispatch_work.request.build_opener", return_value=opener):
            try:
                dispatch_work.main()
            except SystemExit as exc:
                self.assertNotIsInstance(exc, OutboundRefused)
        self.assertEqual(len(opener.bodies), 1, "the clean command reaches the request the refused one never did")

class RoundFourTests(_OutboundHelpers, unittest.TestCase):
    """Normalized encodings, grouped literals and hostname screening."""

    BASIC = "Basic YWRtaW46aHVudGVyMg=="

    def refused(self, text: str) -> bool:
        return not screen_outbound(text, surface="test").allowed

    def test_normalized_escapes_and_percent_sequences_are_decoded(self) -> None:
        for text in ("Note: \uff3cu0070assword=hunter2", "Note: \uff0570assword=hunter2"):
            with self.subTest(text=text):
                self.assertTrue(self.refused(text))
                message = json.dumps({"messages": [{"role": "user", "content": text}]})
                self.assertFalse(screen_outbound(message, surface="test", content_type="application/json").allowed)

    def test_grouped_literals_keep_their_field(self) -> None:
        for text in ("password = ( 'hunter2' )", 'password: ["hunter2"]', '{"password": [ "hunter2" ]}',
                     '{"password": [["hunter2"]]}'):
            with self.subTest(text=text):
                content_type = "application/json" if text.startswith("{") else "text/plain"
                self.assertFalse(screen_outbound(text, surface="test", content_type=content_type).allowed)
        for text in ("passwords = []", "password = (get_password(config))", '{"password": []}'):
            with self.subTest(text=text):
                content_type = "application/json" if text.startswith("{") else "text/plain"
                self.assertTrue(screen_outbound(text, surface="test", content_type=content_type).allowed)

    def _execute_with_private_dns(self, base_url: str, order: list[str], resolver: object) -> object:
        import dispatch_work

        env = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": base_url, "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
        real_screen = dispatch_work.screen_request

        def screen(*args: object, **kwargs: object) -> object:
            order.append("screen")
            return real_screen(*args, **kwargs)

        def resolve(*args: object, **kwargs: object) -> object:
            order.append("resolve")
            return resolver(*args, **kwargs)  # type: ignore[operator]

        from cwo_core.routing import classify_work

        opener = LocalHttpTests.Opener()
        with patch.dict(os.environ, env, clear=False):
            route = classify_work("Documentation review for internal example notes.", local_ok=True, prefer_local=True,
                                  local_profile="openshift-ai-vllm", requested_roles=["documentation"])
            args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None, local_model=None, execute_local=True,
                             local_allow_private_dns=True)
            envelope = dispatch_work.build_local_envelope(task="Documentation review for internal example notes.", route=route,
                                                          dispatch_id="dispatch-local-test", bead_id="cwo-local", epic_id=None, args=args)
            with patch("dispatch_work.request.build_opener", return_value=opener), \
                    patch.object(dispatch_work, "screen_request", side_effect=screen), \
                    patch.object(dispatch_work.socket, "getaddrinfo", side_effect=resolve):
                try:
                    dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
                finally:
                    order.append(f"requests={len(opener.bodies)}")
        return opener

    def test_a_hostname_is_screened_before_it_reaches_a_resolver(self) -> None:
        import socket

        order: list[str] = []
        with self.assertRaises(OutboundRefused):
            self._execute_with_private_dns(f"https://{RoundTwoTests.TOKEN.lower()}.internal.example:8443", order,
                                           lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 8443))])
        self.assertNotIn("resolve", order)
        self.assertEqual(order[-1], "requests=0")

    def test_a_clean_hostname_is_resolved_only_after_screening(self) -> None:
        import socket

        order: list[str] = []
        self._execute_with_private_dns("https://vllm.internal.example:8443", order,
                                       lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 8443))])
        self.assertIn("resolve", order)
        self.assertGreater(order.index("resolve"), max(index for index, step in enumerate(order) if step == "screen"))
        self.assertEqual(order[-1], "requests=1")

    def test_credential_headers_as_quoted_members_in_text_are_found(self) -> None:
        for text in (
            'Config: {"Authorization":"' + self.BASIC + '"}',
            'Use this:\n```json\n{"Authorization": "' + self.BASIC + '"}\n```\n',
            "headers = {'Authorization': '" + self.BASIC + "'}",
            'Config: {"Authorization": ["' + self.BASIC + '"]}',
            'Settings: {"X-Api-Key": "' + RoundTwoTests.TOKEN[4:] + '"}',
        ):
            with self.subTest(text=text[:40]):
                self.assertTrue(self.refused(text))
        self.assertFalse(self.refused('Config: {"Authorization": "Bearer <your token>"}'), "a placeholder stays allowed")

    def test_data_uris_left_after_the_last_level_refuse(self) -> None:
        for levels in (4, 5):
            with self.subTest(levels=levels):
                text = "data:," * (levels - 1) + "data:;base64,cGFzc3dvcmQ9aHVudGVyMg=="
                self.assertTrue(self.refused(text))

    def test_quoted_member_header_is_refused_in_a_local_request(self) -> None:
        opener = LocalHttpTests.Opener()
        with self.assertRaises(OutboundRefused):
            self._execute('Review notes. Config: {"Authorization":"' + self.BASIC + '"}', opener)
        self.assertEqual(opener.bodies, [])

    def test_resolution_errors_do_not_repeat_the_hostname(self) -> None:
        import socket

        def fail(*args: object, **kwargs: object) -> object:
            raise socket.gaierror("Name or service not known")

        order: list[str] = []
        with self.assertRaises(SystemExit) as raised:
            self._execute_with_private_dns("https://vllm-unresolvable.internal.example:8443", order, fail)
        self.assertNotIn("vllm-unresolvable", str(raised.exception))
        self.assertIn("host sha256", str(raised.exception))

def recording_screen(record: list[tuple[str, tuple]]) -> object:
    """Observe the production require_clean scan without repeating it."""
    def observe(payload: bytes | str, *, surface: str, content_type: str = "text/plain") -> object:
        screened = screen_outbound(payload, surface=surface, content_type=content_type)
        text = payload if isinstance(payload, str) else payload.decode("utf-8")
        record.append((text, screened.findings))
        return screened

    def screen(payload: bytes | str, *, surface: str, content_type: str = "text/plain") -> object:
        # Observe require_clean's real scan, including the findings it refuses.
        # Each call still obtains a fresh bound payload; nothing is cached.
        with patch.object(outbound_screen, "screen_outbound", observe):
            return require_clean(payload, surface=surface, content_type=content_type)
    return screen


def only_injected(test: unittest.TestCase, text: str, findings: tuple, injected: list[str]) -> None:
    """Every finding overlaps an injected value, and every injected value is covered, so a refusal
    cannot rest on the surrounding template."""
    occurrences = [occurrence for value in injected for occurrence in raw_occurrences(text, value)]
    test.assertTrue(occurrences, "the injected value reached the screened text")
    test.assertEqual(uncovered(text, injected, findings), [])
    for finding in findings:
        test.assertTrue(any(finding.start < end and finding.end > start for start, end in occurrences),
                        f"{finding.rule} at {finding.start}-{finding.end} is not on an injected value")


class RoundFiveTests(_OutboundHelpers, unittest.TestCase):
    """Embedded containers, data URI charsets and bound request screening."""

    TOKEN = RoundTwoTests.TOKEN
    BASIC = RoundFourTests.BASIC
    EMBEDDED = (
        ('Config: {"Authorization": [["' + RoundFourTests.BASIC + '"]]}', RoundFourTests.BASIC),
        ('Config: {"password": ["", "hunter2"]}', "hunter2"),
        ("password = ( ( 'hunter2' ) )", "hunter2"),
        ("creds = {'password': {'value': ('', \"hunter2\")}}", "hunter2"),
        ('Use {"token": {"primary": ["", ["s3cr3tTok3n9"]]}} for the job.', "s3cr3tTok3n9"),
    )

    def test_embedded_containers_keep_their_credential_context(self) -> None:
        for text, secret in self.EMBEDDED:
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, [secret])
        for text in ("password = (get_password(config))", "passwords = []", 'api_key = [os.environ["OPENAI_API_KEY"]]', "token = (None)",
                     'headers = {"Authorization": ["Bearer <your token>"]}', "password = {'value': '<your password>'}"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())
        # Round 9: plain words inside a credential field are values, not prose (they passed until round 8).
        for text, words in (("Password: (stored in the vault)", ["stored in the vault"]), ("Secrets: (a) rotate them weekly", ["(a)"])):
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, words)
        # A nested key never takes a value out of the field, whatever it is called.
        self.assertTrue(screen_outbound('credentials = {"path": "hunter2"}', surface="test").findings)
        for text in ('password = ["hunter2"', "password = (('hunter2')]"):
            with self.subTest(text=text):
                rules = {finding.rule for finding in screen_outbound(text, surface="test").findings}
                self.assertIn("assignment-unreadable", rules, "a literal that cannot be read whole refuses")


    def test_embedded_containers_never_leave_by_export_or_request(self) -> None:
        from cwo_core.routing import classify_work
        from generate_manual_dispatch_prompt import render_prompt

        for text, secret in self.EMBEDDED:
            task = "Review the retry plan. " + text
            with self.subTest(text=text):
                # A task the router keeps in-house is exported unredacted, so the screen is what stops it.
                self.assertIn(secret, render_prompt(task, classify_work(task)))
                for extra in ([], ["--json"]):
                    printed, record = self.export([task, *extra])
                    self.assertEqual(printed, "")
                    only_injected(self, record[-1][0], record[-1][1], [secret])
                opener = self.Opener()
                with self.assertRaises(OutboundRefused):
                    self._execute("Documentation review for internal example notes. " + text, opener)
                self.assertEqual(opener.bodies, [])

    def test_data_uri_charsets_are_read_as_declared_or_refused(self) -> None:
        import base64

        utf7 = "data:text/plain;charset=utf-7,+AHAAYQBzAHMAdwBvAHIAZAA9AGgAdQBuAHQAZQByADI-"
        utf16 = "data:text/plain;charset=utf-16;base64," + base64.b64encode("password=hunter2".encode("utf-16")).decode()
        for text in (utf7, utf16, "data:text/plain;charset=utf-8;charset=utf-7,hello"):
            with self.subTest(text=text[:40]):
                rules = {finding.rule for finding in screen_outbound(f"see {text} here", surface="test").findings}
                self.assertEqual(rules, {"encoded-content"}, "an undeclared or unsupported charset is opaque")
        for text in ("data:text/plain;charset=utf-8,password%3Dhunter2",
                     "data:text/plain;charset=US-ASCII;base64," + base64.b64encode(b"password=hunter2").decode(),
                     'data:text/plain;charset="utf-8",password%3Dhunter2'):
            with self.subTest(text=text[:40]):
                findings = screen_outbound(f"see {text} here", surface="test").findings
                self.assertIn(("assignment", "data-uri"), {(finding.rule, finding.view) for finding in findings},
                              "a supported charset is decoded and read by the data-URI path")
        for text in ("data:text/plain;charset=utf-8,hello%20world", "data:text/plain;charset=US-ASCII,hello"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())
        opener = self.Opener()
        with self.assertRaises(OutboundRefused):
            self._execute("Documentation review for internal example notes. See " + utf7, opener)
        self.assertEqual(opener.bodies, [])

    def _clean_packet(self, tmpdir: str) -> Path:
        path = Path(tmpdir) / "packet.json"
        path.write_text(json.dumps(packet_with("Review the retry plan for duplicate jobs.")), encoding="utf-8")
        return path

    def test_clean_json_exports_pass_in_both_commands(self) -> None:
        import dispatch_work
        import generate_manual_dispatch_prompt

        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._clean_packet(tmpdir)
            stdout = io.StringIO()
            with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", "--packet", str(path), "--json"]), \
                    contextlib.redirect_stdout(stdout), with_provenance(json.loads(path.read_text(encoding="utf-8"))):
                generate_manual_dispatch_prompt.main()
            self.assertIn("Secret or personal-data spill:\nScope compliance:", json.loads(stdout.getvalue())["prompt"])
            argv = ["dispatch_work.py", "--packet", str(path), "--allow-unlinked-packet", "--json",
                    "--waiver-reason", "outbound screening test"]
            stdout = io.StringIO()
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event") as audit:
                dispatch_work.main()
        self.assertEqual(audit.call_count, 1)
        self.assertIn("Scope compliance:", json.loads(stdout.getvalue())["manual_prompt"])

    def test_refused_json_exports_rest_on_the_injected_value(self) -> None:
        import dispatch_work
        import generate_manual_dispatch_prompt

        with tempfile.TemporaryDirectory() as tmpdir:
            argv = ["dispatch_work.py", "--packet", str(self._clean_packet(tmpdir)), "--allow-unlinked-packet", "--json",
                    "--epic", self.TOKEN, "--waiver-reason", "outbound screening test"]
            record: list[tuple[str, tuple]] = []
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event") as audit, \
                    patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
                with self.assertRaises(OutboundRefused):
                    dispatch_work.main()
            self.assertEqual(audit.call_count, 0)
            only_injected(self, record[-1][0], record[-1][1], [self.TOKEN])
        survivor = next(case for case in cases("seed-corpus.json") if case["id"] == "seed-a/ghp_prose")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            survivor_packet = packet_with(survivor["text"])
            path.write_text(json.dumps(survivor_packet), encoding="utf-8")
            with with_provenance(survivor_packet):
                printed, record = self.export(["--packet", str(path), "--json"])
        self.assertEqual(printed, "")
        only_injected(self, record[-1][0], record[-1][1], survivor["sensitive"])
        printed, record = self.export(["Review the retry plan. " + survivor["text"], "--json"])
        only_injected(self, record[-1][0], record[-1][1], survivor["sensitive"])

    def test_an_exhausted_quota_names_the_epic_only_by_digest_on_stderr(self) -> None:
        import subprocess
        import textwrap

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            packet = self._clean_packet(tmpdir)
            log = tmp / "audit.jsonl"
            event = {"event_type": "chatgpt_browser_dispatch", "quota_event_type": "external_manual_dispatch",
                     "epic_id": self.TOKEN, "executor_external": True, "status": "completed"}
            log.write_text("".join(json.dumps({**event, "dispatch_id": f"d{i}", "event_hash": f"h{i}"}) + "\n" for i in range(5)),
                           encoding="utf-8")
            counts = tmp / "counts.json"
            driver = tmp / "driver.py"
            driver.write_text(textwrap.dedent(f"""\
                import json, sys
                from pathlib import Path
                from unittest.mock import patch
                sys.path.insert(0, {str(ROOT / "scripts")!r})
                import cwo_core.audit as audit
                import dispatch_work
                calls = {{"audit": 0, "opener": 0}}
                def count(name):
                    def spy(*args, **kwargs):
                        calls[name] += 1
                        raise AssertionError(name)
                    return spy
                sys.argv = ["dispatch_work.py", "--packet", {str(packet)!r}, "--allow-unlinked-packet", "--epic", {self.TOKEN!r},
                            "--json", "--waiver-reason", "quota disclosure test"]
                try:
                    with patch.object(audit, "AUDIT_LOG", Path({str(log)!r})), \\
                            patch.object(dispatch_work, "record_audit_event", side_effect=count("audit")), \\
                            patch("dispatch_work.request.build_opener", side_effect=count("opener")):
                        dispatch_work.main()
                finally:
                    Path({str(counts)!r}).write_text(json.dumps(calls))
                """), encoding="utf-8")
            before = log.read_bytes()
            completed = subprocess.run([sys.executable, "-I", str(driver)], capture_output=True, text=True, timeout=120, cwd=ROOT)
            calls = json.loads(counts.read_text(encoding="utf-8"))
            after = log.read_bytes()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("external_manual_dispatches_per_epic exhausted for epic sha256:", completed.stderr)
        self.assertNotIn(self.TOKEN, completed.stderr)
        self.assertNotIn(self.TOKEN[4:16], completed.stderr)
        self.assertEqual((completed.stdout, calls, after), ("", {"audit": 0, "opener": 0}, before))

    def test_both_requests_are_bound_before_resolution(self) -> None:
        import socket

        import dispatch_work

        resolver = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 8443))]  # noqa: E731
        real_transport = dispatch_work.local_transport
        for preflight in (False, True):
            with self.subTest(preflight=preflight):
                order: list[str] = []
                with patch.object(dispatch_work, "local_transport",
                                  side_effect=lambda *a, **k: {**real_transport(*a, **k), "model_preflight_required": preflight}), \
                        self.assertRaisesRegex(OutboundRefused, "changed after it was screened"):
                    RoundFourTests._execute_with_private_dns(self, " https://vllm.internal.example:8443", order, resolver)
                self.assertNotIn("resolve", order, "a request that will be refused never reaches the resolver")
                self.assertEqual(order[-1], "requests=0")

    def test_json_credentials_keep_their_context_through_objects_and_numbers(self) -> None:
        for payload, secret in (('{"password":{"value":"hunter2"}}', "hunter2"), ('{"pin":[4831]}', "4831"),
                                (json.dumps({"password": {"value": "hunter2"}}), "hunter2"), (json.dumps({"pin": [4831]}), "4831"),
                                (json.dumps({"secrets": {"github": {"value": ["", "s3cr3tTok3n9"]}}}), "s3cr3tTok3n9"),
                                (json.dumps({"Authorization": {"primary": self.BASIC}}), self.BASIC)):
            with self.subTest(payload=payload):
                findings = screen_outbound(payload, surface="test", content_type="application/json").findings
                self.assertTrue(findings)
                only_injected(self, payload, findings, [secret])
                opener = self.Opener()
                with self.assertRaises(OutboundRefused):
                    self._execute(payload, opener)
                self.assertEqual(opener.bodies, [], "the request is never sent")
        for payload in ({"password": None}, {"max_tokens": 4096}, {"password": {"required": True}},
                        {"api_key": {"value": "<your api key>"}}):
            with self.subTest(payload=payload):
                self.assertEqual(screen_outbound(json.dumps(payload), surface="test", content_type="application/json").findings, ())
        for payload in ({"password": {"id": "hunter2"}}, {"api_key": {"env": "s3cr3tTok3n9"}}):
            with self.subTest(payload=payload):
                self.assertTrue(screen_outbound(json.dumps(payload), surface="test", content_type="application/json").findings,
                                "a nested key never takes a value out of the field")


class RoundSixTests(_OutboundHelpers, unittest.TestCase):
    """Credential suffixes, output counts and content-free diagnostics."""

    TOKEN = RoundTwoTests.TOKEN
    SOURCE_NAMES = (
        ("password_source=hunter2", "hunter2"),
        ('{"password_source":"hunter2"}', "hunter2"),
        ("api_key_sources = ['hunter2']", "hunter2"),
        ('{"token_source": {"value": "s3cr3tTok3n9"}}', "s3cr3tTok3n9"),
        ("credential_source: hunter2", "hunter2"),
    )

    def test_a_source_suffix_never_exempts_a_credential(self) -> None:
        from cwo_core.routing import classify_work
        from generate_manual_dispatch_prompt import render_prompt

        for text, secret in self.SOURCE_NAMES:
            task = "Review the retry plan. " + text
            with self.subTest(text=text):
                content_type = "application/json" if text.startswith("{") else "text/plain"
                findings = screen_outbound(text, surface="test", content_type=content_type).findings
                self.assertTrue(findings)
                only_injected(self, text, findings, [secret])
                self.assertIn(secret, render_prompt(task, classify_work(task)))
                for extra in ([], ["--json"]):
                    printed, record = self.export([task, *extra])
                    self.assertEqual(printed, "")
                    only_injected(self, record[-1][0], record[-1][1], [secret])
                opener = self.Opener()
                with self.assertRaises(OutboundRefused):
                    self._execute("Documentation review for internal example notes. " + text, opener)
                self.assertEqual(opener.bodies, [], "the request is never sent")

    def test_the_clean_raw_json_export_carries_no_credential_sources(self) -> None:
        import generate_manual_dispatch_prompt
        from cwo_core.routing import classify_work
        from generate_manual_dispatch_prompt import content_free_route

        task = "Review the retry plan for duplicate jobs."
        record: list[tuple[str, tuple]] = []
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", task, "--json"]), contextlib.redirect_stdout(stdout), \
                patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
            generate_manual_dispatch_prompt.main()
        self.assertNotIn("credential_sources", record[-1][0], "the export carries no credential-named field")
        self.assertIn('"credential_source_count"', record[-1][0])
        self.assertEqual(record[-1][1], ())
        exported = json.loads(stdout.getvalue())["route"]
        self.assertNotIn("credential_sources", json.dumps(exported))
        self.assertIn("credential_sources", json.dumps(classify_work(task)), "the route itself still lists them")
        self.assertEqual(content_free_route({"a": [{"credential_sources": {"required_env": ["X"], "optional_env": ["Y", "Z"]}}]}),
                         {"a": [{"credential_source_count": 3}]})

    def _child(self, script: str, tmp: Path) -> subprocess.CompletedProcess:
        driver = tmp / "driver.py"
        driver.write_text(script, encoding="utf-8")
        return subprocess.run([sys.executable, "-I", str(driver)], capture_output=True, text=True, timeout=180, cwd=ROOT)

    def test_exact_model_diagnostics_name_the_model_only_by_digest_on_stderr(self) -> None:
        import textwrap

        task = "Use exact GLM-5.3 BF16 as an independent architecture critic second opinion."
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            # Envelope building (before any screen): the command line's own path.
            command = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "dispatch_work.py"), task, "--local-ok", "--local-profile",
                 "openshift-ai-glm-5-3-direct", "--requested-role", "architecture", "--local-base-url",
                 "http://127.0.0.1:8000/v1", "--local-model", self.TOKEN, "--json"],
                capture_output=True, text=True, timeout=180, cwd=ROOT)
            # Execution: an envelope built for the right model, then rebound (model and transport digest) to
            # another, as a stale or edited envelope would be; execution's own exact-model check stops it.
            execution = self._child(textwrap.dedent(f"""\
                import sys
                from argparse import Namespace
                sys.path.insert(0, {str(ROOT / "scripts")!r})
                import dispatch_work
                dispatch_work.LOCAL_INVOCATION_AVAILABLE = True  # as setUpModule does in-process; shipped code keeps it off
                from cwo_core.routing import classify_work
                route = classify_work({task!r}, local_ok=True, local_profile="openshift-ai-glm-5-3-direct",
                                      requested_roles=["architecture"])
                args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url="http://127.0.0.1:8000/v1",
                                 local_model="glm-5.3-bf16", local_allow_private_dns=False, local_ca_bundle=None,
                                 local_insecure_tls=False, local_max_tokens=None, local_thinking="default",
                                 allow_offline_access_profile=True, execute_local=True)
                envelope = dispatch_work.build_local_envelope(task={task!r}, route=route, dispatch_id="d-1", bead_id="b-1",
                                                              epic_id=None, args=args)
                args.local_model = {self.TOKEN!r}
                transport = dispatch_work.local_transport(route["selected_executor"], args)
                envelope["model"] = transport["model"]
                envelope["transport_binding_sha256"] = dispatch_work._canonical_json_hash(transport)
                dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
                """), tmp)
        for label, completed in (("envelope", command), ("execution", execution)):
            with self.subTest(path=label):
                self.assertEqual(completed.returncode, 1, completed.stderr[-400:])
                self.assertIn("requires exact model 'glm-5.3-bf16'; got a different model (sha256 ", completed.stderr)
                self.assertNotIn(self.TOKEN, completed.stderr)
                self.assertNotIn(self.TOKEN[4:16], completed.stderr)
                self.assertNotIn(self.TOKEN, completed.stdout)

    def test_diagnostics_that_repeat_refused_content_are_withheld(self) -> None:
        import generate_manual_dispatch_prompt
        from cwo_core.policy import boundary_config

        with self.assertRaises(SystemExit) as raised:
            boundary_config(self.TOKEN)
        self.assertNotIn(self.TOKEN, str(raised.exception))
        self.assertIn("unknown share boundary (sha256 ", str(raised.exception))
        forged = packet_with("Review the retry plan for duplicate jobs.")
        forged["provider_key"] = self.TOKEN  # the validator names a mismatched provider in its diagnostic
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "packet.json"
            path.write_text(json.dumps(forged), encoding="utf-8")
            with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", "--packet", str(path)]), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                generate_manual_dispatch_prompt.main()
        message = str(raised.exception.code)
        self.assertNotIsInstance(raised.exception, OutboundRefused)
        self.assertNotIn(self.TOKEN, message)
        self.assertNotIn(self.TOKEN[4:16], message)
        self.assertIn("diagnostic is withheld", message)
        with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", "--packet", "/nonexistent/packet.json"]), \
                self.assertRaisesRegex(SystemExit, r"cannot read the packet file \(path sha256 [0-9a-f]{12}\): No such file"):
            generate_manual_dispatch_prompt.main()

    def test_quoted_data_uri_parameters_are_read_or_refused(self) -> None:
        import base64

        encoded = base64.b64encode(b"password=hunter2").decode()
        for text in (f'data:text/plain;charset="UTF-8";base64,{encoded}', f"data:text/plain;charset='utf-8';base64,{encoded}",
                     f'data:text/plain;name="notes, v2.txt";charset="us-ascii";base64,{encoded}'):
            with self.subTest(text=text[:50]):
                findings = screen_outbound(f"see {text} here", surface="test").findings
                self.assertIn(("assignment", "data-uri"), {(finding.rule, finding.view) for finding in findings},
                              "a quoted parameter is read and the payload decoded by the data-URI path")
        utf7 = "+AHAAYQBzAHMAdwBvAHIAZAA9AGgAdQBuAHQAZQByADI-"
        for text in (f'data:text/plain;charset="utf-7",{utf7}', f"data:text/plain;charset='UTF-7',{utf7}",
                     'data:text/plain;charset="utf-16";base64,' + base64.b64encode("password=hunter2".encode("utf-16")).decode(),
                     f'data:text/plain;charset="UTF-8;base64,{encoded}', f"data:text/plain;charset=utf-8';base64,{encoded}"):
            with self.subTest(text=text[:50]):
                rules = {finding.rule for finding in screen_outbound(f"see {text} here", surface="test").findings}
                self.assertEqual(rules, {"encoded-content"}, "an unsupported or unreadable parameter makes the URI opaque")
        self.assertEqual(screen_outbound('data:text/plain;charset="utf-8",hello%20world', surface="test").findings, ())
        quoted = f'data:text/plain;charset="UTF-8";base64,{encoded}'
        printed, record = self.export(["Review the retry plan. See " + quoted])
        self.assertEqual(printed, "")
        only_injected(self, record[-1][0], record[-1][1], [encoded])
        opener = self.Opener()
        with self.assertRaises(OutboundRefused):
            self._execute("Documentation review for internal example notes. See " + quoted, opener)
        self.assertEqual(opener.bodies, [])

class RoundSevenTests(_OutboundHelpers, unittest.TestCase):
    """Unterminated credentials and complete encoded payload reads."""

    TOKEN = RoundTwoTests.TOKEN
    PASSWORD_B64 = "cGFzc3dvcmQ9aHVudGVyMg=="


    def test_unterminated_credentials_are_unreadable(self) -> None:
        for text, rule in (('password="hunter2\nNext line.', "assignment-unreadable"), ('password = "hunter2', "assignment-unreadable"),
                           ('password = """hunter2\nmore', "assignment-unreadable"), ('password = """hunter2\nmore"""', "assignment"),
                           ('{"Authorization": "' + RoundFourTests.BASIC + '\n}', "header-unreadable")):
            with self.subTest(text=text):
                self.assertIn(rule, {finding.rule for finding in screen_outbound(text, surface="test").findings})
        self.refused_everywhere('password="hunter2\nNext line.', ["hunter2"])
        self.assertEqual(screen_outbound('password="<your password>"\nNext line.', surface="test").findings, ())

    def test_clean_quoted_data_uris_pass_through_json_transport(self) -> None:
        import generate_manual_dispatch_prompt

        uri = 'data:text/plain;charset="utf-8",hello%20world'
        self.assertEqual(screen_outbound(json.dumps({"prompt": "See " + uri}), surface="test", content_type="application/json").findings, ())
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["generate_manual_dispatch_prompt.py", "Review the retry plan. See " + uri, "--json"]), \
                contextlib.redirect_stdout(stdout):
            generate_manual_dispatch_prompt.main()
        self.assertIn(uri, json.loads(stdout.getvalue())["prompt"])
        opener = self.Opener()
        self._execute("Documentation review for internal example notes. See " + uri, opener)
        self.assertEqual(len(opener.bodies), 1, "the clean request is sent")
        self.assertIn(b'charset=\\"utf-8\\"', opener.bodies[0], "the URI is inside the JSON body, quotes escaped")

    def test_file_loading_errors_name_the_path_only_by_digest_on_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            missing = str(tmp / self.TOKEN / "packet.json")
            malformed = tmp / f"{self.TOKEN}.json"
            malformed.write_text("{not json", encoding="utf-8")
            runs = {
                "manual export, missing packet": ["generate_manual_dispatch_prompt.py", "--packet", missing],
                "manual export, malformed packet": ["generate_manual_dispatch_prompt.py", "--packet", str(malformed)],
                "manual export, missing task file": ["generate_manual_dispatch_prompt.py", "--file", missing],
                "dispatch, missing packet": ["dispatch_work.py", "--packet", missing, "--allow-unlinked-packet",
                                             "--waiver-reason", "file loading test"],
                "dispatch, missing task file": ["dispatch_work.py", "--file", missing],
            }
            results = {label: subprocess.run([sys.executable, str(ROOT / "scripts" / argv[0]), *argv[1:]], capture_output=True,
                                             text=True, timeout=180, cwd=ROOT) for label, argv in runs.items()}
        for label, completed in results.items():
            with self.subTest(run=label):
                self.assertEqual(completed.returncode, 1, completed.stderr[-300:])
                self.assertRegex(completed.stderr, r"(cannot read the (packet|task) file|the packet file is not valid JSON) \(path sha256 [0-9a-f]{12}\)")
                self.assertNotIn(self.TOKEN[4:16], completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)
                self.assertEqual(completed.stdout, "")

    def test_base64_payloads_are_read_across_whitespace_or_refused(self) -> None:
        for text in ("data:text/plain;base64, " + self.PASSWORD_B64, "data:text/plain;base64,cGFz c3dvcmQ9aHVudGVyMg==",
                     "data:text/plain;base64,\n" + self.PASSWORD_B64, "data:text/plain;base64,cGFz\tc3dvcmQ9aHVudGVyMg=="):
            with self.subTest(text=text):
                findings = screen_outbound(f"see {text} here", surface="test").findings
                self.assertIn(("assignment", "data-uri"), {(finding.rule, finding.view) for finding in findings})
        self.refused_everywhere("See data:text/plain;base64, " + self.PASSWORD_B64, [self.PASSWORD_B64])
        # Padding does not end what a lenient decoder joins, and a byte that is not text does not hide the rest.
        for text in ("data:text/plain;base64,YSA= " + self.PASSWORD_B64, "data:text/plain;base64,YSA= /w== " + self.PASSWORD_B64):
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertIn(("assignment", "data-uri"), {(finding.rule, finding.view) for finding in findings})
        for text in ("see data:text/plain;base64,aGVsbG8gd29ybGQ=\nNext line.", "data:text/plain;base64,aGVsbG8gd29ybGQ=",
                     "data:text/plain;base64,aGVsbG8gd29ybGQ= is the greeting"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    def test_decoded_json_gets_the_structural_checks(self) -> None:
        encoded = base64.b64encode(b'{"pwd!":"abc"}').decode()
        for text in (f"data:application/json;base64,{encoded}", "Note %7B%22pwd!%22%3A%22abc%22%7D", 'Config: {"pwd!":"abc"}'):
            with self.subTest(text=text):
                self.assertTrue(screen_outbound(text, surface="test").findings)
        findings = screen_outbound(f"data:application/json;base64,{encoded}", surface="test").findings
        self.assertIn(("json-pair", "json"), {(finding.rule, finding.view) for finding in findings})
        self.refused_everywhere(f"See data:application/json;base64,{encoded}", [encoded])
        clean = base64.b64encode(b'{"a":1}').decode()
        self.assertEqual(screen_outbound(f"data:application/json;base64,{clean}", surface="test").findings, ())

    def test_no_credential_sources_field_is_exempt_in_any_form(self) -> None:
        for text in ('Config: {" credential_sources":{"required_env":["CWO_HUNTER2"],"optional_env":[]}}',
                     "Config: {'credential_sources': {'required_env': ['CWO_HUNTER2'], 'optional_env': []}}",
                     'credential_sources = {"required_env": ["CWO_HUNTER2"], "optional_env": []}',
                     'Config: {"credential_sources": {"required_env": ["CWO_HUNTER2"]}}',
                     'Config: {"credential_sources": {"required_env": ["CWO_X1"], "required_env": ["CWO_HUNTER2"], "optional_env": []}}',
                     'Config: {"credential_sources": {"required_env": ["CWO_HUNTER2"], "optional_env": []}}'):
            with self.subTest(text=text):
                self.refused_everywhere(text, ["CWO_HUNTER2", "CWO_X1"] if "CWO_X1" in text else ["CWO_HUNTER2"])

    def test_no_outbound_payload_carries_credential_sources(self) -> None:
        import dispatch_work

        argv = ["dispatch_work.py", "Security review the contractor redaction flow.", "--external-ok", "--share-boundary",
                "redacted-packet", "--requested-role", "security", "--allow-raw-manual-prompt", "--rehearsal",
                "--waiver-reason", "outbound screening test", "--json"]
        record: list[tuple[str, tuple]] = []
        stdout = io.StringIO()
        import generate_manual_dispatch_prompt
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                patch.object(dispatch_work, "record_audit_event"), \
                patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
            dispatch_work.main()
        self.assertTrue(record, "the manual export was screened")
        self.assertNotIn("credential_sources", record[-1][0])
        self.assertIn('"credential_source_count"', record[-1][0])
        self.assertEqual(record[-1][1], ())
        opener = self.Opener()
        self._execute("Documentation review for internal example notes.", opener)
        self.assertEqual(len(opener.bodies), 1)
        self.assertNotIn(b"credential_sources", opener.bodies[0])


class RoundEightTests(_OutboundHelpers, unittest.TestCase):
    """Credential name parts, continuation budgets and structural JSON reads."""

    TOKEN = RoundTwoTests.TOKEN
    PASSWORD_B64 = RoundSevenTests.PASSWORD_B64
    # Every name part that used to take a name out of the credential names.
    FORMER_EXEMPT_PARTS = ("max", "min", "count", "num", "limit", "budget", "used", "usage", "length", "size", "total",
                           "estimate", "env", "var", "name", "file", "path", "type", "field", "url", "id", "hash", "sha256",
                           "source", "sources")


    # P1: no name-based exemption from caller-controlled text.

    def test_no_name_part_exempts_a_credential(self) -> None:
        for text in ('{"password_count":"hunter2"}', '{"credential_sources_env":{"value":"hunter2"}}'):
            with self.subTest(text=text):
                self.refused_everywhere(text, ["hunter2"])
        for part in self.FORMER_EXEMPT_PARTS:
            for text in (f'{{"password_{part}": "hunter2"}}', f"api_key_{part} = hunter2", f"{part}Token: hunter2",
                         f'Config: {{"secret_{part}": {{"value": "hunter2"}}}}'):
                with self.subTest(text=text):
                    findings = screen_outbound(text, surface="test").findings
                    self.assertTrue(findings)
                    only_injected(self, text, findings, ["hunter2"])

    def test_exports_carry_credential_references_only_as_a_count(self) -> None:
        import dispatch_work
        import generate_manual_dispatch_prompt
        from generate_manual_dispatch_prompt import content_free_route

        self.assertEqual(content_free_route({"transport": {"api_key_env": "CWO_X_API_KEY", "max_tokens": 4096},
                                             "local": {"api_key_env": ""}, "profile": {"credential_sources": {"required_env": ["A"]},
                                                                                       "api_key_env": "B"}}),
                         {"transport": {"credential_source_count": 1, "max_tokens": 4096}, "local": {"credential_source_count": 0},
                          "profile": {"credential_source_count": 2}})
        for argv in (["generate_manual_dispatch_prompt.py", "Review the retry plan for duplicate jobs.", "--local-ok", "--json"],
                     ["dispatch_work.py", "Security review the contractor redaction flow.", "--external-ok", "--share-boundary",
                      "redacted-packet", "--requested-role", "security", "--allow-raw-manual-prompt", "--rehearsal",
                      "--waiver-reason", "outbound screening test", "--json"]):
            record: list[tuple[str, tuple]] = []
            with self.subTest(command=argv[0]), patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event"), \
                    patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
                (dispatch_work if argv[0] == "dispatch_work.py" else generate_manual_dispatch_prompt).main()
                self.assertTrue(record)
                self.assertNotIn("api_key_env", record[-1][0])
                self.assertNotIn("credential_sources", record[-1][0])
                self.assertEqual(record[-1][1], ())

    # P2: an inspection limit that is reached refuses.

    def test_a_continuation_over_the_run_budget_is_opaque(self) -> None:
        text = "data:text/plain;base64," + "YSAK " * 66 + self.PASSWORD_B64
        with self.subTest(everywhere="66 continuation runs"):
            self.assertEqual(self.rules(text), {"encoded-content"})
            self.refused_everywhere("See " + text, [self.PASSWORD_B64])
        # Round 10: the clean control has no padding inside its stream. "aGVsbG8=" followed by more runs passed
        # until round 9, but Python 3.14's decoder refuses that stream, so it is opaque.
        self.assertEqual(self.rules("data:text/plain;base64,aGVsbG8=" + " YSAK" * outbound_screen.MAX_CONTINUATION_RUNS), {"encoded-content"})
        within = "data:text/plain;base64,aGVsbG8h" + " YSAK" * outbound_screen.MAX_CONTINUATION_RUNS
        self.assertEqual(screen_outbound(within, surface="test").findings, ())
        self.assertEqual(self.rules(within + " YSAK"), {"encoded-content"})

    def test_names_of_any_length_are_read(self) -> None:
        for text in ("x" * 5000 + "_password = hunter2", "the " * 40 + "password: hunter2",
                     "'" + "y" * 300 + " password': 'hunter2'"):
            with self.subTest(text=text[-40:]):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, ["hunter2"])

    # P3: an encoded payload that cannot be read whole refuses.

    def test_empty_quoted_split_and_undecodable_payloads_are_opaque(self) -> None:
        for text in ('data:text/plain;base64,"' + self.PASSWORD_B64 + '"', "data:text/plain;base64,'" + self.PASSWORD_B64 + "'",
                     'data:text/plain,"password=hunter2"', "data:text/plain;base64,", "data:text/plain;base64,cGFz\"c3dvcmQ9aHVudGVyMg==\""):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(f"see {text} here"))
        with self.subTest(everywhere="quoted payload"):
            self.refused_everywhere('See data:text/plain;base64,"' + self.PASSWORD_B64 + '"', [self.PASSWORD_B64])
        split = "data:text/plain;base64,cGFz\nc3dvcmQ9aHVudGVyMg=="
        with self.subTest(everywhere="payload split by a line break"):
            findings = screen_outbound(split, surface="test").findings
            self.assertIn(("assignment", "data-uri"), {(finding.rule, finding.view) for finding in findings})
            self.refused_everywhere("See " + split, ["cGFz", "c3dvcmQ9aHVudGVyMg=="])
        for text in ("see %FF%FEpassword%3Dhunter2 here", "see \\ud800 here"):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(text))
        for text in ('<img src="data:text/plain;base64,aGVsbG8=">', "see data:text/plain;base64,aGVsbG8gd29ybGQ=\nNext line.",
                     '{"prompt": "see data:text/plain;base64,aGVsbG8="}', "caf%C3%A9 and \\ud83d\\ude00"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P4: JSON inside text is read structurally.

    LONG_KEY = "db password, rotated 'quarterly': ".ljust(200, "x")

    def test_embedded_json_is_read_structurally(self) -> None:
        self.assertEqual(len(self.LONG_KEY), 200)
        for text in ('Config: {"pwd\'!":"abc"}', 'Config: {"' + self.LONG_KEY + '":"abc"}',
                     'Use [1, {"a": {"pwd\'!": ["", "abc"]}}] here', 'Config: {"\\u0070wd\'!":"abc"}'):
            with self.subTest(text=text[:40]):
                findings = screen_outbound(text, surface="test").findings
                self.assertIn(("json-pair", "json"), {(finding.rule, finding.view) for finding in findings})
                only_injected(self, text, findings, ["abc"])
                # The --json export carries a route_sha256 that changes with the time, so it can itself hold
                # "abc", which every injected occurrence must cover. The export path uses a value that cannot
                # occur in a hexadecimal digest.
                self.refused_everywhere(text.replace("abc", "abq"), ["abq"])
        for text in ('Config: {"retries": 3, "label": "nightly"}', 'Config: {"pwd\'!": "<your password>"}', "see [1] and [2, 3]",
                     "{{ template }} and {not json}"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    def test_only_the_generated_count_with_an_integer_is_a_quantity(self) -> None:
        for text in ('{"credential_source_count": 3}', '{"credential_source_count": 0}', "credential_source_count: 2",
                     '{"max_tokens": 4096, "max_output_tokens": 8192}', "Set `max_tokens=4096` or max_tokens: 2048."):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())
        for text, value in (('{"credential_source_count": "hunter2"}', "hunter2"), ('{"credential_source_count": "3"}', "3"),
                            ('{"credential_source_count": -3}', "-3"), ('{"credential_source_count": 3.5}', "3.5"),
                            ('{"credential_source_count": ["hunter2"]}', "hunter2"), ("credential_source_count: hunter2", "hunter2"),
                            ('{"Credential_source_count": 3}', "3"), ('{"credential_source_counts": 3}', "3"),
                            ('{"max_tokens": "hunter2"}', "hunter2"), ("`max_tokens=4096x`", "4096x"), ("max_tokens: 40.96", "40.96"),
                            ("the password max_tokens: 4096", "4096")):
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, [value])
        self.refused_everywhere('Config: {"credential_source_count": "hunter2"}', ["hunter2"])

    def test_every_scanner_bound_refuses_when_reached(self) -> None:
        screen = outbound_screen._Screen
        detector = outbound_screen._Detector
        cases = (
            ("continuation runs", patch.object(outbound_screen, "MAX_CONTINUATION_RUNS", 2),
             "data:text/plain;base64,aGVsbG8= YSAK YSAK YSAK", {"encoded-content"}),
            ("structure length", patch.object(detector, "STRUCTURE_LIMIT", 16), "password = ['a', 'b', 'c', 'd', 'e']",
             {"assignment-unreadable"}),
            ("structure length, header", patch.object(detector, "STRUCTURE_LIMIT", 16),
             '{"Authorization": ["a", "b", "c", "d"]} and more', {"header-unreadable"}),
            ("decoding levels", patch.object(screen, "DECODING_DEPTH", 1), "note %2541 here", {"encoded-content"}),
            ("decoded views", patch.object(screen, "MAX_VIEWS", 1), "note %2541 and %2542 here", {"encoded-content"}),
            ("embedded JSON budget", patch.multiple(screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=0),
             'Config: {"a": 1} and {"b": 2}', {"json-unreadable"}),
            # The JSON depth limit and the decoder's own recursion limit, reached as they are.
            ("embedded JSON depth", contextlib.nullcontext(), "Config: " + "[" * 70 + "]" * 70, {"json-unreadable"}),
            ("embedded JSON recursion", contextlib.nullcontext(), "Config: " + "[" * 200000, {"json-unreadable"}),
        )
        for label, bound, text, expected in cases:
            with self.subTest(bound=label):
                with bound:
                    actual = self.rules(text)
                    self.assertTrue(expected <= actual, actual)
        self.assertEqual(screen_outbound("data:text/plain;base64,aGVsbG8h YSAK YSAK YSAK", surface="test").findings, ())
        self.assertEqual(self.rules("data:text/plain;base64,aGVsbG8= YSAK YSAK YSAK"), {"encoded-content"})  # round 10: 3.14 refuses it
        self.assertEqual(screen_outbound('Config: {"a": 1} and {"b": 2}', surface="test").findings, ())
        # Oversize and too-deep payloads refuse as before.
        with self.assertRaisesRegex(OutboundRefused, "screening limit"):
            require_clean(b"a" * (2 * 1024 * 1024 + 1), surface="test")
        with self.assertRaisesRegex(OutboundRefused, "screening depth"):
            require_clean("[" * 70 + "]" * 70, surface="test", content_type="application/json")

    # The backstop prints no unscreened exception text.


class RoundNineTests(_OutboundHelpers, unittest.TestCase):
    """Compound credential names, complete decoding and JSON budgets."""

    TOKEN = RoundTwoTests.TOKEN
    PASSWORD_B64 = RoundSevenTests.PASSWORD_B64


    # P1: a credential name, a separator and a value is a credential, whatever the value looks like.

    def test_ordinary_words_never_exempt_a_credential_value(self) -> None:
        with self.subTest(everywhere="multiword assignment"):
            self.refused_everywhere("password: correct horse battery staple", ["correct horse battery staple"])
        for text, value in (("password: correct horse battery staple", "correct horse battery staple"),
                            ("Passwords: never share them", "never share them"), ("api_key = open sesame", "open sesame"),
                            ("Token: Alpha Bravo", "Alpha Bravo"), ("secret:\ncorrect horse battery staple", "correct horse battery staple"),
                            ("password: (correct horse battery staple)", "correct horse battery staple"),
                            ("token = [alpha bravo]", "alpha bravo")):
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, [value])

    def test_only_the_exact_generated_heading_passes(self) -> None:
        from generate_manual_dispatch_prompt import contractor_return_template

        template = contractor_return_template()
        self.assertIn("\nSecret or personal-data spill:\nScope compliance:\n", template)
        for text in (template, json.dumps({"prompt": template}), "Status:\nSecret or personal-data spill:\nScope compliance:\n"):
            with self.subTest(text=text[-60:]):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())
        for text, value in (("Secret or personal-data spill: hunter2\nScope compliance:", "hunter2"),
                            ("Secret or personal-data spill:\nhunter2", "hunter2"),
                            ("Secret or personal-data spill:\nScope compliance", "Scope"),
                            ("secret or personal-data spill:\nScope compliance:", "Scope"),
                            ("My Secret or personal-data spill:\nScope compliance:", "Scope")):
            with self.subTest(text=text):
                findings = screen_outbound(text, surface="test").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, [value])

    ACRONYM_NAMES = ("DBPassword", "DBPASSWORD", "dbPassword", "DbPassword", "db_password", "DB-Password", "dbpassword",
                     "HTTPToken", "HTTP_TOKEN", "httpToken", "HttpToken", "httptoken", "OAuth2Token", "AWSSecretAccessKey",
                     "awsaccesskey", "X509Pass", "SSLCookie", "UserPWD", "DBPasswords", "SMTPCredentials", "MyAPIKey")

    def test_acronym_and_compound_names_are_credential_names(self) -> None:
        for text in ('{"DBPassword":"hunter2"}', "DBPassword = hunter2", '{"HTTPToken":"hunter2"}'):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, ["hunter2"])
        self.assertTrue(screen_outbound('{"HTTPToken":"abc"}', surface="test").findings)
        for name in self.ACRONYM_NAMES:
            for text in (f'{{"{name}": "hunter2"}}', f"{name} = hunter2", f"{name}: hunter2", f'Config: {{"{name}": "hunter2"}}'):
                with self.subTest(text=text):
                    findings = screen_outbound(text, surface="test").findings
                    self.assertTrue(findings)
                    only_injected(self, text, findings, ["hunter2"])
        for text in ('Config: {"HTTPTimeout": 30, "DBHost": "db.internal", "tokenizer": "cl100k"}', "Tokenizer: cl100k",
                     "Bypass: enabled", "Compass: north", "Spin: fast", "Secretary: Jordan"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P3: every run read as payload decodes completely to text, or the whole URI is opaque.

    def test_payload_runs_decode_completely_or_the_uri_is_opaque(self) -> None:
        for text in ("data:;base64,YQ== A", "data:;base64,YQ== /w=="):
            with self.subTest(everywhere=text):
                self.assertEqual(self.rules(text), {"encoded-content"})
                self.refused_everywhere("See " + text, [text[len("data:;base64,"):]])
        # An incomplete group, a second padded group a skipping decoder reads as control bytes, bytes that
        # are not UTF-8, and control characters.
        # Round 10: "YSA= aGVsbG8=" passed until round 9, but Python 3.14's decoder refuses that stream, so it is opaque.
        for text in ("data:text/plain;base64,YQ== YQ", "data:text/plain;base64,YQ== YQ==", "data:text/plain;base64,aGVsbG8= 7w==",
                     "data:text/plain;base64,aGVsbG8= AAAA", "data:text/plain;base64,aGVsbG8= I", "data:text/plain;base64,YSA= aGVsbG8="):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(text))
        # Legible content in a URI that is opaque is still named.
        self.assertTrue({("encoded-content", "raw"), ("assignment", "data-uri")}
                        <= self.views("data:text/plain;base64,YSA= /w== " + self.PASSWORD_B64))
        # A join through ordinary words is read too when it decodes to text: "password:" then "bla".
        self.assertIn(("assignment", "data-uri"), self.views("data:text/plain;base64,cGFzc3dvcmQ6 Ymxh"))
        for text in ("data:text/plain;base64,aGVsbG8gd29ybGQ= is the greeting", "data:text/plain;base64,aGVsbG8gd29ybGQ=\nNext line.",
                     "data:text/plain;base64,aGVsbG8= Next step.",
                     "data:text/plain;base64,cGFz c3dvcmQ=\nIt is the word."):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    @unittest.skipUnless(sys.version_info >= (3, 14), "Python 3.14's decoder is the reference for the flat reading")
    def test_the_flat_reading_is_how_python_314_decodes(self) -> None:
        import binascii
        import random

        generator = random.Random(9)
        for _ in range(20000):
            stream = "".join(generator.choice("AQYw/=") for _ in range(generator.randint(1, 14)))
            if "=" not in stream.rstrip("="):
                continue
            try:
                expected = binascii.a2b_base64(stream.encode("ascii"))
            except binascii.Error:
                expected = None
            self.assertEqual(outbound_screen._flat_reading(stream), expected, stream)

    def test_whitespace_in_data_uri_metadata_is_read(self) -> None:
        for text in ("data: text/plain;base64," + self.PASSWORD_B64, "data:text/plain ;base64," + self.PASSWORD_B64):
            with self.subTest(everywhere=text):
                self.refused_everywhere("See " + text, [self.PASSWORD_B64])
        for prefix in ("data: text/plain;base64,", "data:text/plain ;base64,", "data:text/plain ; charset=utf-8 ;base64,",
                       "data: ;base64,", "data:\ttext/plain;base64,", "data:\ntext/plain;base64,", "data: text/plain; base64,",
                       "data: text/plain;charset = UTF-8;base64,", "DATA: text/plain;BASE64,", "data: text/plain x;base64,",
                       "data: text/plain;base64 ,", "data: x metadata: ;base64,"):
            with self.subTest(prefix=prefix):
                self.assertIn(("assignment", "data-uri"), self.views(f"see {prefix}{self.PASSWORD_B64} here"))
        # An unsupported charset, and metadata that declares base64 but cannot be read, are opaque, as is
        # whitespace after the first parameter separator of a URI that starts without whitespace (as before).
        for text in ("data: text/plain; charset=utf-16,%70%00%61%00", 'data: text/plain;charset="utf-8;base64,' + self.PASSWORD_B64,
                     "data:text/plain;base64 ," + self.PASSWORD_B64, "data:text/plain; base64," + self.PASSWORD_B64,
                     "data: ;charset=utf-16 data: text/plain,%70%00%61%00"):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(f"see {text} here"))
        for text in ("Input data: text/csv, one row per job.", "Training data: logs; metrics, traces",
                     "see data: text/plain;base64,aGVsbG8gd29ybGQ= here", "data: text/plain; charset=utf-8,hello%20world"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P2: the JSON budget is enforced inside the decoder and is never exceeded.

    def test_the_json_budget_is_never_exceeded(self) -> None:
        screens: list[outbound_screen._Screen] = []

        class Recording(outbound_screen._Screen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                screens.append(self)

        text = 'Config: {"a":1}'
        with patch.multiple(outbound_screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=0):
            self.assertEqual(self.rules(text), {"json-unreadable"})
        with patch.object(outbound_screen, "_Screen", Recording):
            self.assertEqual(screen_outbound(text, surface="test").findings, ())
        cost = screens[-1].json_examined
        self.assertGreater(cost, 0)
        for allowance, expected in ((cost, set()), (cost - 1, {"json-unreadable"})):
            with self.subTest(allowance=allowance), patch.object(outbound_screen, "_Screen", Recording), \
                    patch.multiple(outbound_screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=allowance):
                self.assertEqual(self.rules(text), expected)
                self.assertLessEqual(screens[-1].json_examined, screens[-1].json_budget)
        # The last of several candidates is charged too.
        two = 'Config: {"a":1} and {"b":2}'
        with patch.object(outbound_screen, "_Screen", Recording):
            screen_outbound(two, surface="test")
        with patch.multiple(outbound_screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=screens[-1].json_examined - 1):
            self.assertEqual(self.rules(two), {"json-unreadable"})

        # A benign JSON fragment at the actual end of the supplied text cannot
        # become complete by retrying the same final bytes. The public screen
        # remains clean rather than exhausting its budget on an impossible
        # continuation; a complete sensitive value still refuses.
        for incomplete in ('Config: {"value": ', 'Config: {"value": "unfinished'):
            with self.subTest(final_incomplete_json=incomplete):
                self.assertEqual(screen_outbound(incomplete, surface="test").findings, ())
        self.assertEqual(screen_outbound('Config: {"value": "ordinary"}', surface="test").findings, ())
        self.assertIn("assignment", self.rules('Config: {"password": "hunter2"}'))

    # P4: JSON is read structurally once, whichever entry point reaches it first.

    INNER = {f"k{index}": "%41" for index in range(30)}

    # The backstop covers failures while a diagnostic is screened.

    DIGITS = "1" * 4500

    def test_a_json_integer_too_long_to_convert_is_unreadable(self) -> None:
        for text in ('Config: {"a": ' + self.DIGITS + "}", "Use [" + self.DIGITS + "] here"):
            with self.subTest(text=text[:12]):
                self.assertIn("json-unreadable", self.rules(text))

    def test_json_inside_strings_is_read_once(self) -> None:
        inner = json.dumps(self.INNER)
        for text, content_type in ((inner, "application/json"), (json.dumps({"note": inner}), "application/json"),
                                   ("Config: " + json.dumps({"note": inner}), "text/plain"), (json.dumps(inner), "text/plain")):
            with self.subTest(text=text[:40]):
                self.assertEqual(screen_outbound(text, surface="test", content_type=content_type).findings, ())
        # Still read structurally, with every finding on the value.
        text = json.dumps({"note": json.dumps({**self.INNER, "password": "hunter2"})})
        findings = screen_outbound(text, surface="test", content_type="application/json").findings
        self.assertIn(("json-pair", "json"), {(finding.rule, finding.view) for finding in findings})
        only_injected(self, text, findings, ["hunter2"])
        # Depth still counts the levels around the string: 30 levels inside a string 41 levels down refuse.
        nested: object = json.dumps(json.loads("[" * 30 + "]" * 30))
        for _ in range(40):
            nested = [nested]
        with self.assertRaisesRegex(OutboundRefused, "screening depth"):
            require_clean(json.dumps({"a": nested}), surface="test", content_type="application/json")


class RoundTenTests(_OutboundHelpers, unittest.TestCase):
    """Case variants, phrase names, placeholders and view allowances."""

    TOKEN = RoundTwoTests.TOKEN
    PASSWORD_B64 = RoundSevenTests.PASSWORD_B64
    WORDS = "abandon ability able"


    @staticmethod
    def case_variants(word: str) -> list[str]:
        import itertools

        return ["".join(character.upper() if upper else character for character, upper in zip(word, pattern))
                for pattern in itertools.product((False, True), repeat=len(word))]

    # P1, names: splitting at case changes adds a reading of a name; it never replaces the unsplit one.

    def test_every_case_variant_of_a_credential_word_is_a_credential_name(self) -> None:
        for text in ("PaSsWoRd=hunter2", '{"PaSsWoRd":"hunter2"}'):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, ["hunter2"])
        variants = {"password": self.case_variants("password"), "token": self.case_variants("token")}
        self.assertEqual((len(set(variants["password"])), len(set(variants["token"]))), (256, 32))
        for name in variants["password"] + variants["token"]:
            for text in (f'{{"{name}":"hunter2"}}', f"{name}=hunter2", f"{name}: hunter2", f'Config: {{"{name}": "hunter2"}}'):
                with self.subTest(text=text):
                    self.refused_on(text, ["hunter2"])
        for text in ('Config: {"HTTPTimeout": 30, "DBHost": "db.internal", "TOKENIZER": "cl100k", "SeCrEtArY": "Jordan"}',
                     "ToKeNiZeR: cl100k", "BYPASS: enabled", "CoMpAsS: north", "SPIN: fast"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    def test_policy_phrase_names_are_credential_names(self) -> None:
        for text in (f"mnemonic: {self.WORDS}", f'{{"seed phrase": "{self.WORDS}"}}', f"recovery phrase = {self.WORDS}"):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, [self.WORDS])
        phrases = outbound_screen._rules()["phrase_names"]
        self.assertTrue({"mnemonic", "seed phrase", "recovery phrase"} <= set(phrases))
        for phrase in phrases:
            words = phrase.split()
            spellings = {phrase, phrase.upper(), "_".join(words), "-".join(words), "".join(words),
                         words[0] + "".join(word.title() for word in words[1:]), "".join(word.title() for word in words)}
            for name in spellings:
                for text in (f'{{"{name}": "{self.WORDS}"}}', f"{name}: {self.WORDS}", f"{name} = {self.WORDS}",
                             f'Config: {{"{name}": ["{self.WORDS}"]}}', f"My {name}: {self.WORDS}"):
                    with self.subTest(text=text):
                        self.refused_on(text, [self.WORDS])
        for text in ("Phrasebook: page 4", 'Config: {"phrase": "hello"}', "Seed: 42"):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P1, values: an exemption applies only to a whole value.

    def test_a_placeholder_exempts_only_a_whole_value(self) -> None:
        for text, value in (("password: secret horse battery staple", "secret horse battery staple"),
                            ("password: example hunter2", "example hunter2")):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, [value])
        for text in ("password: <your password> hunter2", 'password: "example" hunter2', "password = 'changeme' 'hunter2'",
                     'password = """example""" hunter2', 'password = os.getenv("PW") or "hunter2"', "password = changeme, hunter2",
                     "password: ${DB_PASSWORD} hunter2", "token = {{ api_token }} hunter2", "Authorization: Bearer example hunter2",
                     '{"Authorization": "Bearer example hunter2"}', '{"Authorization": "Bearer <your token> hunter2"}',
                     "Cookie: example hunter2", "max_tokens: 5 hunter2", "credential_source_count: 2 hunter2",
                     'curl -H "Authorization: Bearer example hunter2" https://example.invalid', "password: example`hunter2`",
                     json.dumps({"prompt": "password: example hunter2"})):
            with self.subTest(text=text):
                self.refused_on(text, ["hunter2"])
        for text in ("password: changeme", "password = <your password>", 'password = "<your password>",', "password: ${DB_PASSWORD}",
                     "password = os.getenv('PW')", '{"password": "changeme", "user": "bob"}', "{password: changeme}",
                     "password=changeme\nuser=bob", json.dumps({"prompt": "password: changeme\nnext line"}),
                     'headers = {"Authorization": ["Bearer <your token>"]}', "Authorization: Bearer [REDACTED]",
                     "max_tokens: 512", "credential_source_count: 2", "Set `password=changeme` in the file.",
                     'curl -H "Authorization: Bearer $API_TOKEN" https://example.invalid'):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

        for text in ("Authorization: ordinary", "postgres://user:changeme@localhost/db"):
            with self.subTest(benign_header_or_url=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())
        self.assertIn("header:authorization", self.rules("Authorization: abcdef12"))
        self.assertIn("url-userinfo", self.rules("postgres://user:hunter2@localhost/db"))

    # P3: a payload a lenient decoder reads past a delimiter is read whole or refused.

    def test_a_delimiter_never_ends_what_a_lenient_decoder_reads(self) -> None:
        text = "data:;base64,cGFz) c3dvcmQ9aHVudGVyMg=="
        with self.subTest(everywhere=text):
            self.assertTrue({("encoded-content", "raw"), ("assignment", "data-uri")} <= self.views(text))
            self.refused_everywhere(text, ["cGFz) c3dvcmQ9aHVudGVyMg=="])
        for text, payload in (("data:;base64,cGFz)\nc3dvcmQ9aHVudGVyMg==", "cGFz)\nc3dvcmQ9aHVudGVyMg=="),
                              ('data:;base64,cGFz" c3dvcmQ9aHVudGVyMg==', 'cGFz" c3dvcmQ9aHVudGVyMg=='),
                              ("data:;base64,cGFz> c3dvcmQ9aHVudGVyMg==", "cGFz> c3dvcmQ9aHVudGVyMg=="),
                              ("data:;base64,cGFz), c3dvcmQ9aHVudGVyMg==", "cGFz), c3dvcmQ9aHVudGVyMg=="),
                              ("(data:;base64,cGFz) c3dvcmQ9aHVudGVyMg==", "cGFz) c3dvcmQ9aHVudGVyMg=="),
                              ("data:text/plain;base64,cGFz c3dv. cmQ9aHVudGVyMg==", "cGFz c3dv. cmQ9aHVudGVyMg=="),
                              ("data:text/plain;base64,cGFz c3dv. (cmQ9aHVudGVyMg==)", "cGFz c3dv. (cmQ9aHVudGVyMg==")):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(f"see {text} here"))
                self.assertIn(("assignment", "data-uri"), self.views(f"see {text} here"))
                self.refused_on(f"see {text}", [payload])
        # As after whitespace, the join through the words after a delimiter is read when it is text: "password:" then "bla".
        self.assertIn(("assignment", "data-uri"), self.views("data:text/plain;base64,cGFzc3dvcmQ6) Ymxh"))
        # The continuation counts toward the run budget.
        self.assertIn("encoded-content", self.rules("data:;base64,aGVsbG8=)" + " YSAK" * outbound_screen.MAX_CONTINUATION_RUNS + " x"))
        for text in ("(see data:text/plain;base64,aGVsbG8=) for details", "[greeting](data:text/plain;base64,aGVsbG8=) Next.",
                     '<img src="data:text/plain;base64,aGVsbG8="> and more', '["data:text/plain;base64,aGVsbG8=", "next"]',
                     "data:text/plain;base64,aGVsbG8h YSAK. Then more."):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P2: every bound is checked before what it bounds is created.

    # P4: JSON is decoded and charged once.

    # The backstop: an exit value Python prints that is not a plain string is withheld.

    def test_exit_values_that_are_not_text_are_withheld(self) -> None:
        with self.assertRaises(SystemExit) as raised, outbound_screen.withheld_diagnostics("cmd"):
            raise SystemExit({"note": self.TOKEN})
        self.assertRegex(str(raised.exception.code), r"^cmd stopped on an unexpected SystemExit; its details are withheld "
                                                     r"\(traceback sha256:[0-9a-f]{16}\)$")
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)
        for code in (0, 3, None, True, "clean message"):
            with self.subTest(code=code), self.assertRaises(SystemExit) as kept, outbound_screen.withheld_diagnostics("cmd"):
                raise SystemExit(code)
            self.assertEqual(kept.exception.code, code)

    def test_a_reading_that_fails_is_not_the_same_reading(self) -> None:
        for text in ("data:;base64,YQ== YWI=", "data:text/plain;base64,YSA= aGVsbG8="):
            with self.subTest(text=text):
                self.assertIn("encoded-content", self.rules(text))
        self.refused_everywhere("See data:;base64,YQ== YWI=", ["YQ== YWI="])
        # The same reading both ways: no padding inside the stream.
        for text in ("data:text/plain;base64,YWJj ZGVm", "data:text/plain;base64,aGVsbG8gd29ybGQ="):
            with self.subTest(text=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    def test_embedded_json_counts_the_depth_around_it(self) -> None:
        def payload(levels: int, prefix: str) -> str:
            nested: object = prefix + json.dumps(json.loads("[" * levels + "]" * levels))
            for _ in range(40):
                nested = [nested]
            return json.dumps({"a": nested})

        self.assertIn("json-unreadable", self.rules(payload(30, "Config: "), "application/json"))
        with self.assertRaisesRegex(OutboundRefused, "screening depth"):
            require_clean(payload(30, ""), surface="test", content_type="application/json")
        for text in (payload(20, "Config: "), payload(20, "")):
            with self.subTest(text=text[-30:]):
                self.assertEqual(screen_outbound(text, surface="test", content_type="application/json").findings, ())

    def test_json_already_read_is_never_decoded_or_charged_again(self) -> None:
        screens: list[outbound_screen._Screen] = []

        class Recording(outbound_screen._Screen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                screens.append(self)

        benign = json.dumps("{} abc " * 15000)
        require_clean(benign, surface="test", content_type="application/json")
        text = json.dumps("{} abc " * 15000 + 'x {"password": "hunter2"}')
        findings = screen_outbound(text, surface="test", content_type="application/json").findings
        self.assertIn(("json-pair", "json"), {(finding.rule, finding.view) for finding in findings})
        only_injected(self, text, findings, ["hunter2"])
        # JSON read in the raw view is not decoded again in the normalized view, nor the payload's own JSON in the raw view.
        costs = []
        for sample in ('Config: {"a":1} ABC', 'Config: {"a":1} ＡＢＣ', '{"a": [1, {"b": 2}]}'):
            with patch.object(outbound_screen, "_Screen", Recording):
                self.assertEqual(screen_outbound(sample, surface="test").findings, ())
            costs.append(screens[-1].json_examined)
        self.assertEqual(costs[0], costs[1])
        self.assertEqual(costs[2], len('{"a": [1, {"b": 2}]}'))

    def test_the_view_allowance_is_never_exceeded(self) -> None:
        screens: list[outbound_screen._Screen] = []

        class Recording(outbound_screen._Screen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                screens.append(self)

        allowance = outbound_screen._Screen.MAX_VIEWS
        with patch.object(outbound_screen, "_Screen", Recording):
            self.assertEqual(screen_outbound(" ".join(["data:,hello"] * allowance), surface="test").findings, ())
            self.assertEqual(screens[-1].views, allowance)
            for text in (" ".join(["data:,hello"] * (allowance + 1)), " ".join(["data:,hello"] * allowance) + " %41 \\u0041"):
                with self.subTest(text=text[-20:]):
                    self.assertEqual(self.rules(text), {"encoded-content"})
                    self.assertLessEqual(screens[-1].views, allowance)


class RiskRouteExportTests(unittest.TestCase):
    """A manual JSON export carries the route, and with it the routing risk assessment. Its own wording must
    never read as a credential assignment, or every task that names a credential would be refused for the
    template rather than for anything the caller wrote."""

    TASK = "Review the password rotation runbook for the retry service."

    def test_no_floor_reason_reads_as_an_assignment(self) -> None:
        from cwo_core import risk_features

        policy = risk_features._policy()
        groups = [[name] for name in policy["features"]] + [list(item["all"]) for item in policy.get("combinations", [])]
        for names in groups:
            _, reasons, _ = risk_features._floor(names)
            for reason in reasons:
                with self.subTest(reason=reason):
                    exported = json.dumps({"route": {"risk_assessment": {"floor_reasons": [reason]}}}, indent=2) + "\n"
                    self.assertEqual(screen_outbound(exported, surface="test", content_type="application/json").findings, ())
                    self.assertEqual(screen_outbound(reason, surface="test").findings, ())

    def test_a_task_that_names_a_credential_exports_its_route_cleanly(self) -> None:
        import dispatch_work
        import generate_manual_dispatch_prompt
        from cwo_core.routing import classify_work

        route = classify_work(self.TASK, text_segments=[self.TASK])
        self.assertIn("asset:credentials", {item["feature"] for item in route["risk_assessment"]["features"]})
        for argv in (["generate_manual_dispatch_prompt.py", self.TASK, "--json"],
                     ["dispatch_work.py", self.TASK, "--external-ok", "--share-boundary", "redacted-packet",
                      "--allow-raw-manual-prompt", "--rehearsal", "--waiver-reason", "outbound screening test", "--json"]):
            record: list[tuple[str, tuple]] = []
            stdout = io.StringIO()
            with self.subTest(command=argv[0]), patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    patch.object(dispatch_work, "enforce_contracting_quota", return_value=QUOTA_INFO), \
                    patch.object(dispatch_work, "record_audit_event"), \
                    patch.object(generate_manual_dispatch_prompt, "require_clean", side_effect=recording_screen(record)):
                (dispatch_work if argv[0] == "dispatch_work.py" else generate_manual_dispatch_prompt).main()
                self.assertTrue(record)
                self.assertIn("asset:credentials sets the floor to", record[-1][0])
                self.assertEqual(record[-1][1], (), [finding.describe() for finding in record[-1][1]])
                self.assertEqual(stdout.getvalue(), record[-1][0])


GUARD_DRIVER = """\
import json, os, socket, sys, urllib.request
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, SCRIPTS)
import dispatch_work
import generate_manual_dispatch_prompt
from cwo_core.routing import classify_work
from cwo_core.host_records import HostRecordStore, using_test_store
_host_scope = using_test_store(HostRecordStore.for_tests(Path(RESULT).parent / 'host-records'))
_host_scope.__enter__()

# The shipped default, read before anything in this fresh interpreter could change it.
result = {"flag": dispatch_work.LOCAL_INVOCATION_AVAILABLE, "calls": {}, "exit": None}
calls = result["calls"]


def refuse(name):
    calls[name] = 0

    def spy(*args, **kwargs):
        calls[name] += 1
        raise AssertionError(f"{name} reached")
    return spy


real_audit = dispatch_work.record_audit_event
calls["audit"] = 0


def audit(*args, **kwargs):
    calls["audit"] += 1
    return real_audit(*args, **kwargs)


effects = (
    patch.object(urllib.request, "Request", side_effect=refuse("request")),
    patch.object(urllib.request, "build_opener", side_effect=refuse("opener")),
    patch.object(urllib.request, "urlopen", side_effect=refuse("urlopen")),
    patch.object(socket, "getaddrinfo", side_effect=refuse("resolve")),
    patch.object(socket, "create_connection", side_effect=refuse("connect")),
    patch.object(dispatch_work, "record_audit_event", side_effect=audit),
)
for effect in effects:
    effect.start()
try:
    if MODE == "function":
        task = "Documentation review for internal example notes."
        route = classify_work(task, local_ok=True, prefer_local=True, local_profile="openshift-ai-vllm",
                              requested_roles=["documentation"])
        args = dispatch_work.argparse.Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None,
                                                local_model=None, execute_local=True)
        envelope = dispatch_work.build_local_envelope(task=task, route=route, dispatch_id="dispatch-guard-test",
                                                      bead_id="cwo-guard", epic_id=None, args=args)
        dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
    else:
        sys.argv = ARGV
        (dispatch_work if ARGV[0] == "dispatch_work.py" else generate_manual_dispatch_prompt).main()
except SystemExit as exc:
    result["exit"] = exc.code if isinstance(exc.code, int) or exc.code is None else str(exc.code)
    raise
finally:
    Path(RESULT).write_text(json.dumps(result), encoding="utf-8")
"""


class ProductionGuardTests(unittest.TestCase):
    """The shipped state, in fresh interpreters: local invocation is off, and nothing here enables it.

    Each run spies on request construction, opener construction, DNS resolution, connection and the audit
    write. The local route refuses before any of them; manual export still screens and refuses on the CLI path.
    """

    LOCAL_ENV = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
    LOCAL_ARGV = ["dispatch_work.py", "Documentation review for internal example notes.", "--local-ok", "--prefer-local",
                  "--local-profile", "openshift-ai-vllm", "--requested-role", "documentation", "--json"]
    NO_EFFECTS = {"request": 0, "opener": 0, "urlopen": 0, "resolve": 0, "connect": 0, "audit": 0}

    def _run(self, tmp: Path, *, mode: str = "cli", argv: list[str] | None = None) -> tuple[subprocess.CompletedProcess, dict]:
        driver = tmp / "guard_driver.py"
        result = tmp / "guard_result.json"
        result.unlink(missing_ok=True)
        driver.write_text(f"SCRIPTS = {str(ROOT / 'scripts')!r}\nMODE = {mode!r}\nARGV = {argv!r}\nRESULT = {str(result)!r}\n"
                          + GUARD_DRIVER, encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if not key.startswith("CWO_")}
        env.update(self.LOCAL_ENV)
        env["CWO_AUDIT_FILE"] = str(tmp / "audit.jsonl")
        completed = subprocess.run([sys.executable, "-I", str(driver)], capture_output=True, text=True, timeout=180,
                                   cwd=ROOT, env=env)
        self.assertTrue(result.exists(), completed.stderr[-800:])
        return completed, json.loads(result.read_text(encoding="utf-8"))

    def test_the_shipped_flag_is_off_in_a_fresh_interpreter(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r}); import dispatch_work; "
             "print(repr(dispatch_work.LOCAL_INVOCATION_AVAILABLE))"],
            capture_output=True, text=True, timeout=120, cwd=ROOT)
        self.assertEqual((completed.returncode, completed.stdout), (0, "False\n"), completed.stderr[-400:])

    def test_the_execute_local_cli_refuses_before_any_request_or_resolution(self) -> None:
        import dispatch_work

        with tempfile.TemporaryDirectory() as tmpdir:
            completed, result = self._run(Path(tmpdir), argv=[*self.LOCAL_ARGV, "--execute-local"])
            self.assertFalse((Path(tmpdir) / "audit.jsonl").exists())
        self.assertIs(result["flag"], False)
        self.assertEqual(result["calls"], self.NO_EFFECTS)
        self.assertEqual(result["exit"], dispatch_work.LOCAL_INVOCATION_UNAVAILABLE)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Nothing was sent", completed.stderr)

    def test_the_local_effect_function_refuses_before_any_request_or_resolution(self) -> None:
        import dispatch_work

        with tempfile.TemporaryDirectory() as tmpdir:
            completed, result = self._run(Path(tmpdir), mode="function")
        self.assertIs(result["flag"], False)
        self.assertEqual(result["calls"], self.NO_EFFECTS)
        self.assertEqual(result["exit"], dispatch_work.LOCAL_INVOCATION_UNAVAILABLE)
        self.assertEqual((completed.returncode, completed.stdout), (1, ""))

    def test_manual_export_cli_screens_and_refuses_with_the_shipped_flag(self) -> None:
        token = RoundTwoTests.TOKEN
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            packet = tmp / "packet.json"
            packet.write_text(json.dumps(packet_with("Review the retry plan for duplicate jobs.")), encoding="utf-8")
            refused = (
                ("generate_manual_dispatch_prompt.py", ["Review the retry plan. password_source=hunter2"], "hunter2"),
                ("generate_manual_dispatch_prompt.py", ["Review the retry plan. password_source=hunter2", "--json"], "hunter2"),
                ("dispatch_work.py", ["--packet", str(packet), "--allow-unlinked-packet", "--json", "--epic", token,
                                      "--waiver-reason", "outbound screening test"], token),
            )
            for command, argv, secret in refused:
                with self.subTest(command=command, argv=argv[-1]):
                    completed, result = self._run(tmp, argv=[command, *argv])
                    self.assertIs(result["flag"], False)
                    self.assertEqual(result["calls"], self.NO_EFFECTS)
                    self.assertEqual(completed.returncode, 1, completed.stderr[-400:])
                    self.assertIn("outbound screening refused manual export", completed.stderr)
                    self.assertEqual(completed.stdout, "")
                    self.assertNotIn(secret, completed.stderr)
                    self.assertFalse((tmp / "audit.jsonl").exists(), "a refused export records no dispatch")
            clean = (
                ("generate_manual_dispatch_prompt.py", ["Review the retry plan for duplicate jobs.", "--local-ok"], 0),
                ("dispatch_work.py", ["--packet", str(packet), "--allow-unlinked-packet", "--waiver-reason",
                                      "outbound screening test"], 1),
            )
            for command, argv, audits in clean:
                with self.subTest(command=command, clean=True):
                    completed, result = self._run(tmp, argv=[command, *argv])
                    self.assertIs(result["flag"], False)
                    self.assertEqual(result["calls"], {**self.NO_EFFECTS, "audit": audits})
                    self.assertEqual(completed.returncode, 0, completed.stderr[-400:])
                    self.assertIn("Review the retry plan for duplicate jobs.", completed.stdout)


class RoundElevenTests(_OutboundHelpers, unittest.TestCase):
    """Whole-value exemptions, adjacent literals and lenient payload joins."""

    TOKEN = RoundTwoTests.TOKEN

    def passes(self, texts: tuple[str, ...]) -> None:
        for text in texts:
            with self.subTest(passes=text):
                self.assertEqual(screen_outbound(text, surface="test").findings, ())

    # P1, names: every word of a credential pair, a credential word and a phrase name is read with its plural.

    # P1, values: a structure exempts only a whole value; what follows its closing bracket is not exempt.

    def test_a_structure_exempts_only_a_whole_value(self) -> None:
        for text in ('password = [REDACTED] + "hunter2"', 'password = ("example") + "hunter2"'):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, ["hunter2"])
        for text in ("password = (None) or 'hunter2'", 'password = {"value": "<your password>"} | "hunter2"', 'password = [REDACTED]"hunter2"',
                     "password = [REDACTED] hunter2", "password = ['changeme'].pop() or 'hunter2'",
                     # A more indented next line continues a plain value, as YAML folds it and HTTP folds a header.
                     "password = [REDACTED]\n    hunter2", "password: changeme\n  hunter2", "token: <your token>\n    hunter2",
                     "password=changeme\r\n  hunter2", "Authorization: Bearer [REDACTED]\n  hunter2", "Authorization: example hunter2",
                     json.dumps({"prompt": 'password = [REDACTED] + "hunter2"'})):
            with self.subTest(text=text):
                self.refused_on(text, ["hunter2"])
        self.passes(("password = [REDACTED]", 'password = ("example")', "Set `token = [REDACTED]` in the file.", "password = [REDACTED],\nuser = bob",
                     "x = f(password=[REDACTED]\n      )", "config:\n  password: changeme\n  user: bob\n", "- password: changeme\n  user: bob",
                     '{"password": ["<your password>"], "user": "bob"}', "password: changeme\n    # set in the vault",
                     "password = [REDACTED];\nnext()", "- Authorization: see the auth section"))

    # P1, values: adjacent string literals are one value, as Python joins them; checks apply to the joined value.

    def test_adjacent_literals_are_one_value(self) -> None:
        for text in ("headers = {'Authorization': 'Bearer example' 'hunter2'}", "headers = {'Authorization': ('Bearer example' 'hunter2')}"):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, ["hunter2"])
        for text in ("headers = {'Authorization': 'Bearer example' f'hunter2'}", "headers = {'Authorization': ('Bearer example' rb'hunter2')}",
                     "headers = {\n    'Authorization': 'Bearer example'\n    'hunter2'}", "headers = {'Authorization': ('Bearer example'\n 'hunter2')}",
                     "headers = {'Authorization': ('Bearer example') + 'hunter2'}", "headers = {'Authorization': 'Bearer example' + 'hunter2'}",
                     "headers = {'Authorization': ['Bearer example' 'hunter2']}", "headers = {'Authorization': f'Bearer hunter2'}",
                     '{"Authorization": "Bearer example" "hunter2"}', "connect(password='changeme'\n         'hunter2')",
                     "{'password': 'example'\n 'hunter2'}", 'password = """example"""\n"hunter2"',
                     # A shell joins quoted words with what follows them at once.
                     "curl -H 'Authorization: Bearer example''hunter2' https://example.invalid", 'tool --password "example""hunter2"',
                     "tool --password 'example'hunter2", 'curl -H "Authorization: Bearer $API_TOKEN"hunter2 https://example.invalid'):
            with self.subTest(text=text):
                self.refused_on(text, ["hunter2"])
        # An f-string is read as the literal it is: an interpolation is not a placeholder.
        self.assertIn("header:authorization", self.rules("headers = {'Authorization': f'Bearer {token}'}"))
        self.passes(("headers = {'Authorization': 'Bearer example'}", "headers = {'Authorization': ('Bearer example')}",
                     "headers = {'Authorization': 'Bearer <token>',\n           'Accept': 'application/json'}",
                     '"Authorization": "Bearer <token>"\n"Content-Type": "application/json"', "password: 'changeme'\nuser: bob",
                     "password = 'changeme'\n'user': 'bob'", 'curl -H "Authorization: Bearer $API_TOKEN" https://example.invalid',
                     'tool --password "$PW" next', '$(tool --token "$TOKEN")', "Use `password=changeme` then restart."))

    # P3: a word followed by a delimiter never ends what a lenient decoder joins.

    # P4: unchanged JSON is read once across structural readings.

    # The backstop: every BaseException other than an interrupt or an integer or plain-string exit is withheld.

    def test_exception_groups_are_withheld(self) -> None:
        for raised_group in (BaseExceptionGroup("clean", [SystemExit({"note": self.TOKEN})]),
                             BaseExceptionGroup("clean", [KeyboardInterrupt(self.TOKEN)]),
                             BaseExceptionGroup(self.TOKEN, [GeneratorExit()])):
            with self.subTest(group=type(raised_group.exceptions[0]).__name__), self.assertRaises(SystemExit) as raised, \
                    outbound_screen.withheld_diagnostics("cmd"):
                raise raised_group
            self.assertRegex(str(raised.exception.code), r"^cmd stopped on an unexpected BaseExceptionGroup; its details are withheld "
                                                         r"\(traceback sha256:[0-9a-f]{16}\)$")
            self.assertIsNone(raised.exception.__cause__)
            self.assertTrue(raised.exception.__suppress_context__)
        with self.assertRaises(KeyboardInterrupt), outbound_screen.withheld_diagnostics("cmd"):
            raise KeyboardInterrupt
        for code in (0, 3, None, "clean message"):
            with self.subTest(code=code), self.assertRaises(SystemExit) as kept, outbound_screen.withheld_diagnostics("cmd"):
                raise SystemExit(code)
            self.assertEqual(kept.exception.code, code)

    def test_a_word_and_a_delimiter_never_end_a_lenient_join(self) -> None:
        text = "data:;base64,cGFzc3dv cm) Q9aHVudGVyMg=="
        with self.subTest(everywhere=text):
            self.assertTrue({("encoded-content", "raw"), ("assignment", "data-uri")} <= self.views(text))
            self.refused_everywhere(text, ["cGFzc3dv cm) Q9aHVudGVyMg=="])
        quoted = json.dumps({"note": text})
        self.assertTrue({"encoded-content", "assignment"} <= self.rules(quoted))
        self.assertTrue({"encoded-content", "assignment"} <= self.rules(quoted, "application/json"))
        for text, payload in (('data:;base64,cGFzc3dv cm" Q9aHVudGVyMg==', 'cGFzc3dv cm" Q9aHVudGVyMg=='),
                              ("data:;base64,cGFzc3dv cm>\nQ9aHVudGVyMg==", "cGFzc3dv cm>\nQ9aHVudGVyMg=="),
                              ("data:text/plain;base64,cGFzc3dv cm). Q9aHVudGVyMg==", "cGFzc3dv cm). Q9aHVudGVyMg=="),
                              ("data:;base64,cGFz c3dv cm) Q9aHVudGVyMg==", "cGFz c3dv cm) Q9aHVudGVyMg==")):
            with self.subTest(text=text):
                self.assertIn(("assignment", "data-uri"), self.views(f"see {text}"))
                self.refused_on(f"see {text}", [payload])
        # A join through several words and delimiters is followed to its end.
        self.assertIn("encoded-content", self.rules("data:;base64,cGFzc3dv ab) cd) Q9aHVudGVyMg=="))
        # Each word and delimiter counts toward the run budget; past it, the whole join is opaque.
        budget = outbound_screen.MAX_CONTINUATION_RUNS
        over = "data:;base64,cGFzc3dv" + " ab)" * (budget + 3) + " Q9aHVudGVyMg=="
        self.assertIn("encoded-content", self.rules(over))
        self.refused_on(over, ["Q9aHVudGVyMg=="])
        within = "data:text/plain;base64,aGVsbG8h" + " ab)" * (budget - 2) + " Then more."
        self.assertEqual(screen_outbound(within, surface="test").findings, ())
        self.assertIn("encoded-content", self.rules("data:text/plain;base64,aGVsbG8h" + " ab)" * (budget - 1) + " Then more."))
        self.passes(("data:text/plain;base64,aGVsbG8h and more) text here", "data:text/plain;base64,aGVsbG8= is the greeting (see docs) and more",
                     "data:text/plain;base64,aGVsbG8h is here. More text follows.", "[greeting](data:text/plain;base64,aGVsbG8=) Next."))

    def test_plural_credential_pairs_are_credential_names(self) -> None:
        for text in ("api_keys=hunter2", "access_keys=hunter2", '{"private_keys":["hunter2"]}'):
            with self.subTest(everywhere=text):
                self.refused_everywhere(text, ["hunter2"])
        pairs = outbound_screen._rules()["secret_name_pairs"]
        self.assertTrue({("api", "key"), ("access", "key"), ("private", "key")} <= {tuple(pair) for pair in pairs})
        forms = outbound_screen._Detector.word_forms
        for first, second in pairs:
            for one in sorted(forms(first)):
                for two in sorted(forms(second)):
                    spellings = {f"{one}_{two}", f"{one}-{two}", f"{one}{two}", f"{one}{two.title()}", f"{one.title()}{two.title()}",
                                 f"{one.upper()}_{two.upper()}", f"{one.upper()}{two.title()}", f"db_{one}_{two}", f"db{one}_{two}"}
                    for name in spellings:
                        for text in (f'{{"{name}":"hunter2"}}', f"{name}=hunter2", f"{name}: hunter2", f'Config: {{"{name}": ["hunter2"]}}'):
                            with self.subTest(text=text):
                                self.refused_on(text, ["hunter2"])
        # The same holds for single credential words, phrase names and the CLI flags.
        for text in ("passes: hunter2", "pins_list: hunter2", "seed_phrases: hunter2", "SeedsPhrase: hunter2", "mnemonics = hunter2",
                     "tool --api-keys hunter2", "tool --passwords hunter2", "tool --access-keys=hunter2"):
            with self.subTest(text=text):
                self.refused_on(text, ["hunter2"])
        self.passes(('Config: {"keys": [1, 2], "apis": ["v1"], "access": "granted", "private": true}', "Bypasses: 2",
                     "Compasses: north", "Tokenizers: cl100k", "Spins: 3", "Phrasebooks: 4", "tool --pass-through x"))

    def test_unchanged_json_is_read_once_across_readings(self) -> None:
        screens: list[outbound_screen._Screen] = []

        class Recording(outbound_screen._Screen):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)  # type: ignore[arg-type]
                screens.append(self)

        views = []
        for marker in ("Ａ", "A"):
            text = json.dumps({"values": ["%41"] * 32, "marker": marker}, ensure_ascii=False)
            with self.subTest(marker=marker), patch.object(outbound_screen, "_Screen", Recording):
                require_clean(text, surface="test", content_type="application/json")
                views.append(screens[-1].views)
        self.assertEqual(views, [33, 33])
        # What changed between readings is still read, and nothing already read is hidden.
        for text in (json.dumps({"values": ["%41"] * 32, "marker": "Ａ", "password": "hunter2"}, ensure_ascii=False),
                     json.dumps({"values": ["%41"] * 32, "note": "ｐａｓｓｗｏｒｄ=hunter2"}, ensure_ascii=False)):
            with self.subTest(text=text[-40:]):
                findings = screen_outbound(text, surface="test", content_type="application/json").findings
                self.assertTrue(findings)
                only_injected(self, text, findings, ["hunter2"])


class DiagnosticCase(NamedTuple):
    label: str
    setup: str
    raiser: str
    stderr_pattern: str


class DiagnosticFamily(NamedTuple):
    original: str
    cases: tuple[DiagnosticCase, ...]
    forbidden: tuple[str, ...]
    digest_message: str


def _diagnostic_families() -> tuple[DiagnosticFamily, ...]:
    unexpected = (r"^{command} stopped on an unexpected %s; its details are withheld "
                  r"\(traceback sha256:[0-9a-f]{16}\)\n$")
    breaking = ("from cwo_core import outbound_screen\ndef broken(*args, **kwargs):\n"
                "    raise ValueError(TOKEN)\noutbound_screen.screen_outbound = broken\n")
    return (
        DiagnosticFamily("RoundEightTests.test_unexpected_exceptions_print_only_a_digest", (
            DiagnosticCase("chained cause", "", "raise RuntimeError('clean') from ValueError(TOKEN)",
                           unexpected % "RuntimeError"),
            DiagnosticCase("implicit context", "", "try:\n    raise ValueError(TOKEN)\nexcept ValueError:\n    raise RuntimeError('clean')",
                           unexpected % "RuntimeError"),
            DiagnosticCase("note", "", "error = RuntimeError('clean')\nerror.add_note(TOKEN)\nraise error",
                           unexpected % "RuntimeError"),
            DiagnosticCase("exception group", "", "raise ExceptionGroup('clean', [ValueError(TOKEN)])",
                           unexpected % "ExceptionGroup"),
        ), ("clean",), "the digest covers the chained, noted or grouped content"),
        DiagnosticFamily("RoundNineTests.test_failures_while_screening_a_diagnostic_print_only_a_digest", (
            DiagnosticCase("screening raises", breaking, "raise SystemExit(f'cannot use {TOKEN}')", unexpected % "ValueError"),
            DiagnosticCase("4,500-digit integer", "", "raise SystemExit(f'cannot use {TOKEN} in {{\"a\": {DIGITS}}}')",
                           r"^{command} stopped; its diagnostic is withheld because it repeats content "
                           r"the outbound screen refuses \([a-z:, -]*json-unreadable[a-z:, -]*; message sha256:[0-9a-f]{16}\)\n$"),
        ), ("Traceback",), "the digest covers the withheld content"),
        DiagnosticFamily("RoundTenTests.test_exit_values_that_are_not_text_print_only_a_digest", (
            DiagnosticCase("mapping", "", "raise SystemExit({'note': TOKEN})", unexpected % "SystemExit"),
            DiagnosticCase("list", "", "raise SystemExit([TOKEN])", unexpected % "SystemExit"),
            DiagnosticCase("str subclass", "", "raise SystemExit(type('Text', (str,), {})(TOKEN))", unexpected % "SystemExit"),
        ), ("note",), "the digest covers the withheld value"),
        DiagnosticFamily("RoundElevenTests.test_exception_groups_print_only_a_digest", (
            DiagnosticCase("base exception group", "", "raise BaseExceptionGroup('clean', [SystemExit({'note': TOKEN})])",
                           unexpected % "BaseExceptionGroup"),
        ), ("note", "clean"), "the digest covers the grouped exit value"),
    )


class DiagnosticCommandTests(unittest.TestCase):
    def test_withheld_diagnostic_command_rows(self) -> None:
        for family in _diagnostic_families():
            with self.subTest(original=family.original):
                results = {}
                with tempfile.TemporaryDirectory() as tmpdir:
                    driver = Path(tmpdir) / "driver.py"
                    for command in ("dispatch_work", "generate_manual_dispatch_prompt"):
                        for row in family.cases:
                            for token in (RoundTwoTests.TOKEN, RoundTwoTests.TOKEN[:-4] + "WXYZ"):
                                source = (
                                    f"import sys\nsys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
                                    f"import {command} as command\nTOKEN = {token!r}\n"
                                    f"DIGITS = {RoundNineTests.DIGITS!r}\n"
                                )
                                driver.write_text(source + row.setup + "def boom():\n" +
                                                  textwrap.indent(row.raiser, "    ") +
                                                  "\ncommand._main = boom\ncommand.main()\n", encoding="utf-8")
                                results[(command, row, token)] = subprocess.run(
                                    [sys.executable, "-I", str(driver)], capture_output=True,
                                    text=True, timeout=180, cwd=ROOT,
                                )
                digests = {}
                for (command, row, token), completed in results.items():
                    with self.subTest(command=command, case=row.label, token=token):
                        self.assertEqual(completed.returncode, 1, completed.stderr[-300:])
                        self.assertRegex(completed.stderr, row.stderr_pattern.replace("{command}", command))
                        self.assertNotIn(token[4:16], completed.stderr)
                        for forbidden in family.forbidden:
                            self.assertNotIn(forbidden, completed.stderr)
                        self.assertEqual(completed.stdout, "")
                        digests.setdefault((command, row.label), set()).add(completed.stderr)
                for key, messages in digests.items():
                    with self.subTest(digest=key):
                        self.assertEqual(len(messages), 2, family.digest_message)


class Batch4cScreenDispatchGuards(_OutboundHelpers, unittest.TestCase):
    def test_F4_M064_preflight_rechecks_the_actual_request_before_open(self):
        """Changed preflight bytes refuse with zero opener calls."""
        from unittest.mock import Mock
        import dispatch_work

        url = "http://127.0.0.1:8000"
        screened = screen_request("GET", url + "/v1/models", {}, b"", surface="preflight request")
        for path in ("/v1/changed-models", "/v1/models"):
            with self.subTest(path=path):
                opener = Mock()
                if path == "/v1/changed-models":
                    with self.assertRaisesRegex(OutboundRefused, "changed after it was screened"):
                        dispatch_work._preflight_local_model(opener, base_url=url,
                            transport={"model_preflight_endpoint_path": path}, headers={}, model="F4-model", screened=screened)
                    opener.open.assert_not_called()
                else:
                    from tests.test_local_dispatch import FakeModelsResponse

                    opener.open.return_value = FakeModelsResponse()
                    result = dispatch_work._preflight_local_model(opener, base_url=url,
                        transport={"model_preflight_endpoint_path": path}, headers={},
                        model="glm-5.2-bf16-256k", screened=screened)
                    self.assertIsInstance(result, dict)
                    opener.open.assert_called_once()

    def test_F4_M007_entropy_threshold_is_inclusive(self):
        """A policy threshold includes its exact entropy boundary."""
        import copy

        token = "aB3dE6gH9jK2mN5pQ8sT1vW4"
        rules = copy.deepcopy(outbound_screen._rules())
        boundary = outbound_screen._entropy(token)
        rules["entropy"]["mixed_min_bits"] = boundary
        with patch.object(outbound_screen, "_rules", return_value=rules):
            self.assertIn("entropy", {item.rule for item in screen_outbound(token, surface="entropy boundary").findings})
            rules["entropy"]["mixed_min_bits"] = boundary + .001
            self.assertNotIn("entropy", {item.rule for item in screen_outbound(token, surface="entropy boundary").findings})

    def test_F4_M014_declared_json_budget_refuses_clean_content(self):
        """Budget refusal is independent of sensitive raw-text findings."""
        payload = '{"note":"plain text"}'
        self.assertEqual(screen_outbound(payload, surface="JSON budget", content_type="application/json").findings, ())
        with patch.multiple(outbound_screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=0):
            with self.assertRaisesRegex(OutboundRefused, "JSON exceeds the screening budget"):
                screen_outbound(payload, surface="JSON budget", content_type="application/json")

    def test_F4_M069_malformed_response_never_marks_content_usable(self):
        """Malformed metadata stays unusable before and after final eligibility."""
        import dispatch_work
        from tests.test_local_dispatch import FakeResponse

        states = []

        class ObservedMetadata(dict):
            def __setitem__(self, key, value):
                if key == "usable_final_content" and self.get("payload_validation_error"):
                    states.append(value)
                return super().__setitem__(key, value)

        class Malformed(FakeResponse):
            def read(self, size=None):
                return b'{invalid JSON'[:size]

        class Opener:
            def open(self, *args, **kwargs):
                return Malformed()

        original = dispatch_work.sanitize_local_response_payload

        def observe(*args, **kwargs):
            payload, metadata = original(*args, **kwargs)
            return payload, ObservedMetadata(metadata)

        with patch.object(dispatch_work, "sanitize_local_response_payload", side_effect=observe):
            result = self._execute("Documentation review for internal example notes.", Opener())
        self.assertEqual(result["completion_status"], "malformed-response")
        self.assertIs(result["usable_final_content"], False)
        self.assertTrue(states)
        self.assertTrue(all(value is False for value in states), states)

if __name__ == "__main__":
    unittest.main()
