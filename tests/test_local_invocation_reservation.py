"""Reservations, aggregate accounting and crash ambiguity at the controlled local HTTP route.

The route stays disabled in shipped code (``dispatch_work.LOCAL_INVOCATION_AVAILABLE`` is False). Each test here
enables it with a patch scoped to that test, points the invocation ledger at the test's own temporary directory, and
puts a fake or a spy on every effect boundary: endpoint resolution, DNS, socket connection, the urllib opener,
``urlopen``, subprocess (which is also how Beads would be reached), the audit log and any file write outside the
test's temporary directory. Refusals assert zero effects at all of them. ``ShippedGuardTests`` prove, in fresh
interpreters with nothing patched, that the shipped flag refuses before the ledger is touched.
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from argparse import Namespace
from collections import Counter
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_work  # noqa: E402

import cwo_core.audit as audit_lib  # noqa: E402
from cwo_core import local_invocation  # noqa: E402
from cwo_core.invocation_ledger import InvocationLedger  # noqa: E402
from cwo_core.policy import load_contracting_controls  # noqa: E402
from cwo_core.host_records import HostRecordStore, using_test_store  # noqa: E402
from tests.test_local_dispatch import FakeHardenedOpener, FakeResponse  # noqa: E402

LOCAL_ENV = {"CWO_OPENSHIFT_AI_VLLM_BASE_URL": "http://127.0.0.1:8000", "CWO_OPENSHIFT_AI_VLLM_MODEL": "test-model"}
TASK = "Documentation review for internal example notes."
GLM_TASK = "Use exact GLM-5.2 BF16 256K thinking as an independent architecture critic second opinion."
EPIC = "cwo-epic-41"
NO_EFFECTS = {"resolve": 0, "dns": 0, "connect": 0, "socket_connect": 0, "build_opener": 0, "urlopen": 0,
              "subprocess": 0, "system": 0, "audit_write": 0}


import contextvars
import threading
class RecordingOpener:
    """The fake HTTP boundary: records the exact method, URL, headers, body and timeout of every request."""

    def __init__(self, *, raises: BaseException | None = None, during: Any = None, response: Any = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.raises = raises
        self.during = during
        self.response = response

    def open(self, req: Any, **kwargs: Any) -> Any:
        self.requests.append({"method": req.get_method(), "url": req.full_url, "headers": sorted(req.header_items()),
                              "body": req.data, "timeout": kwargs.get("timeout")})
        if self.during is not None:
            self.during(req)
        if self.raises is not None:
            raise self.raises
        return self.response if self.response is not None else FakeResponse()


class Boundaries:
    """Spies on every effect boundary. ``build_opener`` hands out the test's fake opener; everything else that would
    reach the network or another process counts and raises. File writes are recorded with their paths."""

    WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def __init__(self, tmp: Path, opener: Any = None) -> None:
        self.tmp = tmp.resolve()
        self.opener = opener
        self.calls: Counter[str] = Counter({name: 0 for name in NO_EFFECTS})
        self.writes: list[str] = []
        self.order: list[str] = []
        self._stack = contextlib.ExitStack()

    def _refuse(self, name: str) -> Any:
        def spy(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] += 1
            raise AssertionError(f"{name} reached")
        return spy

    def _record_write(self, path: Any, directory: Any = None) -> None:
        if isinstance(path, (str, bytes, os.PathLike)):
            if directory is not None and not os.path.isabs(path):
                path = Path(os.readlink('/proc/self/fd/' + str(directory))) / os.fsdecode(path)
            self.writes.append(os.path.abspath(os.fsdecode(path)))

    def __enter__(self) -> Boundaries:
        real_os_open, real_open, real_replace = os.open, builtins.open, os.replace
        real_mkdir, real_unlink = os.mkdir, os.unlink
        real_pinned = dispatch_work.pinned_local_endpoint_address

        def os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if flags & self.WRITE_FLAGS:
                self._record_write(path, kwargs.get('dir_fd'))
            return real_os_open(path, flags, *args, **kwargs)

        def py_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if any(flag in mode for flag in "wax+"):
                self._record_write(file)
            return real_open(file, mode, *args, **kwargs)

        def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            self._record_write(dst, kwargs.get('dst_dir_fd'))
            return real_replace(src, dst, *args, **kwargs)

        def mkdir(path: Any, *args: Any, **kwargs: Any) -> None:
            self._record_write(path, kwargs.get('dir_fd'))
            return real_mkdir(path, *args, **kwargs)

        def unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            self._record_write(path, kwargs.get('dir_fd'))
            return real_unlink(path, *args, **kwargs)

        def pinned(*args: Any, **kwargs: Any) -> Any:
            self.calls["resolve"] += 1
            self.order.append("resolve")
            return real_pinned(*args, **kwargs)

        def build_opener(*args: Any, **kwargs: Any) -> Any:
            self.calls["build_opener"] += 1
            self.order.append("build_opener")
            if self.opener is None:
                raise AssertionError("build_opener reached")
            return self.opener

        for target, name, replacement in (
            (os, "open", os_open), (builtins, "open", py_open), (io, "open", py_open), (os, "replace", replace),
            (os, "mkdir", mkdir), (os, "unlink", unlink),
            (dispatch_work, "pinned_local_endpoint_address", pinned),
            (urllib.request, "build_opener", build_opener),
            (urllib.request, "urlopen", self._refuse("urlopen")),
            (socket, "getaddrinfo", self._refuse("dns")),
            (socket, "create_connection", self._refuse("connect")),
            (socket.socket, "connect", self._refuse("socket_connect")),
            (subprocess, "Popen", self._refuse("subprocess")),
            (os, "system", self._refuse("system")),
        ):
            self._stack.enter_context(patch.object(target, name, replacement))
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stack.close()
        audit = self.tmp / "audit.jsonl"
        self.calls["audit_write"] = len(audit.read_text(encoding="utf-8").splitlines()) if audit.exists() else 0

    def outside(self) -> list[str]:
        return [path for path in self.writes if not Path(path).resolve().is_relative_to(self.tmp)]


class RouteTestCase(unittest.TestCase):
    """The wired route, enabled for this test only, with its ledger and audit log in the test's directory."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name).resolve()
        self.root = self.tmp / "ledger"
        self.enterContext(using_test_store(HostRecordStore.for_tests(self.tmp / 'host')))
        self.ledger_options: dict[str, Any] = {}
        for patcher in (
            patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True),
            patch.object(local_invocation, "open_ledger", lambda: InvocationLedger(self.root, **self.ledger_options)),
            patch.object(audit_lib, "AUDIT_LOG", self.tmp / "audit.jsonl"),
            patch.dict(os.environ, LOCAL_ENV, clear=False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def set_quota(self, quota: Any) -> None:
        controls = copy.deepcopy(load_contracting_controls())
        controls["quota_policy"]["local_worker_dispatches_per_epic"] = quota
        patcher = patch.object(local_invocation, "load_contracting_controls", return_value=controls)
        patcher.start()
        self.addCleanup(patcher.stop)

    def envelope(self, dispatch_id: str, *, epic: str | None = EPIC, task: str = TASK) -> tuple[dict, dict, Namespace]:
        from cwo_core.routing import classify_work

        route = classify_work(TASK, local_ok=True, prefer_local=True, local_profile="openshift-ai-vllm",
                              requested_roles=["documentation"])
        args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None, local_model=None,
                         execute_local=True)
        envelope = dispatch_work.build_local_envelope(task=task, route=route, dispatch_id=dispatch_id, bead_id="cwo-41",
                                                      epic_id=epic, args=args)
        return envelope, route, args

    def glm_envelope(self, dispatch_id: str) -> tuple[dict, dict, Namespace]:
        from cwo_core.routing import classify_work

        route = classify_work(GLM_TASK, local_ok=True, local_profile="openshift-ai-glm-256k",
                              requested_roles=["architecture"])
        args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url="http://127.0.0.1:8000",
                         local_model=None, local_allow_private_dns=False, local_ca_bundle=None, local_insecure_tls=False,
                         local_max_tokens=None, local_thinking="default", allow_offline_access_profile=True,
                         execute_local=True)
        envelope = dispatch_work.build_local_envelope(task="Compact independent architecture review.", route=route,
                                                      dispatch_id=dispatch_id, bead_id="cwo-41", epic_id=EPIC, args=args)
        return envelope, route, args

    def execute(self, built: tuple[dict, dict, Namespace], opener: Any = None,
                boundaries: Boundaries | None = None) -> tuple[Any, Boundaries]:
        """``execute_local_envelope`` with every boundary spied. Returns the result or the exception raised."""
        envelope, route, args = built
        boundaries = boundaries or Boundaries(self.tmp, opener)
        outcome: Any
        with boundaries:
            try:
                outcome = dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
            except BaseException as exc:  # noqa: BLE001 - the caller asserts on the exact exception
                outcome = exc
        return outcome, boundaries

    def run_cli(self, dispatch_id: str, opener: Any = None, *, epic: str = EPIC) -> tuple[Any, str, Boundaries]:
        argv = ["dispatch_work.py", TASK, "--local-ok", "--prefer-local", "--local-profile", "openshift-ai-vllm",
                "--requested-role", "documentation", "--json", "--execute-local", "--dispatch-id", dispatch_id,
                "--epic", epic]
        stdout = io.StringIO()
        boundaries = Boundaries(self.tmp, opener)
        outcome: Any = None
        with boundaries, patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            try:
                dispatch_work.main()
            except BaseException as exc:  # noqa: BLE001
                outcome = exc
        return outcome, stdout.getvalue(), boundaries

    def ledger(self) -> InvocationLedger:
        return InvocationLedger(self.root, **self.ledger_options)

    def attempts(self) -> list[dict[str, Any]]:
        path = self.root / "ledger.json"
        if not path.exists():
            return []
        document = json.loads(path.read_text(encoding="utf-8"))
        return sorted(document["attempts"].values(), key=lambda attempt: attempt["sequence"])

    def epic_budget(self) -> str:
        return local_invocation.local_http_budget(EPIC)[0]

    def assert_refused_with_zero_effects(self, outcome: Any, boundaries: Boundaries, *fragments: str,
                                         audit_lines: int = 0) -> None:
        self.assertIsInstance(outcome, SystemExit, repr(outcome))
        message = str(outcome.code)
        self.assertIn("controlled local invocation refused", message)
        for fragment in fragments:
            self.assertIn(fragment, message)
        self.assertEqual(dict(boundaries.calls), {**NO_EFFECTS, "audit_write": audit_lines})
        self.assertEqual(boundaries.outside(), [])
        if boundaries.opener is not None and hasattr(boundaries.opener, "requests"):
            self.assertEqual(boundaries.opener.requests, [])


class RouteRefusalsProduceZeroEffectsTests(RouteTestCase):
    """Negative regressions first: every refusal happens before resolution, the opener or any other effect."""


    def test_the_cli_entry_point_enforces_the_same_aggregate_and_writes_nothing_on_refusal(self) -> None:
        self.set_quota(1)
        opener = RecordingOpener()
        outcome, stdout, boundaries = self.run_cli("dispatch-cli-0", opener)
        self.assertIsNone(outcome, repr(outcome))
        self.assertEqual((len(opener.requests), boundaries.calls["audit_write"]), (1, 1))
        self.assertEqual(json.loads(stdout)["local_response"]["status_code"], 200)
        opener = RecordingOpener()
        outcome, stdout, boundaries = self.run_cli("dispatch-cli-1", opener)
        self.assert_refused_with_zero_effects(outcome, boundaries, "aggregate allowance exhausted", audit_lines=1)
        self.assertEqual(stdout, "")

    def test_requests_beyond_the_reservation_are_never_sent(self) -> None:
        envelope, _, _ = self.envelope("dispatch-gate")
        post = urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions", data=b'{"exact":true}',
                                      headers={"Content-Type": "application/json"}, method="POST")
        preflight = urllib.request.Request("http://127.0.0.1:8000/v1/models", method="GET")
        changed = urllib.request.Request(post.full_url, data=b'{"exact":false}', headers=dict(post.headers), method="POST")
        cases = (
            ("a second POST", None, [post, post], 1, "already sent once"),
            ("an unreserved preflight", None, [preflight], 0, "names no preflight"),
            ("the POST before the reserved preflight", preflight, [post], 0, "must be sent before the POST"),
            ("a changed POST", None, [changed], 0, "changed after it was reserved"),
        )
        for index, (label, reserved_preflight, sends, delivered, fragment) in enumerate(cases):
            with self.subTest(label):
                opener = RecordingOpener()
                envelope = dict(envelope, dispatch_id=f"dispatch-gate-{index}", epic_id=f"epic-gate-{index}")
                with self.assertRaises(SystemExit) as raised, Boundaries(self.tmp) as boundaries:
                    with local_invocation.reserved_local_invocation(envelope, post, reserved_preflight) as gate:
                        gate.bind(opener)
                        for req in sends:
                            gate.open(req, timeout=5)
                self.assertIn(fragment, str(raised.exception.code))
                self.assertIn("stays charged in full", str(raised.exception.code))
                self.assertEqual(len(opener.requests), delivered)
                self.assertEqual(boundaries.outside(), [])
                attempt = self.attempts()[-1]
                self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "unknown"))
                self.assertEqual(attempt["charge"], attempt["amount"])

    def test_retry_after_an_ambiguous_crash_is_refused_with_zero_effects(self) -> None:
        crashing = RecordingOpener(raises=KeyboardInterrupt())
        outcome, _ = self.execute(self.envelope("dispatch-crash"), crashing)
        self.assertIsInstance(outcome, KeyboardInterrupt)
        self.assertEqual(len(crashing.requests), 1)
        (crashed,) = self.attempts()
        self.assertEqual((crashed["state"], crashed["charge"]), ("reconciliation-required", {"attempts": 1, "requests": 1}))
        for label, built in (("the same dispatch", self.envelope("dispatch-crash")),
                             ("a new dispatch in the epic", self.envelope("dispatch-after-crash"))):
            with self.subTest(label):
                opener = RecordingOpener()
                outcome, boundaries = self.execute(built, opener)
                self.assert_refused_with_zero_effects(outcome, boundaries, "Nothing was sent")
        opener = RecordingOpener()
        # Keep the real causal refusal separate from the public outbound screen:
        # a random reservation ID can legitimately trigger entropy withholding.
        causes = []
        reserve = local_invocation._reserve

        def capture_refusal(*args: Any, **kwargs: Any) -> Any:
            try:
                return reserve(*args, **kwargs)
            except SystemExit as exc:
                causes.append(exc)
                raise

        with patch.object(local_invocation, "_reserve", capture_refusal):
            outcome, stdout, boundaries = self.run_cli("dispatch-cli-after-crash", opener)
        self.assertEqual(len(causes), 1)
        self.assert_refused_with_zero_effects(causes[0], boundaries, "blocks a blind retry")
        with self.assertRaises(SystemExit) as public:
            with dispatch_work.withheld_diagnostics("dispatch_work"):
                raise causes[0]
        self.assertIsInstance(outcome, SystemExit, repr(outcome))
        self.assertEqual(outcome.code, public.exception.code)
        self.assertEqual(stdout, "")
        # Another aggregate is unaffected; this one opens again only after reconciliation, still charged.
        other = RecordingOpener()
        outcome, _ = self.execute(self.envelope("dispatch-other-epic", epic="cwo-epic-other"), other)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.ledger().reconcile(crashed["attempt_id"], reason="operator: the endpoint log shows no request")
        retried = RecordingOpener()
        outcome, _ = self.execute(self.envelope("dispatch-after-reconcile"), retried)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.assertEqual(len(retried.requests), 1)
        outcome, boundaries = self.execute(self.envelope("dispatch-crash"), RecordingOpener())
        self.assert_refused_with_zero_effects(outcome, boundaries)
        self.assertEqual(self.ledger().summary(self.epic_budget())["charged"], {"attempts": 2, "requests": 2})


    def test_malformed_or_unknown_ledger_state_refuses_every_dispatch(self) -> None:
        outcome, _ = self.execute(self.envelope("dispatch-seed"), RecordingOpener())
        self.assertIsInstance(outcome, dict, repr(outcome))
        original = (self.root / "ledger.json").read_text(encoding="utf-8")
        document = json.loads(original)
        (attempt_id,) = document["attempts"]

        def mutated(change: Any) -> str:
            copy_ = json.loads(original)
            change(copy_)
            return json.dumps(copy_)

        cases = {
            "unknown state": mutated(lambda d: (d["attempts"][attempt_id].update(state="paused"),
                                                d["attempts"][attempt_id]["history"][-1].update(state="paused"))),
            "skipped transition": mutated(lambda d: d["attempts"][attempt_id]["history"].pop(1)),
            "lowered charge": mutated(lambda d: d["attempts"][attempt_id]["charge"].update(attempts=0)),
            "unknown version": mutated(lambda d: d.update(version=2)),
            "malformed JSON": original[:-10],
            "repeated key": original.replace('{"attempts":', '{"attempts":{},"attempts":', 1),
            "oversized timestamp": mutated(lambda d: d["attempts"][attempt_id].update(created_at=10**1000)),
            "oversized integer": original.replace('"sequence":1', '"sequence":' + "9" * 5000, 1),
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.assertNotEqual(text, original)
                (self.root / "ledger.json").write_text(text, encoding="utf-8")
                opener = RecordingOpener()
                outcome, boundaries = self.execute(self.envelope(f"dispatch-{label.replace(' ', '-')}"), opener)
                self.assert_refused_with_zero_effects(outcome, boundaries, "Nothing was sent")
                self.assertEqual((self.root / "ledger.json").read_text(encoding="utf-8"), text)
        (self.root / "ledger.json").write_text(original, encoding="utf-8")
        with self.subTest("budget limits changed by policy"):
            self.set_quota(3)
            opener = RecordingOpener()
            outcome, boundaries = self.execute(self.envelope("dispatch-new-limits"), opener)
            self.assert_refused_with_zero_effects(outcome, boundaries, "limits never change", "Nothing was sent")


    def test_overflow_inputs_refuse_before_any_effect(self) -> None:
        quotas = {"oversized quota": 10**1000, "quota past the unit bound": 2**52, "boolean quota": True,
                  "zero quota": 0, "text quota": "20"}
        for label, quota in quotas.items():
            with self.subTest(label):
                self.set_quota(quota)
                opener = RecordingOpener()
                outcome, boundaries = self.execute(self.envelope(f"dispatch-q-{len(label)}"), opener)
                self.assert_refused_with_zero_effects(outcome, boundaries, "local_worker_dispatches_per_epic")
                self.assertFalse((self.root / "ledger.json").exists())
        self.set_quota(2)
        for label, clock in (("oversized clock", lambda: 10**1000), ("infinite clock", lambda: float("inf")),
                             ("negative clock", lambda: -1.0)):
            with self.subTest(label):
                self.ledger_options = {"clock": clock}
                opener = RecordingOpener()
                outcome, boundaries = self.execute(self.envelope("dispatch-clock"), opener)
                self.assert_refused_with_zero_effects(outcome, boundaries, "clock returned an invalid time")
        self.ledger_options = {}

    def test_a_real_process_crash_after_intent_blocks_a_blind_retry(self) -> None:
        driver = self.tmp / "crash_driver.py"
        marker = self.tmp / "sent.log"
        driver.write_text(CRASH_DRIVER, encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if not key.startswith("CWO_")}
        env.update(LOCAL_ENV)
        env["CWO_AUDIT_FILE"] = str(self.tmp / "child-audit.jsonl")
        completed = subprocess.run(
            [sys.executable, "-I", str(driver), str(ROOT / "scripts"), str(self.root), str(marker), EPIC, TASK],
            capture_output=True, text=True, timeout=180, cwd=self.tmp, env=env)
        self.assertEqual(completed.returncode, 9, completed.stderr[-800:])
        self.assertEqual(len(marker.read_bytes().splitlines()), 1)
        (pending,) = self.attempts()
        self.assertEqual(pending["state"], "invocation-intent")
        opener = RecordingOpener()
        outcome, boundaries = self.execute(self.envelope("dispatch-after-real-crash"), opener)
        self.assert_refused_with_zero_effects(outcome, boundaries, "requires reconciliation", "blocks a blind retry")
        (marked,) = self.attempts()
        self.assertEqual((marked["state"], marked["charge"]), ("reconciliation-required", {"attempts": 1, "requests": 1}))

    def test_concurrent_double_reservation_sends_once(self) -> None:
        for label, second_dispatch, quota in (("same dispatch", "dispatch-race", 2),
                                              ("last attempt", "dispatch-race-other", 1)):
            with self.subTest(label):
                self.set_quota(quota)  # with room for two, only the one-use rule can refuse the same dispatch
                self.root = self.tmp / f"ledger-{second_dispatch}"
                first_inside, second_done = threading.Event(), threading.Event()

                def hold(_req: Any) -> None:
                    first_inside.set()
                    self.assertTrue(second_done.wait(60))

                opener = RecordingOpener(during=hold)
                results: dict[str, Any] = {}
                first_built = self.envelope("dispatch-race")
                second_built = self.envelope(second_dispatch)
                boundaries = Boundaries(self.tmp, opener)

                def call(name: str, built: tuple[dict, dict, Namespace]) -> None:
                    envelope, route, args = built
                    try:
                        results[name] = dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
                    except BaseException as exc:  # noqa: BLE001
                        results[name] = exc
                    finally:
                        if name == "second":
                            second_done.set()

                with boundaries:
                    first = threading.Thread(target=contextvars.copy_context().run, args=(call, "first", first_built))
                    first.start()
                    self.assertTrue(first_inside.wait(60))
                    second = threading.Thread(target=contextvars.copy_context().run, args=(call, "second", second_built))
                    second.start()
                    second.join(120)
                    first.join(120)
                self.assertIsInstance(results["first"], dict, repr(results["first"]))
                self.assertIsInstance(results["second"], SystemExit, repr(results["second"]))
                self.assertIn("Nothing was sent", str(results["second"].code))
                self.assertEqual(len(opener.requests), 1)
                self.assertEqual(boundaries.calls["resolve"], 1)
                self.assertEqual(boundaries.outside(), [])
                self.assertEqual([a["state"] for a in self.attempts()], ["terminal"])

    def test_exhausting_the_aggregate_budget_refuses_before_any_effect(self) -> None:
        self.set_quota(2)
        for index in range(2):
            opener = RecordingOpener()
            outcome, boundaries = self.execute(self.envelope(f"dispatch-agg-{index}"), opener)
            self.assertIsInstance(outcome, dict, repr(outcome))
            self.assertEqual(len(opener.requests), 1)
            self.assertEqual(boundaries.outside(), [])
        opener = RecordingOpener()
        outcome, boundaries = self.execute(self.envelope("dispatch-agg-2"), opener)
        self.assert_refused_with_zero_effects(outcome, boundaries, "aggregate allowance exhausted", "Nothing was sent")
        summary = self.ledger().summary(self.epic_budget())
        self.assertEqual(summary["charged"], {"attempts": 2, "requests": 2})
        self.assertEqual(summary["limits"], {"attempts": 2, "requests": 4})
        # A dispatch in another epic charges another aggregate and still proceeds.
        other = RecordingOpener()
        outcome, _ = self.execute(self.envelope("dispatch-agg-other", epic="cwo-epic-other"), other)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.assertEqual(len(other.requests), 1)


class RouteAccountingTests(RouteTestCase):
    """The connected path: one dispatch, one reservation, the exact reserved requests once, conservative charges."""

    def test_one_dispatch_sends_exactly_the_reserved_request_once_after_durable_intent(self) -> None:
        # Named row: shipped-hold-exact-envelope; stop before the positive if it fails.
        held_opener = RecordingOpener()
        held_envelope = self.envelope("dispatch-held-exact-envelope")
        with patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", False):
            held, held_boundaries = self.execute(held_envelope, held_opener)
        self.assertEqual(dict(held_boundaries.calls), NO_EFFECTS,
                         "shipped-hold-exact-envelope reached an effect")
        self.assertEqual(held_opener.requests, [])
        self.assertIsInstance(held, SystemExit)
        self.assertEqual(str(held), dispatch_work.LOCAL_INVOCATION_UNAVAILABLE)
        self.assertFalse(self.root.exists())
        observed: list[tuple[str, str, str | None]] = []
        opener = RecordingOpener(during=lambda req: boundaries.order.append("opener"))
        boundaries = Boundaries(self.tmp, opener)

        def observer(event: dict[str, Any]) -> None:
            stored = {a["attempt_id"]: a for a in self.attempts()}[event["attempt"]["attempt_id"]]
            observed.append((event["event"], stored["state"], event["detail"].get("kind")))
            boundaries.order.append(f"observer:{event['event']}")

        built = self.envelope("dispatch-one")
        with patch.object(local_invocation, "OBSERVERS", [observer]):
            outcome, _ = self.execute(built, boundaries=boundaries)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.assertEqual(outcome["status_code"], 200)
        # Intent is persisted and the observer notified before resolution, the first network effect.
        self.assertEqual(boundaries.order, ["observer:invocation-intent", "resolve", "build_opener", "observer:request",
                                            "opener", "observer:terminal"])
        self.assertEqual(observed[:2], [("invocation-intent", "invocation-intent", None),
                                        ("request", "invocation-intent", "post")])
        (sent,) = opener.requests
        envelope = built[0]
        body = json.loads(sent["body"])
        self.assertEqual((sent["method"], sent["url"]), ("POST", "http://127.0.0.1:8000/v1/chat/completions"))
        self.assertEqual(body["messages"], envelope["messages"])
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(sent["timeout"], int(envelope["timeout_seconds"]))
        (attempt,) = self.attempts()
        expected = {"post": {"method": "POST", "url": sent["url"],
                             "headers": sorted([k.lower(), v] for k, v in sent["headers"]),
                             "body_sha256": hashlib.sha256(sent["body"]).hexdigest(),
                             "body_bytes": len(sent["body"])},
                    "preflight": None}
        self.assertEqual(attempt["request_sha256"],
                         hashlib.sha256(local_invocation._canonical(expected)).hexdigest())
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "completed"))
        self.assertEqual((attempt["amount"], attempt["charge"], attempt["observed_usage"]),
                         ({"attempts": 1, "requests": 1},) * 3)
        self.assertEqual(attempt["observers"], [observer.__qualname__])
        self.assertEqual(attempt["request_id"], local_invocation.request_id_for(envelope))
        self.assertEqual(boundaries.outside(), [])

    def test_the_model_preflight_is_charged_to_the_same_allowance(self) -> None:
        opener = FakeHardenedOpener()
        outcome, boundaries = self.execute(self.glm_envelope("dispatch-glm"), opener)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.assertEqual(outcome["model_preflight"]["status"], "passed")
        self.assertTrue(opener.chat_called)
        (attempt,) = self.attempts()
        self.assertEqual((attempt["amount"], attempt["charge"]), ({"attempts": 1, "requests": 2},) * 2)
        self.assertEqual(attempt["observed_usage"], {"attempts": 1, "requests": 2})
        self.assertEqual(boundaries.outside(), [])

    def test_timeouts_and_failures_are_charged_in_full_and_do_not_block_later_dispatches(self) -> None:
        from urllib.error import HTTPError

        cases = (
            ("socket timeout", TimeoutError("timed out"), TimeoutError, "timeout"),
            ("urlopen timeout", URLError(TimeoutError("timed out")), SystemExit, "timeout"),
            ("connection refused", URLError(ConnectionRefusedError()), SystemExit, "unknown"),
            ("HTTP 500", HTTPError("http://127.0.0.1:8000/v1/chat/completions", 500, "error", {},
                                   io.BytesIO(b"{}")), SystemExit, "unknown"),
        )
        for index, (label, raised, expected_type, outcome_name) in enumerate(cases):
            with self.subTest(label):
                opener = RecordingOpener(raises=raised)
                outcome, boundaries = self.execute(self.envelope(f"dispatch-fail-{index}"), opener)
                self.assertIsInstance(outcome, expected_type, repr(outcome))
                if expected_type is TimeoutError:
                    self.assertIs(outcome, raised)
                self.assertEqual(len(opener.requests), 1)
                attempt = self.attempts()[-1]
                self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", outcome_name))
                self.assertEqual(attempt["charge"], {"attempts": 1, "requests": 1})
                self.assertEqual(boundaries.outside(), [])
        opener = RecordingOpener()
        outcome, _ = self.execute(self.envelope("dispatch-after-failures"), opener)
        self.assertIsInstance(outcome, dict, repr(outcome))
        self.assertEqual(self.ledger().summary(self.epic_budget())["charged"], {"attempts": 5, "requests": 5})


    def test_refusals_before_the_reservation_point_leave_the_ledger_untouched(self) -> None:
        envelope, route, args = self.envelope("dispatch-drifted")
        envelope["messages_sha256"] = "0" * 64  # drifted envelope: the binding check refuses before reserving
        opener = RecordingOpener()
        outcome, boundaries = self.execute((envelope, route, args), opener)
        self.assertIsInstance(outcome, SystemExit)
        self.assertEqual(dict(boundaries.calls), NO_EFFECTS)
        self.assertFalse(self.root.exists())


class ShippedGuardTests(unittest.TestCase):
    """The shipped state in fresh interpreters: every flag is off, and the route refuses before the ledger."""

    def test_f5_held_route_five_shipped_flags_are_off(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r}); "
             "import dispatch_work, chatgpt_browser_review, run_native_pool_activation_preview as preview; "
             "print(dispatch_work.LOCAL_INVOCATION_AVAILABLE, chatgpt_browser_review.BROWSER_DISPATCH_AVAILABLE, "
             "preview.live_availability.N1_LIVE_AVAILABLE, preview.live_availability.POOL_LIVE_AVAILABLE, "
             "preview.live_availability.CAMPAIGN_LIVE_AVAILABLE)"],
            capture_output=True, text=True, timeout=120, cwd=ROOT)
        self.assertEqual((completed.returncode, completed.stdout), (0, "False False False False False\n"), completed.stderr[-400:])

    def test_the_shipped_route_refuses_before_reserving_or_touching_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            env = {key: value for key, value in os.environ.items() if not key.startswith("CWO_")}
            env.update(LOCAL_ENV)
            env["CWO_INVOCATION_LEDGER_ROOT"] = str(tmp / "ledger")
            env["CWO_AUDIT_FILE"] = str(tmp / "audit.jsonl")
            for mode in ("function", "cli"):
                with self.subTest(mode=mode):
                    completed = subprocess.run(
                        [sys.executable, "-I", "-c", SHIPPED_DRIVER, str(ROOT / "scripts"), mode, TASK],
                        capture_output=True, text=True, timeout=180, cwd=tmp, env=env)
                    self.assertEqual(completed.returncode, 1, completed.stderr[-800:])
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(dispatch_work.LOCAL_INVOCATION_UNAVAILABLE, completed.stderr)
                    self.assertFalse((tmp / "ledger").exists())
                    self.assertFalse((tmp / "audit.jsonl").exists())

    def test_the_reservation_is_entered_only_inside_the_effect_function_after_the_flag_check(self) -> None:
        """Supporting static evidence: the reservation context is the only parent of resolution and the opener."""
        tree = ast.parse((ROOT / "scripts" / "dispatch_work.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "execute_local_envelope")
        first = function.body[0]
        self.assertIsInstance(first, ast.If)
        self.assertEqual(ast.unparse(first.test), "not LOCAL_INVOCATION_AVAILABLE")
        reservations = [node for node in function.body if isinstance(node, ast.With)
                        and ast.unparse(node.items[0].context_expr).startswith("_local_review_scope(")]
        self.assertEqual(len(reservations), 1)
        inside = {ast.unparse(node.func) for node in ast.walk(reservations[0]) if isinstance(node, ast.Call)}
        self.assertTrue({"pinned_local_endpoint_address", "_build_local_opener", "_preflight_local_model",
                         "opener.open"} <= inside)
        outside = [node for statement in function.body if statement is not reservations[0]
                   for node in ast.walk(statement) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) in {"pinned_local_endpoint_address", "_build_local_opener",
                                                  "_preflight_local_model", "opener.open"}]
        self.assertEqual(outside, [])
        callers = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   for call in ast.walk(node) if isinstance(call, ast.Call)
                   and ast.unparse(call.func) == "reserved_local_invocation"}
        self.assertEqual(callers, {"_local_review_scope"})


CRASH_DRIVER = """\
import os, sys
from pathlib import Path
from argparse import Namespace
from unittest.mock import patch
SCRIPTS, LEDGER, MARKER, EPIC, TASK = sys.argv[1:6]
sys.path.insert(0, SCRIPTS)
import dispatch_work
from cwo_core import local_invocation
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.routing import classify_work
from cwo_core.host_records import HostRecordStore, using_test_store
_host_scope = using_test_store(HostRecordStore.for_tests(Path(LEDGER).parent / 'child-host-records'))
_host_scope.__enter__()


class CrashingOpener:
    def open(self, req, **kwargs):
        with open(MARKER, "ab") as handle:
            handle.write(req.data + b"\\n")
        os._exit(9)


route = classify_work(TASK, local_ok=True, prefer_local=True, local_profile="openshift-ai-vllm",
                      requested_roles=["documentation"])
args = Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None, local_model=None, execute_local=True)
envelope = dispatch_work.build_local_envelope(task=TASK, route=route, dispatch_id="dispatch-real-crash",
                                              bead_id="cwo-41", epic_id=EPIC, args=args)
with patch.object(dispatch_work, "LOCAL_INVOCATION_AVAILABLE", True), \\
        patch.object(local_invocation, "open_ledger", lambda: InvocationLedger(LEDGER)), \\
        patch.object(dispatch_work.request, "build_opener", return_value=CrashingOpener()):
    dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
raise SystemExit("the crashing opener was not reached")
"""

SHIPPED_DRIVER = """\
import sys
SCRIPTS, MODE, TASK = sys.argv[1:4]
sys.path.insert(0, SCRIPTS)
import dispatch_work
from cwo_core.routing import classify_work
if MODE == "function":
    route = classify_work(TASK, local_ok=True, prefer_local=True, local_profile="openshift-ai-vllm",
                          requested_roles=["documentation"])
    args = dispatch_work.argparse.Namespace(local_api_key_env=None, local_timeout=None, local_base_url=None,
                                            local_model=None, execute_local=True)
    envelope = dispatch_work.build_local_envelope(task=TASK, route=route, dispatch_id="dispatch-shipped",
                                                  bead_id="cwo-41", epic_id="cwo-epic-41", args=args)
    dispatch_work.execute_local_envelope(envelope, route["selected_executor"], args)
else:
    sys.argv = ["dispatch_work.py", TASK, "--local-ok", "--prefer-local", "--local-profile", "openshift-ai-vllm",
                "--requested-role", "documentation", "--json", "--execute-local", "--epic", "cwo-epic-41"]
    dispatch_work.main()
"""


if __name__ == "__main__":
    unittest.main()
