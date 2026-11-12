"""Exercise the real admission, ledger, native host and original adapter offline."""
from __future__ import annotations

import copy
import inspect
import json
import os
import stat
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from itertools import product
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_admitted_n1 as client  # noqa: E402
import test_invocation_ledger as ledger_fixtures  # noqa: E402
import test_offline_n1_host as host_fixtures  # noqa: E402
import test_run_native_pool_live_canaries as live_fixtures  # noqa: E402
from test_local_admission_preparation import example_route  # noqa: E402
from test_route_feasibility_preparation import bind  # noqa: E402

native = client.native
admission = client.admission_api
ledger_api = admission.ledger_api
PINS = {"w14": "FAKE_CONFIGURATION_R1", "w15": "FAKE_PROFILE_R1"}


def _bind_fake_user_text(value, task):
    if type(value) is dict:
        if value.get("type") == "user_message":
            value["message"] = task
        if value.get("role") == "user":
            for item in value.get("content", []):
                if type(item) is dict and item.get("type") in ("input_text", "text"):
                    item["text"] = task
        for child in value.values():
            _bind_fake_user_text(child, task)
    elif type(value) is list:
        for child in value:
            _bind_fake_user_text(child, task)


class AdmittedFakeServer(host_fixtures.CompletingFakeServer):
    """Keep original fake tool evidence and bind its user records to the admitted task."""

    def __init__(self, root, worker, task):
        self.expected_task = task
        super().__init__(root, worker)

    def set_boundary(self, mode):
        result = super().set_boundary(mode)
        if mode != "valid":
            return result
        records = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]
        for record in records:
            _bind_fake_user_text(record, self.expected_task)
        self.path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return result

    def observe_intent(self, message):
        if message != self.expected_task:
            raise AssertionError("The fake send must receive the exact admitted task.")
        document = json.loads((self.ledger.root / ledger_api.LEDGER_FILE).read_bytes())
        matches = [value for value in document["attempts"].values()
                   if value["admission_sha256"] == admission._receipt_sha256(self.admission)]
        if len(matches) != 1 or matches[0]["state"] != "invocation-intent":
            raise AssertionError("The real ledger intent must precede the native fake send.")
        if matches[0]["observers"] != self.expected_observers:
            raise AssertionError("The real ledger must persist the actual observer names.")
        self.ledger_intent = copy.deepcopy(matches[0])
        super().observe_intent(message)


class RepositoryFixture:
    """Compose disposable repository helpers without inheriting their test cases."""

    git = host_fixtures.OfflineN1HostTests.git
    clone = host_fixtures.OfflineN1HostTests.clone

    def __init__(self, test):
        self.addCleanup = test.addCleanup
        self.assertIsNotNone = test.assertIsNotNone
        host_fixtures.OfflineN1HostTests.setUp(self)


class OfflineAdmittedN1Tests(unittest.TestCase):
    def setUp(self):
        self.repositories = RepositoryFixture(self)

    def storage_snapshot(self, roots):
        result = {}
        for root in roots:
            if not root.exists():
                result[str(root)] = None
                continue
            entries = {}
            for path in (root, *sorted(root.rglob("*"))):
                info = path.lstat()
                data = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
                entries[str(path.relative_to(root))] = (info.st_mode, data)
            result[str(root)] = entries
        return result

    def observe_diagnostics(self, observations, roots, original, *args):
        before = self.storage_snapshot(roots)
        with (
            host_fixtures.repository_write_boundaries(roots) as writes,
            patch.object(os, "chmod", wraps=os.chmod) as chmod,
            patch.object(os, "fchmod", wraps=os.fchmod) as fchmod,
            patch.object(os, "open", wraps=os.open) as opened,
        ):
            try:
                return original(*args)
            finally:
                names = {ledger_api.LEDGER_FILE, ledger_api.LOCK_FILE, "host.lock", "operation.json"}
                reads = [Path(os.fsdecode(call.args[0])).name for call in opened.call_args_list
                         if Path(os.fsdecode(call.args[0])).name in names]
                observations.append((
                    before, self.storage_snapshot(roots), list(writes),
                    chmod.call_count, fchmod.call_count, reads,
                ))

    def assert_diagnostic_boundaries(self, observations, *, readable):
        self.assertEqual(len(observations), 1)
        before, after, writes, chmods, fchmods, reads = observations[0]
        self.assertEqual(after, before)
        self.assertEqual(writes, [])
        self.assertEqual((chmods, fchmods), (0, 0))
        self.assertNotIn(ledger_api.LOCK_FILE, reads)
        if readable:
            self.assertIn(ledger_api.LEDGER_FILE, reads)
        else:
            self.assertEqual(reads, [])

    def diagnostic_fixture(self, kind):
        case = self.case(name="bounded-" + kind)
        case.ledger.root.mkdir(mode=0o750)
        path = case.ledger.root / ledger_api.LEDGER_FILE
        if kind == "fifo":
            os.mkfifo(path, 0o600)
        elif kind == "symlink":
            path.symlink_to(self.repositories.source / "seed.txt")
        elif kind == "special":
            path.mkdir()
        elif kind == "oversized":
            with path.open("wb") as stream:
                stream.truncate(client.reconciliation.MAX_BYTES + 1)
        else:
            path.write_bytes(json.dumps(ledger_api.empty_ledger()).encode("utf-8"))
        return case

    def bounded_diagnostic_control(self, kind):
        case = self.diagnostic_fixture(kind)
        original_invoke, original_diagnostics = client._INVOKE, client._diagnostics
        real_open, real_read, real_close, real_fstat = os.open, os.read, os.close, os.fstat
        roots = (case.ledger.root, case.host.state, case.host.target, case.host.worker)
        failures, observations, unsafe, forbidden = [], [], [], []
        flags_seen, opened, closed, read_sizes = [], [], [], []
        active = set()
        secondary = host_fixtures.FixtureCrash("FAKE secondary diagnostic interruption.")
        required = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        write_flags = os.O_CREAT | os.O_TRUNC | os.O_APPEND

        def open_file(path, flags, mode=0o777, *, dir_fd=None):
            if Path(os.fsdecode(path)).name != ledger_api.LEDGER_FILE:
                return real_open(path, flags, mode, dir_fd=dir_fd)
            flags_seen.append(flags)
            if (flags & required != required or flags & os.O_ACCMODE != os.O_RDONLY
                    or flags & write_flags):
                unsafe.append("open")
                raise OSError("FAKE unsafe diagnostic open was refused.")
            if kind == "unreadable":
                raise PermissionError("FAKE diagnostic file is unreadable.")
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(descriptor)
            active.add(descriptor)
            return descriptor

        def read_file(descriptor, size):
            if descriptor not in active:
                return real_read(descriptor, size)
            read_sizes.append(size)
            if not 0 < size <= client.reconciliation.MAX_BYTES + 1:
                unsafe.append("read")
                raise OSError("FAKE diagnostic read exceeded its bound.")
            if kind == "read-interruption":
                raise secondary
            if kind == "excess":
                return b" " * size
            value = real_read(descriptor, size)
            if kind == "binding":
                case.ledger.clock = object()
            return value

        def fstat_file(descriptor):
            info = real_fstat(descriptor)
            if descriptor in active:
                if kind == "wrong-owner":
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1)
                if kind == "file-identity" or (kind == "file-change" and read_sizes):
                    values = {name: getattr(info, name) for name in (
                        "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid")}
                    values["st_ino"] += 1
                    return SimpleNamespace(**values)
            return info

        def close_file(descriptor):
            if descriptor not in active:
                return real_close(descriptor)
            active.remove(descriptor)
            closed.append(descriptor)
            real_close(descriptor)
            if kind == "close-interruption":
                raise secondary

        def refuse_legacy(*_args, **_kwargs):
            forbidden.append(True)
            raise AssertionError("A diagnostic used a ledger lock or an unbounded file wrapper.")

        def invoke(*args, **kwargs):
            case.clock.now = case.receipt.expires_at
            try:
                return original_invoke(*args, **kwargs)
            except BaseException as failure:
                failures.append(failure)
                raise

        def diagnose(*args):
            with (
                patch.object(os, "open", side_effect=open_file),
                patch.object(os, "read", side_effect=read_file),
                patch.object(os, "fstat", side_effect=fstat_file),
                patch.object(os, "close", side_effect=close_file),
                patch.object(os, "fdopen", side_effect=refuse_legacy),
                patch.object(native.fcntl, "flock", side_effect=refuse_legacy),
            ):
                return self.observe_diagnostics(observations, roots, original_diagnostics, *args)

        with (
            patch.object(client, "_INVOKE", side_effect=invoke),
            patch.object(client, "_diagnostics", side_effect=diagnose),
        ):
            with self.assertRaisesRegex(admission.AdmissionError, "expired") as raised:
                self.run_case(case)
        self.assertEqual(len(failures), 1)
        self.assertIs(raised.exception, failures[0])
        self.assert_diagnostic_boundaries(observations, readable=True)
        self.assertEqual(len(flags_seen), 1)
        self.assertFalse(unsafe)
        self.assertFalse(forbidden)
        self.assertFalse(active)
        self.assertEqual(len(opened), len(closed))
        self.assertTrue(all(closed.count(descriptor) == 1 for descriptor in opened))
        for descriptor in opened:
            with self.assertRaises(OSError):
                real_fstat(descriptor)
        expected_read = kind in (
            "valid", "excess", "file-change", "binding", "read-interruption", "close-interruption")
        self.assertEqual(len(read_sizes), int(expected_read))
        self.assertLessEqual(sum(read_sizes), client.reconciliation.MAX_BYTES + 1)
        if kind == "valid":
            self.assertEqual(len(raised.exception.ledger_attempts), 0)
        else:
            self.assertFalse(hasattr(raised.exception, "ledger_attempts"))
        self.assertFalse((case.ledger.root / ledger_api.LOCK_FILE).exists())
        self.assertFalse((case.host.state / "operation.json").exists())
        self.assertEqual(case.server.sends, 0)
        self.assertEqual(case.adapter.callback_latencies, {})

    def test_pre_storage_expiry_diagnostics_refuse_unsafe_files(self):
        for kind in ("fifo", "symlink", "wrong-owner", "special", "unreadable", "oversized"):
            with self.subTest(kind=kind):
                self.bounded_diagnostic_control(kind)

    def test_diagnostic_read_bounds_identity_and_secondary_interruptions(self):
        for kind in ("valid", "excess", "file-identity", "file-change", "binding",
                     "read-interruption", "close-interruption"):
            with self.subTest(kind=kind):
                self.bounded_diagnostic_control(kind)

    def test_overlapping_original_ledgers_refuse_without_storage_writes(self):
        for name, valid, mode in product(("target", "worker", "state"), (True, False), (0o750, 0o755)):
            with self.subTest(root=name, valid=valid, mode=mode):
                case = self.case(name=f"refused-{name}-{valid}-{mode:o}")
                root = getattr(case.host, name)
                raw = json.dumps(ledger_api.empty_ledger()).encode("utf-8") if valid else b"{"
                (root / ledger_api.LEDGER_FILE).write_bytes(raw)
                root.chmod(mode)
                rejected = ledger_api.InvocationLedger(root, clock=case.clock, owner_probe=case.owners)
                roots = (case.host.target, case.host.worker, case.host.state, case.ledger.root)
                before = self.storage_snapshot(roots)
                with (
                    host_fixtures.repository_write_boundaries(roots) as writes,
                    patch.object(os, "chmod", wraps=os.chmod) as chmod,
                    patch.object(os, "fchmod", wraps=os.fchmod) as fchmod,
                    patch.object(client, "_diagnostics", wraps=client._diagnostics) as diagnostics,
                ):
                    with self.assertRaises(native.OfflineHostError):
                        self.run_case(case, ledger=rejected)
                diagnostics.assert_not_called()
                self.assertEqual(self.storage_snapshot(roots), before)
                self.assertEqual(writes, [])
                chmod.assert_not_called()
                fchmod.assert_not_called()
                self.assertEqual((root / ledger_api.LEDGER_FILE).read_bytes(), raw)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), mode)
                self.assertFalse((root / ledger_api.LOCK_FILE).exists())
                self.assertEqual(case.adapter.callback_latencies, {})
                self.assertEqual(case.server.sends, 0)

    def test_observer_failures_retain_read_only_ledger_diagnostics(self):
        failures = (RuntimeError("FAKE_OBSERVER_FAILURE"), StopIteration("FAKE_OBSERVER_STOP"),
                    host_fixtures.FixtureCrash("FAKE_OBSERVER_INTERRUPTION"))
        original = client._diagnostics
        for index, failure in enumerate(failures):
            case = self.case(name=f"diagnostics-{index}")
            observations = []
            roots = (case.ledger.root, case.host.state, case.host.target, case.host.worker)

            def observer(event):
                if event["event"] == "invocation-intent":
                    raise failure

            def diagnose(*args):
                return self.observe_diagnostics(observations, roots, original, *args)

            case.server.expected_observers = [observer.__qualname__]
            with patch.object(client, "_diagnostics", side_effect=diagnose):
                with self.assertRaises(type(failure)) as raised:
                    self.run_case(case, observer=observer)
            self.assertIs(raised.exception, failure)
            self.assert_diagnostic_boundaries(observations, readable=True)
            current = self.assert_charged(case)
            self.assertEqual(failure.ledger_attempts, [current])
            expected = "terminal" if isinstance(failure, Exception) else "reconciliation-required"
            self.assertEqual(current["state"], expected)
            self.assertEqual(case.server.sends, 0)
            self.assertEqual(case.adapter.callback_latencies, {})

    def test_failure_binding_drift_skips_diagnostic_data_reads_and_writes(self):
        original_invoke, original_diagnostics = client._INVOKE, client._diagnostics
        for mutation in ("root", "clock", "owner_probe", "_fsync", "_locked", "state", "target", "worker"):
            case = self.case(name="drift-" + mutation)
            failure = host_fixtures.FixtureCrash("FAKE_OBSERVER_BINDING_FAILURE")
            replacement = self.repositories.root / ("FAKE_REJECTED_ROOT_" + mutation)
            replacement.mkdir(mode=0o750)
            (replacement / ledger_api.LEDGER_FILE).write_bytes(b"{")
            original_root = case.ledger.root
            roots = (original_root, replacement, case.host.state, case.host.target, case.host.worker)
            observations = []

            def change_binding():
                if mutation in ("state", "target", "worker"):
                    setattr(case.host, mutation, replacement)
                else:
                    values = {"root": replacement, "clock": object(), "owner_probe": object(),
                              "_fsync": object(), "_locked": object()}
                    setattr(case.ledger, mutation, values[mutation])

            def observer(event):
                if event["event"] == "invocation-intent":
                    if mutation in ("state", "target", "worker"):
                        change_binding()
                    raise failure

            def invoke(*args, **kwargs):
                try:
                    return original_invoke(*args, **kwargs)
                except BaseException:
                    if mutation not in ("state", "target", "worker"):
                        change_binding()
                    raise

            def diagnose(*args):
                return self.observe_diagnostics(observations, roots, original_diagnostics, *args)

            case.server.expected_observers = [observer.__qualname__]
            with (
                patch.object(client, "_INVOKE", side_effect=invoke),
                patch.object(client, "_diagnostics", side_effect=diagnose),
            ):
                with self.assertRaises(host_fixtures.FixtureCrash) as raised:
                    self.run_case(case, observer=observer)
            self.assertIs(raised.exception, failure)
            self.assert_diagnostic_boundaries(observations, readable=False)
            self.assertFalse(hasattr(failure, "ledger_attempts"))
            document = json.loads((original_root / ledger_api.LEDGER_FILE).read_bytes())
            attempts = list(document["attempts"].values())
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["state"], "reconciliation-required")
            self.assertEqual(attempts[0]["charge"], json.loads(case.receipt.amounts_bytes))
            self.assertEqual((replacement / ledger_api.LEDGER_FILE).read_bytes(), b"{")
            self.assertFalse((replacement / ledger_api.LOCK_FILE).exists())
            self.assertEqual(case.adapter.callback_latencies, {})
            self.assertEqual(case.server.sends, 0)

    def test_terminal_observer_drift_retains_the_known_native_report(self):
        case = self.case()
        original_state = case.host.state
        replacement = self.repositories.root / "FAKE_CHANGED_HOST_STATE"
        replacement.mkdir()
        roots = (case.ledger.root, original_state, case.host.target, case.host.worker, replacement)
        observations = []
        failure = host_fixtures.FixtureCrash("FAKE_TERMINAL_OBSERVER_INTERRUPTION")
        original = client._diagnostics

        def observer(event):
            if event["event"] == "terminal":
                case.host.state = replacement
                raise failure

        def diagnose(*args):
            return self.observe_diagnostics(observations, roots, original, *args)

        case.server.expected_observers = [observer.__qualname__]
        with patch.object(client, "_diagnostics", side_effect=diagnose):
            with self.assertRaises(host_fixtures.FixtureCrash) as raised:
                self.run_case(case, observer=observer)
        self.assertIs(raised.exception, failure)
        self.assert_diagnostic_boundaries(observations, readable=False)
        report = native._validate_record(json.loads((original_state / "operation.json").read_bytes()))
        self.assertEqual(failure.native_report, report)
        self.assertEqual(self.assert_charged(case)["outcome"], "completed")
        self.assertEqual(case.server.sends, 1)

    def test_diagnostic_interruption_preserves_the_failure_and_known_report(self):
        case = self.case()
        failure = host_fixtures.FixtureCrash("FAKE_PRIMARY_OBSERVER_INTERRUPTION")
        secondary = host_fixtures.FixtureCrash("FAKE_SECONDARY_DIAGNOSTIC_INTERRUPTION")

        def observer(event):
            if event["event"] == "terminal":
                raise failure

        case.server.expected_observers = [observer.__qualname__]
        with patch.object(client, "_diagnostics", side_effect=secondary) as diagnostics:
            with self.assertRaises(host_fixtures.FixtureCrash) as raised:
                self.run_case(case, observer=observer)
        self.assertIs(raised.exception, failure)
        diagnostics.assert_called_once()
        self.assertEqual(failure.native_report, case.host.status("FAKE_OPERATION"))
        self.assertEqual(self.assert_charged(case)["outcome"], "completed")
        self.assertEqual(case.server.sends, 1)

    def test_exact_successful_entry_return_interruption_releases_its_token(self):
        case = self.case()
        claim = client._ClientClaim(case.host, case.adapter)
        self.addCleanup(claim._release, None)
        before = dict(client._CLIENT_CLAIMS)
        lines, start = inspect.getsourcelines(client._ClientClaim.__enter__)
        target = start + next(index for index, line in enumerate(lines) if line.strip() == "return self")
        failure = KeyboardInterrupt("FAKE_SUCCESSFUL_ENTRY_RETURN_INTERRUPTION")
        previous = sys.gettrace()
        injected = []

        def trace(frame, event, _argument):
            if (frame.f_code is client._ClientClaim.__enter__.__code__
                    and event == "line" and frame.f_lineno == target):
                injected.append(True)
                raise failure
            return trace

        try:
            sys.settrace(trace)
            with self.assertRaises(KeyboardInterrupt) as raised:
                claim.__enter__()
        finally:
            sys.settrace(previous)
        self.assertIs(sys.gettrace(), previous)
        self.assertEqual(injected, [True])
        self.assertIs(raised.exception, failure)
        self.assertEqual(client._CLIENT_CLAIMS, before)
        with client._ClientClaim(case.host, case.adapter) as subsequent:
            self.assertTrue(all(client._CLIENT_CLAIMS.get(key) is subsequent._token for key in subsequent._keys))
        self.assertEqual(client._CLIENT_CLAIMS, before)
        self.assertTrue(self.run_case(case)["offline_completed"])
        self.assertEqual(case.server.sends, 1)

    def test_state_keys_refuse_a_different_original_adapter_and_fake_server(self):
        case = self.case()
        other = self.case(name="independent-state-control")
        other_host = native.OfflineN1Host(case.host.state, case.host.target, case.host.worker)
        self.assertIsNot(other.adapter, case.adapter)
        self.assertIsNot(other.server, case.server)
        before = dict(client._CLIENT_CLAIMS)
        with client._ClientClaim(case.host, case.adapter) as winner:
            candidate_keys, _server = client._claim_keys(other_host, other.adapter)
            overlap = set(winner._keys).intersection(candidate_keys)
            self.assertEqual({key[0] for key in overlap}, {"state-path", "state-identity"})
            with patch.object(client, "_adapter_snapshot", side_effect=AssertionError("A losing state claim probed the adapter.")):
                with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy"):
                    self.run_case(other, host=other_host)
            self.assertTrue(all(client._CLIENT_CLAIMS.get(key) is winner._token for key in winner._keys))
            self.assertIsNone(self.disk(other))
            self.assertEqual(other.adapter.callback_latencies, {})
            self.assertEqual(other.server.sends, 0)
        self.assertEqual(client._CLIENT_CLAIMS, before)
        self.assertTrue(self.run_case(case)["offline_completed"])
        self.assertEqual(case.server.sends, 1)

    def case(self, name="fake", mode="complete", *, node_id="plan"):
        repositories = self.repositories
        target, worker = repositories.clone("target-" + name), repositories.clone("worker-" + name)
        state = repositories.root / ("state-" + name)
        state.mkdir()
        records = state / "records"
        records.mkdir()
        clock, owners = ledger_fixtures.FakeClock(), ledger_fixtures.FakeOwners()
        store = ledger_api.InvocationLedger(repositories.root / ("ledger-" + name), clock=clock, owner_probe=owners)
        route = example_route(alternatives=True)
        receipt = admission.prepare(route, node_id, now=clock.now, expires_at=clock.now + 60)
        task = receipt.request_bytes.decode("utf-8")
        server = AdmittedFakeServer(state / "fake-server", worker, task)
        server.mode = mode
        server.ledger, server.admission = store, receipt
        server.expected_observers, server.ledger_intent = [], None
        policy = {
            "minimum_tool_calls": 1,
            "required_evidence": {
                "predicates": ["trusted-terminal-boundary", "trusted-tool-call", "expected-workspace-mutation"],
                "sha256": [],
            },
            "allow_zero_tool_completion": False, "expected_mutation_mode": "mutable-isolated",
        }
        adapter = native.LiveThreadAdapter(
            server, server.thread_response(mutable=True), prompt=task, expected_token=host_fixtures.TOKEN,
            worktree=worker, mutable=True, expected_mutation="result.txt",
            completion_evidence_policy=policy, record_dir=records, campaign_live_route=False,
        )
        boundary = live_fixtures.LiveThreadBoundaryPhaseTests.controller_bind_and_arm(object(), adapter, arm=False)
        control = copy.deepcopy(boundary["control_contract"])
        host = native.OfflineN1Host(state, target, worker)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})
        self.assertFalse(store.root.exists())
        return SimpleNamespace(
            host=host, adapter=adapter, server=server, control=control, receipt=receipt, route=route,
            ledger=store, clock=clock, owners=owners, pins=dict(PINS), outputs=["result.txt"],
            node_id=node_id,
        )

    def run_case(self, case, **changes):
        values = {
            "ledger": case.ledger, "host": case.host, "adapter": case.adapter, "contract": case.control,
            "operation_id": "FAKE_OPERATION", "outputs": case.outputs, "max_steps": 128,
            "configuration_pins": case.pins,
        }
        values.update(changes)
        return client.run_offline_admitted_n1(case.receipt, case.route, case.node_id, **values)

    def disk(self, case):
        path = case.ledger.root / ledger_api.LEDGER_FILE
        return path.read_bytes() if path.exists() else None

    def attempt(self, case):
        values = json.loads(self.disk(case))["attempts"]
        self.assertEqual(len(values), 1)
        return next(iter(values.values()))

    def assert_charged(self, case):
        attempt = self.attempt(case)
        amount = json.loads(case.receipt.amounts_bytes)
        self.assertEqual(set(amount), set(admission.planner.RESOURCES))
        self.assertEqual(attempt["amount"], amount)
        self.assertEqual(attempt["charge"], amount)
        self.assertEqual(attempt["charge"], ledger_api.derived_charge(attempt))
        self.assertIsNone(attempt["observed_usage"])
        return attempt

    def assert_refused(self, case, **changes):
        before = self.disk(case)
        with patch.object(case.server, "start_turn", wraps=case.server.start_turn) as send:
            with self.assertRaises((ValueError, TypeError)):
                self.run_case(case, **changes)
        send.assert_not_called()
        self.assertEqual(case.server.sends, 0)
        self.assertEqual(case.adapter.callback_latencies, {})
        self.assertEqual(self.disk(case), before)
        self.assertFalse((case.host.state / "operation.json").exists())

    def test_exact_task_real_durable_order_and_full_conservative_accounting(self):
        case = self.case()
        events = []

        def observer(event):
            events.append(event["event"])
            stored = case.ledger.attempt(event["attempt"]["reservation_id"])
            self.assertEqual(stored, event["attempt"])
            if event["event"] == "invocation-intent":
                self.assertFalse((case.host.state / "operation.json").exists())

        case.server.expected_observers = [observer.__qualname__]
        with patch.object(case.server, "start_turn", wraps=case.server.start_turn) as send:
            with host_fixtures.repository_write_boundaries((case.host.target,)) as writes:
                result = self.run_case(case, observer=observer)
        self.assertEqual(writes, [])
        send.assert_called_once_with(case.adapter.thread_id, case.receipt.request_bytes.decode("utf-8"))
        self.assertEqual(events, ["invocation-intent", "terminal"])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(case.server.ledger_intent["state"], "invocation-intent")
        self.assertEqual(case.server.intent_observed["status"], "reconciliation-required")
        self.assertIsNone(case.server.intent_observed["receipt"])
        self.assertIsNone(case.server.intent_observed["artifact"])
        report = result["native_report"]
        self.assertIs(result["offline_completed"], True)
        self.assertEqual(report, case.host.status("FAKE_OPERATION"))
        self.assertEqual(report["binding"]["task"].encode("utf-8"), case.receipt.request_bytes)
        self.assertEqual(result["declared_execution"], json.loads(case.receipt.execution_bytes))
        self.assertEqual(result["declared_execution"]["options"], case.route["nodes"][0]["execution"]["options"])
        self.assertEqual(report["binding"]["max_steps"], 128)
        self.assertEqual(report["binding"]["outputs"], ["result.txt"])
        self.assertEqual(report["binding"]["configuration_pins"], PINS)
        self.assertEqual(report["binding"]["contract"], case.control)
        self.assertEqual(report["receipt"]["terminal_state"], "completed")
        self.assertEqual(report["receipt"]["actions"][-1], "close")
        self.assertTrue(case.server.archived and case.adapter.archived)
        self.assertEqual(report["summary"]["completed_tool_calls"], 1)
        self.assertTrue(result["artifact_verification"]["valid"])
        self.assertEqual(result["native_receipt"], report["receipt"])
        self.assertEqual(result["artifact"], report["artifact"])
        self.assertEqual((case.host.state / "artifact" / "file-0000").read_bytes(), host_fixtures.OUTPUT)
        self.assertEqual(result["attempt"], self.assert_charged(case))
        self.assertEqual(result["admission_sha256"], admission._receipt_sha256(case.receipt))
        self.assertEqual(result["scope_sha256"], case.receipt.scope_sha256)
        self.assertEqual(result["request_sha256"], result["attempt"]["request_sha256"])
        self.assertEqual(result["budget_id"], result["attempt"]["budget_id"])
        self.assertEqual(result["declared_allowance"], result["attempt"]["amount"])
        self.assertEqual(result["declared_aggregate_limits"], case.route["limits"])
        self.assertEqual(result["attempt"]["admission_sha256"], result["admission_sha256"])
        self.assertIsNone(result["effective_backend_metadata"])
        self.assertIs(result["effective_backend_metadata_supported"], False)
        for field in client.FALSE_FIELDS:
            self.assertIs(result[field], False)
        for observation in (report, result["artifact_verification"]):
            for field in native._FLAGS_FALSE:
                self.assertIs(observation[field], False)

    def test_all_caller_records_are_frozen_before_observation(self):
        case = self.case()
        expected = copy.deepcopy(case.control)

        def observer(event):
            if event["event"] == "invocation-intent":
                case.control["allowed_actions"].clear()
                case.outputs.clear()
                case.pins["w14"] = "FAKE_CHANGED_CONFIGURATION"
                case.route["nodes"].clear()

        case.server.expected_observers = [observer.__qualname__]
        result = self.run_case(case, observer=observer)
        self.assertEqual(result["native_report"]["binding"]["contract"], expected)
        self.assertEqual(result["native_report"]["binding"]["configuration_pins"], PINS)
        self.assertEqual(result["native_report"]["binding"]["outputs"], ["result.txt"])
        self.assertEqual(case.server.sends, 1)

    def test_wrong_task_adapter_worktree_and_original_methods_refuse(self):
        case = self.case()
        prompt = case.adapter.prompt
        case.adapter.prompt = "FAKE_WRONG_TASK"
        self.assert_refused(case)
        case.adapter.prompt = prompt
        worker = case.adapter.worktree
        case.adapter.worktree = case.host.target
        self.assert_refused(case)
        case.adapter.worktree = worker
        case.adapter.send_input = lambda **_values: {"submission_id": "FAKE_FORGED"}
        self.assert_refused(case)
        del case.adapter.send_input
        self.assert_refused(case, host={})
        self.assert_refused(case, adapter={})
        self.assert_refused(case, ledger={})
        self.assert_refused(case, task="FAKE_TASK_OVERRIDE")
        self.assert_refused(case, effect=lambda *_values: None)
        self.assert_refused(case, usage={})

    def test_contract_configuration_and_bounds_refuse_before_writes(self):
        case = self.case()
        changed = copy.deepcopy(case.control)
        changed["control_turn_id"] = "FAKE_CHANGED_CONTROL"
        changed["contract_sha256"] = native._digest({key: value for key, value in changed.items()
                                                   if key != "contract_sha256"})
        self.assert_refused(case, contract=changed)
        for pins in ({}, {**PINS, "extra": "FAKE_EXTRA"}, {**PINS, "w15": False}):
            self.assert_refused(case, configuration_pins=pins)
        for outputs in ([], ["../escape"], [".git/HEAD"], ["result.txt", "result.txt"]):
            self.assert_refused(case, outputs=outputs)
        for steps in (0, True, native.MAX_STEPS + 1):
            self.assert_refused(case, max_steps=steps)

    def test_expiry_and_adapter_drift_during_observation_never_send(self):
        for mutation in ("expiry", "adapter"):
            case = self.case(name=mutation)

            def observer(event):
                if event["event"] == "invocation-intent":
                    if mutation == "expiry":
                        case.clock.now = case.receipt.expires_at
                    else:
                        case.adapter.worktree = case.host.target

            case.server.expected_observers = [observer.__qualname__]
            with patch.object(case.server, "start_turn", wraps=case.server.start_turn) as send:
                with self.assertRaises(ValueError):
                    self.run_case(case, observer=observer)
            send.assert_not_called()
            self.assertEqual(case.server.sends, 0)
            self.assert_charged(case)
            self.assertFalse((case.host.state / "operation.json").exists())

    def current_gate_delay_control(self, stage, remaining):
        case = self.case(name=f"current-gate-{stage}-{remaining}")
        original_graph = admission._graph_state
        current_attempts, advanced = [], []
        state = {"armed": False}

        def graph(receipt, prior, store, current_attempt_id=None):
            if current_attempt_id is not None:
                current_attempts.append(current_attempt_id)
                state["armed"] = len(current_attempts) == 2
            return original_graph(receipt, prior, store, current_attempt_id)

        def delayed(read, label):
            def checked(*args, **kwargs):
                value = read(*args, **kwargs)
                if state["armed"] and label == stage and not advanced:
                    self.assertLess(case.clock.now, case.receipt.expires_at)
                    case.clock.now = case.receipt.expires_at - remaining
                    advanced.append(label)
                return value
            return checked

        with ExitStack() as stack:
            graph_gate = stack.enter_context(patch.object(admission, "_graph_state", side_effect=graph))
            deadlines = stack.enter_context(patch.object(
                admission, "_final_deadlines", wraps=admission._final_deadlines))
            for target, name, label in (
                    (case.owners, "status", "status"), (case.owners, "current", "owner"),
                    (ledger_api, "_charged_totals", "charge"), (admission, "_read_policy_bytes", "policy")):
                stack.enter_context(patch.object(
                    target, name, side_effect=delayed(getattr(target, name), label)))
            if remaining:
                result = self.run_case(case)
                self.assertIs(result["offline_completed"], True)
                self.assertTrue(result["artifact_verification"]["valid"])
            else:
                with self.assertRaisesRegex(admission.AdmissionError, "expired"):
                    self.run_case(case)
            self.assertEqual(graph_gate.call_count, 3)
            self.assertEqual(deadlines.call_count, 2)
        self.assertEqual(len(current_attempts), 2)
        current = self.assert_charged(case)
        self.assertTrue(all(value == current["attempt_id"] for value in current_attempts))
        self.assertNotEqual(current["attempt_id"], current["reservation_id"])
        self.assertEqual(advanced, [stage])
        self.assertEqual(current["outcome"], "completed" if remaining else "unknown")
        self.assertEqual(case.server.sends, int(bool(remaining)))
        if not remaining:
            self.assertEqual(case.adapter.callback_latencies, {})
            self.assertFalse((case.host.state / "operation.json").exists())

    def test_current_graph_gate_checks_expiry_after_owner_and_accounting_delays(self):
        for stage, remaining in product(("status", "owner", "charge", "policy"), (0, 1)):
            with self.subTest(stage=stage, remaining=remaining):
                self.current_gate_delay_control(stage, remaining)

    def test_nonprimary_nodes_and_prior_mappings_refuse_before_storage(self):
        for node_id in ("review", "retry", "fallback", "sibling"):
            case = self.case(name="unsupported-" + node_id)
            receipt = admission.prepare(
                case.route, node_id, now=case.clock.now,
                expires_at=case.clock.now + 60)
            with patch.object(
                    client, "_native_gate", side_effect=AssertionError("An unsupported graph node reached native preflight.")):
                with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "only a primary"):
                    client.run_offline_admitted_n1(
                        receipt, case.route, node_id, ledger=case.ledger,
                        host=case.host, adapter=case.adapter,
                        contract=case.control, operation_id="FAKE_OPERATION", outputs=case.outputs,
                        max_steps=128, configuration_pins=case.pins)
            self.assertFalse(case.ledger.root.exists())
            self.assertFalse((case.host.state / "operation.json").exists())
            self.assertEqual(case.server.sends, 0)
            self.assertEqual(case.adapter.callback_latencies, {})
        self.assert_refused(
            self.case(name="unsupported-mapping"),
            node_attempts={"plan": "FAKE_SELECTED_ATTEMPT"})

    def test_exhausted_whole_route_aggregate_never_reaches_the_native_host(self):
        case = self.case()
        limits = json.loads(case.receipt.limits_bytes)
        case.ledger.open_budget(case.receipt.budget_id, limits, scope_sha256=case.receipt.scope_sha256)
        case.ledger.reserve(
            budget_id=case.receipt.budget_id, request_id="FAKE_BLOCKER",
            request_sha256=ledger_api.request_sha256(b"FAKE_BLOCKER_REQUEST"),
            admission_sha256=ledger_api.request_sha256(b"FAKE_BLOCKER_ADMISSION"),
            amount=limits, expires_at=case.receipt.expires_at,
        )
        self.assert_refused(case)
        self.assertEqual(case.ledger.summary(case.receipt.budget_id)["charged"], limits)

    def test_native_failures_keep_original_diagnostics_and_full_charges(self):
        for mode in ("failure", "unclosed", "pending", "bad-token", "missing-tool-receipt", "partial-tail"):
            case = self.case(name=mode, mode=mode)
            with self.assertRaises(client.OfflineAdmittedN1Error) as raised:
                self.run_case(case, max_steps=8 if mode == "pending" else 128)
            self.assertEqual(case.server.sends, 1)
            self.assertEqual(raised.exception.native_report, case.host.status("FAKE_OPERATION"))
            self.assertEqual(raised.exception.native_report["status"], "reconciliation-required")
            self.assertIsNone(raised.exception.native_report["artifact"])
            self.assertEqual(self.assert_charged(case)["outcome"], "unknown")
            before = self.disk(case)
            with self.assertRaises(ValueError):
                self.run_case(case)
            self.assertEqual(self.disk(case), before)
            self.assertEqual(case.server.sends, 1)

    def test_terminal_observer_artifact_drift_cannot_return_offline_completed(self):
        case = self.case()

        def observer(event):
            if event["event"] == "terminal":
                blob = case.host.state / "artifact" / "file-0000"
                blob.chmod(0o600)
                blob.write_bytes(b"FAKE_ARTIFACT_DRIFT\n")
                blob.chmod(0o400)

        case.server.expected_observers = [observer.__qualname__]
        with self.assertRaises(client.OfflineAdmittedN1Error) as raised:
            self.run_case(case, observer=observer)
        self.assertFalse(raised.exception.verification["valid"])
        self.assertEqual(self.assert_charged(case)["outcome"], "completed")
        self.assertEqual(case.server.sends, 1)

    def test_replays_never_reserve_again_or_send_again(self):
        case = self.case()
        self.run_case(case)
        before = self.disk(case)
        mutations = ({}, {"operation_id": "FAKE_OTHER_OPERATION"},
                     {"configuration_pins": {**PINS, "w15": "FAKE_OTHER_PROFILE"}}, {"max_steps": 127})
        for changes in mutations:
            with self.assertRaises(ValueError):
                self.run_case(case, **changes)
            self.assertEqual(self.disk(case), before)
        case.receipt = replace(case.receipt, expires_at=case.receipt.expires_at + 1)
        with self.assertRaises(ValueError):
            self.run_case(case)
        self.assertEqual(self.disk(case), before)
        self.assertEqual(case.server.sends, 1)

    def test_concurrent_admission_and_operation_claims_send_at_most_once(self):
        case = self.case()
        entered, release = threading.Event(), threading.Event()

        def pause():
            entered.set()
            if not release.wait(10):
                raise RuntimeError("The fake send wait exceeded its bound.")

        case.server.on_send = pause
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(self.run_case, case)
            self.assertTrue(entered.wait(10))
            try:
                before = self.disk(case)
                for changes in ({}, {"operation_id": "FAKE_COMPETING_OPERATION"}):
                    with self.assertRaises(ValueError):
                        self.run_case(case, **changes)
                self.assertEqual(self.disk(case), before)
            finally:
                release.set()
            self.assertTrue(running.result(timeout=20)["offline_completed"])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(len(json.loads(self.disk(case))["attempts"]), 1)

    def test_interruption_preserves_exception_identity_intents_and_charges(self):
        case = self.case()
        failure = host_fixtures.FixtureCrash("FAKE_INTERRUPTION")

        def interrupt():
            raise failure

        case.server.on_send = interrupt
        with self.assertRaises(host_fixtures.FixtureCrash) as raised:
            self.run_case(case)
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.assert_charged(case)["state"], "reconciliation-required")
        self.assertEqual(failure.native_report, case.host.status("FAKE_OPERATION"))
        self.assertIsNone(failure.native_report["receipt"])
        self.assertEqual(failure.ledger_attempts[0]["state"], "reconciliation-required")
        before = self.disk(case)
        with self.assertRaises(ValueError):
            self.run_case(case)
        self.assertEqual(self.disk(case), before)
        self.assertEqual(case.server.sends, 1)

    def test_simultaneous_first_entry_is_claimed_before_native_preflight(self):
        case = self.case()
        ready = threading.Barrier(2)
        entered, refused, release = threading.Event(), threading.Event(), threading.Event()
        original_keys, original_gate = client._claim_keys, client._native_gate

        def keys(host, adapter):
            result = original_keys(host, adapter)
            ready.wait(timeout=10)
            return result

        def gate(*args):
            if not entered.is_set():
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("The fake preflight wait exceeded its deadlock guard.")
            return original_gate(*args)

        def consume():
            try:
                return self.run_case(case)["offline_completed"]
            except client.OfflineAdmittedN1Error:
                refused.set()
                return False

        with patch.object(client, "_claim_keys", side_effect=keys):
            with patch.object(client, "_native_gate", side_effect=gate):
                with patch.object(native, "_adapter_binding", wraps=native._adapter_binding) as binding:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures = [pool.submit(consume) for _ in range(2)]
                        try:
                            self.assertTrue(entered.wait(10))
                            self.assertTrue(refused.wait(10))
                            self.assertIsNone(self.disk(case))
                            self.assertEqual(case.server.sends, 0)
                            binding.assert_not_called()
                        finally:
                            release.set()
                        results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(self.assert_charged(case)["outcome"], "completed")

    def test_shared_host_state_adapter_and_server_refuse_before_probes(self):
        case = self.case()
        other_host = native.OfflineN1Host(case.host.state, case.host.target, case.host.worker)
        shared_adapter = self.case(name="shared-adapter")
        shared_server = self.case(name="shared-server")
        shared_server.adapter.server = case.server
        entered, release = threading.Event(), threading.Event()

        def pause():
            entered.set()
            if not release.wait(10):
                raise RuntimeError("The fake send wait exceeded its deadlock guard.")

        case.server.on_send = pause
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(self.run_case, case)
            try:
                self.assertTrue(entered.wait(10))
                before = self.disk(case)
                calls = copy.deepcopy(case.adapter.callback_latencies)
                with patch.object(client, "_adapter_snapshot",
                                  side_effect=AssertionError("A losing claim probed the adapter.")):
                    for candidate, changes in (
                        (case, {"host": other_host}),
                        (shared_adapter, {"adapter": case.adapter}),
                        (shared_server, {}),
                    ):
                        with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy"):
                            self.run_case(candidate, **changes)
                self.assertEqual(self.disk(case), before)
                self.assertEqual(case.adapter.callback_latencies, calls)
                self.assertIsNone(self.disk(shared_adapter))
                self.assertIsNone(self.disk(shared_server))
            finally:
                release.set()
            self.assertTrue(running.result(timeout=20)["offline_completed"])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(shared_adapter.server.sends, 0)
        self.assertEqual(shared_server.server.sends, 0)

    def test_synchronous_observer_reentry_keeps_the_active_claim(self):
        case = self.case()
        events = []

        with patch.object(client, "_adapter_snapshot", wraps=client._adapter_snapshot) as probe:
            def observer(event):
                events.append(event["event"])
                before = self.disk(case)
                count = probe.call_count
                for changes in ({}, {"operation_id": "FAKE_COMPETING_OPERATION"}):
                    with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy"):
                        self.run_case(case, **changes)
                self.assertEqual(self.disk(case), before)
                self.assertEqual(probe.call_count, count)

            case.server.expected_observers = [observer.__qualname__]
            result = self.run_case(case, observer=observer)
        self.assertTrue(result["offline_completed"])
        self.assertEqual(events, ["invocation-intent", "terminal"])
        self.assertEqual(case.server.sends, 1)
        self.assertEqual(self.assert_charged(case)["outcome"], "completed")

    def test_persisted_claims_refuse_before_live_probes_or_new_reservations(self):
        for mode in ("complete", "failure", "crash"):
            case = self.case(name=mode, mode=mode)
            if mode == "crash":
                with self.assertRaises(host_fixtures.FixtureCrash):
                    self.run_case(case)
            elif mode == "failure":
                with self.assertRaises(client.OfflineAdmittedN1Error):
                    self.run_case(case)
            else:
                self.run_case(case)
            report = case.host.status("FAKE_OPERATION")
            restarted = native.OfflineN1Host(case.host.state, case.host.target, case.host.worker)
            before = self.disk(case)
            new_store = ledger_api.InvocationLedger(
                self.repositories.root / ("ledger-new-" + mode), clock=case.clock, owner_probe=case.owners)
            case.receipt = replace(case.receipt, expires_at=case.receipt.expires_at + 1)
            with patch.object(client, "_adapter_snapshot",
                              side_effect=AssertionError("A retained claim probed the adapter.")):
                with patch.object(native, "_adapter_binding",
                                  side_effect=AssertionError("A retained claim probed the native boundary.")):
                    for changes in (
                        {"host": restarted},
                        {"host": restarted, "operation_id": "FAKE_COMPETING_OPERATION"},
                        {"host": restarted, "configuration_pins": {**PINS, "w15": "FAKE_CHANGED_PROFILE"}},
                        {"host": restarted, "ledger": new_store},
                    ):
                        with self.assertRaises(client.OfflineAdmittedN1Error) as raised:
                            self.run_case(case, **changes)
                        self.assertEqual(raised.exception.native_report, report)
                        self.assertEqual(self.disk(case), before)
            self.assertFalse(new_store.root.exists())
            self.assertEqual(case.server.sends, 1)

    def test_failed_claim_entry_releases_only_its_own_token(self):
        original = client._take_client_claim
        for phase in ("before", "after"):
            case = self.case(name=phase)
            for failure in (RuntimeError("FAKE_CLAIM_FAILURE"), StopIteration("FAKE_CLAIM_STOP"),
                            host_fixtures.FixtureCrash("FAKE_CLAIM_INTERRUPTION")):

                def fail(keys, token):
                    if phase == "after":
                        original(keys, token)
                    raise failure

                with patch.object(client, "_take_client_claim", side_effect=fail):
                    with self.assertRaises(type(failure)) as raised:
                        self.run_case(case)
                self.assertIs(raised.exception, failure)
                self.assertIsNone(self.disk(case))
                self.assertFalse((case.host.state / "operation.json").exists())
            self.assertTrue(self.run_case(case)["offline_completed"])
            self.assertEqual(case.server.sends, 1)

    def test_losing_and_reentrant_entries_cannot_release_the_winner(self):
        case = self.case()
        original = client._release_client_claim
        secondary = host_fixtures.FixtureCrash("FAKE_SECONDARY_CLEANUP_FAILURE")

        def cleanup(keys, token):
            original(keys, token)
            raise secondary

        with client._ClientClaim(case.host, case.adapter) as winner:
            with patch.object(client, "_release_client_claim", side_effect=cleanup):
                with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy") as raised:
                    self.run_case(case)
            self.assertIsNot(raised.exception, secondary)
            self.assertTrue(any("original failure is retained" in note
                                for note in raised.exception.__notes__))
            with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "one-shot"):
                winner.__enter__()
            with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy"):
                self.run_case(case)
            self.assertIsNone(self.disk(case))
            self.assertEqual(case.adapter.callback_latencies, {})
        self.assertTrue(self.run_case(case)["offline_completed"])
        self.assertEqual(case.server.sends, 1)

    def test_claim_exit_cleanup_preserves_primary_failure_and_allows_new_entry(self):
        case = self.case()
        original = client._release_client_claim
        secondary = host_fixtures.FixtureCrash("FAKE_SECONDARY_EXIT_FAILURE")

        def cleanup(keys, token):
            original(keys, token)
            raise secondary

        for failure in (RuntimeError("FAKE_PREFLIGHT_FAILURE"), StopIteration("FAKE_PREFLIGHT_STOP"),
                        host_fixtures.FixtureCrash("FAKE_PREFLIGHT_INTERRUPTION")):
            with patch.object(client, "_native_gate", side_effect=failure):
                with patch.object(client, "_release_client_claim", side_effect=cleanup):
                    with self.assertRaises(type(failure)) as raised:
                        self.run_case(case)
            self.assertIs(raised.exception, failure)
            self.assertIsNone(self.disk(case))
            self.assertTrue(any("original failure is retained" in note
                                for note in raised.exception.__notes__))
        self.assertTrue(self.run_case(case)["offline_completed"])
        self.assertEqual(case.server.sends, 1)

    def test_target_drift_before_and_during_execution_refuses_readiness(self):
        before = self.case(name="before")
        (before.host.target / "seed.txt").write_bytes(b"FAKE_TARGET_DRIFT\n")
        self.assert_refused(before)
        during = self.case(name="during")
        during.server.on_send = lambda: (during.host.target / "seed.txt").write_bytes(b"FAKE_TARGET_DRIFT\n")
        with self.assertRaises(client.OfflineAdmittedN1Error) as raised:
            self.run_case(during)
        self.assertEqual(raised.exception.native_report["status"], "reconciliation-required")
        self.assertEqual(self.assert_charged(during)["outcome"], "unknown")


    def test_mutated_admission_source_policy_and_expiry_refuse_before_writes(self):
        case = self.case()
        original = case.receipt
        flagged = replace(original)
        object.__setattr__(flagged, "qualified", True)
        for receipt in (None, {}, replace(original, request_bytes=b"FAKE_SUBSTITUTED"),
                        replace(original, amounts_bytes=b"42"), flagged):
            case.receipt = receipt
            self.assert_refused(case)
        case.receipt = original
        route = copy.deepcopy(case.route)
        case.route["nodes"][0]["sources"][0]["text"] = "FAKE_CHANGED_SOURCE"
        bind(case.route)
        self.assert_refused(case)
        case.route = route
        with patch.object(admission, "_read_policy_bytes", return_value=original.policy_bytes + b"\n"):
            self.assert_refused(case)
        case.clock.now = original.expires_at
        self.assert_refused(case)

    def test_policy_drift_during_observation_never_sends(self):
        case = self.case()
        current = [case.receipt.policy_bytes]

        def observer(event):
            if event["event"] == "invocation-intent":
                current[0] += b"\n"

        case.server.expected_observers = [observer.__qualname__]
        with patch.object(admission, "_read_policy_bytes", side_effect=lambda: current[0]):
            with self.assertRaises(admission.AdmissionError):
                self.run_case(case, observer=observer)
        self.assertEqual(case.server.sends, 0)
        self.assert_charged(case)


class OfflineGraphAdmittedN1Tests(unittest.TestCase):
    """Check optional graph bindings with the original offline native effects."""

    setUp = OfflineAdmittedN1Tests.setUp
    case = OfflineAdmittedN1Tests.case
    run_case = OfflineAdmittedN1Tests.run_case
    disk = OfflineAdmittedN1Tests.disk
    assert_refused = OfflineAdmittedN1Tests.assert_refused

    def child(self, name, node_id, parent):
        case = self.case(name=name, node_id=node_id)
        case.ledger, case.clock, case.owners = parent.ledger, parent.clock, parent.owners
        case.receipt = admission.prepare(
            case.route, node_id, now=case.clock.now, expires_at=case.clock.now + 60)
        case.server.ledger, case.server.admission = case.ledger, case.receipt
        return case

    def parent(self, case, *, state="terminal", outcome="completed"):
        receipt = admission.prepare(
            case.route, "plan", now=case.clock.now, expires_at=case.clock.now + 60)
        case.ledger.open_budget(
            receipt.budget_id, json.loads(receipt.limits_bytes), scope_sha256=receipt.scope_sha256)
        parent = case.ledger.reserve(
            budget_id=receipt.budget_id, request_id="plan",
            request_sha256=ledger_api.request_sha256(receipt.request_bytes),
            admission_sha256=admission._receipt_sha256(receipt),
            amount=json.loads(receipt.amounts_bytes), expires_at=receipt.expires_at,
            lineage={"kind": "initial", "parent_attempt_id": None}, refuse_while_unresolved=True)
        if state == "reserved":
            return parent
        parent = case.ledger.begin_invocation(parent["reservation_id"], receipt.request_bytes)
        if state == "invocation-intent":
            return parent
        if state == "reconciliation-required":
            return case.ledger.mark_reconciliation_required(
                parent["reservation_id"], reason="FAKE parent outcome remains unknown.")
        return case.ledger.finish(
            parent["reservation_id"], outcome, reason="FAKE original parent terminal observation.")

    def document(self, case):
        return json.loads(self.disk(case))

    def assert_completed(self, case, result, kind, parent=None):
        document = self.document(case)
        self.assertEqual(ledger_api.validate_ledger(document), [])
        attempt = result["attempt"]
        self.assertEqual(document["attempts"][attempt["attempt_id"]], attempt)
        self.assertEqual(case.ledger.attempt(attempt["reservation_id"]), attempt)
        self.assertNotEqual(attempt["attempt_id"], attempt["reservation_id"])
        self.assertEqual((attempt["state"], attempt["outcome"]), ("terminal", "completed"))
        self.assertEqual(attempt["lineage"], {
            "kind": kind, "parent_attempt_id": None if parent is None else parent["attempt_id"]})
        self.assertEqual(attempt["request_sha256"], ledger_api.request_sha256(case.receipt.request_bytes))
        self.assertEqual(attempt["admission_sha256"], admission._receipt_sha256(case.receipt))
        self.assertEqual(attempt["amount"], json.loads(case.receipt.amounts_bytes))
        self.assertEqual(result["request_bytes"], case.receipt.request_bytes)
        self.assertEqual(result["native_report"]["binding"]["task"].encode("utf-8"), case.receipt.request_bytes)
        self.assertTrue(result["offline_completed"])
        self.assertTrue(result["artifact_verification"]["valid"])
        self.assertEqual((case.host.state / "artifact" / "file-0000").read_bytes(), host_fixtures.OUTPUT)
        self.assertEqual(case.server.sends, 1)
        for item in document["attempts"].values():
            self.assertEqual(set(item["amount"]), set(admission.planner.RESOURCES))
            self.assertEqual(item["charge"], item["amount"])
            self.assertEqual(item["charge"], ledger_api.derived_charge(item))
            self.assertIsNone(item["observed_usage"])
        budget = document["budgets"][case.receipt.budget_id]
        self.assertEqual(budget["scope_sha256"], case.receipt.scope_sha256)
        self.assertEqual(budget["limits"], json.loads(case.receipt.limits_bytes))
        selected = [item for item in document["attempts"].values()
                    if item["budget_id"] == case.receipt.budget_id]
        self.assertEqual(case.ledger.summary(case.receipt.budget_id)["charged"], {
            name: sum(item["charge"][name] for item in selected) for name in admission.planner.RESOURCES})
        if parent is not None:
            self.assertEqual(document["attempts"][parent["attempt_id"]], parent)
        for field in client.FALSE_FIELDS:
            self.assertIs(result[field], False)
        return document

    def assert_graph_refused(self, case, mapping):
        with (
            patch.object(ledger_api, "_new_attempt", wraps=ledger_api._new_attempt) as reserved,
            patch.object(client, "_RUN", wraps=client._RUN) as executed,
        ):
            self.assert_refused(case, node_attempts=mapping)
        reserved.assert_not_called()
        executed.assert_not_called()

    def extra(self, case, budget_id):
        request = b"FAKE_UNRELATED_REQUEST"
        receipt = case.receipt
        case.ledger.open_budget(
            budget_id, json.loads(receipt.limits_bytes), scope_sha256=receipt.scope_sha256)
        extra = case.ledger.reserve(
            budget_id=budget_id, request_id="FAKE_UNRELATED_NODE",
            request_sha256=ledger_api.request_sha256(request),
            admission_sha256=ledger_api.request_sha256(b"FAKE_UNRELATED_ADMISSION"),
            amount=json.loads(receipt.amounts_bytes), expires_at=receipt.expires_at)
        case.ledger.begin_invocation(extra["reservation_id"], request)
        return case.ledger.finish(
            extra["reservation_id"], "unknown", reason="FAKE unrelated outcome remains unknown.")

    def test_optional_signature_and_legacy_primary(self):
        for function in (client.run_offline_admitted_n1, client._run_claimed):
            parameter = inspect.signature(function).parameters["node_attempts"]
            self.assertIsNone(parameter.default)
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        case = self.case(name="graph-legacy-primary")
        with (
            patch.object(client, "_require_primary", wraps=client._require_primary) as required,
            patch.object(client, "_INVOKE", wraps=client._INVOKE) as invoked,
        ):
            result = self.run_case(case, node_attempts=None)
        required.assert_called_once()
        self.assertNotIn("node_attempts", invoked.call_args.kwargs)
        self.assert_completed(case, result, "initial")

    def test_explicit_empty_primary_uses_original_graph_validation(self):
        case = self.case(name="graph-explicit-primary")
        mapping = {}
        with (
            patch.object(client, "_require_primary", wraps=client._require_primary) as required,
            patch.object(client, "_INVOKE", wraps=client._INVOKE) as invoked,
            patch.object(admission, "_graph_state", wraps=admission._graph_state) as graph,
        ):
            result = self.run_case(case, node_attempts=mapping)
        required.assert_not_called()
        frozen = invoked.call_args.kwargs["node_attempts"]
        self.assertEqual(frozen, {})
        self.assertIsNot(frozen, mapping)
        self.assertIs(graph.call_args.args[1], frozen)
        self.assertEqual(graph.call_args.args[3], result["attempt"]["attempt_id"])
        self.assert_completed(case, result, "initial")

    def test_original_native_sequence_reuses_one_fixed_aggregate(self):
        root = self.case(name="graph-sequence-plan")
        mapping = {}
        for node_id in ("plan", "review", "synthesis", "validation"):
            case = self.child("graph-sequence-" + node_id, node_id, root) if node_id != "plan" else root
            result = self.run_case(case, node_attempts=mapping)
            node = next(item for item in case.route["nodes"] if item["id"] == node_id)
            parent_id = mapping.get(node["lineage_parent"])
            parent = self.document(case)["attempts"].get(parent_id)
            kind = "initial" if parent is None else "successor"
            document = self.assert_completed(case, result, kind, parent)
            self.assertEqual(set(document["budgets"]), {case.receipt.budget_id})
            mapping[node_id] = result["attempt"]["attempt_id"]
        self.assertEqual(len(document["attempts"]), 4)

    def test_retry_and_fallback_use_actual_failed_parents_and_shared_charges(self):
        root = self.case(name="graph-failed-parent")
        parent = self.parent(root, outcome="failed")
        mapping = {"plan": parent["attempt_id"]}
        for node_id in ("retry", "fallback"):
            case = self.child("graph-failed-child-" + node_id, node_id, root)
            result = self.run_case(case, node_attempts=mapping)
            self.assert_completed(case, result, node_id, parent)
            mapping[node_id] = result["attempt"]["attempt_id"]
            replay = self.child("graph-replayed-" + node_id, node_id, root)
            self.assert_graph_refused(replay, {"plan": parent["attempt_id"]})
        self.assertEqual(root.server.sends, 0)

    def test_sibling_uses_only_original_supported_parent_states(self):
        for state in ("reserved", "invocation-intent", "terminal"):
            with self.subTest(state=state):
                root = self.case(name="graph-sibling-parent-" + state)
                parent = self.parent(root, state=state)
                case = self.child("graph-sibling-child-" + state, "sibling", root)
                result = self.run_case(case, node_attempts={"plan": parent["attempt_id"]})
                self.assert_completed(case, result, "sibling", parent)

    def test_started_or_completed_parent_keeps_its_original_deadline_rules(self):
        for state, node_id in product(("invocation-intent", "terminal"), ("sibling", "review")):
            with self.subTest(state=state, node_id=node_id):
                root = self.case(name=f"graph-old-parent-{state}-{node_id}")
                parent = self.parent(root, state=state)
                root.clock.now = parent["expires_at"]
                case = self.child(f"graph-old-child-{state}-{node_id}", node_id, root)
                mapping = {"plan": parent["attempt_id"]}
                if state == "invocation-intent" and node_id == "review":
                    self.assert_graph_refused(case, mapping)
                else:
                    result = self.run_case(case, node_attempts=mapping)
                    self.assert_completed(case, result, "sibling" if node_id == "sibling" else "successor", parent)

    def test_mapping_types_names_identities_and_count_refuse_before_storage(self):
        mappings = (
            [], True, "FAKE_MAPPING", {"plan": True}, {"plan": []}, {"plan": "FAKE invalid identity"},
            {"review": "FAKE_ATTEMPT"}, {"FAKE_UNDECLARED_NODE": "FAKE_ATTEMPT"},
            {"plan": "FAKE_ATTEMPT", "synthesis": "FAKE_ATTEMPT"},
            {f"FAKE_NODE_{index}": "FAKE_ATTEMPT" for index in range(admission.planner.MAX_NODES + 1)},
        )
        for index, mapping in enumerate(mappings):
            with self.subTest(index=index):
                case = self.case(name=f"graph-invalid-mapping-{index}", node_id="review")
                with patch.object(client, "_native_gate", wraps=client._native_gate) as gate:
                    self.assert_graph_refused(case, mapping)
                gate.assert_not_called()
                self.assertFalse(case.ledger.root.exists())

    def test_missing_foreign_and_stale_mappings_never_reserve_or_send(self):
        root = self.case(name="graph-mapping-parent")
        parent = self.parent(root)
        for index, mapping in enumerate(({}, {"plan": "FAKE_MISSING_ATTEMPT"})):
            case = self.child(f"graph-missing-child-{index}", "review", root)
            self.assert_graph_refused(case, mapping)
        foreign = self.case(name="graph-foreign-attempt", node_id="review")
        self.assert_graph_refused(foreign, {"plan": parent["attempt_id"]})
        pending = self.case(name="graph-stale-parent")
        stale = self.parent(pending, state="reserved")
        pending.clock.now = stale["expires_at"]
        child = self.child("graph-stale-child", "sibling", pending)
        self.assert_graph_refused(child, {"plan": stale["attempt_id"]})

    def test_wrong_route_scope_and_mixed_node_requests_keep_original_refusals(self):
        for field in ("purpose", "aggregate_id"):
            with self.subTest(field=field):
                case = self.case(name="graph-wrong-route-" + field, node_id="review")
                route = copy.deepcopy(case.route)
                route[field] += "-FAKE_OTHER_ROUTE"
                bind(route)
                source = SimpleNamespace(route=route, clock=case.clock, ledger=case.ledger)
                parent = self.parent(source)
                self.assert_graph_refused(case, {"plan": parent["attempt_id"]})
        root = self.case(name="graph-mixed-parent")
        parent = self.parent(root)
        route = copy.deepcopy(root.route)
        route["aggregate_id"] = "FAKE_OTHER_AGGREGATE"
        bind(route)
        receipt = admission.prepare(
            route, "plan", now=root.clock.now, expires_at=root.clock.now + 60)
        root.ledger.open_budget(
            receipt.budget_id, json.loads(receipt.limits_bytes), scope_sha256=receipt.scope_sha256)
        before = self.disk(root)
        with self.assertRaisesRegex(ledger_api.InvocationLedgerError, "already has attempt"):
            self.parent(SimpleNamespace(route=route, clock=root.clock, ledger=root.ledger))
        self.assertEqual(self.disk(root), before)
        self.assertEqual(root.server.sends, 0)
        case = self.child("graph-mixed-child", "review", root)
        result = self.run_case(case, node_attempts={"plan": parent["attempt_id"]})
        self.assert_completed(case, result, "successor", parent)

    def test_caller_mapping_mutation_keeps_one_snapshot_and_the_client_claim(self):
        root = self.case(name="graph-snapshot-parent")
        parent = self.parent(root)
        case = self.child("graph-snapshot-child", "review", root)
        mapping = {"plan": parent["attempt_id"]}
        expected = dict(mapping)
        original_invoke, original_graph = client._INVOKE, admission._graph_state
        invocations, graphs, events = [], [], []

        def invoke(*args, **kwargs):
            invocations.append(kwargs["node_attempts"])
            return original_invoke(*args, **kwargs)

        def graph(*args, **kwargs):
            graphs.append(args)
            return original_graph(*args, **kwargs)

        def observer(event):
            events.append(event["event"])
            if event["event"] == "invocation-intent":
                mapping.clear()
                mapping["FAKE_UNDECLARED_NODE"] = "FAKE_CHANGED_ATTEMPT"
            before = self.disk(case)
            with self.assertRaisesRegex(client.OfflineAdmittedN1Error, "busy"):
                self.run_case(case, node_attempts=mapping)
            self.assertEqual(self.disk(case), before)

        case.server.expected_observers = [observer.__qualname__]
        with (
            patch.object(client, "_INVOKE", side_effect=invoke),
            patch.object(admission, "_graph_state", side_effect=graph),
        ):
            result = self.run_case(case, observer=observer, node_attempts=mapping)
        self.assertEqual(events, ["invocation-intent", "terminal"])
        self.assertEqual(len(invocations), 1)
        self.assertEqual(len(graphs), 3)
        self.assertIsNot(invocations[0], mapping)
        self.assertEqual(invocations[0], expected)
        self.assertTrue(all(args[1] == expected for args in graphs))
        self.assertIs(graphs[-1][1], invocations[0])
        self.assertEqual(graphs[-1][3], result["attempt"]["attempt_id"])
        self.assert_completed(case, result, "successor", parent)

    def test_unsupported_parent_outcomes_never_enable_native_children(self):
        for outcome, node_id in product(
            ("completed", "failed", "unknown", "timeout", "cancelled", "aborted-before-effect"),
            ("review", "retry", "fallback", "sibling"),
        ):
            supported = (outcome == "failed" and node_id in ("retry", "fallback")) or (
                outcome == "completed" and node_id in ("review", "sibling"))
            if supported:
                continue
            with self.subTest(outcome=outcome, node_id=node_id):
                root = self.case(name=f"graph-refused-{outcome}-{node_id}")
                parent = self.parent(root, outcome=outcome)
                case = self.child(f"graph-refused-child-{outcome}-{node_id}", node_id, root)
                self.assert_graph_refused(case, {"plan": parent["attempt_id"]})

    def test_reconciliation_and_released_parents_never_restart(self):
        for state, node_id in product(
            ("reconciliation-required", "reconciled", "released"),
            ("review", "retry", "fallback", "sibling"),
        ):
            with self.subTest(state=state, node_id=node_id):
                root = self.case(name=f"graph-retained-{state}-{node_id}")
                parent = self.parent(root, state="reserved" if state == "released" else "reconciliation-required")
                if state == "released":
                    parent = root.ledger.release(parent["reservation_id"], reason="FAKE unused parent reservation.")
                elif state == "reconciled":
                    parent = root.ledger.reconcile(parent["attempt_id"], reason="FAKE retained reconciliation.")
                case = self.child(f"graph-retained-child-{state}-{node_id}", node_id, root)
                self.assert_graph_refused(case, {"plan": parent["attempt_id"]})

    def test_pending_sibling_parent_requires_a_known_live_owner(self):
        for state, status in product(("reserved", "invocation-intent"), ("gone", "unknown")):
            with self.subTest(state=state, status=status):
                root = self.case(name=f"graph-owner-parent-{state}-{status}")
                parent = self.parent(root, state=state)
                case = self.child(f"graph-owner-child-{state}-{status}", "sibling", root)
                with patch.object(root.owners, "status", return_value=status):
                    self.assert_graph_refused(case, {"plan": parent["attempt_id"]})

    def test_selected_owner_drift_after_observation_keeps_full_charges(self):
        root = self.case(name="graph-owner-drift-parent")
        parent = self.parent(root)
        case = self.child("graph-owner-drift-child", "review", root)
        owner = dict(parent["owner"])
        owner["pid"] += 1

        with ExitStack() as stack:
            def observer(event):
                if event["event"] == "invocation-intent":
                    stack.enter_context(patch.object(case.owners, "current", return_value=owner))

            case.server.expected_observers = [observer.__qualname__]
            with self.assertRaises(ledger_api.InvocationLedgerError) as raised:
                self.run_case(case, observer=observer, node_attempts={"plan": parent["attempt_id"]})
        current = next(item for item in self.document(case)["attempts"].values()
                       if item["request_id"] == "review")
        self.assertEqual(current["state"], "reconciliation-required")
        self.assertEqual(current["charge"], json.loads(case.receipt.amounts_bytes))
        self.assertEqual(raised.exception.ledger_attempts, [current])
        self.assertEqual(len(self.document(case)["attempts"]), 2)
        self.assertEqual(case.server.sends, 0)
        self.assertFalse((case.host.state / "operation.json").exists())

    def deadline_control(self, node_id, stage, remaining, *, parent_first):
        root = self.case(name=f"graph-deadline-parent-{node_id}-{stage}-{remaining}-{parent_first}")
        parent = self.parent(root, state="reserved" if parent_first else "terminal")
        root.clock.now = parent["expires_at"] - 2
        case = self.child(f"graph-deadline-child-{node_id}-{stage}-{remaining}-{parent_first}", node_id, root)
        deadline = parent["expires_at"] if parent_first else case.receipt.expires_at
        original = admission._graph_state
        currents, advanced = [], []
        boundary = {"armed": False}

        def graph(receipt, prior, store, current_attempt_id=None):
            if current_attempt_id is not None:
                currents.append(current_attempt_id)
                boundary["armed"] = len(currents) == 2
            return original(receipt, prior, store, current_attempt_id)

        def delayed(read, label):
            def checked(*args, **kwargs):
                value = read(*args, **kwargs)
                if boundary["armed"] and label == stage and not advanced:
                    case.clock.now = deadline - remaining
                    advanced.append(label)
                return value
            return checked

        with ExitStack() as stack:
            stack.enter_context(patch.object(admission, "_graph_state", side_effect=graph))
            for target, name, label in (
                (case.owners, "status", "status"), (case.owners, "current", "owner"),
                (ledger_api, "_charged_totals", "charge"), (admission, "_read_policy_bytes", "policy"),
            ):
                stack.enter_context(patch.object(target, name, side_effect=delayed(getattr(target, name), label)))
            if remaining:
                result = self.run_case(case, node_attempts={"plan": parent["attempt_id"]})
                self.assert_completed(case, result, "sibling" if parent_first else "successor", parent)
            else:
                with self.assertRaisesRegex(ValueError, "expired") as raised:
                    self.run_case(case, node_attempts={"plan": parent["attempt_id"]})
                current = next(item for item in self.document(case)["attempts"].values()
                               if item["request_id"] == node_id)
                self.assertEqual((current["state"], current["outcome"]), ("terminal", "unknown"))
                self.assertEqual(current["charge"], json.loads(case.receipt.amounts_bytes))
                self.assertEqual(raised.exception.ledger_attempts, [current])
                self.assertEqual(case.server.sends, 0)
                self.assertEqual(case.adapter.callback_latencies, {})
                self.assertFalse((case.host.state / "operation.json").exists())
        self.assertEqual(advanced, [stage])
        self.assertEqual(len(currents), 2)
        self.assertEqual(len(self.document(case)["attempts"]), 2)
        current = next(item for item in self.document(case)["attempts"].values() if item["request_id"] == node_id)
        self.assertTrue(all(value == current["attempt_id"] for value in currents))
        self.assertNotEqual(current["attempt_id"], current["reservation_id"])
        self.assertEqual(self.document(case)["attempts"][parent["attempt_id"]], parent)

    def test_final_graph_gate_rechecks_parent_and_selected_deadlines_after_delays(self):
        for stage, remaining in product(("status", "owner", "charge", "policy"), (0, 1)):
            with self.subTest(stage=stage, remaining=remaining):
                self.deadline_control("review", stage, remaining, parent_first=False)
                self.deadline_control("sibling", stage, remaining, parent_first=True)

    def test_unmatched_unknown_attempts_keep_the_original_budget_boundary(self):
        for same_budget in (True, False):
            with self.subTest(same_budget=same_budget):
                root = self.case(name=f"graph-unmatched-parent-{same_budget}")
                parent = self.parent(root)
                case = self.child(f"graph-unmatched-child-{same_budget}", "review", root)
                budget_id = case.receipt.budget_id if same_budget else "FAKE_OTHER_AGGREGATE"
                extra = self.extra(case, budget_id)
                mapping = {"plan": parent["attempt_id"]}
                if same_budget:
                    self.assert_graph_refused(case, mapping)
                else:
                    result = self.run_case(case, node_attempts=mapping)
                    self.assert_completed(case, result, "successor", parent)
                self.assertEqual(self.document(case)["attempts"][extra["attempt_id"]], extra)

    def test_explicit_graph_exhaustion_keeps_the_original_aggregate(self):
        root = self.case(name="graph-exhaustion-parent")
        parent = self.parent(root)
        case = self.child("graph-exhaustion-child", "review", root)
        limits = json.loads(case.receipt.limits_bytes)
        charged = case.ledger.summary(case.receipt.budget_id)["charged"]
        request = b"FAKE_AGGREGATE_BLOCKER_REQUEST"
        case.ledger.reserve(
            budget_id=case.receipt.budget_id, request_id="FAKE_AGGREGATE_BLOCKER",
            request_sha256=ledger_api.request_sha256(request),
            admission_sha256=ledger_api.request_sha256(b"FAKE_AGGREGATE_BLOCKER_ADMISSION"),
            amount={name: limits[name] - charged[name] for name in admission.planner.RESOURCES},
            expires_at=case.receipt.expires_at,
        )
        self.assert_graph_refused(case, {"plan": parent["attempt_id"]})
        self.assertEqual(case.ledger.summary(case.receipt.budget_id)["charged"], limits)


if __name__ == "__main__":
    unittest.main()
