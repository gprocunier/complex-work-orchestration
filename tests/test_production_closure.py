"""The original Beads subprocess boundary; all effects are EXAMPLE."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_qualified_closure as fixtures
from tests import test_mixed_delivery_closure as mixed_cases
from tests.real_beads_fixture import initialize_real_beads, run_fixture_subprocess
from tests.host_acceptance_fixtures import provision_acceptance
from cwo_core import host_records
from tests.real_beads_fixture import configure_git_fixture
import fcntl

closure, original, qualified = fixtures.closure, fixtures.original, fixtures.qualified


class ExampleProcess:
    """Only fake the bd process and executable lookup; validators run normally."""

    def __init__(self, bead, database):
        self.bead = copy.deepcopy(bead)
        self.database = str(database)
        self.calls = []
        self.effects = []
        self.returncode = 0
        self.before = lambda command: None
        self.after = lambda command: None
        self.show_projection = lambda: [self.bead]
        self.run = subprocess.run
        self.which = shutil.which

    def lookup(self, name, *args, **kwargs):
        return "/EXAMPLE/bd" if name == "bd" else self.which(name, *args, **kwargs)

    def __call__(self, command, *args, **kwargs):
        if command[0] != "bd":
            return self.run(command, *args, **kwargs)
        if command[1:5] != ["--db", self.database, "--actor", "EXAMPLE-supervisor"]:
            raise AssertionError("EXAMPLE explicit supervisor database/actor lost")
        action = command[5:]
        self.calls.append(tuple(action))
        self.before(action)
        if action == ["show", "--json", "--include-comments", "--", self.bead["id"]]:
            return subprocess.CompletedProcess(command, 0, json.dumps(self.show_projection()), "")
        if len(action) == 4 and action[:3] == ["comment", "--", self.bead["id"]]:
            self.effects.append(tuple(action))
            self.bead["comments"].append({"text": action[3], "author": "EXAMPLE-supervisor",
                                          "id": 3, "issue_id": self.bead["id"], "created_at": "EXAMPLE-time"})
            self.bead["updated_at"] = "EXAMPLE-after-comment"
            self.bead["comment_count"] += 1
            self.bead["revision"] = "EXAMPLE-after-comment-revision"
        elif action == ["close", "--reason", "Bound delivery accepted", "--", self.bead["id"]]:
            self.effects.append(tuple(action))
            self.bead.update(status="closed", updated_at="EXAMPLE-after-close", closed_at="EXAMPLE-time",
                             close_reason="Bound delivery accepted", revision="EXAMPLE-after-close-revision")
        else:
            raise AssertionError("EXAMPLE unexpected Beads command")
        self.after(action)
        return subprocess.CompletedProcess(command, self.returncode, "", "EXAMPLE Beads error" if self.returncode else "")


class ProductionClosureTests(unittest.TestCase):
    def setUp(self):
        self.builders = fixtures.QualifiedClosureTests(methodName="runTest")
        self.addCleanup(self.builders.doCleanups)

    @contextlib.contextmanager
    def provisioned(self, case, *, directory_database=False):
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-production-supervisor-") as temporary:
            parent = Path(temporary)
            custody, storage = parent / "custody", parent / "database"
            custody.mkdir(mode=0o700)
            storage.mkdir(mode=0o700)
            db = storage / "EXAMPLE.db"
            if directory_database:
                db.mkdir(mode=0o700)
            else:
                db.touch(mode=0o600)
            self.builders.provision(case, custody)
            contract = json.loads((custody / "contract.json").read_bytes())
            contract["record_type"] = "cwo-production-closure-custody"
            del contract["scope"]
            contract["bead"]["updated_at"] = "EXAMPLE-before"
            contract["bead"]["comment_count"] = len(contract["bead"]["comments"])
            contract["bead"]["revision"] = "EXAMPLE-before-revision"
            self.builders.write(custody, "contract.json", original._freeze(contract))
            process = ExampleProcess(contract["bead"], db)
            store = host_records.HostRecordStore.for_tests(
                parent / "host-state", worker_writable_roots=(Path(contract["root"]), custody))
            identity = store.setup_database_identity(db)
            process.store = store
            process.authority = provision_acceptance(
                store, bead_id=contract["bead"]["id"], database_identity=identity)
            with host_records.using_test_store(store), \
                    patch.object(subprocess, "run", side_effect=process), \
                    patch.object(shutil, "which", side_effect=process.lookup):
                yield process, custody, db

    @contextlib.contextmanager
    def registered(self, case, *, directory_database=False):
        with self.provisioned(case, directory_database=directory_database) as (process, custody, db), \
                patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True), \
                qualified.production_custody(str(custody), database=str(db), actor="EXAMPLE-supervisor",
                                             **process.authority) as host:
            yield host, process, custody

    def reviewed(self, case, host, custody, *, native=False):
        options = {}
        if native:
            options["native"] = {"host": case.host, "policy": case.policy,
                                 "report": case.report, "expected_target": case.expected_target}
        observed = qualified.observe(host, **options)
        qualified.bind(host)
        return observed

    def test_host_acceptance_refusals_have_zero_calls_and_writes_with_positive_controls(self):
        """S4 exact authority: each refusal is paired with fake-bd completed control."""
        faults = ("missing", "bead", "return", "evaluation", "tamper", "chain",
                  "outside", "database", "gate")
        for fault in faults:
            with self.subTest(check=fault):
                case = self.builders.compact()
                with self.provisioned(case) as (process, custody, database):
                    selected = dict(process.authority)
                    gate = True
                    if fault == "missing":
                        selected["acceptance_record"] = "0" * 64
                    elif fault == "bead":
                        selected = provision_acceptance(
                            process.store, bead_id="EXAMPLE-another-bead",
                            database_identity=process.store.require_database_identity(database))
                    elif fault in ("return", "evaluation"):
                        selected[fault + "_sha256"] = "0" * 64
                    elif fault == "tamper":
                        record = process.store.root / (selected["acceptance_record"] + ".json")
                        record.write_bytes(record.read_bytes() + b" ")
                    elif fault == "chain":
                        audit_file = process.store.audit_file
                        events = audit_file.read_text().splitlines()
                        event = json.loads(events[0])
                        event["event_hash"] = "0" * 64
                        events[0] = json.dumps(event)
                        audit_file.write_text("\n".join(events) + "\n")
                    elif fault == "outside":
                        record = custody / "caller-acceptance.json"
                        record.write_bytes((process.store.root / (selected["acceptance_record"] + ".json")).read_bytes())
                        selected["acceptance_record"] = str(record)
                    elif fault == "database":
                        other = database.with_name("EXAMPLE-other.db")
                        other.touch(mode=0o600)
                        process.store.setup_database_identity(other)
                        database = other
                    else:
                        gate = False
                    parent = custody.parent
                    before = {str(p.relative_to(parent)): p.read_bytes()
                              for p in parent.rglob("*") if p.is_file()}
                    with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", gate):
                        with self.assertRaises(original.ClosureError):
                            with qualified.production_custody(
                                    str(custody), database=str(database), actor="EXAMPLE-supervisor",
                                    **selected):
                                self.fail("invalid acceptance registered")
                    self.assertEqual(process.calls, [], fault)
                    self.assertEqual(process.effects, [], fault)
                    self.assertEqual({str(p.relative_to(parent)): p.read_bytes()
                                      for p in parent.rglob("*") if p.is_file()}, before)
                # A fresh genuine chain demonstrates that each refusal check guards
                # the same reachable production effect boundary.
                with self.registered(case) as (host, process, custody):
                    self.reviewed(case, host, custody)
                    result = closure.execute_qualified_completed(host)
                    self.assertTrue(result["completed"])
                    self.assertEqual([e[0] for e in process.effects], ["comment", "close"])
                    self.assertEqual(result["database_identity"],
                                     process.store.require_database_identity(Path(process.database)))
                    events = [json.loads(line) for line in process.store.audit_file.read_text().splitlines()]
                    closed = [e for e in events if e.get("event_type") == "production_closure_consumed"]
                    self.assertEqual(len(closed), 1)
                    self.assertEqual(closed[0]["database_identity"], result["database_identity"])

    def test_gate_first_registration_and_consumption_before_validation_or_io(self):
        """S4 gate-first: malformed inputs and a live issued host cannot touch I/O."""
        with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", False), \
                patch.object(qualified, "_directory", side_effect=AssertionError("I/O")) as io:
            with self.assertRaisesRegex(original.ClosureError, "unavailable"):
                with qualified.production_custody(None, database=None, actor=None):
                    self.fail("gate-off registration")
            io.assert_not_called()
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            before_calls = list(process.calls)
            with patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", False), \
                    patch.object(qualified, "_guard", side_effect=AssertionError("I/O")) as io:
                with self.assertRaisesRegex(original.ClosureError, "unavailable"):
                    qualified.consume(host, dry_run="EXAMPLE invalid bool")
                io.assert_not_called()
            self.assertEqual(process.calls, before_calls)
            self.assertEqual(process.effects, [])

    def test_database_identity_is_rechecked_before_each_effect(self):
        """S4 effect recheck: a changed identity after comment prevents close."""
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            def drift(action):
                if action[0] == "comment":
                    database = Path(process.database)
                    database.rename(database.with_suffix(".original"))
                    database.touch(mode=0o600)
            process.after = drift
            with self.assertRaises(original.ClosureError):
                closure.execute_qualified_completed(host)
            self.assertEqual([e[0] for e in process.effects], ["comment"])
            self.assertTrue(host.report["partial_persistence"])
            self.assertTrue(host.report["completion_unconfirmed"])

    def test_bound_acceptance_cannot_be_replaced_before_consumption(self):
        """S4 binding identity: an issued observation alone cannot authorize effects."""
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            qualified._state(host).bound = object()
            before_calls = list(process.calls)
            with self.assertRaisesRegex(original.ClosureError, "host acceptance binding"):
                closure.execute_qualified_completed(host)
            self.assertEqual(process.calls, before_calls)
            self.assertEqual(process.effects, [])

    @unittest.skipUnless(shutil.which("bd"), "bd CLI not available")
    def test_r5_installed_beads_persists_original_adapter_summary_and_close(self):
        """Patch the gate for disposable Beads, preserving the original effect callable."""
        with tempfile.TemporaryDirectory(prefix="EXAMPLE-native-closure-") as temporary:
            parent = Path(temporary)
            storage, custody = parent / "database", parent / "custody"
            storage.mkdir(mode=0o700)
            custody.mkdir(mode=0o700)
            database = storage / ".beads"
            actor = "EXAMPLE-supervisor"
            env = {**os.environ, "BEADS_DIR": str(database), "BEADS_ACTOR": actor,
                   "CWO_BEADS_TIMEOUT_SECONDS": "20"}
            with patch.dict(os.environ, env, clear=True):
                run_fixture_subprocess(["git", "init", "-q"], cwd=storage,
                                       env=env, check=True, capture_output=True)
                configure_git_fixture(storage, env=env)
                initialize_real_beads(
                    ["bd", "--actor", actor, "init", "--non-interactive", "--skip-agents",
                     "--skip-hooks", "-p", "EXAMPLE"],
                    cwd=storage, env=env, check=True, capture_output=True, text=True)

                def bd(*args):
                    return run_fixture_subprocess(
                        ["bd", "--db", str(database), "--actor", actor, *args],
                        cwd=storage, env=env, check=True, capture_output=True, text=True).stdout

                case = self.builders.compact(additive=True)
                bd("create", case.bead["title"], "--id", case.bead["id"], "--silent")
                for comment in case.bead["comments"]:
                    bd("comment", "--", case.bead["id"], comment["text"])
                before = json.loads(bd("show", "--json", "--include-comments", "--", case.bead["id"]))[0]
                case.bead = before
                self.builders.provision(case, custody)
                contract = json.loads((custody / "contract.json").read_bytes())
                contract["record_type"] = "cwo-production-closure-custody"
                del contract["scope"]
                self.builders.write(custody, "contract.json", original._freeze(contract))
                store = host_records.HostRecordStore.for_tests(
                    parent / "host-state", worker_writable_roots=(Path(contract["root"]), custody))
                authority = provision_acceptance(
                    store, bead_id=case.bead["id"],
                    database_identity=store.setup_database_identity(database))
                with host_records.using_test_store(store), \
                        patch.object(qualified, "PRODUCTION_CLOSURE_AVAILABLE", True), \
                        qualified.production_custody(str(custody), database=str(database), actor=actor,
                                                     **authority) as host:
                    self.reviewed(case, host, custody)
                    self.assertEqual(closure.execute_qualified_completed(host, dry_run=True)["state"], "VALIDATED")
                    self.assertEqual(json.loads(bd("show", "--json", "--include-comments", "--", case.bead["id"]))[0], before)
                    result = closure.execute_qualified_completed(host)
                    after = json.loads(bd("show", "--json", "--include-comments", "--", case.bead["id"]))[0]
                    self.assertEqual(result["state"], "COMPLETED")
                    self.assertTrue(result["completed"])
                    self.assertTrue(result["persistence_known"])
                    self.assertFalse(result["fake_completed"])
                    self.assertFalse(result["completion_unconfirmed"])
                    self.assertEqual(after["status"], "closed")
                    self.assertEqual(after["close_reason"], "Bound delivery accepted")
                    self.assertEqual(after["comments"][:-1], before["comments"])
                    self.assertEqual(after["comments"][-1]["text"], result["summary"])
                    self.assertEqual(after["comments"][-1]["author"], actor)
                    self.assertEqual(after["comments"][-1]["issue_id"], case.bead["id"])
                    self.assertTrue(all(result[name] is False for name in original.AUTHORITY_FIELDS))
                    with self.assertRaises(original.ClosureError):
                        closure.execute_qualified_completed(host)
                    self.assertEqual(json.loads(bd("show", "--json", "--include-comments", "--", case.bead["id"]))[0], after)
                    executable = Path(shutil.which("bd"))
                    print(json.dumps({"native_beads": bd("--version").strip(),
                                      "executable": str(executable),
                                      "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                                      "before_sha256": hashlib.sha256(original._freeze(before)).hexdigest(),
                                      "after_sha256": hashlib.sha256(original._freeze(after)).hexdigest(),
                                      "state": result["state"], "new_comments": 1, "status": after["status"]}))

    def test_actual_adapter_positive_compact_amendment_native_and_zero_write_dry_run(self):
        for mode in ("compact", "amendment", "native", "directory", "in-progress"):
            with self.subTest(mode=mode):
                case = self.builders.native() if mode == "native" else self.builders.compact(additive=mode == "amendment")
                if mode == "in-progress":
                    case.bead["status"] = "in_progress"
                with self.registered(case, directory_database=mode == "directory") as (host, process, custody):
                    self.reviewed(case, host, custody, native=mode == "native")
                    before = sorted(p.name for p in custody.iterdir())
                    self.assertEqual(closure.execute_qualified_completed(host, dry_run=True)["state"], "VALIDATED")
                    self.assertEqual(process.effects, [])
                    self.assertEqual(sorted(p.name for p in custody.iterdir()), before)
                    result = closure.execute_qualified_completed(host)
                    self.assertEqual(result["state"], "COMPLETED")
                    self.assertTrue(result["completed"])
                    self.assertFalse(result["fake_completed"])
                    self.assertFalse(result["completion_unconfirmed"])
                    self.assertEqual([e[0] for e in process.effects], ["comment", "close"])
                    self.assertIn("- Disposition: completed", result["summary"])
                    self.assertEqual(process.effects[0][2], case.bead["id"])
                    self.assertEqual(process.effects[1][-1], case.bead["id"])
                    with self.assertRaises(original.ClosureError):
                        closure.execute_qualified_completed(host)
                    self.assertTrue(host.report["completed"])
                    self.assertEqual(len(process.effects), 2)
                    self.assertFalse(qualified.PUBLIC_ACTIVATION)
                    self.assertTrue(all(result[name] is False for name in original.AUTHORITY_FIELDS))

    def test_artifact_only_contract_completes_without_inventing_validator_obligations(self):
        for content in (mixed_cases.fixtures.AFTER, b"EXAMPLE wrong artifact bytes\n"):
            with self.subTest(valid=content == mixed_cases.fixtures.AFTER):
                case = mixed_cases.MixedDeliveryClosureTests(methodName="runTest")
                self.addCleanup(case.doCleanups)
                case.begin(count=0, content=content)
                self.assertEqual(case.commands, {})
                with self.registered(case) as (host, process, custody):
                    if content != mixed_cases.fixtures.AFTER:
                        with self.assertRaises(original.ClosureError):
                            self.reviewed(case, host, custody)
                        self.assertEqual(process.effects, [])
                        continue
                    observed = self.reviewed(case, host, custody)
                    self.assertEqual(observed.production["checked_command_calls"], 0)
                    self.assertEqual(observed.production["required_criterion_ids"], ["EXAMPLE-artifact"])
                    self.assertEqual(closure.execute_qualified_completed(host, dry_run=True)["state"], "VALIDATED")
                    self.assertEqual(process.effects, [])
                    self.assertTrue(closure.execute_qualified_completed(host)["completed"])
                    self.assertEqual([effect[0] for effect in process.effects], ["comment", "close"])

    def test_production_drift_refuses_before_effect_and_remains_sticky(self):
        for target in ("task", "contract", "candidate", "acceptance", "database"):
            with self.subTest(target=target):
                case = self.builders.compact()
                with self.registered(case) as (host, process, custody):
                    self.reviewed(case, host, custody)
                    if target == "task":
                        process.bead["title"] = "EXAMPLE changed task"
                    elif target == "candidate":
                        (case.repo / "src/item.txt").write_text("EXAMPLE changed candidate\n")
                    elif target == "database":
                        db = Path(process.database)
                        db.rename(db.with_suffix(".original"))
                        db.touch(mode=0o600)
                    elif target == "acceptance":
                        path = process.store.root / (process.authority["acceptance_record"] + ".json")
                        path.write_bytes(path.read_bytes() + b" ")
                    else:
                        path = custody / "contract.json"
                        path.write_bytes(path.read_bytes() + b" ")
                    with self.assertRaises(original.ClosureError) as first:
                        closure.execute_qualified_completed(host)
                    with self.assertRaises(original.ClosureError) as second:
                        closure.execute_qualified_completed(host)
                    self.assertIs(first.exception, second.exception)
                    self.assertEqual(process.effects, [])

    def test_drift_after_summary_prevents_close_with_truthful_partial_state(self):
        for target in ("task", "candidate", "contract"):
            with self.subTest(target=target):
                case = self.builders.compact()
                with self.registered(case) as (host, process, custody):
                    self.reviewed(case, host, custody)
                    def drift(action):
                        if action[0] == "comment":
                            if target == "task":
                                process.bead["title"] = "EXAMPLE task drift"
                            elif target == "candidate":
                                (case.repo / "src/item.txt").write_text("EXAMPLE drift\n")
                            else:
                                path = custody / "contract.json"
                                path.write_bytes(path.read_bytes() + b" ")
                    process.after = drift
                    with self.assertRaises(original.ClosureError):
                        closure.execute_qualified_completed(host)
                    self.assertEqual([e[0] for e in process.effects], ["comment"])
                    self.assertTrue(host.report["comment_posted"])
                    self.assertTrue(host.report["partial_persistence"])
                    self.assertTrue(host.report["completion_unconfirmed"])

    def test_real_adapter_timeout_failure_and_interrupt_keep_original_exception_and_no_retry(self):
        for action_name, failure in (("comment", KeyboardInterrupt("EXAMPLE interruption")),
                                     ("comment", subprocess.TimeoutExpired(["bd"], 1)),
                                     ("close", subprocess.TimeoutExpired(["bd"], 1)),
                                     ("close", SystemExit("EXAMPLE close error")), ("close", None)):
            with self.subTest(action=action_name, failure=type(failure).__name__):
                case = self.builders.compact()
                with self.assertRaises(BaseException) as outside:
                    with self.registered(case) as (host, process, custody):
                        self.reviewed(case, host, custody)
                        def fail(action):
                            if action[0] == action_name:
                                if failure is None:
                                    process.returncode = 7
                                else:
                                    raise failure
                        process.after = fail
                        with self.assertRaises(BaseException) as first:
                            closure.execute_qualified_completed(host)
                        with self.assertRaises(BaseException) as second:
                            closure.execute_qualified_completed(host)
                        self.assertIs(first.exception, second.exception)
                        if isinstance(failure, subprocess.TimeoutExpired):
                            self.assertIs(first.exception.__cause__, failure)
                        elif failure is not None:
                            self.assertIs(first.exception, failure)
                        else:
                            self.assertIsInstance(first.exception, SystemExit)
                            self.assertEqual(str(first.exception), "EXAMPLE Beads error")
                        self.assertFalse(host.report["persistence_known"])
                        self.assertEqual(host.report["comment_posted"], action_name == "close")
                        self.assertEqual(len(process.effects), 2 if action_name == "close" else 1)
                        raise first.exception
                self.assertIs(outside.exception, first.exception)
                self.assertFalse(host.report["registration_active"])
                self.assertTrue(host.report["completion_unconfirmed"])

    def test_summary_author_and_task_metadata_are_required(self):
        for field in ("author", "issue_id"):
            with self.subTest(field=field):
                case = self.builders.compact()
                with self.registered(case) as (host, process, custody):
                    self.reviewed(case, host, custody)
                    def corrupt(action):
                        if action[0] == "comment":
                            added = process.bead["comments"][-1]
                            if field == "author":
                                added.pop("author")
                            else:
                                added["issue_id"] = "EXAMPLE-other-task"
                    process.after = corrupt
                    with self.assertRaises(original.ClosureError):
                        closure.execute_qualified_completed(host)
                    self.assertEqual([a[0] for a in process.effects], ["comment"])

    def test_post_close_drift_retains_confirmed_persistence_and_original_failure(self):
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            def drift(action):
                if action[0] == "close":
                    path = custody / "contract.json"
                    path.write_bytes(path.read_bytes() + b" ")
            process.after = drift
            with self.assertRaises(original.ClosureError) as first:
                closure.execute_qualified_completed(host)
            self.assertTrue(host.report["closed"])
            self.assertTrue(host.report["persistence_known"])
            self.assertFalse(host.report["completed"])
            self.assertTrue(host.report["completion_unconfirmed"])
            with self.assertRaises(original.ClosureError) as second:
                closure.execute_qualified_completed(host)
            self.assertIs(first.exception, second.exception)
            self.assertEqual([a[0] for a in process.effects], ["comment", "close"])
        self.assertTrue(host.report["closed"])
        self.assertTrue(host.report["persistence_known"])
        self.assertFalse(host.report["registration_active"])

    def test_database_and_candidate_cooperative_ownership_exclude_reuse(self):
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            checked = []
            def check(action):
                if action[0] not in ("comment", "close"):
                    return
                for path in (case.repo, Path(process.database).parent):
                    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(fd)
                checked.append(action[0])
            process.before = check
            self.assertTrue(closure.execute_qualified_completed(host)["completed"])
            self.assertEqual(checked, ["comment", "close"])


    def test_captured_original_callable_ignores_worker_global_adapter_replacement(self):
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            self.reviewed(case, host, custody)
            with patch.object(closure, "run_bd", side_effect=AssertionError("EXAMPLE worker callback")) as worker:
                self.assertTrue(closure.execute_qualified_completed(host)["completed"])
                worker.assert_not_called()
            self.assertEqual(len(process.effects), 2)

    def test_caller_written_production_approval_files_are_retired(self):
        """S4 approval retirement: production never reads the former sources."""
        case = self.builders.compact()
        with self.registered(case) as (host, process, custody):
            for name in ("review.json", "expectation.json"):
                (custody / name).write_bytes(b"EXAMPLE invalid caller approval")
            self.reviewed(case, host, custody)
            self.assertTrue(closure.execute_qualified_completed(host)["completed"])
            self.assertEqual([e[0] for e in process.effects], ["comment", "close"])


if __name__ == "__main__":
    unittest.main()
