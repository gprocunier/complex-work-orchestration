from __future__ import annotations

import concurrent.futures
import copy
import json
import os
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import offline_n1_host as HOST  # noqa: E402
import test_run_native_pool_live_canaries as FIXTURES  # noqa: E402
from cwo_core.native_control import NativeControlTurn, build_control_turn_contract  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture


TASK = "Produce the fake bounded result file."
TOKEN = "FAKE_OFFLINE_DONE"
OUTPUT = b"FAKE_RESULT: useful offline fixture output\n"
PINS = {"w14": "FAKE_CONFIGURATION_R1", "w15": "FAKE_PROFILE_R1"}
FAKE_WRITE_CALL_ID = "fake-result-write"
FAKE_WRITE_COMMAND = "FAKE_WRITE_RESULT result.txt"
FAKE_WRITE_ACK = "FAKE_RESULT_FILE_WRITTEN\n"


class FixtureCrash(BaseException):
    pass


@contextmanager
def repository_write_boundaries(roots):
    writes = []
    original_open, original_mkdir = os.open, os.mkdir

    def observe(path, dir_fd):
        raw = os.fsdecode(path)
        if not os.path.isabs(raw) and dir_fd is not None:
            raw = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), raw)
        resolved = Path(raw).resolve()
        if any(HOST._within(resolved, root) for root in roots):
            writes.append(str(resolved))

    def open_file(path, flags, mode=0o777, *, dir_fd=None):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            observe(path, dir_fd)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def make_directory(path, mode=0o777, *, dir_fd=None):
        observe(path, dir_fd)
        return original_mkdir(path, mode, dir_fd=dir_fd)

    with patch.object(os, "open", side_effect=open_file), patch.object(os, "mkdir", side_effect=make_directory):
        yield writes


class CompletingFakeServer(FIXTURES.FakeLiveThreadServer):
    def __init__(self, root, worker):
        super().__init__(root)
        self.root = worker
        self.sends = 0
        self.mode = "complete"
        self.on_send = None
        self.intent_path = root.parent / "operation.json"
        self.intent_observed = None
        self.partial_tail_boundary = None

    def observe_intent(self, message):
        intent = json.loads(self.intent_path.read_bytes())
        if intent["status"] != "reconciliation-required" or intent["receipt"] is not None:
            raise AssertionError("Durable invocation intent must precede the fake send.")
        if intent["binding"]["task"] != message or not intent["binding_sha256"]:
            raise AssertionError("Durable invocation intent must bind the exact fake task.")
        self.intent_observed = intent

    def start_turn(self, thread_id, message):
        self.sends += 1
        self.observe_intent(message)
        if self.on_send is not None:
            self.on_send()
        if self.mode == "crash":
            raise FixtureCrash("Fake crash after durable invocation intent.")
        if self.mode == "failure":
            raise RuntimeError("Fake synchronous send failure.")
        result = super().start_turn(thread_id, message)
        if self.mode == "pending":
            return result
        self.complete_turn()
        return result

    def complete_turn(self):
        self.set_boundary("valid")
        if self.mode == "missing-tool-receipt":
            (self.root / "result.txt").write_bytes(OUTPUT)
        else:
            self.record_completed_write()
        self.append_terminal("task_complete")
        self.status = "completed"
        self.items = [
            {
                "id": FAKE_WRITE_CALL_ID, "type": "commandExecution",
                "command": FAKE_WRITE_COMMAND, "cwd": str(self.root),
                "status": "completed", "exitCode": 0,
                "aggregatedOutput": FAKE_WRITE_ACK,
            },
            {"type": "agentMessage", "text": TOKEN if self.mode != "bad-token" else "FAKE_BAD"},
        ]

    def append_fake_record(self, kind, payload):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"type": kind, "payload": payload}) + "\n")

    def record_completed_write(self):
        event = {
            "turn_id": self.turn_id, "call_id": FAKE_WRITE_CALL_ID,
            "command": FAKE_WRITE_COMMAND.split(), "cwd": str(self.root),
            "source": "agent",
        }
        result = (
            "Chunk ID: FAKE_RESULT_WRITE\nWall time: 0.001 seconds\n"
            "Process exited with code 0\nFinal output:\n" + FAKE_WRITE_ACK
        )
        self.append_fake_record("response_item", {
            "type": "function_call", "name": "exec_command",
            "call_id": FAKE_WRITE_CALL_ID,
            "arguments": json.dumps({"cmd": FAKE_WRITE_COMMAND, "workdir": str(self.root)}),
        })
        self.append_fake_record("event_msg", {"type": "exec_command_begin", **event})
        (self.root / "result.txt").write_bytes(OUTPUT)
        self.append_fake_record("event_msg", {
            "type": "exec_command_end", **event, "exit_code": 0,
            "stdout": FAKE_WRITE_ACK, "stderr": "",
            "aggregated_output": FAKE_WRITE_ACK, "formatted_output": result,
            "status": "completed", "duration": {"secs": 0, "nanos": 1_000_000},
        })
        self.append_fake_record("response_item", {
            "type": "function_call_output", "call_id": FAKE_WRITE_CALL_ID,
            "output": result,
        })

    def archive_thread(self, thread_id):
        if self.mode == "unclosed":
            raise RuntimeError("Fake archive failure.")
        result = super().archive_thread(thread_id)
        if self.mode == "partial-tail":
            with self.path.open("ab") as stream:
                stream.write(b"{")
            self.partial_tail_boundary = "after-fake-archive-before-return"
        return result


class OfflineN1HostTests(unittest.TestCase):
    def setUp(self, *, seed_source=None):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.git(self.source, "init", "--quiet")
        configure_git_fixture(self.source)
        (self.source / "seed.txt").write_text("FAKE_SEED\n", encoding="utf-8")
        self.git(self.source, "add", "--", "seed.txt")
        self.git(self.source, "commit", "--quiet", "-m", "Fake seed fixture")
        if seed_source is not None:
            seed_source(self)
        self.target = self.clone("target")
        self.worker = self.clone("worker")

    def git(self, directory, *args):
        executable = HOST.workspace_capture.trusted_git()
        self.assertIsNotNone(executable)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Fake Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fake Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        return subprocess.run([executable.path, "-c", "core.hooksPath=/dev/null", "-C", str(directory), *args],
                              env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)

    def clone(self, name):
        destination = self.root / name
        self.git(self.root, "clone", "--quiet", "--no-hardlinks", "--", str(self.source), str(destination))
        configure_git_fixture(destination)
        return destination

    def case(self, name="host", mode="complete"):
        state = self.root / name
        state.mkdir()
        records = state / "records"
        records.mkdir()
        server = CompletingFakeServer(state / "fake-server", self.worker)
        server.mode = mode
        policy = {
            "minimum_tool_calls": 1,
            "required_evidence": {
                "predicates": ["trusted-terminal-boundary", "trusted-tool-call", "expected-workspace-mutation"],
                "sha256": [],
            },
            "allow_zero_tool_completion": False, "expected_mutation_mode": "mutable-isolated",
        }
        adapter = HOST.LiveThreadAdapter(
            server, server.thread_response(mutable=True), prompt=TASK, expected_token=TOKEN,
            worktree=self.worker, mutable=True, expected_mutation="result.txt",
            completion_evidence_policy=policy, record_dir=records, campaign_live_route=False,
        )
        bound = FIXTURES.LiveThreadBoundaryPhaseTests.controller_bind_and_arm(object(), adapter, arm=False)
        control = copy.deepcopy(bound["control_contract"])
        host = HOST.OfflineN1Host(state, self.target, self.worker)
        return host, adapter, server, control

    def run_case(self, case, **changes):
        host, adapter, _server, control = case
        values = {"outputs": ("result.txt",), "max_steps": 128, "configuration_pins": PINS}
        values.update(changes)
        return host.run("fake-operation", TASK, control, adapter, **values)

    def assert_capture_refused(self, action):
        with repository_write_boundaries((self.target, self.worker)) as writes:
            with patch.object(tempfile, "gettempdir", side_effect=AssertionError("Scratch probing is forbidden before validation.")):
                with patch.object(HOST.workspace_capture, "capture", wraps=HOST.workspace_capture.capture) as capture:
                    with self.assertRaisesRegex(HOST.OfflineHostError, "Scratch"):
                        action()
        self.assertEqual(writes, [])
        capture.assert_not_called()

    def test_scratch_candidates_refuse_before_capture_writes_or_callbacks(self):
        safe = self.root / "fake-safe-scratch"
        target = self.target / "fake-scratch"
        worker = self.worker / "fake-scratch"
        for path in (safe, target, worker):
            path.mkdir()
        alias = self.root / "fake-target-scratch-alias"
        alias.symlink_to(target, target_is_directory=True)
        case = self.case()
        host, adapter, server, _control = case
        defaults = HOST.workspace_capture.SCRATCH_PARENTS
        configurations = (
            ("cached-target", str(target), {}, defaults),
            ("cached-worker", str(worker), {}, defaults),
            ("cached-alias", str(alias), {}, defaults),
            ("alias-parent", str(alias) + "/..", {}, defaults),
            ("environment-tmpdir", None, {"TMPDIR": str(target)}, defaults),
            ("environment-temp", str(safe), {"TEMP": str(target)}, defaults),
            ("environment-tmp", str(safe), {"TMP": str(alias)}, defaults),
            ("alternate-parent", str(safe), {}, (str(safe), str(target))),
        )
        for name, cached, changes, parents in configurations:
            environment = {"TMPDIR": str(safe), "TEMP": str(safe), "TMP": str(safe), **changes}
            with self.subTest(configuration=name), patch.dict(os.environ, environment):
                with patch.object(tempfile, "tempdir", cached), patch.object(HOST.workspace_capture, "SCRATCH_PARENTS", parents):
                    self.assert_capture_refused(lambda: HOST.OfflineN1Host(host.state, self.target, self.worker))
                    self.assert_capture_refused(lambda: self.run_case(case))
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})
        self.assertFalse((host.state / "operation.json").exists())

    def test_mutable_zero_tool_policy_still_refuses_before_send(self):
        host, adapter, server, _control = self.case()
        policy = {
            "minimum_tool_calls": 0,
            "required_evidence": {"predicates": ["trusted-terminal-boundary", "expected-workspace-mutation"], "sha256": []},
            "allow_zero_tool_completion": True, "expected_mutation_mode": "mutable-isolated",
        }
        with self.assertRaisesRegex(FIXTURES.LIVE.AppServerError, "zero-tool-policy-must-be-read-only") as raised:
            HOST.LiveThreadAdapter(
                server, server.thread_response(mutable=True), prompt=TASK, expected_token=TOKEN,
                worktree=self.worker, mutable=True, expected_mutation="result.txt",
                completion_evidence_policy=policy, record_dir=adapter.record_dir,
            )
        self.assertIn("zero-tool-policy-observable-action-conflict", str(raised.exception))
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})
        self.assertFalse((host.state / "operation.json").exists())

    def test_missing_record_reaches_original_callbacks_after_durable_intent(self):
        case = self.case()
        host, adapter, server, _control = case
        self.assertFalse((host.state / "operation.json").exists())
        report = self.run_case(case)
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        self.assertEqual(server.sends, 1)
        self.assertEqual(server.intent_observed["status"], "reconciliation-required")
        self.assertIsNone(server.intent_observed["receipt"])
        self.assertIsNone(server.intent_observed["artifact"])
        self.assertEqual(server.intent_observed["binding"], report["binding"])
        self.assertEqual(report["receipt"]["actions"][:4], ["arm", "send-input", "mark-dispatched", "check"])
        self.assertTrue({"arm", "send_input", "mark_dispatched", "check", "finalize", "close"} <= set(adapter.callback_latencies))
        dispatch = json.loads((adapter.record_dir / f"{server.thread_id}-dispatch.json").read_bytes())
        self.assertEqual(dispatch["turn_id"], report["receipt"]["submission_id"])
        self.assertEqual(host.status("fake-operation"), report)

    def test_missing_record_with_unsettled_file_refuses_before_callbacks(self):
        case = self.case()
        host, adapter, server, _control = case
        (host.state / "operation.next").write_text("FAKE_UNSETTLED_STATE\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reconciliation"):
            self.run_case(case)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})
        self.assertFalse((host.state / "operation.json").exists())

    def test_projected_tool_without_trusted_completion_is_not_ready(self):
        case = self.case(mode="missing-tool-receipt")
        host, adapter, server, _control = case
        report = self.run_case(case)
        self.assertEqual(server.sends, 1)
        self.assertIsNotNone(server.intent_observed)
        self.assertTrue(adapter.callback_latencies["check"])
        self.assertEqual(report["status"], "reconciliation-required")
        self.assertIsNone(report["artifact"])
        self.assertFalse((host.state / "artifact").exists())
        self.assertNotIn("complete", report["receipt"]["decisions"])
        self.assertEqual(report["summary"]["completed_tool_calls"], 0)
        self.assertEqual(report["summary"]["projected_tool_calls"], 1)

    def test_real_composition_and_immutable_completed_bytes(self):
        case = self.case()
        host, adapter, server, _control = case
        self.assertIs(HOST.NativeControlTurn, NativeControlTurn)
        self.assertIs(type(adapter), HOST.LiveThreadAdapter)
        callbacks = adapter.callbacks()
        self.assertIs(callbacks["send_input"].__self__, adapter)
        self.assertIs(callbacks["send_input"].__func__, HOST.LiveThreadAdapter.send_input)
        with repository_write_boundaries((self.target,)) as writes:
            report = self.run_case(case)
        self.assertEqual(writes, [])
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        self.assertEqual(report["summary"]["adapter_evidence"]["reasons"], [])
        self.assertEqual(report["summary"]["adapter_evidence"]["artifact_disposition"], "accepted")
        self.assertEqual(report["summary"]["tool_calls"], 1)
        self.assertEqual(report["summary"]["completed_tool_calls"], 1)
        self.assertEqual(report["summary"]["projected_tool_calls"], 1)
        self.assertTrue(report["summary"]["completion_evidence_observation"]["minimum_tool_calls_met"])
        receipt = report["summary"]["trusted_tool_receipts"][0]
        self.assertEqual(receipt["tool"], "exec_command")
        self.assertEqual(receipt["pairing_status"], "paired")
        self.assertEqual(receipt["result_kind"], "paired-success")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertTrue(server.archived)
        self.assertTrue(adapter.archived)
        self.assertEqual(report["receipt"]["terminal_state"], "completed")
        self.assertEqual((host.state / "artifact" / "file-0000").read_bytes(), OUTPUT)
        self.assertEqual(report["artifact"]["files"][0]["size"], len(OUTPUT))
        self.assertFalse(any(report[name] for name in HOST._FLAGS_FALSE))
        (self.worker / "result.txt").write_bytes(b"FAKE_CHANGED_WORKER\n")
        verification = host.verify_artifact(report, report["binding"]["target"])
        self.assertTrue(verification["valid"], verification["errors"])
        self.assertFalse(any(verification[name] for name in HOST._FLAGS_FALSE))
        self.assertEqual((host.state / "artifact" / "file-0000").read_bytes(), OUTPUT)

    def test_completed_guard_requires_original_evidence_and_rejects_partial_tail(self):
        case = self.case()
        report = self.run_case(case)
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        self.assertGreater(case[1]._evidence_sequence, 0)
        self.assertTrue(HOST._successful(report["receipt"], report["summary"], case[3]))
        summary = copy.deepcopy(report["summary"])
        summary["session_boundary"]["trailing_partial"] = True
        self.assertFalse(HOST._successful(report["receipt"], summary, case[3]))
        summary = copy.deepcopy(report["summary"])
        summary.pop("adapter_evidence")
        self.assertFalse(HOST._successful(report["receipt"], summary, case[3]))
        summary = copy.deepcopy(report["summary"])
        summary["adapter_evidence"]["reasons"].append("FAKE_ORIGINAL_REJECTION")
        self.assertFalse(HOST._successful(report["receipt"], summary, case[3]))

    def test_real_partial_tail_after_fake_archive_preserves_original_refusal(self):
        case = self.case(mode="partial-tail")
        host, adapter, server, _control = case
        report = self.run_case(case)
        self.assertEqual(server.partial_tail_boundary, "after-fake-archive-before-return")
        self.assertEqual(server.sends, 1)
        self.assertTrue(server.archived)
        self.assertTrue({"check", "finalize", "close"} <= set(adapter.callback_latencies))
        self.assertIn("close", report["receipt"]["actions"])
        raw = server.path.read_bytes()
        self.assertTrue(raw.endswith(b"\n{"))
        records = [json.loads(line) for line in raw[:-1].splitlines()]
        self.assertEqual(records[-1]["payload"]["type"], "task_complete")
        self.assertTrue(any(record.get("payload", {}).get("type") == "exec_command_end" for record in records))
        self.assertEqual((self.worker / "result.txt").read_bytes(), OUTPUT)
        self.assertEqual(report["status"], "reconciliation-required")
        self.assertIsNone(report["artifact"])
        self.assertFalse((host.state / "artifact").exists())
        evidence = (report["summary"] or {}).get("adapter_evidence")
        if evidence is None:
            self.assertIn("partial", report["error"].lower())
        else:
            self.assertIn("terminal-session-boundary-partial", evidence["reasons"])
            self.assertTrue(evidence["protected_fault"])
            self.assertEqual(evidence["artifact_disposition"], "rejected")
        self.assertEqual(host.status("fake-operation"), report)

    def test_identical_replay_and_mutated_inputs(self):
        case = self.case()
        host, adapter, server, control = case
        report = self.run_case(case)
        calls = copy.deepcopy(adapter.callback_latencies)
        self.assertEqual(self.run_case(case), report)
        self.assertEqual(adapter.callback_latencies, calls)
        self.assertEqual(server.sends, 1)
        with self.assertRaises(ValueError):
            host.run("fake-operation", "FAKE_CHANGED_TASK", control, adapter, outputs=("result.txt",), max_steps=128, configuration_pins=PINS)
        with self.assertRaises(ValueError):
            self.run_case(case, max_steps=127)
        with self.assertRaises(ValueError):
            self.run_case(case, configuration_pins={**PINS, "w15": "FAKE_CHANGED_PIN"})
        with self.assertRaises(ValueError):
            host.run("fake-other", TASK, control, adapter, outputs=("result.txt",), max_steps=128, configuration_pins=PINS)
        self.assertEqual(server.sends, 1)

    def test_contract_is_copied_before_synchronous_send(self):
        case = self.case()
        _host, _adapter, server, control = case
        server.on_send = lambda: control["allowed_actions"].clear()
        report = self.run_case(case)
        self.assertEqual(report["status"], "artifact-ready")
        self.assertTrue(report["binding"]["contract"]["allowed_actions"])
        self.assertEqual(control["allowed_actions"], [])

    def test_real_adapter_and_actual_contract_are_required(self):
        case = self.case()
        host, adapter, server, control = case
        changed = build_control_turn_contract(
            state_file=control["state_file"], agent_id=control["agent_id"],
            control_turn_id="fake-different-turn", task_sha256=control["task_sha256"],
            poll_interval_ms=control["poll_interval_ms"],
        )
        with self.assertRaises(ValueError):
            host.run("fake-operation", TASK, changed, adapter, outputs=("result.txt",), max_steps=128, configuration_pins=PINS)
        with self.assertRaises(ValueError):
            host.run("fake-operation", TASK, control, {}, outputs=("result.txt",), max_steps=128, configuration_pins=PINS)
        adapter.send_input = lambda **_kwargs: {"submission_id": "FAKE_FORGED"}
        with self.assertRaises(ValueError):
            self.run_case(case)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})

    def test_competing_claims_send_at_most_once(self):
        import threading
        case = self.case()
        host, _adapter, server, _control = case
        other = HOST.OfflineN1Host(host.state, self.target, self.worker)
        entered, release = threading.Event(), threading.Event()
        def pause():
            entered.set()
            if not release.wait(10):
                raise RuntimeError("Fake send wait exceeded its bound.")
        server.on_send = pause
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.run_case, case)
            self.assertTrue(entered.wait(10))
            try:
                with self.assertRaisesRegex(ValueError, "busy"):
                    self.run_case((other, *case[1:]))
            finally:
                release.set()
            self.assertEqual(future.result(timeout=20)["status"], "artifact-ready")
        self.assertEqual(server.sends, 1)

    def test_restart_never_redispatches_unknown_intent(self):
        case = self.case(mode="crash")
        host, adapter, server, control = case
        with self.assertRaises(FixtureCrash):
            self.run_case(case)
        restarted = HOST.OfflineN1Host(host.state, self.target, self.worker)
        stored = restarted.status("fake-operation")
        self.assertEqual(stored["status"], "reconciliation-required")
        self.assertEqual(self.run_case((restarted, adapter, server, control)), stored)
        self.assertEqual(server.sends, 1)
        self.assertIsNone(stored["artifact"])

    def test_failed_missing_unclosed_and_control_lost_are_not_ready(self):
        for mode in ("failure", "bad-token", "unclosed", "pending"):
            with self.subTest(mode=mode):
                case = self.case(name="host-" + mode, mode=mode)
                report = self.run_case(case, max_steps=8 if mode == "pending" else 128)
                self.assertEqual(report["status"], "reconciliation-required")
                self.assertIsNone(report["artifact"])
                self.assertFalse((case[0].state / "artifact").exists())
                if mode == "pending" and report["receipt"] is not None:
                    self.assertIn("interrupt:control-lost", report["receipt"]["decisions"])

    def test_target_drift_during_execution_invalidates_readiness(self):
        case = self.case()
        case[2].on_send = lambda: (self.target / "seed.txt").write_bytes(b"FAKE_TARGET_DRIFT\n")
        report = self.run_case(case)
        self.assertEqual(report["status"], "reconciliation-required")
        self.assertIsNone(report["artifact"])

    def test_target_and_original_worktree_drift_refuse_before_callbacks(self):
        case = self.case()
        host, adapter, server, _control = case
        original = adapter.worktree
        adapter.worktree = self.target
        with self.assertRaises(ValueError):
            self.run_case(case)
        adapter.worktree = original
        (self.target / "seed.txt").write_bytes(b"FAKE_TARGET_DRIFT\n")
        with self.assertRaises(ValueError):
            self.run_case(case)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})

    def test_invalid_bounded_inputs_refuse_before_callbacks(self):
        case = self.case()
        for paths in (("../escape",), ("/absolute",), ("result.txt", "result.txt"), (".git/HEAD",), ("x" * 241,)):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                self.run_case(case, outputs=paths)
        with self.assertRaises(ValueError):
            self.run_case(case, max_steps=0)
        host, adapter, server, control = case
        with self.assertRaises(ValueError):
            host.run("fake-operation", "X" * (HOST.MAX_TASK_BYTES + 1), control, adapter,
                     outputs=("result.txt",), max_steps=128, configuration_pins=PINS)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})

    def test_unsafe_and_oversized_worker_outputs_are_rejected(self):
        for kind in ("symlink", "special", "oversize", "missing"):
            case = self.case(name="host-" + kind)
            host, _adapter, server, _control = case
            def replace_output(kind=kind):
                output = self.worker / "result.txt"
                if output.exists() or output.is_symlink():
                    output.unlink()
                if kind == "symlink":
                    output.symlink_to(self.source / "seed.txt")
                elif kind == "special":
                    os.mkfifo(output)
                elif kind == "oversize":
                    output.write_bytes(b"X" * (HOST.MAX_FILE_BYTES + 1))
            original_archive = server.archive_thread
            def archive(thread_id):
                result = original_archive(thread_id)
                replace_output()
                return result
            server.archive_thread = archive
            report = self.run_case(case)
            self.assertEqual(report["status"], "reconciliation-required")
            self.assertIsNone(report["artifact"])
            output = self.worker / "result.txt"
            if output.exists() or output.is_symlink():
                output.unlink()

    def test_artifact_and_target_freshness_are_rechecked(self):
        case = self.case()
        host, _adapter, _server, _control = case
        report = self.run_case(case)
        expected = report["binding"]["target"]
        self.assertFalse(host.verify_artifact(report, {})["valid"])
        (self.target / "seed.txt").write_bytes(b"FAKE_DRIFT\n")
        self.assertFalse(host.verify_artifact(report, expected)["valid"])
        (self.target / "seed.txt").write_bytes(b"FAKE_SEED\n")
        (host.state / "artifact").chmod(0o700)
        (host.state / "artifact" / "file-0000").unlink()
        (host.state / "artifact").chmod(0o500)
        self.assertFalse(host.verify_artifact(report, expected)["valid"])

    def test_malformed_stored_state_refuses_before_callbacks(self):
        case = self.case()
        host, adapter, server, _control = case
        (host.state / "operation.json").write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_case(case)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})

    def assert_head_refused(self, case):
        host, adapter, server, _control = case
        with self.assertRaises((HOST.OfflineHostError, OSError)):
            HOST.OfflineN1Host(host.state, self.target, self.worker)
        with self.assertRaises((HOST.OfflineHostError, OSError)):
            self.run_case(case)
        self.assertEqual(server.sends, 0)
        self.assertEqual(adapter.callback_latencies, {})
        self.assertFalse((host.state / "operation.json").exists())

    def test_detached_commit_heads_allow_real_fake_completion(self):
        commit = self.git(self.source, "rev-parse", "HEAD").stdout.decode("ascii").strip()
        for root in (self.target, self.worker):
            (root / ".git" / "HEAD").write_text(commit + "\n", encoding="ascii")
        case = self.case()
        report = self.run_case(case)
        self.assertEqual(report["status"], "artifact-ready", report["error"])
        self.assertEqual(report["binding"]["worker_identity"]["head_commit"], commit)
        self.assertEqual(report["binding"]["target_identity"]["head_commit"], commit)

    def test_tree_heads_refuse_constructor_and_callbacks(self):
        case = self.case()
        tree = self.git(self.source, "rev-parse", "HEAD^{tree}").stdout.decode("ascii").strip()
        for root in (self.target, self.worker):
            (root / ".git" / "HEAD").write_text(tree + "\n", encoding="ascii")
        with self.assertRaisesRegex(HOST.OfflineHostError, "HEAD must name a verified commit"):
            HOST._capture(self.worker, (self.target, self.worker))
        self.assert_head_refused(case)

    def test_missing_and_malformed_head_objects_refuse_before_callbacks(self):
        case = self.case()
        commit = self.git(self.source, "rev-parse", "HEAD").stdout.decode("ascii").strip()
        for root in (self.target, self.worker):
            head = root / ".git" / "HEAD"
            original_head = head.read_bytes()
            object_path = root / ".git" / "objects" / commit[:2] / commit[2:]
            original_object = object_path.read_bytes()
            for kind in ("missing-object", "malformed-object", "malformed-head"):
                with self.subTest(repository=root.name, failure=kind):
                    try:
                        if kind == "missing-object":
                            object_path.unlink()
                        elif kind == "malformed-object":
                            object_path.write_bytes(b"FAKE_INVALID_OBJECT\n")
                        else:
                            head.write_bytes(b"FAKE_INVALID_HEAD\n")
                        self.assert_head_refused(case)
                    finally:
                        object_path.write_bytes(original_object)
                        head.write_bytes(original_head)

    def test_shared_git_metadata_and_missing_store_are_refused(self):
        state = self.root / "host"
        state.mkdir()
        for kind in ("commondir", "alternate", "hardlink", "missing", "gitfile"):
            worker = self.clone("worker-" + kind)
            git = worker / ".git"
            if kind == "commondir":
                (git / "commondir").write_text(str(self.target / ".git") + "\n", encoding="utf-8")
            elif kind == "alternate":
                (git / "objects" / "info" / "alternates").write_text(str(self.target / ".git" / "objects") + "\n", encoding="utf-8")
            elif kind == "hardlink":
                (git / "HEAD").unlink()
                os.link(self.source / ".git" / "HEAD", git / "HEAD")
            elif kind == "missing":
                (git / "objects").rename(worker / "fake-unused-store")
            else:
                git.rename(worker / "fake-unused-store")
                (worker / ".git").write_text("gitdir: " + str(self.target / ".git") + "\n", encoding="utf-8")
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                HOST.OfflineN1Host(state, self.target, worker)

    def test_noncanonical_nested_symlink_and_special_roots_are_refused(self):
        state = self.root / "host"
        state.mkdir()
        alias = self.root / "worker-alias"
        alias.symlink_to(self.worker, target_is_directory=True)
        special = self.root / "fake-fifo"
        os.mkfifo(special)
        nested = self.target / "nested-worker"
        nested.mkdir()
        for worker in (self.target, nested, alias, special, str(self.worker) + "/../worker"):
            with self.subTest(worker=str(worker)), self.assertRaises((ValueError, OSError)):
                HOST.OfflineN1Host(state, self.target, worker)


if __name__ == "__main__":
    unittest.main()
