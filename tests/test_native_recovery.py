from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_recovery import (
    build_recovery_contract,
    build_recovery_lineage,
    replay_is_allowed,
    verify_native_worker_semantics,
)
from cwo_core.native_worker_contracts import (
    normalize_action_receipts,
    packet_v3_phase_contract,
    verify_first_action,
)
from cwo_core.workspace import (
    WriteScopeLeaseCollision,
    acquire_write_scope_lease,
    capture_workspace_baseline,
    clear_write_scope_leases,
    compare_workspace_baseline,
)


MODEL = "gpt-5.3-codex-spark"


def _packet() -> dict:
    return {
        "packet_id": "packet-1",
        "bead_id": "bead-1",
        "session_id": "session-1",
        "segment_id": "segment-1",
        "requested_model": MODEL,
        "phase_contract": packet_v3_phase_contract("implementation"),
    }


def _claims(**overrides) -> dict:
    value = {
        "packet_id": "packet-1",
        "bead_id": "bead-1",
        "session_id": "session-1",
        "segment_id": "segment-1",
        "requested_model": MODEL,
        "actual_model": MODEL,
        "attestation_status": "trusted",
        "attestation_source": "trusted-session-jsonl",
        "status": "completed",
        "artifact_class": "implementation-patch",
        "files_touched": ["src/a.py"],
        "commands_run": [],
        "usage": {"tool_calls": 1},
    }
    value.update(overrides)
    return value


def _trusted_usage() -> dict:
    return {
        "session_id": "session-1",
        "segment_id": "segment-1",
        "actual_model": MODEL,
        "attestation_status": "trusted",
        "attestation_source": "trusted-session-jsonl",
        "tool_calls": 1,
    }


def _workspace(**overrides) -> dict:
    value = {
        "changed_paths": ["src/a.py"],
        "unexpected_mutation_detected": False,
        "attribution_ambiguous": False,
        "incomplete": False,
    }
    value.update(overrides)
    return value


class NativeRecoveryTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_write_scope_leases()

    def test_recovery_contract_and_replay_remain_inert(self) -> None:
        for version in (2, 3):
            contract = build_recovery_contract(version=version)
            self.assertFalse(contract["enabled"])
            self.assertFalse(contract["autonomous_replay"])
            self.assertEqual(contract["max_retries"], 0)
            self.assertFalse(replay_is_allowed(recovery_contract=contract))
        with self.assertRaises(ValueError):
            build_recovery_contract(version=4)
        self.assertFalse(
            replay_is_allowed(
                recovery_contract={"enabled": True, "autonomous_replay": True},
                workspace_evidence={"incomplete": False},
            )
        )

    def test_lineage_is_strict_and_deterministic(self) -> None:
        self.assertEqual(
            build_recovery_lineage("root"),
            {"root_packet_id": "root", "parent_packet_id": None, "attempt": 0},
        )
        self.assertEqual(
            build_recovery_lineage("child", root_packet_id="root", parent_packet_id="root", attempt=1),
            {"root_packet_id": "root", "parent_packet_id": "root", "attempt": 1},
        )
        for kwargs in (
            {"packet_id": ""},
            {"packet_id": "x", "attempt": 2},
            {"packet_id": "x", "parent_packet_id": "p", "attempt": 0},
            {"packet_id": "x", "attempt": 1},
            {"packet_id": "x", "parent_packet_id": "x", "attempt": 1},
        ):
            with self.assertRaises(ValueError):
                build_recovery_lineage(**kwargs)

    def test_action_receipts_pair_function_and_custom_calls(self) -> None:
        records = [
            {"type": "response_item", "payload": {"type": "function_call", "call_id": "a", "name": "exec_command", "arguments": json.dumps({"cmd": "python -m unittest tests.test_x"})}},
            {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "a", "output": "ok", "exit_code": 0}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "b", "name": "apply_patch", "input": "*** Begin Patch"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "b", "output": "Done!", "exit_code": 0}},
        ]
        receipts = normalize_action_receipts(records, segment_id="segment-1")
        self.assertEqual([item["pairing_status"] for item in receipts], ["paired", "paired"])
        self.assertEqual([item["action_class"] for item in receipts], ["test", "write"])
        self.assertEqual([item["exit_code"] for item in receipts], [0, 0])
        self.assertTrue(all(item["segment"] == "segment-1" for item in receipts))

    def test_action_receipts_fail_closed_for_unpaired_output(self) -> None:
        records = [{"type": "response_item", "payload": {"type": "function_call_output", "call_id": "lost", "output": "x"}}]
        receipt = normalize_action_receipts(records)[0]
        self.assertEqual(receipt["pairing_status"], "unpaired")
        self.assertEqual(receipt["action_class"], "unknown")
        self.assertEqual(receipt["typed_result"]["kind"], "unpaired-output")

    def test_action_receipts_classify_only_exact_exec_interruption(self) -> None:
        def result(output: str, **overrides: object) -> dict:
            records = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "interrupt",
                        "name": "exec_command",
                        "arguments": json.dumps({"cmd": "sleep 20"}),
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call_output",
                        "call_id": "interrupt",
                        "output": output,
                        **overrides,
                    },
                },
            ]
            return normalize_action_receipts(records)[0]

        interrupted = result("aborted by user after 1.3s")
        self.assertEqual(interrupted["pairing_status"], "paired")
        self.assertEqual(
            interrupted["typed_result"]["kind"],
            "paired-interrupted",
        )
        self.assertIsNone(interrupted["exit_code"])

        for output in (
            "aborted by user",
            "aborted by user after -1.3s",
            "aborted by user after 1.3 seconds",
            "prefix aborted by user after 1.3s",
            "aborted by user after 1.3s\n",
        ):
            with self.subTest(output=output):
                receipt = result(output)
                self.assertEqual(
                    receipt["typed_result"]["kind"],
                    "paired-unknown",
                )

        contradictory = result(
            "aborted by user after 1.3s",
            exit_code=0,
        )
        self.assertEqual(contradictory["pairing_status"], "ambiguous")
        self.assertEqual(
            contradictory["typed_result"]["kind"],
            "ambiguous-call-or-output-cardinality",
        )

    def test_action_receipts_preserve_failed_patch_retry_trace(self) -> None:
        turn_id = "turn-1"
        patch = (
            "*** Begin Patch\n"
            "*** Update File: targets/activation.txt\n"
            "@@\n"
            "+activation-preview-mutated\n"
            "*** End of File\n"
            "*** End Patch\n"
        )
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "patch-failed",
                    "name": "apply_patch",
                    "input": patch.replace("+activation", "activation"),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "patch-failed",
                    "output": "apply_patch verification failed: missing line",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "patch-ok",
                    "name": "apply_patch",
                    "input": patch,
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "patch_apply_end",
                    "call_id": "patch-ok",
                    "turn_id": turn_id,
                    "success": True,
                    "status": "completed",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "patch-ok",
                    "output": "Exit code: 0\nOutput:\nSuccess.\n",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "check",
                    "name": "exec_command",
                    "arguments": json.dumps(
                        {"cmd": "git diff --check"}
                    ),
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "check",
                    "output": (
                        "Chunk ID: abc\nWall time: 0.1 seconds\n"
                        "Process exited with code 0\nOutput:\n"
                    ),
                },
            },
        ]
        receipts = normalize_action_receipts(
            records,
            segment_id=turn_id,
        )
        self.assertEqual(
            [item["typed_result"]["kind"] for item in receipts],
            ["paired-failure", "paired-success", "paired-success"],
        )
        self.assertEqual(
            [item["exit_code"] for item in receipts],
            [1, 0, 0],
        )
        self.assertEqual(
            [item["sequence"] for item in receipts],
            [0, 1, 2],
        )

    def test_action_receipts_reject_unknown_and_contradictory_results(
        self,
    ) -> None:
        cases = (
            (
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call",
                            "call_id": "patch",
                            "name": "apply_patch",
                            "input": "*** Begin Patch",
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call_output",
                            "call_id": "patch",
                            "output": "Exit code: 0\nOutput:\nSuccess.\n",
                        },
                    },
                ],
                "paired-unknown",
            ),
            (
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "call_id": "exec",
                            "name": "exec_command",
                            "arguments": "{}",
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "exec",
                            "exit_code": 0,
                            "output": "Process exited with code 7\n",
                        },
                    },
                ],
                "ambiguous-call-or-output-cardinality",
            ),
            (
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call",
                            "call_id": "patch",
                            "name": "apply_patch",
                            "input": "*** Begin Patch",
                        },
                    },
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "patch_apply_end",
                            "call_id": "patch",
                            "success": True,
                            "status": "completed",
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call_output",
                            "call_id": "patch",
                            "output": (
                                "apply_patch verification failed: "
                                "target mismatch"
                            ),
                        },
                    },
                ],
                "ambiguous-call-or-output-cardinality",
            ),
        )
        for records, expected in cases:
            with self.subTest(expected=expected):
                receipt = normalize_action_receipts(records)[0]
                self.assertEqual(
                    receipt["typed_result"]["kind"],
                    expected,
                )

    def test_duplicate_call_ids_preserve_every_attempt(self) -> None:
        records = []
        for tool, arguments in (
            (
                "apply_patch",
                {"input": "*** Begin Patch\n*** End Patch"},
            ),
            (
                "exec_command",
                {"cmd": "git diff --check"},
            ),
        ):
            records.extend(
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call"
                            if tool == "apply_patch"
                            else "function_call",
                            "call_id": "reused",
                            "name": tool,
                            **arguments,
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "custom_tool_call_output"
                            if tool == "apply_patch"
                            else "function_call_output",
                            "call_id": "reused",
                            "exit_code": 0,
                            "output": "bounded",
                        },
                    },
                ]
            )

        receipts = normalize_action_receipts(records)

        self.assertEqual(len(receipts), 2)
        self.assertEqual(
            [receipt["tool"] for receipt in receipts],
            ["apply_patch", "exec_command"],
        )
        self.assertEqual(
            [receipt["sequence"] for receipt in receipts],
            [0, 1],
        )
        self.assertTrue(
            all(
                receipt["pairing_status"] == "ambiguous"
                and receipt["typed_result"]["kind"]
                == "ambiguous-call-or-output-cardinality"
                for receipt in receipts
            )
        )
        self.assertNotEqual(
            receipts[0]["canonical_argument_hash"],
            receipts[1]["canonical_argument_hash"],
        )

    def test_patch_completion_event_must_match_call_order_and_turn(
        self,
    ) -> None:
        call = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "patch",
                "name": "apply_patch",
                "input": "*** Begin Patch",
            },
        }
        output = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "patch",
                "output": "Exit code: 0\nOutput:\nSuccess.\n",
            },
        }
        event = {
            "type": "event_msg",
            "payload": {
                "type": "patch_apply_end",
                "call_id": "patch",
                "turn_id": "turn-1",
                "success": True,
                "status": "completed",
            },
        }
        for label, records in (
            ("event-after-output", [call, output, event]),
            (
                "wrong-turn",
                [
                    call,
                    {
                        **event,
                        "payload": {
                            **event["payload"],
                            "turn_id": "other-turn",
                        },
                    },
                    output,
                ],
            ),
        ):
            with self.subTest(label=label):
                receipt = normalize_action_receipts(
                    records,
                    segment_id="turn-1",
                )[0]
                self.assertEqual(receipt["pairing_status"], "ambiguous")
                self.assertEqual(
                    receipt["typed_result"]["kind"],
                    "ambiguous-call-or-output-cardinality",
                )

        missing_id_event = {
            **event,
            "payload": {
                key: value
                for key, value in event["payload"].items()
                if key != "call_id"
            },
        }
        receipts = normalize_action_receipts(
            [call, missing_id_event, output],
            segment_id="turn-1",
        )
        self.assertEqual(
            receipts[0]["typed_result"]["kind"],
            "paired-unknown",
        )
        self.assertTrue(
            any(
                receipt["pairing_status"] == "unpaired"
                and receipt["action_class"] == "unknown"
                for receipt in receipts[1:]
            )
        )

    def test_first_action_contract_is_fail_closed(self) -> None:
        phase = packet_v3_phase_contract("implementation")
        self.assertTrue(
            verify_first_action(
                {"action_class": "read", "pairing_status": "paired"},
                phase,
                elapsed_seconds=1,
            )["eligible"]
        )
        for receipt, elapsed in (
            (None, 1),
            ({"action_class": "unknown", "pairing_status": "unpaired"}, 1),
            ({"action_class": "write", "pairing_status": "paired"}, 1),
            ({"action_class": "read", "pairing_status": "paired"}, 31),
        ):
            self.assertTrue(verify_first_action(receipt, phase, elapsed_seconds=elapsed)["fail_closed"])

    def test_semantic_verifier_accepts_receipt_bound_claims(self) -> None:
        result = verify_native_worker_semantics(
            _packet(), _claims(), _trusted_usage(), [], _workspace(), {"status": "pass"}
        )
        self.assertTrue(result["eligible"])
        self.assertFalse(result["fail_closed"])

    def test_semantic_verifier_rejects_identity_model_usage_and_file_contradictions(self) -> None:
        cases = (
            (_claims(packet_id="other"), _trusted_usage(), _workspace()),
            (_claims(actual_model="other"), _trusted_usage(), _workspace()),
            (_claims(usage={"tool_calls": 99}), _trusted_usage(), _workspace()),
            (_claims(files_touched=["src/missing.py"]), _trusted_usage(), _workspace()),
        )
        for claims, usage, workspace in cases:
            with self.subTest(claims=claims):
                result = verify_native_worker_semantics(_packet(), claims, usage, [], workspace, {"status": "pass"})
                self.assertTrue(result["fail_closed"])
                self.assertTrue(result["errors"])

    def test_semantic_verifier_rejects_unpaired_commands_results_artifacts_and_validation(self) -> None:
        bad_receipt = {"pairing_status": "unpaired", "action_class": "unknown", "redacted_command": "", "exit_code": None}
        cases = (
            (_claims(), [bad_receipt], {"status": "pass"}),
            (_claims(commands_run=["python missing.py"]), [], {"status": "pass"}),
            (_claims(command_results=[{"exit_code": 7}]), [], {"status": "pass"}),
            (_claims(artifact_class="wrong"), [], {"status": "pass"}),
            (_claims(), [], {"status": "failed"}),
            (_claims(), [], {"status": "pass", "contradiction": True}),
        )
        for claims, receipts, validation in cases:
            with self.subTest(validation=validation):
                result = verify_native_worker_semantics(_packet(), claims, _trusted_usage(), receipts, _workspace(), validation)
                self.assertTrue(result["fail_closed"])
                self.assertTrue(result["errors"])

    def test_semantic_verifier_rejects_incomplete_or_ambiguous_workspace_evidence(self) -> None:
        for workspace in (
            _workspace(incomplete=True),
            _workspace(attribution_ambiguous=True),
            _workspace(unexpected_mutation_detected=True),
        ):
            result = verify_native_worker_semantics(_packet(), _claims(), _trusted_usage(), [], workspace, {"status": "pass"})
            self.assertTrue(result["fail_closed"], result)
            self.assertTrue(result["errors"], result)

    def test_content_baseline_detects_same_status_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            path = root / "tracked.txt"
            path.write_text("base\\n")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True)
            path.write_text("first\\n")
            before = capture_workspace_baseline(root, allowed_paths=["tracked.txt"])
            path.write_text("second\\n")
            after = capture_workspace_baseline(root, allowed_paths=["tracked.txt"])
            result = compare_workspace_baseline(before, after, allowed_paths=["tracked.txt"])
            self.assertTrue(result["mutation_detected"])
            self.assertEqual(result["mutation_categories"]["scoped"], ["tracked.txt"])
            self.assertFalse(result["unexpected_mutation_detected"])

    def test_content_baseline_caps_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            path = root / "large.bin"
            path.write_bytes(b"x" * 64)
            subprocess.run(["git", "-C", str(root), "add", "large.bin"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"], check=True)
            baseline = capture_workspace_baseline(root, allowed_paths=["large.bin"], max_bytes=8)
            self.assertTrue(baseline["incomplete"], baseline)
            self.assertFalse(baseline["baseline_complete"])
            self.assertFalse(baseline["replay_allowed"])

    def test_workspace_diff_separates_out_of_scope_and_unchanged_dirty(self) -> None:
        before = {
            "cwd": "/tmp/example",
            "allowed_paths": ["src"],
            "include_untracked": True,
            "tracked_status": [" M src/dirty.py"],
            "preexisting_dirty_paths": ["src/dirty.py"],
            "content_fingerprints": {
                "src/dirty.py": {"sha256": "a", "size": 1},
                "outside.py": {"sha256": "a", "size": 1},
            },
            "incomplete": False,
        }
        after = {
            **before,
            "content_fingerprints": {
                "src/dirty.py": {"sha256": "a", "size": 1},
                "outside.py": {"sha256": "b", "size": 1},
            },
        }
        result = compare_workspace_baseline(before, after, allowed_paths=["src"])
        self.assertEqual(result["unchanged_dirty"], ["src/dirty.py"])
        self.assertEqual(result["mutation_categories"]["out-of-scope"], ["outside.py"])
        self.assertTrue(result["unexpected_mutation_detected"])

    def test_write_scope_lease_collides_in_process(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first = acquire_write_scope_lease(raw, ["src"], owner="one")
            with self.assertRaises(WriteScopeLeaseCollision):
                acquire_write_scope_lease(raw, ["src/nested"], owner="two")
            disjoint = acquire_write_scope_lease(raw, ["docs"], owner="three")
            disjoint.release()
            first.release()

    def test_write_scope_lease_collides_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            child_code = """
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts'))
from cwo_core.workspace import acquire_write_scope_lease
lease = acquire_write_scope_lease(sys.argv[2], ['src'], owner='child')
print('READY', flush=True)
time.sleep(2)
lease.release()
"""
            child = subprocess.Popen(
                [sys.executable, "-c", child_code, str(ROOT), raw],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "READY")
                with self.assertRaises(WriteScopeLeaseCollision):
                    acquire_write_scope_lease(raw, ["src/nested"], owner="parent")
            finally:
                child.wait(timeout=5)
            lease = acquire_write_scope_lease(raw, ["src/nested"], owner="parent-after")
            lease.release()


if __name__ == "__main__":
    unittest.main()
