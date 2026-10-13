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
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
    canonical_argument_hash,
    decode_namespaced_exec_source,
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
    def patch_wrapper_fixture(self, text, *, call_id="reject", tool="apply_patch"):
        patch="*** Begin Patch\n*** Update File: one.txt\n@@\n-old\n+new\n*** End Patch"
        args=patch if tool=="apply_patch" else {"cmd":"false","workdir":"/tmp"}
        return [
            {"type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":call_id,
             "input":"const result = await tools."+tool+"("+json.dumps(args)+"); text(JSON.stringify(result));"}},
            {"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":call_id,"output":text}},
        ]

    def test_namespaced_atomic_patch_rejection_is_failure_not_lost_evidence(self):
        text="Script failed\nWall time 0.0 seconds\nOutput:\nScript error:\napply_patch verification failed: invalid patch: multiple operations target one.txt"
        receipt=normalize_action_receipts(self.patch_wrapper_fixture(text),tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
        self.assertEqual(receipt["tool"],"apply_patch")
        self.assertEqual(receipt["pairing_status"],"paired")
        self.assertEqual(receipt["typed_result"]["kind"],"paired-failure")
        self.assertIsNone(receipt["exit_code"])

    def test_namespaced_patch_rejection_does_not_expand_other_error_grammars(self):
        good="Script failed\nWall time 0.0 seconds\nOutput:\nScript error:\napply_patch verification failed: invalid patch"
        for bad in ("prefix"+good,good+"\nextra",good.replace("0.0","NaN"),good.replace("apply_patch verification failed:","TypeError:"),good.replace("Script failed","Script completed")):
            receipt=normalize_action_receipts(self.patch_wrapper_fixture(bad),tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
            self.assertNotEqual(receipt["typed_result"]["kind"],"paired-failure")
        for code in (0,2,False):
            records=self.patch_wrapper_fixture(good);records[-1]["payload"]["exit_code"]=code
            receipt=normalize_action_receipts(records,tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
            self.assertEqual(receipt["pairing_status"],"ambiguous")
        receipt=normalize_action_receipts(self.patch_wrapper_fixture(good,tool="exec_command"),tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
        self.assertNotEqual(receipt["typed_result"]["kind"],"paired-failure")

    def test_namespaced_patch_rejection_rejects_any_intervening_lifecycle_event(self):
        text="Script failed\nWall time 0.0 seconds\nOutput:\nScript error:\napply_patch verification failed: invalid patch"
        for changes in ({"one.txt":{"type":"update"}}, {}, None):
            records=self.patch_wrapper_fixture(text)
            records.insert(1,{"type":"event_msg","payload":{"type":"patch_apply_end","call_id":"unmatched-nested-id","turn_id":"turn","success":True,"status":"completed","changes":changes}})
            receipt=normalize_action_receipts(records,tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
            self.assertEqual(receipt["pairing_status"],"ambiguous")

    def test_healthy_patch_failure_then_corrected_success_retains_distinct_receipts(self):
        failed=self.patch_wrapper_fixture("Script failed\nWall time 0.0 seconds\nOutput:\nScript error:\napply_patch verification failed: invalid patch")
        good=self.patch_wrapper_fixture("Script completed\nWall time 0.0 seconds\nOutput:\n{}",call_id="correct")
        good.insert(1,{"type":"event_msg","payload":{"type":"patch_apply_end","call_id":"nested-correct","turn_id":"turn","success":True,"status":"completed","changes":{"one.txt":{"type":"update"}}}})
        receipts=normalize_action_receipts(failed+good,tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)
        self.assertEqual([r["typed_result"]["kind"] for r in receipts],["paired-failure","paired-success"])
        self.assertEqual([r["call_id"] for r in receipts],["reject","correct"])
        self.assertEqual([r["pairing_status"] for r in receipts],["paired","paired"])

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

    def test_namespaced_exec_receipt_decodes_one_json_bound_nested_call(self) -> None:
        arguments = {
            "cmd": "python -m unittest tests.test_x",
            "workdir": "/tmp/cwo-test",
            "yield_time_ms": 30000,
            "max_output_tokens": 1000,
        }
        source = (
            "const result = await tools.exec_command("
            + json.dumps(arguments, sort_keys=True, separators=(",", ":"))
            + "); text(JSON.stringify(result));"
        )
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "wrapped",
                    "name": "exec",
                    "input": source,
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "wrapped",
                    "output": [
                        {
                            "type": "input_text",
                            "text": "Script completed\nWall time 0.1 seconds\nOutput:\n",
                        },
                        {
                            "type": "input_text",
                            "text": json.dumps(
                                {
                                    "exit_code": 0,
                                    "output": "ok",
                                    "wall_time_seconds": 0.1,
                                },
                                separators=(",", ":"),
                            ),
                        },
                    ],
                },
            },
        ]

        receipt = normalize_action_receipts(
            records,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )[0]
        self.assertEqual(receipt["tool"], "exec_command")
        self.assertEqual(
            receipt["canonical_argument_hash"],
            canonical_argument_hash(arguments),
        )
        self.assertEqual(receipt["redacted_command"], arguments["cmd"])
        self.assertEqual(receipt["pairing_status"], "paired")
        self.assertEqual(receipt["typed_result"]["kind"], "paired-success")
        self.assertEqual(receipt["exit_code"], 0)

    def test_namespaced_exec_tty_is_optional_exact_boolean_and_hash_bound(self) -> None:
        base = {"cmd": "python -B helper.py check check-0 --serve-failure",
                "workdir": "/tmp/cwo-test", "yield_time_ms": 30000,
                "max_output_tokens": 1000}
        hashes = []
        for extra in ({}, {"tty": True}, {"tty": False}):
            arguments = {**base, **extra}
            source = "const result = await tools.exec_command(" + json.dumps(arguments) + "); text(JSON.stringify(result));"
            decoded = decode_namespaced_exec_source(source)
            self.assertEqual(decoded["arguments"], arguments)
            records = [
                {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "tty", "input": source}},
                {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "tty", "output": "Script completed\nWall time 0.1 seconds\nOutput:\n" + json.dumps({"exit_code": 1, "output": "expected baseline failure", "wall_time_seconds": 0.1})}},
            ]
            receipt = normalize_action_receipts(records, tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)[0]
            self.assertEqual(receipt["tool"], "exec_command")
            self.assertEqual(receipt["canonical_argument_hash"], canonical_argument_hash(arguments))
            self.assertEqual(receipt["typed_result"]["kind"], "paired-failure")
            self.assertEqual(receipt["exit_code"], 1)
            hashes.append(receipt["canonical_argument_hash"])
        self.assertEqual(len(set(hashes)), 3)

    def test_namespaced_exec_tty_bad_types_and_other_fields_still_fail_closed(self) -> None:
        base = {"cmd": "true", "workdir": "/tmp/cwo-test"}
        for bad in (0, 1, 0.0, 1.0, "true", "false", None, [], {}, [True], {"tty": True}):
            source = "const result = await tools.exec_command(" + json.dumps({**base, "tty": bad}) + "); text(JSON.stringify(result));"
            with self.subTest(tty=bad), self.assertRaisesRegex(ValueError, "namespaced-exec-tty-invalid"):
                decode_namespaced_exec_source(source)
            receipts = normalize_action_receipts([
                {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "bad", "input": source}},
                {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "bad", "output": "aborted by user after 0.7s"}},
            ], tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT)
            self.assertEqual(receipts[0]["tool"], "exec")
        for args in ({**base, "tty": True, "shell": "bash"}, {**base, "tty": True, "unexpected": False}):
            with self.assertRaisesRegex(ValueError, "argument-fields-invalid"):
                decode_namespaced_exec_source("const r = await tools.exec_command(" + json.dumps(args) + "); text(JSON.stringify(r));")
        with self.assertRaisesRegex(ValueError, "argument-fields-invalid"):
            decode_namespaced_exec_source('const r = await tools.write_stdin({"session_id":1,"tty":true}); text(JSON.stringify(r));')


    def test_namespaced_exec_decoder_rejects_ambiguous_javascript(self) -> None:
        valid = (
            'const result = await tools.exec_command({'
            '"cmd":"true","workdir":"/tmp/cwo-test"}); '
            'text(JSON.stringify(result));'
        )
        self.assertEqual(decode_namespaced_exec_source(valid)["tool"], "exec_command")
        invalid = (
            valid + " await tools.apply_patch(\"*** Begin Patch\");",
            valid.replace("text(JSON.stringify(result))", "text(result.output)"),
            valid.replace('"cmd":"true"', "cmd:'true'"),
            valid.replace("tools.exec_command", "tools['exec_command']"),
        )
        for source in invalid:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    decode_namespaced_exec_source(source)

    def test_namespaced_exec_pending_session_is_deferred_until_matching_wait(
        self,
    ) -> None:
        def call(tool: str, call_id: str, arguments: dict) -> dict:
            source = (
                f"const result = await tools.{tool}("
                + json.dumps(arguments, separators=(",", ":"))
                + "); text(JSON.stringify(result));"
            )
            return {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": call_id,
                    "name": "exec",
                    "input": source,
                },
            }

        def output(call_id: str, result: dict) -> dict:
            return {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": call_id,
                    "output": [
                        {
                            "type": "input_text",
                            "text": "Script completed\nWall time 1.2 seconds\nOutput:\n",
                        },
                        {
                            "type": "input_text",
                            "text": json.dumps(result, separators=(",", ":")),
                        },
                    ],
                },
            }

        pending = [
            call("exec_command", "exec", {"cmd": "sleep 2", "workdir": "/tmp"}),
            output(
                "exec",
                {
                    "chunk_id": "abc",
                    "wall_time_seconds": 1.0,
                    "session_id": 28838,
                    "original_token_count": 1,
                    "output": "partial",
                },
            ),
        ]
        receipt = normalize_action_receipts(
            pending,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )[0]
        self.assertEqual(receipt["pairing_status"], "paired")
        self.assertEqual(receipt["typed_result"]["kind"], "paired-pending")
        self.assertIsNone(receipt["exit_code"])

        resolved = pending + [
            call("write_stdin", "wait", {"session_id": 28838, "chars": ""}),
            output(
                "wait",
                {
                    "chunk_id": "def",
                    "wall_time_seconds": 2.0,
                    "exit_code": 0,
                    "original_token_count": 2,
                    "output": "done",
                },
            ),
        ]
        receipts = normalize_action_receipts(
            resolved,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(
            [item["typed_result"]["kind"] for item in receipts],
            ["paired-deferred", "paired-success"],
        )

        still_pending = pending + [
            call("write_stdin", "wait-1", {"session_id": 28838, "chars": ""}),
            output(
                "wait-1",
                {
                    "chunk_id": "def",
                    "wall_time_seconds": 2.0,
                    "session_id": 28838,
                    "original_token_count": 2,
                    "output": "more",
                },
            ),
        ]
        receipts = normalize_action_receipts(
            still_pending,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(
            [item["typed_result"]["kind"] for item in receipts],
            ["paired-pending", "paired-pending"],
        )
        resolved_failure = still_pending + [
            call("write_stdin", "wait-2", {"session_id": 28838, "chars": ""}),
            output(
                "wait-2",
                {
                    "chunk_id": "ghi",
                    "wall_time_seconds": 2.1,
                    "exit_code": 1,
                    "original_token_count": 3,
                    "output": "failed",
                },
            ),
        ]
        receipts = normalize_action_receipts(
            resolved_failure,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(
            [item["typed_result"]["kind"] for item in receipts],
            ["paired-deferred", "paired-deferred", "paired-failure"],
        )

        mismatched = pending + [
            call("write_stdin", "wait", {"session_id": 28838, "chars": ""}),
            output(
                "wait",
                {
                    "session_id": 28839,
                    "wall_time_seconds": 1.0,
                    "output": "still running",
                },
            ),
        ]
        receipts = normalize_action_receipts(
            mismatched,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(receipts[0]["typed_result"]["kind"], "paired-pending")
        self.assertEqual(receipts[1]["pairing_status"], "ambiguous")

        for invalid_session_id in (True, 0, -1, "28838"):
            with self.subTest(session_id=invalid_session_id):
                malformed = [
                    pending[0],
                    output(
                        "exec",
                        {
                            "session_id": invalid_session_id,
                            "wall_time_seconds": 1.0,
                            "output": "partial",
                        },
                    ),
                ]
                bad = normalize_action_receipts(
                    malformed,
                    tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
                )[0]
                self.assertEqual(bad["pairing_status"], "ambiguous")
                self.assertEqual(
                    bad["typed_result"]["kind"],
                    "ambiguous-call-or-output-cardinality",
                )

    def test_namespaced_exec_invalid_source_remains_forbidden_outer_tool(self) -> None:
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "wrapped",
                    "name": "exec",
                    "input": (
                        "const result = await tools.exec_command({cmd:'true'}); "
                        "text(result.output);"
                    ),
                },
            }
        ]
        receipt = normalize_action_receipts(
            records,
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )[0]
        self.assertEqual(receipt["tool"], "exec")
        self.assertEqual(receipt["typed_result"]["kind"], "unpaired-call")

    def test_namespaced_exec_accepts_only_exact_bare_interruption_result(self) -> None:
        source = (
            'const result = await tools.exec_command({"cmd":"sleep 20",'
            '"workdir":"/tmp/cwo-test"}); text(JSON.stringify(result));\n'
        )

        def result(output: str, *, tool: str = "exec_command") -> dict:
            selected_source = source.replace("tools.exec_command", f"tools.{tool}")
            records = [
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "interrupt",
                        "name": "exec",
                        "input": selected_source,
                    },
                },
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call_output",
                        "call_id": "interrupt",
                        "output": output,
                    },
                },
            ]
            return normalize_action_receipts(
                records,
                tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
            )[0]

        for output in (
            "aborted by user after 1.4s",
            "Wall time: 1.4 seconds\naborted by user",
        ):
            with self.subTest(output=output):
                receipt = result(output)
                self.assertEqual(receipt["tool"], "exec_command")
                self.assertEqual(receipt["pairing_status"], "paired")
                self.assertEqual(
                    receipt["typed_result"]["kind"], "paired-interrupted"
                )
                self.assertIsNone(receipt["exit_code"])

        for output in (
            "aborted by user",
            "aborted by user after 1.4s\n",
            "prefix aborted by user after 1.4s",
        ):
            with self.subTest(output=output):
                self.assertEqual(
                    result(output)["typed_result"]["kind"], "paired-unknown"
                )

        self.assertEqual(
            result("aborted by user after 1.4s", tool="write_stdin")
            ["typed_result"]["kind"],
            "paired-unknown",
        )

    def test_namespaced_patch_correlates_distinct_nested_event_id(self) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: /tmp/work/scripts/child_2.py\n"
            "@@\n"
            "-resolved = path.expanduser().resolve()\n"
            "+raw = path.expanduser()\n"
            "+if current.exists() and not current.is_dir():\n"
            "+    return bool(relative.parts)\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));\n"
        )
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "outer-call",
                    "name": "exec",
                    "input": source,
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "patch_apply_end",
                    "call_id": "nested-call",
                    "turn_id": "turn-1",
                    "success": True,
                    "status": "completed",
                    "changes": {
                        "/tmp/work/scripts/child_2.py": {
                            "type": "update",
                            "move_path": None,
                        }
                    },
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "outer-call",
                    "output": [
                        {
                            "type": "input_text",
                            "text": "Script completed\nWall time 0.3 seconds\nOutput:\n",
                        },
                        {"type": "input_text", "text": "{}"},
                    ],
                },
            },
        ]

        receipts = normalize_action_receipts(
            records,
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["tool"], "apply_patch")
        self.assertEqual(receipts[0]["pairing_status"], "paired")
        self.assertEqual(receipts[0]["typed_result"]["kind"], "paired-success")
        self.assertEqual(
            receipts[0]["determinable_target_paths"],
            ["/tmp/work/scripts/child_2.py"],
        )

    def test_namespaced_patch_event_can_remain_pending_before_outer_output(
        self,
    ) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: scripts/child_2.py\n"
            "@@\n"
            "+VALUE = 12\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));"
        )
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "outer-call",
                    "name": "exec",
                    "input": source,
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "patch_apply_end",
                    "call_id": "nested-call",
                    "turn_id": "turn-1",
                    "success": True,
                    "status": "completed",
                    "changes": {
                        "/tmp/work/scripts/child_2.py": {
                            "type": "update",
                            "move_path": None,
                        }
                    },
                },
            },
        ]

        pending = normalize_action_receipts(
            records,
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["tool"], "apply_patch")
        self.assertEqual(pending[0]["pairing_status"], "unpaired")
        self.assertEqual(pending[0]["typed_result"]["kind"], "unpaired-call")
        self.assertFalse(pending[0]["typed_result"]["output_present"])

        records.append(
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "outer-call",
                    "output": [
                        {
                            "type": "input_text",
                            "text": (
                                "Script completed\n"
                                "Wall time 0.1 seconds\n"
                                "Output:\n"
                            ),
                        },
                        {"type": "input_text", "text": "{}"},
                    ],
                },
            }
        )
        completed = normalize_action_receipts(
            records,
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["pairing_status"], "paired")
        self.assertEqual(completed[0]["typed_result"]["kind"], "paired-success")

    def test_direct_patch_event_is_pending_until_matching_output(self) -> None:
        records = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "direct-call",
                    "name": "apply_patch",
                    "input": (
                        "*** Begin Patch\n"
                        "*** Update File: scripts/child_2.py\n"
                        "@@\n"
                        "+VALUE = 12\n"
                        "*** End Patch"
                    ),
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "patch_apply_end",
                    "call_id": "direct-call",
                    "turn_id": "turn-1",
                    "success": True,
                    "status": "completed",
                    "changes": {
                        "/tmp/work/scripts/child_2.py": {"type": "update"}
                    },
                },
            },
        ]

        pending = normalize_action_receipts(
            records,
            segment_id="turn-1",
            tool_transport=DIRECT_TOOL_TRANSPORT,
        )

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["tool"], "apply_patch")
        self.assertEqual(pending[0]["pairing_status"], "unpaired")
        self.assertEqual(pending[0]["typed_result"]["kind"], "paired-pending")
        self.assertFalse(pending[0]["typed_result"]["output_present"])

        records.append(
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "direct-call",
                    "output": "Exit code: 0\nOutput:\nSuccess.\n",
                },
            }
        )
        completed = normalize_action_receipts(
            records,
            segment_id="turn-1",
            tool_transport=DIRECT_TOOL_TRANSPORT,
        )
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["pairing_status"], "paired")
        self.assertEqual(completed[0]["typed_result"]["kind"], "paired-success")

    def test_namespaced_patch_enforces_global_one_event_one_call_ownership(
        self,
    ) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: scripts/shared.py\n"
            "@@\n"
            "+VALUE = 12\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));"
        )
        calls = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": call_id,
                    "name": "exec",
                    "input": source,
                },
            }
            for call_id in ("outer-a", "outer-b")
        ]
        event = {
            "type": "event_msg",
            "payload": {
                "type": "patch_apply_end",
                "call_id": "nested-only",
                "turn_id": "turn-1",
                "success": True,
                "status": "completed",
                "changes": {
                    "/tmp/work/scripts/shared.py": {"type": "update"}
                },
            },
        }
        outputs = [
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": call_id,
                    "output": [
                        {
                            "type": "input_text",
                            "text": (
                                "Script completed\n"
                                "Wall time 0.1 seconds\n"
                                "Output:\n"
                            ),
                        },
                        {"type": "input_text", "text": "{}"},
                    ],
                },
            }
            for call_id in ("outer-a", "outer-b")
        ]

        receipts = normalize_action_receipts(
            [*calls, event, *outputs],
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        self.assertEqual(len(receipts), 3)
        self.assertTrue(
            all(
                receipt["pairing_status"] == "ambiguous"
                and receipt["typed_result"]["kind"]
                == "ambiguous-call-or-output-cardinality"
                for receipt in receipts[:2]
            )
        )
        self.assertEqual(receipts[2]["tool"], "unknown")
        self.assertEqual(receipts[2]["typed_result"]["kind"], "unpaired-output")

    def test_namespaced_patch_duplicate_matching_events_fail_closed(self) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: scripts/shared.py\n"
            "@@\n"
            "+VALUE = 12\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));"
        )
        call = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "outer",
                "name": "exec",
                "input": source,
            },
        }
        events = [
            {
                "type": "event_msg",
                "payload": {
                    "type": "patch_apply_end",
                    "call_id": event_id,
                    "turn_id": "turn-1",
                    "success": True,
                    "status": "completed",
                    "changes": {
                        "/tmp/work/scripts/shared.py": {"type": "update"}
                    },
                },
            }
            for event_id in ("nested-a", "nested-b")
        ]
        output = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "outer",
                "output": [
                    {
                        "type": "input_text",
                        "text": (
                            "Script completed\n"
                            "Wall time 0.1 seconds\n"
                            "Output:\n"
                        ),
                    },
                    {"type": "input_text", "text": "{}"},
                ],
            },
        }

        receipts = normalize_action_receipts(
            [call, *events, output],
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        self.assertEqual(len(receipts), 3)
        self.assertEqual(receipts[0]["pairing_status"], "ambiguous")
        self.assertEqual(
            receipts[0]["typed_result"]["kind"],
            "ambiguous-call-or-output-cardinality",
        )
        self.assertTrue(
            all(receipt["tool"] == "unknown" for receipt in receipts[1:])
        )

    def test_namespaced_patch_rejects_unidentified_or_misordered_events(
        self,
    ) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: scripts/shared.py\n"
            "@@\n"
            "+VALUE = 12\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));"
        )
        call = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "outer",
                "name": "exec",
                "input": source,
            },
        }
        output = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "outer",
                "output": (
                    "Script completed\n"
                    "Wall time 0.1 seconds\n"
                    "Output:\n{}"
                ),
            },
        }

        def event(**overrides: object) -> dict:
            payload = {
                "type": "patch_apply_end",
                "call_id": "nested",
                "turn_id": "turn-1",
                "success": True,
                "status": "completed",
                "changes": {
                    "/tmp/work/scripts/shared.py": {"type": "update"}
                },
                **overrides,
            }
            return {"type": "event_msg", "payload": payload}

        missing_identity = event()
        missing_identity["payload"].pop("call_id")
        cases = (
            ("missing-identity", [call, missing_identity, output]),
            ("event-before-call", [event(), call, output]),
            ("wrong-turn", [call, event(turn_id="other-turn"), output]),
            (
                "traversal-target",
                [
                    call,
                    event(
                        changes={
                            "/tmp/work/scripts/../scripts/shared.py": {
                                "type": "update"
                            }
                        }
                    ),
                    output,
                ],
            ),
        )
        for label, records in cases:
            with self.subTest(label=label):
                receipts = normalize_action_receipts(
                    records,
                    segment_id="turn-1",
                    tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
                )
                patch_receipt = next(
                    receipt
                    for receipt in receipts
                    if receipt["tool"] == "apply_patch"
                )
                self.assertEqual(patch_receipt["pairing_status"], "ambiguous")
                self.assertEqual(
                    patch_receipt["typed_result"]["kind"],
                    "ambiguous-call-or-output-cardinality",
                )
                self.assertTrue(
                    any(receipt["tool"] == "unknown" for receipt in receipts)
                )

    def test_namespaced_patch_rejects_ambiguous_nested_event_correlation(self) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: scripts/child_2.py\n"
            "@@\n"
            "+VALUE = 12\n"
            "*** End Patch"
        )
        source = (
            "const result = await tools.apply_patch("
            + json.dumps(patch)
            + "); text(JSON.stringify(result));"
        )
        call = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": "outer-call",
                "name": "exec",
                "input": source,
            },
        }
        event = {
            "type": "event_msg",
            "payload": {
                "type": "patch_apply_end",
                "call_id": "nested-call",
                "turn_id": "turn-1",
                "success": True,
                "status": "completed",
                "changes": {
                    "/tmp/work/scripts/other.py": {"type": "update"}
                },
            },
        }
        output = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "outer-call",
                "output": [
                    {"type": "input_text", "text": "Script completed\nOutput:\n"},
                    {"type": "input_text", "text": "{}"},
                ],
            },
        }

        receipts = normalize_action_receipts(
            [call, event, output],
            segment_id="turn-1",
            tool_transport=NAMESPACED_EXEC_TOOL_TRANSPORT,
        )

        self.assertEqual(len(receipts), 2)
        self.assertEqual(receipts[0]["pairing_status"], "ambiguous")
        self.assertEqual(
            receipts[0]["typed_result"]["kind"],
            "ambiguous-call-or-output-cardinality",
        )
        self.assertEqual(receipts[1]["tool"], "unknown")
        self.assertEqual(receipts[1]["pairing_status"], "unpaired")

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

        for output in (
            "aborted by user after 1.3s",
            "Wall time: 1.5 seconds\naborted by user",
        ):
            with self.subTest(output=output):
                interrupted = result(output)
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
            "Wall time: -1.5 seconds\naborted by user",
            "Wall time: 1.5 seconds\nprefix aborted by user",
            "Wall time: 1.5 seconds\naborted by user\n",
            "Wall time: 1.5s\naborted by user",
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

    def test_action_receipts_classify_only_exact_no_process_input_error(self) -> None:
        exact = (
            'exec_command failed: CreateProcess { message: "Rejected(\\"Failed to '
            'create unified exec process: No such file or directory (os error 2)\\")" }'
        )
        arguments = {"cmd": "ls", "workdir": "/tmp/mistyped-workdir"}

        def result(output: str, *, include_private: bool = False) -> dict:
            return normalize_action_receipts(
                [
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "call_id": "missing-workdir",
                            "name": "exec_command",
                            "arguments": json.dumps(arguments),
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "missing-workdir",
                            "output": output,
                        },
                    },
                ],
                include_private_transport_evidence=include_private,
            )[0]

        public = result(exact)
        self.assertEqual(public["pairing_status"], "paired")
        self.assertEqual(public["typed_result"]["kind"], "paired-input-error")
        self.assertIsNone(public["exit_code"])
        self.assertNotIn("_invocation_workdir", public)
        private = result(exact, include_private=True)
        self.assertTrue(private["_invocation_workdir_present"])
        self.assertEqual(private["_invocation_workdir"], arguments["workdir"])

        for near_miss in (
            exact + "\n",
            exact.replace("os error 2", "os error 13"),
            exact.replace("exec_command failed", "exec_command failed for `ls`"),
            "prefix " + exact,
        ):
            with self.subTest(output=near_miss):
                self.assertEqual(
                    result(near_miss)["typed_result"]["kind"],
                    "paired-unknown",
                )

        with self.assertRaisesRegex(
            ValueError, "native-private-transport-evidence-flag-invalid"
        ):
            normalize_action_receipts(
                [], include_private_transport_evidence=1  # type: ignore[arg-type]
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

    def test_content_baseline_allows_declared_new_path_and_rejects_undeclared_new_path(self) -> None:
        before = {
            "cwd": "/tmp/example",
            "allowed_paths": ["planned.txt"],
            "include_untracked": True,
            "tracked_status": [],
            "tracked_paths": [],
            "tracked_paths_complete": True,
            "preexisting_dirty_paths": [],
            "content_fingerprints": {},
            "incomplete": False,
        }
        after = {
            **before,
            "tracked_status": ["?? planned.txt", "?? surprise.txt"],
            "content_fingerprints": {
                "planned.txt": {"sha256": "a", "size": 1},
                "surprise.txt": {"sha256": "b", "size": 1},
            },
        }
        result = compare_workspace_baseline(
            before, after, allowed_paths=["planned.txt"]
        )
        self.assertEqual(result["mutation_categories"]["scoped"], ["planned.txt"])
        self.assertEqual(result["mutation_categories"]["untracked"], ["surprise.txt"])
        self.assertEqual(
            [item["path"] for item in result["unexpected_mutations"]],
            ["surprise.txt"],
        )
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
