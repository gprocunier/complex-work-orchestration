from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "supervise_native_worker.py"
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_native_worker import build_native_worker_packet  # noqa: E402
from cwo_core.work_sizing import canonical_work_estimate_sha256, evaluate_work_estimate
import supervise_native_worker as supervisor  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
LUNA_MODEL = "gpt-5.6-luna"
CONTROL_TURN = "control-turn-test"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def write_records(path: Path, records: list[dict], *, trailing: str = "") -> None:
    text = "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n"
    path.write_text(text + trailing, encoding="utf-8")


def session_meta(session_id: str) -> dict:
    return {
        "timestamp": "2026-07-11T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": {
            "model": MODEL,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
        },
    }


def event(
    timestamp: str,
    session_id: str,
    name: str,
    *,
    model: str = MODEL,
    tool: bool = False,
    command: str | None = None,
    workdir: str | None = str(ROOT),
) -> dict:
    record: dict = {
        "timestamp": timestamp,
        "session_id": session_id,
        "event_msg": name,
        "turn_context": {
            "model": model,
            "attestation_source": "trusted-control-plane-session-metadata",
            "token_count": {"input": 1, "cached_input": 0, "output": 1, "reasoning": 0, "total": 2},
        },
    }
    if tool:
        arguments = {
            "cmd": command
            or "python -m unittest tests.test_supervise_native_worker -v"
        }
        if workdir is not None:
            arguments["workdir"] = workdir
        record["response_item"] = {
            "type": "function_call",
            "name": "exec_command",
            "arguments": json.dumps(arguments),
        }
    return record


def planned_packet(*, packet_id: str, requested_model: str = MODEL, budget_overrides: dict | None = None) -> dict:
    allowed_paths = ["scripts/supervise_native_worker.py"]
    acceptance_checks = ["focused tests pass"]
    context_path = ROOT / allowed_paths[0]
    context_bytes = context_path.read_bytes()
    effective_budget = budget_overrides or {
        "tool_calls_soft": 5,
        "tool_calls_hard": 10,
        "runtime_seconds_soft": 30,
        "runtime_seconds_hard": 60,
    }
    work_plan = evaluate_work_estimate(
        {
            "estimate_type": "cwo-native-work-estimate",
            "version": 1,
            "estimate_contract_version": 2,
            "work_unit_id": f"test-{packet_id}",
            "bead_id": "bead-supervision",
            "requested_model": requested_model,
            "primary_outcome": "exercise native supervisor behavior",
            "expected_artifacts": ["supervision-state"],
            "expert_profiles": ["test_engineering"],
            "frozen_decisions": [
                "operative-readiness:v2",
                "behavior-cluster: native supervisor control",
                "input-contract: trusted JSONL and exact context manifest",
                "output-contract: bounded supervision state and decision",
                "state-transitions: start arm dispatch check finalize",
                "positive-tests: focused supervisor completion and warning paths",
                "negative-tests: malformed telemetry and protected boundaries",
                "authority: workspace evidence determines mutation",
            ],
            "unresolved_decisions": [],
            "subsystems": ["native-supervisor"],
            "write_paths": allowed_paths,
            "context_manifest": [
                {
                    "path": allowed_paths[0],
                    "selector": "whole-file",
                    "purpose": "supervisor implementation under test",
                    "bytes": len(context_bytes),
                    "sha256": hashlib.sha256(context_bytes).hexdigest(),
                }
            ],
            "acceptance_checks": acceptance_checks,
            "estimates": {
                "tool_calls_p50": 2,
                "tool_calls_p90": 5,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 60,
                "context_tokens_p90": 1000,
            },
            "scores": {
                "reasoning_uncertainty": 0,
                "subsystem_coupling": 1,
                "contract_risk": 1,
                "diagnostic_uncertainty": 0,
                "context_breadth": 0,
                "validation_breadth": 1,
            },
            "semantic_estimate": {
                "estimated_diff_p50": 40,
                "estimated_diff_p90": 80,
                "behavioral_changes": 0,
                "state_machine_changes": 0,
                "schema_changes": 0,
                "self_hosting_risk": 1,
                "live_control_risk": 1,
                "contract_surfaces": 1,
                "cli_surfaces": 0,
                "policy_surfaces": 0,
                "telemetry_surfaces": 0,
                "expected_regressions": 3,
                "test_construction_complexity": 1,
                "command_complexity": 1,
                "nested_quote_layers": 0,
                "expected_context_reads": 4,
                "expected_mutations": 2,
                "read_to_mutation_ratio": 2,
            },
            "pm_estimate": {
                "tool_calls_p50": 2,
                "tool_calls_p90": 5,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 60,
            },
            "domain_expert_estimate": {
                "tool_calls_p50": 2,
                "tool_calls_p90": 5,
                "runtime_seconds_p50": 10,
                "runtime_seconds_p90": 60,
            },
        }
    )
    commitment = {
        "commitment_type": "cwo-native-worker-fit-commitment",
        "version": 1,
        "work_unit_id": work_plan["work_unit_id"],
        "bead_id": work_plan["bead_id"],
        "requested_model": requested_model,
        "session_id": "spark-session",
        "attestation_source": "trusted-session-jsonl",
        "attested_model": requested_model,
        "work_estimate_sha256": canonical_work_estimate_sha256(work_plan),
        "decision": "accept",
        "confidence": 0.95,
        "estimates": {
            "tool_calls_p50": 2,
            "tool_calls_p90": 5,
            "runtime_seconds_p50": 10,
            "runtime_seconds_p90": 60,
        },
        "tool_calls_before_commitment": 0,
        "context_compactions_before_commitment": 0,
        "reason": "deterministic supervisor test fixture",
    }
    return build_native_worker_packet(
        bead_id="bead-supervision",
        lane="implementation",
        workdir=str(ROOT),
        allowed_paths=allowed_paths,
        acceptance_checks=acceptance_checks,
        packet_id=packet_id,
        budget_overrides=effective_budget,
        requested_model=requested_model,
        work_plan=work_plan,
        worker_commitment=commitment,
    )


def tool_record(
    command: str,
    *,
    item_type: str = "function_call",
    name: str = "exec_command",
    workdir: str | None = str(ROOT),
) -> dict:
    arguments = {"cmd": command}
    if workdir is not None:
        arguments["workdir"] = workdir
    return {
        "response_item": {
            "type": item_type,
            "name": name,
            "arguments": json.dumps(arguments),
        }
    }


class NativeSupervisorSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = supervisor.load_policy("native-worker-execution")

    def packet(self) -> dict:
        return planned_packet(packet_id="packet-semantic-helper")

    def validation_packet(self, commands: list[list[str]]) -> dict:
        packet = self.packet()
        packet["lane"] = "validation"
        packet["scope"]["prohibited_actions"].append("source-mutation")
        packet["work_plan"]["write_paths"] = []
        packet["work_plan"]["task_profile"] = {
            "task_class": "read-only-validation",
            "declared_outcome_count": 1,
            "command_count": len(commands),
            "check_count": len(commands),
            "focused_test_count": len(commands),
            "full_suite_count": 0,
            "read_context_count": 0,
            "source_mutation_count": 0,
            "source_mutation_paths": [],
            "commands": [{"argv": argv} for argv in commands],
        }
        return packet

    def test_readiness_accepts_complete_frozen_packet(self) -> None:
        readiness, units = supervisor._evaluate_operative_readiness(self.packet(), self.policy)
        self.assertEqual(readiness["decision"], "operative-ready")
        self.assertEqual(readiness["reasons"], [])
        self.assertEqual(readiness["open_decisions"], [])
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0]["selector"], "whole-file")

    def test_readiness_routes_open_decisions_and_invalid_context(self) -> None:
        packet = self.packet()

        no_contract = json.loads(json.dumps(packet))
        no_contract["work_plan"]["frozen_decisions"].remove("operative-readiness:v2")
        readiness, _ = supervisor._evaluate_operative_readiness(no_contract, self.policy)
        self.assertEqual(readiness["decision"], "split-required")
        self.assertIn("missing-operative-readiness-marker", readiness["reasons"])

        unresolved = json.loads(json.dumps(packet))
        unresolved["work_plan"]["unresolved_decisions"] = ["architect must choose behavior"]
        readiness, _ = supervisor._evaluate_operative_readiness(unresolved, self.policy)
        self.assertEqual(readiness["decision"], "architect-resolution-required")

        missing_marker = json.loads(json.dumps(packet))
        missing_marker["work_plan"]["frozen_decisions"] = [
            item
            for item in missing_marker["work_plan"]["frozen_decisions"]
            if not item.startswith("input-contract:")
        ]
        readiness, _ = supervisor._evaluate_operative_readiness(missing_marker, self.policy)
        self.assertEqual(readiness["decision"], "architect-resolution-required")
        self.assertIn("input-contract:", readiness["open_decisions"])

        invalid_context = json.loads(json.dumps(packet))
        invalid_context["work_plan"]["context_manifest"][0]["selector"] = "lines:9-2"
        readiness, _ = supervisor._evaluate_operative_readiness(invalid_context, self.policy)
        self.assertEqual(readiness["decision"], "split-required")
        self.assertTrue(any("selector is invalid" in reason for reason in readiness["reasons"]))

        bad_hash = json.loads(json.dumps(packet))
        bad_hash["work_plan"]["context_manifest"][0]["sha256"] = "0" * 64
        readiness, _ = supervisor._evaluate_operative_readiness(bad_hash, self.policy)
        self.assertEqual(readiness["decision"], "split-required")
        self.assertTrue(any("sha256 does not match" in reason for reason in readiness["reasons"]))

        duplicate = json.loads(json.dumps(packet))
        duplicate["work_plan"]["context_manifest"].append(
            json.loads(json.dumps(duplicate["work_plan"]["context_manifest"][0]))
        )
        readiness, _ = supervisor._evaluate_operative_readiness(duplicate, self.policy)
        self.assertEqual(readiness["decision"], "split-required")
        self.assertTrue(any("duplicates semantic unit" in reason for reason in readiness["reasons"]))

        oversized = json.loads(json.dumps(packet))
        oversized["work_plan"]["semantic_estimate"]["estimated_diff_p90"] = 251
        readiness, _ = supervisor._evaluate_operative_readiness(oversized, self.policy)
        self.assertEqual(readiness["decision"], "split-required")
        self.assertIn("expected-diff-limit-exceeded", readiness["reasons"])

    def test_activity_normalizes_call_types_and_counts_semantic_units(self) -> None:
        _, units = supervisor._evaluate_operative_readiness(self.packet(), self.policy)
        path = units[0]["path"]
        records = [
            tool_record(f"sed -n '1,20p' {path}"),
            tool_record(f"cat {path}", item_type="custom_tool_call"),
            tool_record(f"rg readiness {path}"),
            tool_record(f"wc -l {path}"),
        ]
        activity = supervisor._classify_native_activity(
            records,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertEqual(activity["category_counts"]["targeted-read"], 4)
        self.assertEqual(activity["pre_mutation_read_calls"], 4)
        self.assertEqual(len(activity["pre_mutation_semantic_units"]), 1)
        unit_state = next(iter(activity["semantic_units"].values()))
        self.assertEqual(unit_state["chunks"], 2)
        self.assertEqual(activity["violations"], [])

    def test_activity_ignores_non_tool_response_items(self) -> None:
        _, units = supervisor._evaluate_operative_readiness(self.packet(), self.policy)
        path = units[0]["path"]
        non_tools = [
            {"response_item": {"type": "message", "role": "user", "content": []}},
            {"response_item": {"type": "reasoning", "summary": []}},
            {"response_item": {"type": "function_call_output", "call_id": "call-1", "output": "ok"}},
            {"response_item": {"type": "custom_tool_call_output", "call_id": "call-2", "output": "ok"}},
        ]
        records = [
            *non_tools,
            tool_record(f"rg readiness {path}"),
            tool_record(f"wc -l {path}", item_type="custom_tool_call"),
        ]
        activity = supervisor._classify_native_activity(
            records,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertEqual(activity["processed_items"], 2)
        self.assertEqual(activity["category_counts"]["targeted-read"], 2)
        self.assertEqual(sum(activity["category_counts"].values()), 2)
        self.assertEqual(activity["violations"], [])

        ignored = supervisor._classify_native_activity(
            non_tools,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertEqual(ignored, supervisor._empty_activity())

    def test_activity_warns_then_requires_replan_at_frozen_thresholds(self) -> None:
        units = [
            {
                "identity": f"file-{index}.py::whole-file::{index:064x}",
                "path": f"file-{index}.py",
                "absolute_path": f"/tmp/file-{index}.py",
                "selector": "whole-file",
                "sha256": f"{index:064x}",
            }
            for index in range(1, 5)
        ]
        records = [tool_record(f"rg token {unit['path']}") for unit in units]
        warned = supervisor._classify_native_activity(
            records[:3],
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertIn("semantic-unit-warning", warned["warnings"])
        self.assertEqual(warned["violations"], [])
        replanned = supervisor._classify_native_activity(
            records,
            units,
            warned,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertIn("needs-replan-semantic-unit-limit", replanned["violations"])

        six_reads = [tool_record("rg token file-1.py") for _ in range(6)]
        warned_reads = supervisor._classify_native_activity(
            six_reads,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertIn("pre-mutation-read-warning", warned_reads["warnings"])
        eleven_reads = [tool_record("rg token file-1.py") for _ in range(11)]
        replanned_reads = supervisor._classify_native_activity(
            eleven_reads,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertIn("needs-replan-pre-mutation-read-limit", replanned_reads["violations"])

    def test_activity_denies_broad_memory_unrelated_and_excess_chunks(self) -> None:
        _, units = supervisor._evaluate_operative_readiness(self.packet(), self.policy)
        path = units[0]["path"]
        records = [
            tool_record("rg --files"),
            tool_record("cat /home/example/.codex/memories/MEMORY.md"),
            tool_record("true"),
            *[tool_record(f"sed -n '1,20p' {path}") for _ in range(5)],
        ]
        activity = supervisor._classify_native_activity(
            records,
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=self.packet(),
        )
        self.assertIn("broad-scan-denied", activity["violations"])
        self.assertIn("unauthorized-memory-read", activity["violations"])
        self.assertIn("unrelated-activity-denied", activity["violations"])
        self.assertIn("read-unit-chunk-limit-exceeded", activity["violations"])

    def test_declared_validation_commands_require_exact_valid_profile(self) -> None:
        command = ["python", "scripts/validate_repository.py"]
        packet = self.validation_packet([command])
        self.assertEqual(
            supervisor._declared_validation_commands(packet),
            frozenset({tuple(command)}),
        )

        malformed = json.loads(json.dumps(packet))
        malformed["work_plan"]["task_profile"]["command_count"] = 2
        self.assertEqual(supervisor._declared_validation_commands(malformed), frozenset())

        writable = json.loads(json.dumps(packet))
        writable["work_plan"]["write_paths"] = ["scripts/validate_repository.py"]
        self.assertEqual(supervisor._declared_validation_commands(writable), frozenset())

        duplicate = self.validation_packet([command, command])
        self.assertEqual(supervisor._declared_validation_commands(duplicate), frozenset())

        implementation = self.validation_packet([command])
        implementation["lane"] = "implementation"
        implementation["scope"]["prohibited_actions"].remove("source-mutation")
        implementation["scope"]["allowed_actions"].append("edit-scoped-files")
        implementation["work_plan"]["write_paths"] = ["SKILL.md"]
        implementation["work_plan"]["task_class"] = "narrow-mechanical"
        implementation["work_plan"]["task_profile"]["task_class"] = "narrow-mechanical"
        implementation["work_plan"]["task_profile"]["source_mutation_count"] = 1
        implementation["work_plan"]["task_profile"]["source_mutation_paths"] = ["SKILL.md"]
        self.assertEqual(
            supervisor._declared_validation_commands(implementation),
            frozenset({tuple(command)}),
        )

        malformed_implementation = json.loads(json.dumps(implementation))
        malformed_implementation["work_plan"]["task_profile"]["source_mutation_count"] = True
        self.assertEqual(
            supervisor._declared_validation_commands(malformed_implementation),
            frozenset(),
        )

    def test_declared_validation_command_is_focused_and_undeclared_is_denied(self) -> None:
        command = ["python", "scripts/validate_repository.py"]
        packet = self.validation_packet([command])
        _, units = supervisor._evaluate_operative_readiness(self.packet(), self.policy)
        activity = supervisor._classify_native_activity(
            [
                tool_record("python scripts/validate_repository.py"),
                tool_record("python scripts/validate_repository.py --verbose"),
            ],
            units,
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=packet,
        )
        self.assertEqual(activity["category_counts"]["focused-validation"], 1)
        self.assertEqual(activity["category_counts"]["unrelated"], 1)
        self.assertIn("unrelated-activity-denied", activity["violations"])

    def test_declared_long_running_command_authorizes_only_bound_empty_polls(self) -> None:
        command = ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
        packet = self.validation_packet([command])

        def call(name: str, call_id: str, arguments: dict) -> dict:
            return {
                "response_item": {
                    "type": "function_call",
                    "name": name,
                    "call_id": call_id,
                    "arguments": json.dumps(arguments),
                }
            }

        def output(call_id: str, value: str) -> dict:
            return {
                "response_item": {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": value,
                }
            }

        records = [
            call(
                "exec_command",
                "exec-1",
                {"cmd": " ".join(command), "workdir": str(ROOT)},
            ),
            output("exec-1", "Process running with session ID 51986"),
            call("write_stdin", "poll-1", {"session_id": 51986, "chars": ""}),
            output("poll-1", "Process running with session ID 51986"),
            call("write_stdin", "write-1", {"session_id": 51986, "chars": "q"}),
            call("write_stdin", "orphan-1", {"session_id": 41986, "chars": ""}),
            call("write_stdin", "poll-2", {"session_id": 51986, "chars": ""}),
            output("poll-2", "Process exited with code 0"),
            call("write_stdin", "stale-1", {"session_id": 51986, "chars": ""}),
        ]
        activity = supervisor._classify_native_activity(
            records,
            [],
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=packet,
        )
        self.assertEqual(activity["category_counts"]["focused-validation"], 3)
        self.assertEqual(activity["category_counts"]["unrelated"], 3)
        self.assertIn("unrelated-activity-denied", activity["violations"])

    def test_long_running_command_continuation_pairing_fails_closed(self) -> None:
        command = ["python", "scripts/validate_repository.py"]
        packet = self.validation_packet([command])
        records = [
            {
                "response_item": {
                    "type": "function_call",
                    "name": "exec_command",
                    "call_id": "exec-bad-output",
                    "arguments": json.dumps(
                        {"cmd": " ".join(command), "workdir": str(ROOT)}
                    ),
                }
            },
            {
                "response_item": {
                    "type": "function_call_output",
                    "call_id": "exec-bad-output",
                    "output": "Process running with session ID unavailable",
                }
            },
            {
                "response_item": {
                    "type": "function_call",
                    "name": "write_stdin",
                    "call_id": "unbound-poll",
                    "arguments": json.dumps({"session_id": 51986, "chars": ""}),
                }
            },
            {
                "response_item": {
                    "type": "function_call",
                    "name": "exec_command",
                    "call_id": "exec-spoofed-output",
                    "arguments": json.dumps(
                        {"cmd": " ".join(command), "workdir": str(ROOT)}
                    ),
                }
            },
            {
                "response_item": {
                    "type": "function_call_output",
                    "call_id": "exec-spoofed-output",
                    "output": (
                        "Process exited with code 0\nOutput:\n"
                        "Process running with session ID 51987"
                    ),
                }
            },
            {
                "response_item": {
                    "type": "function_call",
                    "name": "write_stdin",
                    "call_id": "spoofed-poll",
                    "arguments": json.dumps({"session_id": 51987, "chars": ""}),
                }
            },
        ]
        activity = supervisor._classify_native_activity(
            records,
            [],
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=packet,
        )
        self.assertEqual(activity["category_counts"]["focused-validation"], 2)
        self.assertEqual(activity["category_counts"]["unrelated"], 2)
        self.assertIn("unrelated-activity-denied", activity["violations"])

    def test_implementation_declared_validation_precedes_generic_readers(self) -> None:
        commands = [
            ["wc", "-l", "-w", "SKILL.md"],
            ["python", "scripts/validate_repository.py"],
        ]
        packet = self.validation_packet(commands)
        packet["lane"] = "implementation"
        packet["scope"]["prohibited_actions"].remove("source-mutation")
        packet["scope"]["allowed_actions"].append("edit-scoped-files")
        packet["work_plan"]["write_paths"] = ["SKILL.md"]
        packet["work_plan"]["task_class"] = "narrow-mechanical"
        packet["work_plan"]["task_profile"]["task_class"] = "narrow-mechanical"
        packet["work_plan"]["task_profile"]["source_mutation_count"] = 1
        packet["work_plan"]["task_profile"]["source_mutation_paths"] = ["SKILL.md"]
        units = [
            {
                "identity": "SKILL.md::whole-file::" + "0" * 64,
                "path": "SKILL.md",
                "absolute_path": str(ROOT / "SKILL.md"),
                "selector": "whole-file",
                "sha256": "0" * 64,
            }
        ]
        activity = supervisor._classify_native_activity(
            [
                tool_record("wc -l -w SKILL.md"),
                tool_record("python scripts/validate_repository.py"),
                tool_record("python scripts/validate_repository.py --verbose"),
            ],
            units,
            None,
            scoped_mutation=True,
            policy=self.policy,
            packet=packet,
        )
        self.assertEqual(activity["category_counts"]["focused-validation"], 2)
        self.assertEqual(activity["category_counts"]["targeted-read"], 0)
        self.assertEqual(activity["category_counts"]["unrelated"], 1)
        self.assertIn("unrelated-activity-denied", activity["violations"])

    def test_declared_validation_commands_do_not_override_security_precedence(self) -> None:
        commands = [
            ["rg", "--files"],
            ["cat", "/home/example/.codex/memories/MEMORY.md"],
            ["rm", "artifact.txt"],
        ]
        packet = self.validation_packet(commands)
        activity = supervisor._classify_native_activity(
            [tool_record(" ".join(command)) for command in commands],
            [],
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=packet,
        )
        self.assertEqual(activity["category_counts"]["broad-scan"], 1)
        self.assertEqual(activity["category_counts"]["memory-read"], 1)
        self.assertEqual(activity["category_counts"]["mutation"], 1)
        self.assertEqual(activity["category_counts"]["focused-validation"], 0)
        self.assertIn("broad-scan-denied", activity["violations"])
        self.assertIn("unauthorized-memory-read", activity["violations"])

    def test_exec_command_requires_exact_packet_workdir(self) -> None:
        command = ["python", "scripts/validate_repository.py"]
        packet = self.validation_packet([command])
        equivalent = str(ROOT / ".." / ROOT.name)
        activity = supervisor._classify_native_activity(
            [
                tool_record("python scripts/validate_repository.py", workdir=None),
                tool_record("python scripts/validate_repository.py", workdir=str(ROOT.parent)),
                tool_record("python scripts/validate_repository.py", workdir=equivalent),
            ],
            [],
            None,
            scoped_mutation=False,
            policy=self.policy,
            packet=packet,
        )
        self.assertIn("exec-command-workdir-missing", activity["violations"])
        self.assertIn("exec-command-workdir-mismatch", activity["violations"])
        self.assertEqual(activity["category_counts"]["unrelated"], 2)
        self.assertEqual(activity["category_counts"]["focused-validation"], 1)

    def test_workspace_new_owned_file_is_scoped_but_unplanned_file_is_hard(self) -> None:
        before = {
            "cwd": str(ROOT),
            "allowed_paths": ["new-owned.py"],
            "include_untracked": True,
            "tracked_status": [],
            "preexisting_dirty_paths": [],
            "content_fingerprints": {},
            "baseline_complete": True,
            "incomplete": False,
            "caps": {"max_files": 100, "max_bytes": 10000, "max_seconds": 1.0},
        }
        owned_after = {
            **before,
            "tracked_status": ["?? new-owned.py"],
            "content_fingerprints": {"new-owned.py": {"sha256": "1" * 64, "size": 1}},
        }
        with (
            mock.patch.object(supervisor, "_load_workspace_baseline", return_value=before),
            mock.patch.object(supervisor, "capture_workspace_baseline", return_value=owned_after),
        ):
            report = supervisor._compare_live_workspace({})
        self.assertEqual(report["mutation_categories"]["scoped"], ["new-owned.py"])
        self.assertEqual(supervisor._workspace_hard_reasons(report), [])

        unplanned_after = {
            **before,
            "tracked_status": ["?? other.py"],
            "content_fingerprints": {"other.py": {"sha256": "2" * 64, "size": 1}},
        }
        with (
            mock.patch.object(supervisor, "_load_workspace_baseline", return_value=before),
            mock.patch.object(supervisor, "capture_workspace_baseline", return_value=unplanned_after),
        ):
            report = supervisor._compare_live_workspace({})
        self.assertIn("unexpected-untracked-mutation", supervisor._workspace_hard_reasons(report))


class NativeWorkerSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="cwo-supervision-test-")
        self.root = Path(self.tmp.name)
        self.session_id = "spark-session"
        self.session_file = self.root / "session.jsonl"
        self.packet_file = self.root / "packet.json"
        self.state_file = self.root / "state.json"
        self.audit_file = self.root / "audit.jsonl"
        self.activated = False
        packet = planned_packet(
            packet_id="packet-supervision",
            budget_overrides={
                "tool_calls_soft": 5,
                "tool_calls_hard": 10,
                "runtime_seconds_soft": 30,
                "runtime_seconds_hard": 60,
            },
        )
        self.packet_file.write_text(json.dumps(packet), encoding="utf-8")
        write_records(self.session_file, [session_meta(self.session_id)])

    def test_planned_packet_uses_dispatchable_semantic_contract(self) -> None:
        self.assertEqual(self.packet_file.exists(), True)
        packet = json.loads(self.packet_file.read_text(encoding="utf-8"))
        work_plan = packet["work_plan"]
        self.assertEqual(work_plan["estimate_contract_version"], 2)
        self.assertEqual(work_plan["route"], "spark")
        self.assertEqual(work_plan["authority_route"], "spark")
        self.assertEqual(work_plan["operative_route"], "spark")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def start(self, *, now: str = "2026-07-11T00:00:00Z") -> subprocess.CompletedProcess[str]:
        return run_cli(
            "start",
            "--packet",
            str(self.packet_file),
            "--session-id",
            self.session_id,
            "--session-file",
            str(self.session_file),
            "--agent-id",
            "agent-spark",
            "--state-file",
            str(self.state_file),
            "--audit-file",
            str(self.audit_file),
            "--now",
            now,
            "--json",
        )

    def arm(self, now: str, *, control_turn: str = CONTROL_TURN) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "arm",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--now",
            now,
            "--json",
        )

    def mark_dispatched(
        self,
        now: str,
        *,
        control_turn: str = CONTROL_TURN,
    ) -> subprocess.CompletedProcess[str]:
        result = run_cli(
            "mark-dispatched",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--submission-id",
            "submission-test",
            "--now",
            now,
            "--json",
        )
        if result.returncode == 0:
            self.activated = True
        return result

    def activate_before(self, now: str) -> None:
        parsed = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        arm_at = (parsed - dt.timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dispatch_at = (parsed - dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        if state["status"] == "created":
            armed = self.arm(arm_at)
            self.assertEqual(armed.returncode, 0, armed.stderr)
        dispatched = self.mark_dispatched(dispatch_at)
        self.assertEqual(dispatched.returncode, 0, dispatched.stderr)

    def check(self, now: str, *, control_turn: str = CONTROL_TURN) -> subprocess.CompletedProcess[str]:
        if not self.activated:
            self.activate_before(now)
        return run_cli(
            "check",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            control_turn,
            "--now",
            now,
            "--json",
        )

    def finalize(self, action: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "finalize",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--control-action",
            action,
            "--now",
            "2026-07-11T00:01:00Z",
            "--json",
        )

    def test_start_attests_and_refuses_duplicate_state(self) -> None:
        started = self.start()
        self.assertEqual(started.returncode, 0, started.stderr)
        payload = json.loads(started.stdout)
        self.assertEqual(payload["requested_model"], MODEL)
        self.assertEqual(payload["interrupt_thresholds"], {"tool_calls": 7, "runtime_seconds": 54})
        self.assertEqual(payload["segment_start_grace_seconds"], 10)
        self.assertEqual(payload["baseline_record_count"], 1)
        self.assertEqual(payload["status"], "created")
        observed = payload["observed"]
        self.assertEqual(observed["operative_readiness"]["decision"], "operative-ready")
        self.assertEqual(len(observed["context_units"]), 1)
        self.assertTrue(Path(observed["workspace_baseline"]["path"]).is_file())
        self.assertEqual(observed["activity"], supervisor._empty_activity())
        events = [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item["event_type"] for item in events], ["native_supervision_started"])
        self.assertEqual(events[0]["planned_tool_calls_hard"], 10)
        self.assertEqual(events[0]["interrupt_tool_calls_threshold"], 7)
        if HAS_JSONSCHEMA:
            import jsonschema

            state_schema = json.loads((ROOT / "schemas" / "native-supervision-state.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(json.loads(self.state_file.read_text(encoding="utf-8")), state_schema)
        armed = self.arm("2026-07-11T00:00:01Z")
        self.assertEqual(armed.returncode, 0, armed.stderr)
        invalid_receipt = self.finalize("interrupt-confirmed")
        self.assertNotEqual(invalid_receipt.returncode, 0)
        self.assertIn("requires an interrupt", invalid_receipt.stderr)
        invalid_completion = self.finalize("worker-completed")
        self.assertNotEqual(invalid_completion.returncode, 0)
        self.assertIn("requires a complete", invalid_completion.stderr)
        duplicate = self.start()
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("duplicate active", duplicate.stderr)

    def test_start_rejects_attestation_mismatch(self) -> None:
        records = [session_meta(self.session_id)]
        records[0]["turn_context"]["model"] = "gpt-5.6-sol"
        write_records(self.session_file, records)
        result = self.start()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attestation mismatch", result.stderr)

    def test_start_accepts_explicit_authorized_luna_packet(self) -> None:
        packet = planned_packet(packet_id="packet-supervision-luna", requested_model=LUNA_MODEL)
        self.packet_file.write_text(json.dumps(packet), encoding="utf-8")
        records = [session_meta(self.session_id)]
        records[0]["turn_context"]["model"] = LUNA_MODEL
        write_records(self.session_file, records)

        started = self.start()
        self.assertEqual(started.returncode, 0, started.stderr)
        payload = json.loads(started.stdout)
        self.assertEqual(payload["requested_model"], LUNA_MODEL)
        if HAS_JSONSCHEMA:
            import jsonschema

            schema = json.loads((ROOT / "schemas" / "native-supervision-state.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(json.loads(self.state_file.read_text(encoding="utf-8")), schema)

    def test_unarmed_check_and_dispatch_are_rejected(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        unchecked = run_cli(
            "check",
            "--state-file",
            str(self.state_file),
            "--control-turn-id",
            CONTROL_TURN,
            "--now",
            "2026-07-11T00:00:01Z",
            "--json",
        )
        self.assertNotEqual(unchecked.returncode, 0)
        self.assertIn("does not match", unchecked.stderr)
        dispatched = self.mark_dispatched("2026-07-11T00:00:01Z")
        self.assertNotEqual(dispatched.returncode, 0)
        self.assertIn("requires an armed", dispatched.stderr)

    def test_arm_window_and_control_turn_binding_fail_closed(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:01Z").returncode, 0)
        wrong_turn = self.mark_dispatched(
            "2026-07-11T00:00:02Z",
            control_turn="different-turn",
        )
        self.assertEqual(wrong_turn.returncode, 2, wrong_turn.stderr)
        wrong_payload = json.loads(wrong_turn.stdout)
        self.assertEqual(wrong_payload["decision"], "control-lost")
        self.assertIn("control-turn-mismatch-after-dispatch", wrong_payload["reasons"])

        self.state_file.unlink()
        self.audit_file.unlink()
        write_records(self.session_file, [session_meta(self.session_id)])
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:01Z").returncode, 0)
        stale = self.mark_dispatched("2026-07-11T00:00:07Z")
        self.assertEqual(stale.returncode, 2, stale.stderr)
        payload = json.loads(stale.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertIn("arm-to-dispatch-latency-exceeded", payload["reasons"])
        self.assertTrue(payload["control_action_required"])

    def test_wrong_control_turn_during_running_monitor_quarantines(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:00Z").returncode, 0)
        self.assertEqual(self.mark_dispatched("2026-07-11T00:00:01Z").returncode, 0)
        checked = self.check(
            "2026-07-11T00:00:02Z",
            control_turn="different-turn",
        )
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertIn("control-turn-mismatch-during-monitoring", payload["reasons"])
        self.assertEqual(payload["session_disposition"], "quarantined")

    def test_late_first_and_intermediate_polls_fail_closed(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.assertEqual(self.arm("2026-07-11T00:00:00Z").returncode, 0)
        self.assertEqual(self.mark_dispatched("2026-07-11T00:00:01Z").returncode, 0)
        late_first = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(late_first.returncode, 0, late_first.stderr)
        payload = json.loads(late_first.stdout)
        self.assertEqual(payload["decision"], "warn")
        self.assertIn("poll-latency-observed", payload["reasons"])
        self.assertEqual(payload["control_timing"]["dispatch_to_first_poll_ms"], 3000)
        self.assertEqual(payload["control_timing"]["late_poll_count"], 1)

        self.state_file.unlink()
        self.audit_file.unlink()
        self.activated = False
        write_records(self.session_file, [session_meta(self.session_id)])
        self.assertEqual(self.start().returncode, 0)
        first = self.check("2026-07-11T00:00:03Z")
        self.assertEqual(first.returncode, 0, first.stderr)
        late_next = self.check("2026-07-11T00:00:06Z")
        self.assertEqual(late_next.returncode, 0, late_next.stderr)
        next_payload = json.loads(late_next.stdout)
        self.assertEqual(next_payload["decision"], "warn")
        self.assertIn("poll-latency-observed", next_payload["reasons"])
        self.assertEqual(next_payload["control_timing"]["max_poll_gap_ms"], 3000)

    def test_startup_grace_then_fail_closed_without_task_boundary(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        waiting = self.check("2026-07-11T00:00:05Z")
        self.assertEqual(waiting.returncode, 0, waiting.stderr)
        reasons = json.loads(waiting.stdout)["reasons"]
        self.assertIn("awaiting-task-boundary", reasons)
        if HAS_JSONSCHEMA:
            import jsonschema

            decision_schema = json.loads((ROOT / "schemas" / "native-supervision-decision.schema.json").read_text(encoding="utf-8"))
            jsonschema.validate(json.loads(waiting.stdout), decision_schema)
        for second in range(6, 15):
            polled = self.check(f"2026-07-11T00:00:{second:02d}Z")
            self.assertEqual(polled.returncode, 0, polled.stderr)
        expired = self.check("2026-07-11T00:00:15Z")
        self.assertEqual(expired.returncode, 2, expired.stderr)
        payload = json.loads(expired.stdout)
        self.assertEqual(payload["decision"], "control-lost")
        self.assertTrue(payload["control_action_required"])

    def test_delayed_trusted_completion_is_complete_not_quarantine(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:12Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:13Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:16Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "complete")
        self.assertFalse(payload["control_action_required"])

    def test_hard_activity_violation_wins_over_trusted_completion(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event(
                "2026-07-11T00:00:02Z",
                self.session_id,
                "assistant",
                tool=True,
                command="rg --files",
            ),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "interrupt")
        self.assertIn("broad-scan-denied", payload["reasons"])
        self.assertEqual(payload["artifact_disposition"], "architect-adjudication-required")

    def test_exec_workdir_violation_wins_over_trusted_completion(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event(
                "2026-07-11T00:00:02Z",
                self.session_id,
                "assistant",
                tool=True,
                workdir=str(ROOT.parent),
            ),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "interrupt")
        self.assertIn("exec-command-workdir-mismatch", payload["reasons"])
        self.assertEqual(payload["artifact_disposition"], "architect-adjudication-required")

    def test_completed_attestation_segment_is_outside_live_task_watermark(self) -> None:
        attestation_records = [
            session_meta(self.session_id),
            event("2026-07-10T23:59:58Z", self.session_id, "task_started"),
            event("2026-07-10T23:59:59Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, attestation_records)
        started = self.start()
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertEqual(json.loads(started.stdout)["baseline_record_count"], 3)

        waiting = self.check("2026-07-11T00:00:05Z")
        self.assertEqual(waiting.returncode, 0, waiting.stderr)
        self.assertEqual(json.loads(waiting.stdout)["reasons"], ["awaiting-task-boundary"])

        operative_records = [
            event("2026-07-11T00:00:05.100Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:05.200Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:05.300Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, [*attestation_records, *operative_records])
        checked = self.check("2026-07-11T00:00:06Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "complete")
        self.assertEqual(payload["observed"]["tool_calls"], 1)

    def test_under_budget_completion_uses_selected_segment_not_raw_tail(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:02Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        records.extend(
            event(f"2026-07-11T00:00:{second:02d}Z", self.session_id, "token_count")
            for second in range(4, 10)
        )
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:10Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["decision"], "complete")
        finalized = self.finalize("worker-completed")
        self.assertEqual(finalized.returncode, 0, finalized.stderr)
        self.assertEqual(json.loads(finalized.stdout)["status"], "completed")
        events = [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(
            [item["event_type"] for item in events],
            ["native_supervision_started", "native_supervision_armed", "native_supervision_dispatched", "native_supervision_decision", "native_supervision_control_receipt"],
        )
        self.assertEqual(events[3]["observed_tool_calls"], 1)
        self.assertEqual(events[-1]["control_action"], "worker-completed")
        self.assertNotIn("agent_model_calls", events[0])
        self.assertEqual(events[3]["agent_model_calls"], 1)
        self.assertNotIn("agent_model_calls", events[-1])
        self.assertNotIn("workerbee_actual_model", events[-1])
        self.assertTrue(events[3]["monitor_armed_before_dispatch"])
        self.assertEqual(events[3]["arm_to_dispatch_ms"], 1000)
        self.assertEqual(events[3]["dispatch_to_first_poll_ms"], 1000)
        self.assertEqual(events[3]["max_poll_gap_ms"], 1000)
        self.assertEqual(events[3]["late_poll_count"], 0)

    def test_budget_observation_uses_selected_operative_segment(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [
            session_meta(self.session_id),
            event("2026-07-10T23:50:00Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:00Z", self.session_id, "task_complete"),
            event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
            event("2026-07-11T00:00:02Z", self.session_id, "assistant", tool=True),
            event("2026-07-11T00:00:03Z", self.session_id, "task_complete"),
        ]
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:04Z")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "complete")
        self.assertEqual(payload["observed"]["tool_calls"], 1)
        self.assertEqual(payload["observed"]["elapsed_seconds"], 2)

    def test_tool_reserve_interrupts_at_threshold(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        records = [session_meta(self.session_id), event("2026-07-11T00:00:01Z", self.session_id, "task_started")]
        records.extend(
            event(f"2026-07-11T00:00:{second:02d}Z", self.session_id, "assistant", tool=True)
            for second in range(2, 9)
        )
        write_records(self.session_file, records)
        checked = self.check("2026-07-11T00:00:09Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "interrupt")
        self.assertEqual(payload["observed"]["tool_calls"], 7)
        self.assertIn("tool-call-interrupt-threshold", payload["reasons"])

        premature = self.finalize("close-confirmed")
        self.assertNotEqual(premature.returncode, 0)
        self.assertIn("requires an interrupt-confirmed", premature.stderr)
        self.assertEqual(self.finalize("interrupt-confirmed").returncode, 0)
        closed = self.finalize("close-confirmed")
        self.assertEqual(closed.returncode, 0, closed.stderr)
        closed_payload = json.loads(closed.stdout)
        self.assertEqual(closed_payload["status"], "closed")
        self.assertFalse(closed_payload["control_action_required"])

    def test_compaction_full_suite_mismatch_and_trailing_partial_fail_closed(self) -> None:
        cases = [
            (event("2026-07-11T00:00:02Z", self.session_id, "context_compacted"), "context-compaction"),
            (
                event(
                    "2026-07-11T00:00:02Z",
                    self.session_id,
                    "assistant",
                    tool=True,
                    command="python -m unittest discover -s tests -v",
                ),
                "full-suite-limit",
            ),
            (event("2026-07-11T00:00:02Z", self.session_id, "assistant", model="gpt-5.6-sol"), "model-mismatch"),
        ]
        for index, (trigger, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                if index:
                    self.state_file.unlink()
                    write_records(self.session_file, [session_meta(self.session_id)])
                    self.activated = False
                self.assertEqual(self.start().returncode, 0)
                records = [
                    session_meta(self.session_id),
                    event("2026-07-11T00:00:01Z", self.session_id, "task_started"),
                    trigger,
                ]
                write_records(self.session_file, records, trailing='{"timestamp":')
                checked = self.check("2026-07-11T00:00:03Z")
                self.assertEqual(checked.returncode, 2, checked.stderr)
                payload = json.loads(checked.stdout)
                self.assertIn(reason, payload["reasons"])
                self.assertTrue(payload["trailing_partial_record_ignored"])

    def test_malformed_telemetry_fails_closed(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        malformed = (
            json.dumps(session_meta(self.session_id), separators=(",", ":")) + "\n"
            + "{\n"
        )
        self.session_file.write_text(malformed, encoding="utf-8")
        checked = self.check("2026-07-11T00:00:03Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        payload = json.loads(checked.stdout)
        self.assertEqual(payload["decision"], "control-lost")

    def test_missing_session_after_start_is_control_lost(self) -> None:
        self.assertEqual(self.start().returncode, 0)
        self.session_file.unlink()
        checked = self.check("2026-07-11T00:00:01Z")
        self.assertEqual(checked.returncode, 2, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["decision"], "control-lost")
        failed = self.finalize("control-failed")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertFalse(json.loads(failed.stdout)["control_action_required"])
        final_check = self.check("2026-07-11T00:00:02Z")
        self.assertEqual(final_check.returncode, 2, final_check.stderr)


if __name__ == "__main__":
    unittest.main()
