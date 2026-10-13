from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))
from tests.historical_policy_fixtures import historical_v2_policy, historical_cli_args

from cwo_core.native_precommit import (  # noqa: E402
    arm_precommit,
    canonical_sha256,
    check_precommit,
    create_precommit_state,
    finalize_precommit,
    issue_precommit_receipt,
    make_deterministic_receipt,
    mark_fit_dispatched,
    render_fit_prompt,
    validate_precommit_receipt,
)
import cwo_core.native_precommit as native_precommit  # noqa: E402
from cwo_core.paths import cwo_temp_dir  # noqa: E402


MODEL = "gpt-5.3-codex-spark"
CONTROL_TURN = "control-turn-precommit-test"
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def work_plan() -> dict:
    return {
        "work_unit_id": "precommit-work-unit",
        "bead_id": "complex-work-orchestration-fsh.2",
        "requested_model": MODEL,
        "task_class": "bounded-implementation",
        "primary_outcome": "Make the bounded native precommit behavior deterministic.",
        "acceptance_checks": [
            "The focused lifecycle check passes.",
            "Malformed evidence fails closed.",
        ],
        "scores": {
            "reasoning_uncertainty": 1,
            "subsystem_coupling": 2,
            "contract_risk": 2,
            "diagnostic_uncertainty": 1,
            "context_breadth": 1,
            "validation_breadth": 2,
        },
        "aggregate_allowance": {
            "tool_calls_soft": 20,
            "tool_calls_hard": 40,
            "runtime_seconds_soft": 300,
            "runtime_seconds_hard": 600,
        },
    }


def session_record(session_id: str, *, model: str = MODEL, source: str | None = "trusted-control-plane-session-metadata") -> dict:
    context = {
        "model": model,
        "token_count": {"input": 0, "cached_input": 0, "output": 0, "reasoning": 0, "total": 0},
    }
    if source is not None:
        context["attestation_source"] = source
    return {
        "timestamp": "2026-07-15T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id},
        "turn_context": context,
    }


def fit_records(session_id: str, *, item_type: str | None = None, event_name: str | None = None, model: str = MODEL, response: str | None = None) -> list[dict]:
    records: list[dict] = [
        {
            "timestamp": "2026-07-15T00:00:01Z",
            "session_id": session_id,
            "type": "response_item",
            "turn_context": {"model": model, "attestation_source": "trusted-control-plane-session-metadata"},
            "response_item": {"type": "message", "role": "user", "content": "fit"},
        }
    ]
    if event_name:
        records.append(
            {
                "timestamp": "2026-07-15T00:00:02Z",
                "session_id": session_id,
                "event_msg": event_name,
                "turn_context": {"model": model, "attestation_source": "trusted-control-plane-session-metadata"},
            }
        )
    if item_type:
        records.append(
            {
                "timestamp": "2026-07-15T00:00:02Z",
                "session_id": session_id,
                "type": "response_item",
                "turn_context": {"model": model, "attestation_source": "trusted-control-plane-session-metadata"},
                "response_item": {"type": item_type, "name": "exec_command", "arguments": "{}"},
            }
        )
    if response is None:
        response = json.dumps(
            {
                "decision": "accept",
                "tool_calls_p50": 8,
                "tool_calls_p90": 16,
                "runtime_seconds_p50": 120,
                "runtime_seconds_p90": 240,
            },
            sort_keys=True,
        )
    records.extend(
        [
            {
                "timestamp": "2026-07-15T00:00:03Z",
                "session_id": session_id,
                "type": "response_item",
                "turn_context": {
                    "model": model,
                    "attestation_source": "trusted-control-plane-session-metadata",
                    "token_count": {"input": 10, "cached_input": 0, "output": 5, "reasoning": 1, "total": 16},
                },
                "response_item": {"type": "message", "role": "assistant", "content": response},
            },
            {
                "timestamp": "2026-07-15T00:00:04Z",
                "session_id": session_id,
                "event_msg": "task_complete",
                "turn_context": {"model": model, "attestation_source": "trusted-control-plane-session-metadata"},
            },
        ]
    )
    return records


def write_records(path: Path, records: list[dict], *, trailing: str = "") -> None:
    path.write_text(
        "".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records) + trailing,
        encoding="utf-8",
    )


class NativePrecommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cwo-precommit-test-")
        self.addCleanup(self.temp.cleanup)
        temp_root = Path(self.temp.name)
        self.env = mock.patch.dict(
            os.environ,
            {
                "CWO_TEMP_ROOT": str(temp_root),
                "CWO_SESSION_ID": "precommit-fixture-session",
                "CWO_PRECOMMIT_REGISTRY_ROOT": str(temp_root / "precommit-registry"),
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.root = cwo_temp_dir(scope="session")
        self.workdir = self.root / "workspace"
        self.workdir.mkdir()
        (self.workdir / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.workdir, check=True)
        subprocess.run(["git", "add", "tracked.txt"], cwd=self.workdir, check=True)
        self.session_id = "spark-precommit-session"
        self.session_file = self.root / "session.jsonl"
        write_records(self.session_file, [session_record(self.session_id)])
        self.state_file = self.root / "state.json"
        self.receipt_file = self.root / "receipt.json"
        self.audit_file = self.root / "audit.jsonl"
        self.registry = self.root / "registry"

    def create(self, **overrides: object) -> dict:
        values = {
            "packet_id": "packet-precommit-test",
            "attempt_nonce": "nonce-precommit-test",
            "work_plan": work_plan(),
            "session_id": self.session_id,
            "session_file": self.session_file,
            "agent_id": "spark-agent",
            "workdir": self.workdir,
            "state_file": self.state_file,
            "owner_pid": os.getpid(),
            "audit_file": self.audit_file,
            "now": "2026-07-15T00:00:00Z",
        }
        values.update(overrides)
        return create_precommit_state(**values)

    def dispatch(self) -> None:
        arm_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.100Z")
        state, code = mark_fit_dispatched(
            self.state_file,
            CONTROL_TURN,
            "native-submission-1",
            now="2026-07-15T00:00:00.200Z",
        )
        self.assertEqual(code, 0)
        self.assertEqual(state["status"], "fit-dispatched")

    def positive_receipt(self) -> dict:
        self.create()
        self.dispatch()
        write_records(self.session_file, [session_record(self.session_id), *fit_records(self.session_id)])
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 0)
        self.assertEqual(state["status"], "completed")
        finalize_precommit(self.state_file, CONTROL_TURN, "worker-completed", now="2026-07-15T00:00:00.400Z")
        finalize_precommit(self.state_file, CONTROL_TURN, "close-confirmed", now="2026-07-15T00:00:00.500Z")
        return issue_precommit_receipt(self.state_file, receipt_file=self.receipt_file)

    def test_fit_prompt_is_deterministic_and_contains_bounded_semantic_context(self) -> None:
        prompt = render_fit_prompt(work_plan())
        self.assertEqual(prompt, render_fit_prompt(copy.deepcopy(work_plan())))
        payload = json.loads(prompt)
        self.assertEqual(payload["work_plan_sha256"], canonical_sha256(work_plan()))
        self.assertEqual(set(payload), {
            "request_type", "version", "work_plan_sha256", "task_class",
            "primary_outcome", "acceptance_checks",
            "complexity_dimensions", "aggregate_allowance", "decision_vocabulary",
            "required_numeric_fields", "required_numeric_minimum",
            "self_contained", "context_policy", "tool_policy", "response_policy",
        })
        self.assertEqual(payload["required_numeric_minimum"], 1)
        self.assertEqual(payload["version"], 3)
        self.assertEqual(payload["primary_outcome"], work_plan()["primary_outcome"])
        self.assertEqual(payload["acceptance_checks"], work_plan()["acceptance_checks"])
        self.assertIs(payload["self_contained"], True)
        self.assertEqual(
            payload["context_policy"],
            "do-not-read-memory-skills-files-or-other-context",
        )
        self.assertEqual(payload["tool_policy"], "do-not-use-tools")
        self.assertEqual(
            payload["response_policy"],
            "return-exactly-one-json-object-with-no-commentary",
        )
        self.assertNotIn(str(ROOT), prompt)
        self.assertNotIn("/home/", prompt)

    def test_fit_prompt_rejects_text_smuggling_through_names_or_task_class(self) -> None:
        cases = []
        plan = work_plan()
        plan["task_class"] = "/repo/private/path"
        cases.append(plan)
        plan = work_plan()
        plan["scores"]["run_shell_command"] = plan["scores"].pop("contract_risk")
        cases.append(plan)
        plan = work_plan()
        plan["aggregate_allowance"]["source_excerpt"] = 1
        cases.append(plan)
        plan = work_plan()
        plan["scores"]["contract_risk"] = 1.5
        cases.append(plan)
        plan = work_plan()
        plan["primary_outcome"] = "Inspect /repo/private/path before deciding."
        cases.append(plan)
        plan = work_plan()
        plan["acceptance_checks"] = ["Run `git status` to decide."]
        cases.append(plan)
        plan = work_plan()
        plan["acceptance_checks"] = ["first\nsecond"]
        cases.append(plan)
        plan = work_plan()
        plan["acceptance_checks"] = []
        cases.append(plan)
        plan = work_plan()
        plan["acceptance_checks"] = ["bounded"] * 7
        cases.append(plan)
        plan = work_plan()
        plan["primary_outcome"] = "x" * 1001
        cases.append(plan)
        for malformed in cases:
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    render_fit_prompt(malformed)

    def test_positive_lifecycle_issues_live_valid_receipt(self) -> None:
        receipt = self.positive_receipt()
        self.assertTrue(receipt["accepting"])
        self.assertEqual(receipt["observed"]["function_calls"], 0)
        self.assertEqual(receipt["observed"]["custom_tool_calls"], 0)
        self.assertEqual(receipt["observed"]["context_compactions"], 0)
        self.assertEqual(receipt["observed"]["workspace_mutations"], 0)
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        self.assertEqual(validate_precommit_receipt(payload, work_plan(), live=True, require_accepting=True), [])

    def test_accepting_numeric_fit_estimates_are_advisory(self) -> None:
        receipt = self.positive_receipt()
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        payload["fit_result"]["estimates"]["tool_calls_p90"] = 80
        payload["fit_result"]["estimates"]["runtime_seconds_p90"] = 780
        payload["receipt_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        self.assertEqual(
            validate_precommit_receipt(payload, work_plan(), require_accepting=True),
            [],
        )

    def test_explicit_fit_refusal_cannot_be_accepting(self) -> None:
        receipt = self.positive_receipt()
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        payload["fit_result"]["decision"] = "pm-realignment"
        payload["accepting"] = False
        payload["disposition"] = "reject"
        payload["receipt_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        self.assertEqual(validate_precommit_receipt(payload, work_plan()), [])
        self.assertIn(
            "precommit receipt is non-accepting",
            validate_precommit_receipt(payload, work_plan(), require_accepting=True),
        )

    def assert_forbidden_activity_interrupts(
        self,
        *,
        reason: str,
        item_type: str | None = None,
        event_name: str | None = None,
    ) -> None:
        self.create()
        self.dispatch()
        records = fit_records(self.session_id, item_type=item_type, event_name=event_name)
        write_records(self.session_file, [session_record(self.session_id), *records])
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 2)
        self.assertEqual(state["status"], "interrupt-pending")
        self.assertIn(reason, state["reasons"])

    def test_function_call_interrupts(self) -> None:
        self.assert_forbidden_activity_interrupts(reason="function-call", item_type="function_call")

    def test_custom_tool_call_interrupts(self) -> None:
        self.assert_forbidden_activity_interrupts(reason="custom-tool-call", item_type="custom_tool_call")

    def test_compaction_interrupts(self) -> None:
        self.assert_forbidden_activity_interrupts(reason="context-compaction", event_name="context_compacted")

    def test_missing_or_mismatched_attestation_fails_before_state_creation(self) -> None:
        for source, model in ((None, MODEL), ("trusted-control-plane-session-metadata", "gpt-5.6-sol")):
            with self.subTest(source=source, model=model):
                write_records(self.session_file, [session_record(self.session_id, model=model, source=source)])
                with self.assertRaisesRegex(ValueError, "attestation"):
                    self.create()
                self.assertFalse(self.state_file.exists())

    @mock.patch(
        "cwo_core.operative_routing._now_iso",
        new=lambda: "2026-09-03T19:15:00Z",
    )
    @historical_v2_policy()
    def test_fallback_precommit_requires_route_and_exact_attestation(self) -> None:
        from tests.test_operative_routing import (
            GPT55_MODEL, LUNA_MODEL, NOW, TERRA_MODEL, fallback_bundle, select_route, work_plan as fallback_plan,
        )

        for index, model in enumerate((GPT55_MODEL, TERRA_MODEL, LUNA_MODEL), start=1):
            with self.subTest(model=model):
                plan = fallback_plan(requested_model=model, narrow=model == LUNA_MODEL)
                bundle = fallback_bundle(plan=plan)
                route = select_route(bundle, model)
                fallback_session_id = f"fallback-session-{index}"
                fallback_session_file = self.root / f"fallback-session-{index}.jsonl"
                fallback_workdir = self.root / f"fallback-workspace-{index}"
                fallback_workdir.mkdir()
                (fallback_workdir / "tracked.txt").write_text("baseline\n", encoding="utf-8")
                subprocess.run(["git", "init", "-q"], cwd=fallback_workdir, check=True)
                subprocess.run(["git", "add", "tracked.txt"], cwd=fallback_workdir, check=True)
                common = {
                    "work_plan": plan, "requested_model": model,
                    "session_id": fallback_session_id, "session_file": fallback_session_file,
                    "agent_id": f"fallback-agent-{index}", "workdir": fallback_workdir,
                    "owner_pid": os.getpid(), "audit_file": self.root / f"fallback-audit-{index}.jsonl",
                    "now": NOW,
                }
                write_records(fallback_session_file, [session_record(fallback_session_id, model=model)])
                with self.assertRaisesRegex(ValueError, "valid operative routing"):
                    create_precommit_state(
                        **common, operative_routing=None,
                        state_file=self.root / f"fallback-missing-route-{index}.json",
                        packet_id=f"fallback-missing-route-{index}",
                        attempt_nonce=f"fallback-missing-route-{index}",
                    )
                write_records(fallback_session_file, [session_record(fallback_session_id, model=MODEL)])
                with self.assertRaisesRegex(ValueError, "attestation"):
                    create_precommit_state(
                        **common, operative_routing=route,
                        state_file=self.root / f"fallback-wrong-model-{index}.json",
                        packet_id=f"fallback-wrong-model-{index}",
                        attempt_nonce=f"fallback-wrong-model-{index}",
                    )
                write_records(fallback_session_file, [session_record(fallback_session_id, model=model)])
                state = create_precommit_state(
                    **common, operative_routing=route,
                    state_file=self.root / f"fallback-exact-model-{index}.json",
                    packet_id=f"fallback-exact-model-{index}",
                    attempt_nonce=f"fallback-exact-model-{index}",
                )
                self.assertEqual(state["requested_model"], model)
                self.assertEqual(state["attested_model"], model)
                self.assertEqual(state["operative_routing_sha256"], canonical_sha256(route))

    def test_trailing_partial_truncation_and_rewritten_prefix_fail_closed(self) -> None:
        write_records(self.session_file, [session_record(self.session_id)], trailing="{")
        with self.assertRaisesRegex(ValueError, "trailing partial"):
            self.create()
        write_records(self.session_file, [session_record(self.session_id)])
        self.create()
        self.dispatch()
        self.session_file.write_text("{}\n", encoding="utf-8")
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 2)
        self.assertEqual(state["status"], "control-failed")

    def test_control_turn_first_poll_and_interrupt_completion_race_fail_closed(self) -> None:
        self.create()
        self.dispatch()
        write_records(self.session_file, [session_record(self.session_id), *fit_records(self.session_id)])
        state, code = check_precommit(self.state_file, "wrong-control-turn", now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 2)
        self.assertEqual(state["status"], "control-failed")
        self.assertTrue(state["interrupt_requested"])

    def test_invalid_output_completes_with_nonaccepting_receipt(self) -> None:
        self.create()
        self.dispatch()
        write_records(
            self.session_file,
            [session_record(self.session_id), *fit_records(self.session_id, response="not json")],
        )
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 0)
        self.assertEqual(state["semantic_status"], "invalid")
        finalize_precommit(self.state_file, CONTROL_TURN, "worker-completed", now="2026-07-15T00:00:00.400Z")
        finalize_precommit(self.state_file, CONTROL_TURN, "close-confirmed", now="2026-07-15T00:00:00.500Z")
        receipt = issue_precommit_receipt(self.state_file, receipt_file=self.receipt_file)
        self.assertFalse(receipt["accepting"])
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        self.assertTrue(any("non-accepting" in error for error in validate_precommit_receipt(payload, require_accepting=True)))

    def test_zero_tool_call_estimate_is_rejected_and_prompt_states_minimum(self) -> None:
        prompt = json.loads(render_fit_prompt(work_plan()))
        self.assertEqual(prompt["required_numeric_minimum"], 1)
        response = json.dumps(
            {
                "decision": "accept",
                "tool_calls_p50": 0,
                "tool_calls_p90": 0,
                "runtime_seconds_p50": 1,
                "runtime_seconds_p90": 2,
            },
            sort_keys=True,
        )
        with self.assertRaisesRegex(ValueError, "tool_calls_p50 must be a positive integer"):
            native_precommit.parse_fit_result(response)

    def test_workspace_mutation_and_lease_collisions_fail_closed(self) -> None:
        self.create()
        other_session = self.root / "other.jsonl"
        write_records(other_session, [session_record(self.session_id)])
        with self.assertRaisesRegex(ValueError, "duplicate precommit packet_id"):
            self.create(state_file=self.root / "duplicate.json", session_file=other_session)
        self.dispatch()
        (self.workdir / "tracked.txt").write_text("mutated\n", encoding="utf-8")
        write_records(self.session_file, [session_record(self.session_id), *fit_records(self.session_id)])
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 2)
        self.assertIn("workspace-mutation", state["reasons"])

    def test_active_session_worktree_nonce_and_stale_lease_rules(self) -> None:
        sleeper = subprocess.Popen(["sleep", "30"])
        self.addCleanup(lambda: sleeper.poll() is None and sleeper.terminate())
        self.create(owner_pid=sleeper.pid)
        other_session = self.root / "other-session.jsonl"
        write_records(other_session, [session_record("other-session")])
        with self.assertRaisesRegex(ValueError, "overlapping active precommit worktree lease"):
            self.create(
                packet_id="other-packet",
                attempt_nonce="other-nonce",
                session_id="other-session",
                session_file=other_session,
                state_file=self.root / "other-state.json",
            )
        arm_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.100Z")
        finalize_precommit(self.state_file, CONTROL_TURN, "control-failed", now="2026-07-15T00:00:00.200Z")
        finalize_precommit(self.state_file, CONTROL_TURN, "interrupt-confirmed", now="2026-07-15T00:00:00.300Z")
        finalize_precommit(self.state_file, CONTROL_TURN, "close-confirmed", now="2026-07-15T00:00:00.400Z")
        sleeper.terminate()
        sleeper.wait(timeout=5)
        created = self.create(
            packet_id="terminal-cleanup-packet",
            attempt_nonce="terminal-cleanup-nonce",
            session_id="other-session",
            session_file=other_session,
            state_file=self.root / "terminal-cleanup-state.json",
        )
        self.assertEqual(created["status"], "created")

        dead_owner = subprocess.Popen(["sleep", "30"])
        self.addCleanup(lambda: dead_owner.poll() is None and dead_owner.terminate())
        second_state = self.root / "dead-owner-state.json"
        second_session = self.root / "dead-owner-session.jsonl"
        dead_owner_worktree = self.root / "dead-owner-worktree"
        dead_owner_worktree.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=dead_owner_worktree, check=True)
        write_records(second_session, [session_record("dead-owner-session")])
        self.create(
            packet_id="dead-owner-packet",
            attempt_nonce="dead-owner-nonce",
            session_id="dead-owner-session",
            session_file=second_session,
            workdir=dead_owner_worktree,
            state_file=second_state,
            owner_pid=dead_owner.pid,
        )
        dead_owner.terminate()
        dead_owner.wait(timeout=5)
        third_session = self.root / "third-session.jsonl"
        write_records(third_session, [session_record("third-session")])
        with self.assertRaisesRegex(ValueError, "owner is dead.*non-terminal"):
            self.create(
                packet_id="third-packet",
                attempt_nonce="third-nonce",
                session_id="third-session",
                session_file=third_session,
                workdir=dead_owner_worktree,
                state_file=self.root / "third-state.json",
            )

    def test_failed_workspace_comparison_fails_closed(self) -> None:
        self.create()
        self.dispatch()
        with mock.patch.object(native_precommit, "_workspace_report", side_effect=ValueError("comparison failed")):
            state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.300Z")
        self.assertEqual(code, 2)
        self.assertEqual(state["status"], "control-failed")
        self.assertIn("comparison failed", state["reasons"])

    def test_non_git_workspace_is_rejected_fail_closed(self) -> None:
        ordinary = self.root / "ordinary-workspace"
        ordinary.mkdir()
        with self.assertRaisesRegex(
            ValueError, "workspace baseline comparison is incomplete"
        ):
            self.create(
                packet_id="non-git-workspace-packet",
                attempt_nonce="non-git-workspace-attempt",
                workdir=ordinary,
                state_file=self.root / "non-git-workspace-state.json",
            )

    def test_state_transition_lock_serializes_concurrent_writers(self) -> None:
        self.create()

        def arm_once() -> str:
            try:
                arm_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:00.100Z")
            except ValueError as exc:
                return str(exc)
            return "armed"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: arm_once(), range(2)))
        self.assertEqual(results.count("armed"), 1)
        self.assertEqual(sum("requires a created" in result for result in results), 1)
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "armed")
        self.assertEqual(native_precommit.validate_precommit_state(state), [])

    def test_pid_birth_and_topology_identity_changes_fail_closed(self) -> None:
        for field in ("start_time_ticks", "process_group_id", "session_id"):
            with self.subTest(field=field):
                os.environ["CWO_PRECOMMIT_REGISTRY_ROOT"] = str(self.root / f"{field}-registry")
                state_path = self.root / f"{field}-state.json"
                self.create(
                    packet_id=f"{field}-packet",
                    attempt_nonce=f"{field}-nonce",
                    state_file=state_path,
                )
                state = json.loads(state_path.read_text(encoding="utf-8"))
                state["owner_identity"][field] += 1
                native_precommit._write_state(state_path, state)
                with self.assertRaisesRegex(ValueError, "identity or topology changed"):
                    arm_precommit(state_path, CONTROL_TURN, now="2026-07-15T00:00:00.100Z")

    def test_state_lock_symlink_is_rejected(self) -> None:
        lock_path = self.state_file.with_name(self.state_file.name + ".lock")
        lock_path.symlink_to(self.root / "elsewhere.lock")
        with self.assertRaisesRegex(ValueError, "lock must be a current-user regular non-symlink file"):
            self.create()

    def test_late_first_poll_fails_closed(self) -> None:
        self.create()
        self.dispatch()
        state, code = check_precommit(self.state_file, CONTROL_TURN, now="2026-07-15T00:00:02Z")
        self.assertEqual(code, 2)
        self.assertEqual(state["status"], "control-failed")
        self.assertEqual(state["polling"]["poll_count"], 0)

    def test_live_receipt_rejects_intervening_workspace_mutation(self) -> None:
        receipt = self.positive_receipt()
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        (self.workdir / "tracked.txt").write_text("after receipt\n", encoding="utf-8")
        self.assertTrue(
            any(
                "intervening workspace mutation" in error
                for error in validate_precommit_receipt(payload, work_plan(), live=True, require_accepting=True)
            )
        )

    def test_deterministic_receipt_has_equal_boundaries_and_zero_activity(self) -> None:
        receipt = make_deterministic_receipt(
            packet_id="packet-deterministic",
            attempt_nonce="nonce-deterministic",
            work_plan=work_plan(),
            session_id=self.session_id,
            session_file=self.session_file,
            agent_id="spark-agent",
            workdir=self.workdir,
            fit_result={
                "decision": "accept",
                "estimates": {
                    "tool_calls_p50": 8,
                    "tool_calls_p90": 16,
                    "runtime_seconds_p50": 120,
                    "runtime_seconds_p90": 240,
                },
            },
            control_turn_id=CONTROL_TURN,
            state_file=self.state_file,
            receipt_file=self.receipt_file,
            owner_pid=os.getpid(),
            audit_file=self.audit_file,
            now="2026-07-15T00:00:00Z",
        )
        self.assertEqual(receipt["baseline"], receipt["terminal"])
        self.assertTrue(receipt["accepting"])
        self.assertEqual(receipt["submission_id"], "deterministic-policy")
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        self.assertEqual(validate_precommit_receipt(payload, work_plan(), live=True, require_accepting=True), [])
        unequal = copy.deepcopy(payload)
        unequal["terminal"]["record_count"] += 1
        unequal["receipt_sha256"] = canonical_sha256({key: value for key, value in unequal.items() if key != "receipt_sha256"})
        self.assertTrue(any("equal zero-length boundaries" in error for error in validate_precommit_receipt(unequal)))
        active = copy.deepcopy(payload)
        active["observed"]["function_calls"] = 1
        active["receipt_sha256"] = canonical_sha256({key: value for key, value in active.items() if key != "receipt_sha256"})
        self.assertTrue(any("accepting flag contradicts" in error for error in validate_precommit_receipt(active)))

    def test_unknown_fields_and_hash_changes_are_rejected(self) -> None:
        receipt = self.positive_receipt()
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        payload["unknown"] = True
        self.assertTrue(any("unknown" in error for error in validate_precommit_receipt(payload)))
        payload.pop("unknown")
        payload["receipt_sha256"] = "0" * 64
        self.assertTrue(any("canonical hash" in error for error in validate_precommit_receipt(payload)))

    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_state_and_receipt_match_strict_schemas_and_private_modes(self) -> None:
        import jsonschema

        receipt = self.positive_receipt()
        state = json.loads(self.state_file.read_text(encoding="utf-8"))
        payload = {key: value for key, value in receipt.items() if key != "receipt_file"}
        state_schema = json.loads((ROOT / "schemas" / "native-precommit-state.schema.json").read_text(encoding="utf-8"))
        receipt_schema = json.loads((ROOT / "schemas" / "native-precommit-receipt.schema.json").read_text(encoding="utf-8"))
        jsonschema.validate(state, state_schema)
        jsonschema.validate(payload, receipt_schema)
        self.assertEqual(self.state_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipt_file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
