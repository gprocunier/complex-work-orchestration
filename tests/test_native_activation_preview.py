from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_activation_preview import (  # noqa: E402
    MUTABLE_PATCH_INPUT,
    NativeActivationPreviewError,
    acquire_activation_claim,
    activation_dry_run,
    approve_activation_plan,
    fixed_activation_tool_trace,
    generate_activation_key,
    load_activation_plan,
    prepare_activation_plan,
    read_activation_key,
)
from cwo_core.native_activation_ledger import (  # noqa: E402
    NativeActivationLedgerStore,
    validate_activation_ledger,
)
from cwo_core.native_pool_leases import capture_owner_identity  # noqa: E402
from cwo_core.native_pool_admission import BeadsClaimAdapter  # noqa: E402
from cwo_core.native_tool_activation import (  # noqa: E402
    verify_tool_enforcement_activation,
)
from run_native_pool_activation_preview import (  # noqa: E402
    ActivationLedgerTransport,
    _close_accepted_activation_beads,
    _contain_allocated_threads,
    _persist_activation_tool_trace,
    _pool_capability_receipt,
    _persist_pool_outcome,
    _require_accepting_pool_and_tool_trace,
    _require_accepting_pool_receipt,
    _result,
    parser,
)


BD_PATH = shutil.which("bd")
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
RISK = "unlisted-built-ins-may-act-before-detection"


class IntentObservingServer:
    def __init__(
        self,
        ledger: NativeActivationLedgerStore,
        *,
        fail_thread_start: bool = False,
    ) -> None:
        self.ledger = ledger
        self.fail_thread_start = fail_thread_start
        self.started_threads: dict[str, str | None] = {}
        self.observed_events: list[str] = []

    def start_thread(self, _cwd: Path, **_kwargs: object) -> tuple[dict, float]:
        event = self.ledger.load()["entries"][-1]["event"]
        self.observed_events.append(event)
        if self.fail_thread_start:
            raise RuntimeError("fixed-thread-start-failure")
        thread_id = str(uuid.uuid4())
        self.started_threads[thread_id] = None
        return {"thread": {"id": thread_id}}, 0.001

    def start_turn(
        self,
        thread_id: str,
        _prompt: str,
        **_kwargs: object,
    ) -> tuple[dict, float]:
        event = self.ledger.load()["entries"][-1]["event"]
        self.observed_events.append(event)
        turn_id = str(uuid.uuid4())
        self.started_threads[thread_id] = turn_id
        return {"id": turn_id}, 0.001


class StaticTraceAdapter:
    def __init__(self, summary: dict) -> None:
        self.summary = summary

    def final_summary(self) -> dict:
        return copy.deepcopy(self.summary)


class ContainmentServer:
    def __init__(self, *, interrupt_fails: bool = False) -> None:
        self.thread_id = str(uuid.uuid4())
        self.turn_id = str(uuid.uuid4())
        self.started_threads = {self.thread_id: self.turn_id}
        self._turn_dispatch_records: dict[str, dict] = {}
        self.status = "inProgress"
        self.interrupt_fails = interrupt_fails
        self.archived: list[str] = []

    def read_thread(
        self,
        thread_id: str,
        **_kwargs: object,
    ) -> tuple[dict, float]:
        return {
            "id": thread_id,
            "turns": [{"id": self.turn_id, "status": self.status}],
        }, 0.001

    def interrupt_turn(self, _thread_id: str, _turn_id: str) -> None:
        if self.interrupt_fails:
            raise RuntimeError("fixed-interrupt-failure")
        self.status = "interrupted"

    def archive_thread(self, thread_id: str) -> None:
        self.archived.append(thread_id)


def initialize_source(root: Path) -> Path:
    source = root / "source"
    source.mkdir(mode=0o700)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Activation Preview Test"],
        cwd=source,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "config",
            "user.email",
            "activation-preview@example.invalid",
        ],
        cwd=source,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "baseline"],
        cwd=source,
        check=True,
    )
    return source


def claim_worker(
    plan: dict,
    approval: dict,
    start: multiprocessing.Event,
    queue: multiprocessing.Queue,
) -> None:
    start.wait()
    try:
        claim = acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        queue.put(("accepted", claim["claim_sha256"]))
    except BaseException as exc:
        queue.put(("rejected", str(exc)))


@unittest.skipUnless(BD_PATH, "bd CLI not available")
class NativeActivationPreviewTests(unittest.TestCase):
    def fixture(
        self,
        *,
        profile: str = "n1-read-only",
    ) -> tuple[tempfile.TemporaryDirectory, Path, Path, Path, dict, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        root.chmod(0o700)
        source = initialize_source(root)
        control = root / "control"
        generate_activation_key(control)
        plan_path, plan = prepare_activation_plan(
            control,
            profile=profile,
            source_repository=source,
        )
        approval_path, approval = approve_activation_plan(
            plan_path,
            control_root=control,
            actor_id="operator-1",
            identity_source="trusted-control-session",
            ttl_seconds=600,
            risk_acknowledgement=RISK,
        )
        return (
            temporary,
            control,
            plan_path,
            approval_path,
            plan,
            approval,
        )

    def test_keygen_prepare_approve_and_dry_run_are_non_live(self) -> None:
        temporary, control, plan_path, approval_path, plan, _approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        key_path = control / "activation-preview.key"
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key_path.stat().st_nlink, 1)
        self.assertEqual(plan_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(approval_path.stat().st_mode & 0o777, 0o600)

        result = activation_dry_run(
            plan_path,
            approval_path,
            control_root=control,
            actor_id="operator-1",
            identity_source="trusted-control-session",
        )
        self.assertEqual(result["status"], "dry-run-accepted")
        self.assertFalse(result["live"])
        self.assertFalse(result["consumed"])
        for forbidden in (
            Path(plan["paths"]["ledger"]),
            Path(plan["paths"]["leases"]),
            Path(plan["paths"]["result"]),
            Path(plan["paths"]["approval_replay"]),
        ):
            self.assertFalse(forbidden.exists(), forbidden)
        self.assertEqual(list(Path(plan["paths"]["claims"]).glob("*.json")), [])

        if HAS_JSONSCHEMA:
            from jsonschema import Draft202012Validator

            schema = json.loads(
                (
                    ROOT
                    / "schemas"
                    / "native-tool-activation-plan.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(plan)

    def test_all_profiles_compile_only_fixed_tasks(self) -> None:
        for profile, expected_roles in (
            ("n1-read-only", ["read-only-0"]),
            ("n2-read-only", ["read-only-0", "read-only-1"]),
            ("n1-mutable", ["mutable-0"]),
        ):
            with self.subTest(profile=profile):
                temporary, _control, _path, _approval_path, plan, _approval = (
                    self.fixture(profile=profile)
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(
                    [task["role"] for task in plan["tasks"]],
                    expected_roles,
                )
                self.assertTrue(
                    all(
                        task["prompt"].startswith("Use ")
                        for task in plan["tasks"]
                    )
                )
                traces = [
                    fixed_activation_tool_trace(
                        profile,
                        int(task["ordinal"]),
                        worktree=task["worktree"],
                    )
                    for task in plan["tasks"]
                ]
                self.assertTrue(
                    all(len(trace) == 2 for trace in traces)
                )
                self.assertTrue(
                    all(
                        len(step["canonical_argument_hashes"])
                        in {1, 3}
                        for trace in traces
                        for step in trace
                    )
                )
                if profile == "n1-mutable":
                    self.assertEqual(
                        plan["tasks"][0]["integration_target_paths"],
                        ["targets/activation.txt"],
                    )
                    self.assertIn(
                        MUTABLE_PATCH_INPUT,
                        plan["tasks"][0]["prompt"],
                    )
                else:
                    self.assertTrue(
                        all(
                            not task["integration_target_paths"]
                            for task in plan["tasks"]
                        )
                    )
                    self.assertNotEqual(
                        plan["tasks"][0]["worktree"],
                        plan["paths"]["integration"],
                    )
                    self.assertEqual(
                        len(
                            {
                                task["worktree"]
                                for task in plan["tasks"]
                            }
                        ),
                        1,
                    )
                if profile == "n2-read-only":
                    self.assertEqual(
                        plan["proportionality_assessment"][
                            "selected_cohort"
                        ]["worker_count"],
                        2,
                    )
                    self.assertIn(
                        2,
                        {
                            item["worker_count"]
                            for item in plan["readiness_evidence"][
                                "compatible_ready_sets"
                            ]
                        },
                    )

    def test_pool_capability_receipt_is_omitted_for_n1_and_preserved_for_n2(
        self,
    ) -> None:
        capability = {"receipt_sha256": "a" * 64}
        self.assertIsNone(_pool_capability_receipt(capability, 1))
        self.assertIs(_pool_capability_receipt(capability, 2), capability)

    def test_activation_trace_artifact_binds_exact_ordered_receipts(
        self,
    ) -> None:
        temporary, _control, _path, _approval_path, plan, _approval = (
            self.fixture(profile="n1-mutable")
        )
        self.addCleanup(temporary.cleanup)
        task = plan["tasks"][0]
        expected = fixed_activation_tool_trace(
            "n1-mutable",
            0,
            worktree=task["worktree"],
        )
        receipts = [
            {
                "sequence": step["sequence"],
                "tool": step["tool"],
                "canonical_argument_hash": step[
                    "canonical_argument_hashes"
                ][0],
                "action_class": step["action_class"],
                "determinable_target_paths": step[
                    "determinable_target_paths"
                ],
                "pairing_status": "paired",
                "result_kind": "paired-success",
                "exit_code": 0,
            }
            for step in expected
        ]
        expected_sha256 = canonical_json_hash(expected)
        observed_sha256 = canonical_json_hash(receipts)
        adapter = StaticTraceAdapter(
            {
                "exact_tool_trace_observation": {
                    "status": "satisfied",
                    "satisfied": True,
                    "expected_sha256": expected_sha256,
                    "observed_sha256": observed_sha256,
                },
                "trusted_tool_receipts": receipts,
                "exact_tool_trace_satisfied": True,
            }
        )
        artifact = _persist_activation_tool_trace(
            plan,
            {task["child_id"]: adapter},
            pool_receipt_sha256="e" * 64,
        )
        self.assertTrue(artifact["all_satisfied"])
        self.assertTrue(
            (
                Path(plan["paths"]["records"])
                / "activation-tool-trace.json"
            ).is_file()
        )
        self.validate_schema("native-tool-activation-trace", artifact)

    def test_activation_closes_only_exact_authorized_child_before_acceptance(
        self,
    ) -> None:
        for authorized in (True, False):
            with self.subTest(authorized=authorized):
                temporary, _control, _path, _approval_path, plan, _approval = (
                    self.fixture(profile="n1-mutable")
                )
                self.addCleanup(temporary.cleanup)
                actor = "activation-close-test"
                adapter = BeadsClaimAdapter(
                    directory=Path(plan["paths"]["beads_directory"]),
                    database=Path(plan["paths"]["beads_database"]),
                    actor=actor,
                    timeout=20,
                )
                task = plan["tasks"][0]
                claim = adapter.claim(task["bead_id"])
                self.assertTrue(claim.owned)
                reservation = {
                    "reservation_sha256": "b" * 64,
                    "claim_actor": actor,
                    "issue_ids": [task["bead_id"]],
                    "claims": [claim.receipt],
                }
                pool_receipt = {
                    "child_dispositions": [
                        {
                            "child_id": task["child_id"],
                            "bead_id": task["bead_id"],
                            "implementation_bead_close_authorized": (
                                authorized
                            ),
                            "parent_close_authorized": False,
                            "publication_close_authorized": False,
                        }
                    ]
                }
                artifact = _close_accepted_activation_beads(
                    plan,
                    reservation,
                    pool_receipt,
                    adapter,
                    pool_receipt_sha256="e" * 64,
                )
                self.assertEqual(artifact["all_closed"], authorized)
                self.assertEqual(
                    adapter.show_exact(task["bead_id"])["status"],
                    "closed" if authorized else "in_progress",
                )
                self.assertEqual(
                    adapter.show_exact(plan["epic_id"])["status"],
                    "open",
                )
                self.assertFalse(artifact["parent_close_attempted"])
                self.assertFalse(
                    artifact["publication_close_attempted"]
                )
                self.validate_schema(
                    "native-tool-activation-bead-closure",
                    artifact,
                )
                if authorized:
                    result = _result(
                        plan,
                        status="accepted",
                        started_at="2026-07-27T12:00:00.000Z",
                        claim_sha256="c" * 64,
                        approval_sha256="a" * 64,
                        ledger_sha256="f" * 64,
                        reservation_sha256="b" * 64,
                        dispatch_sha256="d" * 64,
                        pool_receipt_sha256="e" * 64,
                        tool_trace_sha256="c" * 64,
                        bead_closure_sha256=artifact[
                            "bead_closure_sha256"
                        ],
                    )
                    self.validate_schema(
                        "native-tool-activation-result-v2",
                        result,
                    )

    def test_n2_partial_close_stops_without_rollback_or_parent_close(
        self,
    ) -> None:
        temporary, _control, _path, _approval_path, plan, _approval = (
            self.fixture(profile="n2-read-only")
        )
        self.addCleanup(temporary.cleanup)
        actor = "activation-partial-close-test"

        class FailSecondCloseAdapter(BeadsClaimAdapter):
            def __init__(self, **kwargs: object) -> None:
                super().__init__(**kwargs)
                self.close_calls: list[str] = []

            def close_owned(
                self,
                bead_id: str,
                *,
                expected_pre_show_sha256: str,
                reason: str,
            ):
                self.close_calls.append(bead_id)
                if len(self.close_calls) == 2:
                    expected_pre_show_sha256 = "0" * 64
                return super().close_owned(
                    bead_id,
                    expected_pre_show_sha256=expected_pre_show_sha256,
                    reason=reason,
                )

        adapter = FailSecondCloseAdapter(
            directory=Path(plan["paths"]["beads_directory"]),
            database=Path(plan["paths"]["beads_database"]),
            actor=actor,
            timeout=20,
        )
        tasks = sorted(plan["tasks"], key=lambda item: item["ordinal"])
        claims = [adapter.claim(task["bead_id"]) for task in tasks]
        self.assertTrue(all(claim.owned for claim in claims))
        reservation = {
            "reservation_sha256": "b" * 64,
            "claim_actor": actor,
            "issue_ids": [task["bead_id"] for task in tasks],
            "claims": [claim.receipt for claim in claims],
        }
        pool_receipt = {
            "child_dispositions": [
                {
                    "child_id": task["child_id"],
                    "bead_id": task["bead_id"],
                    "implementation_bead_close_authorized": True,
                    "parent_close_authorized": False,
                    "publication_close_authorized": False,
                }
                for task in tasks
            ]
        }
        artifact = _close_accepted_activation_beads(
            plan,
            reservation,
            pool_receipt,
            adapter,
            pool_receipt_sha256="e" * 64,
        )
        bead_ids = [task["bead_id"] for task in tasks]
        self.assertFalse(artifact["all_closed"])
        self.assertEqual(adapter.close_calls, bead_ids)
        self.assertEqual(artifact["attempted_bead_ids"], bead_ids)
        self.assertEqual(artifact["unattempted_bead_ids"], [])
        self.assertEqual(
            [adapter.show_exact(bead_id)["status"] for bead_id in bead_ids],
            ["closed", "in_progress"],
        )
        self.assertEqual(
            adapter.show_exact(plan["epic_id"])["status"],
            "open",
        )
        self.assertFalse(artifact["parent_close_attempted"])
        self.assertFalse(artifact["publication_close_attempted"])
        self.assertEqual(
            [error["code"] for error in artifact["errors"]],
            ["child-close-unproven"],
        )
        self.validate_schema(
            "native-tool-activation-bead-closure",
            artifact,
        )

    def test_child_close_rejects_tampered_claim_receipt_before_command(
        self,
    ) -> None:
        temporary, _control, _path, _approval_path, plan, _approval = (
            self.fixture(profile="n1-read-only")
        )
        self.addCleanup(temporary.cleanup)
        actor = "activation-tampered-claim-test"
        adapter = BeadsClaimAdapter(
            directory=Path(plan["paths"]["beads_directory"]),
            database=Path(plan["paths"]["beads_database"]),
            actor=actor,
            timeout=20,
        )
        task = plan["tasks"][0]
        claim = adapter.claim(task["bead_id"])
        tampered_claim = dict(claim.receipt)
        tampered_claim["post_show_sha256"] = "0" * 64
        artifact = _close_accepted_activation_beads(
            plan,
            {
                "reservation_sha256": "b" * 64,
                "claim_actor": actor,
                "issue_ids": [task["bead_id"]],
                "claims": [tampered_claim],
            },
            {
                "child_dispositions": [
                    {
                        "child_id": task["child_id"],
                        "bead_id": task["bead_id"],
                        "implementation_bead_close_authorized": True,
                        "parent_close_authorized": False,
                        "publication_close_authorized": False,
                    }
                ]
            },
            adapter,
            pool_receipt_sha256="e" * 64,
        )
        self.assertFalse(artifact["all_closed"])
        self.assertEqual(artifact["attempted_bead_ids"], [])
        self.assertEqual(
            adapter.show_exact(task["bead_id"])["status"],
            "in_progress",
        )
        self.assertEqual(
            [error["code"] for error in artifact["errors"]],
            ["owned-claim-proof-invalid"],
        )

    def test_cli_has_no_arbitrary_work_or_continuation_options(self) -> None:
        command = parser()
        help_text = command.format_help()
        self.assertEqual(
            set(command._subparsers._group_actions[0].choices),
            {"keygen", "prepare", "approve", "run"},
        )
        run_parser = command._subparsers._group_actions[0].choices["run"]
        all_options = {
            option
            for action in run_parser._actions
            for option in action.option_strings
        }
        for forbidden in (
            "--prompt",
            "--model",
            "--tool",
            "--task",
            "--mutation-path",
            "--retry",
            "--resume",
            "--refill",
            "--replacement",
        ):
            self.assertNotIn(forbidden, all_options)
            self.assertNotIn(forbidden, help_text)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            command.parse_args(
                [
                    "run",
                    "--control-root",
                    "/tmp/control",
                    "--prepared",
                    "/tmp/plan",
                    "--approval",
                    "/tmp/approval",
                    "--operator-id",
                    "operator",
                    "--identity-source",
                    "trusted",
                ]
            )

    def test_bad_approval_is_burned_before_verification(self) -> None:
        temporary, control, plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        bad = copy.deepcopy(approval)
        bad["signature"] = "0" * 64
        claim = acquire_activation_claim(
            plan,
            bad,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        self.assertEqual(claim["approval_sha256"], canonical_json_hash(bad))
        self.validate_schema("native-tool-activation-claim", claim)
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-claim-activation-reused",
        ):
            acquire_activation_claim(
                load_activation_plan(plan_path),
                approval,
                controller_identity=capture_owner_identity(os.getpid()),
            )

    def test_primary_claim_reconstructs_missing_markers(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        claims = Path(plan["paths"]["claims"])
        for marker in claims.glob("marker-*.json"):
            marker.unlink()
        self.assertEqual(list(claims.glob("marker-*.json")), [])
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-claim-activation-reused",
        ):
            acquire_activation_claim(
                plan,
                approval,
                controller_identity=capture_owner_identity(os.getpid()),
            )
        self.assertEqual(len(list(claims.glob("marker-*.json"))), 2)

    def test_two_processes_racing_same_claim_have_one_winner(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        context = multiprocessing.get_context("fork")
        start = context.Event()
        queue = context.Queue()
        workers = [
            context.Process(
                target=claim_worker,
                args=(plan, approval, start, queue),
            )
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        start.set()
        results = [queue.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(timeout=20)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(
            sorted(result[0] for result in results),
            ["accepted", "rejected"],
        )

    def test_approval_replay_rejects_from_fresh_verifier(self) -> None:
        temporary, control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        key = read_activation_key(control)
        from cwo_core.native_activation_preview import operator_approval_verifier

        first = verify_tool_enforcement_activation(
            plan["activation_request"],
            approval_receipt=approval,
            operator_approval_verifier=operator_approval_verifier(
                plan,
                key=key,
                actor_id="operator-1",
                identity_source="trusted-control-session",
            ),
        )
        self.assertEqual(first.state, "available")
        with self.assertRaisesRegex(Exception, "operator-approval-replayed"):
            verify_tool_enforcement_activation(
                plan["activation_request"],
                approval_receipt=approval,
                operator_approval_verifier=operator_approval_verifier(
                    plan,
                    key=key,
                    actor_id="operator-1",
                    identity_source="trusted-control-session",
                ),
            )

    def test_transport_records_calibration_and_worker_intents_before_rpc(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            ledger = NativeActivationLedgerStore.create(
                root / "ledger",
                profile="n1-read-only",
                plan_sha256="a" * 64,
                claim_sha256="b" * 64,
                action_sha256="c" * 64,
                campaign_nonce=str(uuid.uuid4()),
            )
            ledger.append("approval-consume-intent")
            ledger.append("approval-verified")
            ledger.append("activation-dispatch-intent")
            calibration_intent = ledger.allocation_intent("calibration")
            server = IntentObservingServer(ledger)
            transport = ActivationLedgerTransport(
                server,
                ledger,
                pending_allocation_intents={
                    "calibration": calibration_intent,
                },
            )
            calibration_thread = transport.start_thread(
                root,
                mutable=False,
                role="capability-calibration",
            )[0]["thread"]["id"]
            transport.start_turn(calibration_thread, "fixed calibration")
            worker_thread = transport.start_thread(
                root,
                mutable=False,
                role="read-only-0",
            )[0]["thread"]["id"]
            transport.start_turn(worker_thread, "fixed worker")

            self.assertEqual(
                server.observed_events,
                [
                    "allocation-intent",
                    "turn-intent",
                    "allocation-intent",
                    "turn-intent",
                ],
            )
            self.assertEqual(validate_activation_ledger(ledger.load()), [])
            self.assertEqual(ledger.summary()["phase"], "dispatched")

    def test_failed_rpc_leaves_unresolved_durable_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            ledger = NativeActivationLedgerStore.create(
                root / "ledger",
                profile="n1-read-only",
                plan_sha256="a" * 64,
                claim_sha256="b" * 64,
                action_sha256="c" * 64,
                campaign_nonce=str(uuid.uuid4()),
            )
            ledger.append("approval-consume-intent")
            ledger.append("approval-verified")
            ledger.append("activation-dispatch-intent")
            intent = ledger.allocation_intent("calibration")
            transport = ActivationLedgerTransport(
                IntentObservingServer(
                    ledger,
                    fail_thread_start=True,
                ),
                ledger,
                pending_allocation_intents={"calibration": intent},
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "fixed-thread-start-failure",
            ):
                transport.start_thread(
                    root,
                    mutable=False,
                    role="capability-calibration",
                )
            self.assertTrue(ledger.summary()["pending_allocation"])
            self.assertEqual(validate_activation_ledger(ledger.load()), [])

    def test_containment_requires_terminal_observation(self) -> None:
        contained = ContainmentServer()
        evidence = _contain_allocated_threads(contained, None)
        self.assertTrue(evidence["all_contained"])
        self.assertEqual(contained.archived, [contained.thread_id])

        ambiguous = ContainmentServer(interrupt_fails=True)
        evidence = _contain_allocated_threads(ambiguous, None)
        self.assertFalse(evidence["all_contained"])
        self.assertEqual(ambiguous.archived, [])

    def test_activation_containment_persists_proofs_and_pending_intent_wins(
        self,
    ) -> None:
        proof = {
            "proof_type": "app-server-same-process-containment",
            "version": 1,
            "kind": "never-turned-archived",
            "proof_sha256": "d" * 64,
        }
        server = type(
            "ProofReportingServer",
            (),
            {
                "allocation_ledger": None,
                "started_threads": {},
                "_turn_dispatch_records": {},
                "same_process_containment_proofs": lambda self: [proof],
            },
        )()
        evidence = _contain_allocated_threads(server, None)
        self.assertTrue(evidence["all_contained"])
        self.assertEqual(
            evidence["same_process_containment_proofs"],
            [proof],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            ledger = NativeActivationLedgerStore.create(
                root / "ledger",
                profile="n1-read-only",
                plan_sha256="a" * 64,
                claim_sha256="b" * 64,
                action_sha256="c" * 64,
                campaign_nonce=str(uuid.uuid4()),
            )
            ledger.append("approval-consume-intent")
            ledger.append("approval-verified")
            ledger.append("activation-dispatch-intent")
            ledger.allocation_intent("calibration")
            evidence = _contain_allocated_threads(server, ledger)
            self.assertTrue(evidence["preview_pending_allocation"])
            self.assertFalse(evidence["all_contained"])

    def test_activation_containment_deletes_fresh_never_turned_thread(
        self,
    ) -> None:
        class FreshNeverTurnedServer:
            def __init__(self, *, delete_fails: bool = False) -> None:
                self.thread_id = str(uuid.uuid4())
                self.allocation_ledger = None
                self.started_threads = {self.thread_id: None}
                self._turn_dispatch_records: dict[str, dict] = {}
                self.delete_fails = delete_fails
                self.deleted: list[str] = []
                self.proof: dict | None = None

            def same_process_containment_proof(
                self,
                _thread_id: str,
            ) -> dict | None:
                return self.proof

            @staticmethod
            def fresh_never_turned_thread_proof(
                _thread_id: str,
            ) -> dict:
                return {"proof_sha256": "a" * 64}

            def delete_thread(self, thread_id: str) -> None:
                if self.delete_fails:
                    raise RuntimeError("fixed-delete-failure")
                self.deleted.append(thread_id)

            def record_never_turned_delete_containment(
                self,
                _thread_id: str,
            ) -> dict:
                self.proof = {
                    "proof_type": "app-server-same-process-containment",
                    "version": 2,
                    "kind": "never-turned-deleted",
                    "proof_sha256": "b" * 64,
                }
                return self.proof

            def same_process_containment_proofs(self) -> list[dict]:
                return [self.proof] if self.proof is not None else []

            @staticmethod
            def read_thread(_thread_id: str) -> tuple[dict, float]:
                raise AssertionError("thread/read must not run")

            @staticmethod
            def archive_thread(_thread_id: str) -> None:
                raise AssertionError("thread/archive must not run")

        contained = FreshNeverTurnedServer()
        evidence = _contain_allocated_threads(contained, None)
        self.assertTrue(evidence["all_contained"])
        self.assertEqual(contained.deleted, [contained.thread_id])
        self.assertEqual(evidence["deleted_count"], 1)
        self.assertEqual(
            evidence["same_process_containment_proofs"],
            [contained.proof],
        )
        self.assertNotIn("failure_diagnostics", evidence)

        ambiguous = FreshNeverTurnedServer(delete_fails=True)
        evidence = _contain_allocated_threads(ambiguous, None)
        self.assertFalse(evidence["all_contained"])
        self.assertNotIn("deleted_count", evidence)
        self.assertEqual(
            evidence["failure_diagnostics"],
            [
                {
                    "thread_id_sha256": hashlib.sha256(
                        ambiguous.thread_id.encode("utf-8")
                    ).hexdigest(),
                    "substep": "never-turned-delete",
                    "failure_class": "RuntimeError",
                    "failure_message_sha256": hashlib.sha256(
                        b"fixed-delete-failure"
                    ).hexdigest(),
                }
            ],
        )

    def test_pool_receipt_must_be_exactly_accepting(self) -> None:
        accepted = {
            "accepting": True,
            "pool_disposition": "accepted",
            "reasons": [],
            "first_protected_fault": None,
        }
        self.assertEqual(
            _require_accepting_pool_receipt(accepted),
            accepted,
        )
        quarantined = {
            **accepted,
            "accepting": False,
            "pool_disposition": "quarantined",
            "reasons": ["forbidden-tool-activity"],
        }
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-pool-not-accepting",
        ):
            _require_accepting_pool_receipt(quarantined)
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary)
            records.chmod(0o700)
            (
                _dispatch,
                captured,
                dispatch_sha256,
                pool_sha256,
            ) = _persist_pool_outcome(
                records,
                {
                    "dispatch_receipt": {
                        "dispatch_sha256": "d" * 64,
                    },
                    "pool_receipt": quarantined,
                },
            )
            self.assertEqual(dispatch_sha256, "d" * 64)
            self.assertEqual(pool_sha256, canonical_json_hash(quarantined))
            self.assertEqual(captured, quarantined)
            self.assertTrue(
                (records / "activation-pool-receipt.json").is_file()
            )
            self.assertEqual(
                (
                    records / "activation-pool-receipt.json"
                ).stat().st_mode
                & 0o777,
                0o600,
            )

    def test_pool_failure_precedes_derivative_trace_incompleteness(
        self,
    ) -> None:
        accepted = {
            "accepting": True,
            "pool_disposition": "accepted",
            "reasons": [],
            "first_protected_fault": None,
        }
        quarantined = {
            **accepted,
            "accepting": False,
            "pool_disposition": "quarantined",
            "reasons": ["trusted-turn-failed"],
        }
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-pool-not-accepting",
        ):
            _require_accepting_pool_and_tool_trace(
                quarantined,
                {"all_satisfied": False},
            )
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-exact-tool-trace-rejected",
        ):
            _require_accepting_pool_and_tool_trace(
                accepted,
                {"all_satisfied": False},
            )
        self.assertIsNone(
            _require_accepting_pool_and_tool_trace(
                accepted,
                {"all_satisfied": True},
            )
        )

    def test_all_new_schemas_validate_emitted_artifacts(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        claim = acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        ledger = NativeActivationLedgerStore.create(
            Path(plan["paths"]["ledger"]),
            profile=plan["profile"],
            plan_sha256=plan["plan_sha256"],
            claim_sha256=claim["claim_sha256"],
            action_sha256=plan["activation_artifacts"][
                "action_sha256"
            ],
            campaign_nonce=plan["campaign_nonce"],
        ).load()
        result = _result(
            plan,
            status="rejected",
            started_at="2026-07-27T12:00:00.000Z",
            claim_sha256=claim["claim_sha256"],
            approval_sha256=canonical_json_hash(approval),
            ledger_sha256=ledger["ledger_sha256"],
            failure=RuntimeError("fixed failure"),
        )
        for name, artifact in (
            ("native-tool-activation-plan", plan),
            ("native-tool-activation-claim", claim),
            ("native-tool-activation-ledger", ledger),
            ("native-tool-activation-result-v2", result),
        ):
            with self.subTest(schema=name):
                self.validate_schema(name, artifact)

    def validate_schema(self, name: str, artifact: dict) -> None:
        if not HAS_JSONSCHEMA:
            return
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (ROOT / "schemas" / f"{name}.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact)


def canonical_json_hash(value: object) -> str:
    import hashlib

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
