from __future__ import annotations

import copy
from contextlib import redirect_stderr
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
    NativeActivationPreviewError,
    acquire_activation_claim,
    activation_dry_run,
    approve_activation_plan,
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
from cwo_core.native_tool_activation import (  # noqa: E402
    verify_tool_enforcement_activation,
)
from run_native_pool_activation_preview import (  # noqa: E402
    ActivationLedgerTransport,
    _contain_allocated_threads,
    _persist_pool_outcome,
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
                if profile == "n1-mutable":
                    self.assertEqual(
                        plan["tasks"][0]["integration_target_paths"],
                        ["targets/activation.txt"],
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
            ("native-tool-activation-result", result),
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
