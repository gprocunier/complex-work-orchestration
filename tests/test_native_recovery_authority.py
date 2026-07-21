from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event, Thread, current_thread
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_recovery_authority as authority  # noqa: E402
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    NativeLiveAllocationLedgerStore,
    VerifiedContainedTurnDispatch,
)
from cwo_core.native_recovery_authority import (  # noqa: E402
    FIXED_COHORT_LOCK_FILE,
    FIXED_COHORT_STATE_FILE,
    FixedCohortRecoveryActionStore,
    FixedCohortControllerRoot,
    RecoveryAuthorityError,
    VerifiedFixedCohortRecoveryAction,
    VerifiedRecoveryEvidence,
    fixed_cohort_sha256,
)
from cwo_core.native_recovery_policy import (  # noqa: E402
    RECOVERY_SIGNAL_FIELDS,
    build_recovery_audit_decision,
)
from tests.test_native_live_allocation_ledger import (  # noqa: E402
    bindings_v2,
    seed_contained_turn_dispatch,
)


CHILD_A = "a" * 64
CHILD_B = "b" * 64
SOURCE_EVIDENCE = "e" * 64


def _signals(field: str) -> dict[str, bool]:
    result = {name: False for name in RECOVERY_SIGNAL_FIELDS}
    result[field] = True
    return result


class FixedCohortRecoveryActionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="cwo-fixed-cohort-controller-"
        )
        self.root = Path(self.temporary.name)
        self.directory = self.root / "controller"
        self.cohort = [
            {
                "bead_id": "bead-b",
                "work_unit_id": "work-unit-b",
                "admitted_child_sha256": CHILD_B,
            },
            {
                "bead_id": "bead-a",
                "work_unit_id": "work-unit-a",
                "admitted_child_sha256": CHILD_A,
            },
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create(self) -> FixedCohortRecoveryActionStore:
        store, root = FixedCohortRecoveryActionStore.create(
            self.directory,
            self.cohort,
        )
        self.controller_root = root
        return store

    def _evidence(
        self,
        store: FixedCohortRecoveryActionStore,
        decision: dict,
    ) -> VerifiedRecoveryEvidence:
        return store.register_controller_observation(
            self.controller_root,
            recovery_class=decision["recovery_class"],
            bead_id=decision["admitted_bead_id"],
            admitted_work_unit_id=(
                "work-unit-a"
                if decision["admitted_bead_id"] == "bead-a"
                else "work-unit-b"
            ),
            admitted_child_sha256=decision["admitted_child_sha256"],
            evidence_sha256=decision["evidence_sha256"],
        )

    def _issue(
        self,
        store: FixedCohortRecoveryActionStore,
        decision: dict,
    ) -> VerifiedFixedCohortRecoveryAction:
        return store.issue(
            self.controller_root,
            decision,
            self._evidence(store, decision),
        )

    def _consume(
        self,
        store: FixedCohortRecoveryActionStore,
        action: VerifiedFixedCohortRecoveryAction,
    ) -> dict:
        return dict(store.consume(self.controller_root, action))

    def _decision(
        self,
        store: FixedCohortRecoveryActionStore,
        signal: str,
        *,
        bead_id: str = "bead-a",
        child_sha256: str = CHILD_A,
        evidence_sha256: str = SOURCE_EVIDENCE,
    ) -> dict:
        state = store.read_state()
        bead_state = next(
            item for item in state["bead_states"] if item["bead_id"] == bead_id
        )
        return build_recovery_audit_decision(
            _signals(signal),
            replacement_count=bead_state["replacement_count"],
            construction_attempt_count=bead_state[
                "construction_attempt_count"
            ],
            evidence_sha256=evidence_sha256,
            fixed_cohort_sha256=state["fixed_cohort_sha256"],
            admitted_bead_id=bead_id,
            admitted_child_sha256=child_sha256,
        )

    def test_cohort_is_sorted_hashed_create_once_and_has_no_refill_surface(self) -> None:
        reversed_cohort = list(reversed(self.cohort))
        self.assertEqual(
            fixed_cohort_sha256(self.cohort),
            fixed_cohort_sha256(reversed_cohort),
        )
        store = self._create()
        state = store.read_state()
        self.assertEqual(
            [item["bead_id"] for item in state["fixed_cohort"]],
            ["bead-a", "bead-b"],
        )
        self.assertEqual(
            state["fixed_cohort_sha256"],
            fixed_cohort_sha256(self.cohort),
        )
        self.assertEqual(state["revision"], 0)
        self.assertEqual(
            [
                (
                    item["replacement_count"],
                    item["construction_attempt_count"],
                    item["terminal"],
                )
                for item in state["bead_states"]
            ],
            [(0, 0, False), (0, 0, False)],
        )
        self.assertEqual(
            stat.S_IMODE(self.directory.stat().st_mode),
            0o700,
        )
        for name in (FIXED_COHORT_STATE_FILE, FIXED_COHORT_LOCK_FILE):
            self.assertEqual(
                stat.S_IMODE((self.directory / name).stat().st_mode),
                0o600,
            )
        for forbidden in (
            "add",
            "admit",
            "refill",
            "reset",
            "replace_cohort",
        ):
            self.assertFalse(hasattr(store, forbidden))
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "directory-already-exists",
        ):
            FixedCohortRecoveryActionStore.create(
                self.directory,
                self.cohort,
            )

    def test_duplicate_and_invalid_cohort_items_fail_closed(self) -> None:
        invalid_cases = (
            [],
            [
                {
                    "bead_id": "",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_A,
                }
            ],
            [
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": "bad",
                }
            ],
            [
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_A,
                },
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-b",
                    "admitted_child_sha256": CHILD_B,
                },
            ],
            [
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_A,
                },
                {
                    "bead_id": "bead-b",
                    "work_unit_id": "work-unit-b",
                    "admitted_child_sha256": CHILD_A,
                },
            ],
            [
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_A,
                },
                {
                    "bead_id": "bead-b",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_B,
                },
            ],
            [
                {
                    "bead_id": "bead-a",
                    "work_unit_id": "work-unit-a",
                    "admitted_child_sha256": CHILD_A,
                    "extra": False,
                }
            ],
        )
        for index, cohort in enumerate(invalid_cases):
            with self.subTest(index=index):
                with self.assertRaises(RecoveryAuthorityError):
                    FixedCohortRecoveryActionStore.create(
                        self.root / f"invalid-{index}",
                        cohort,
                    )

    def test_reconstruction_once_then_policy_return_marks_terminal(self) -> None:
        store = self._create()
        first = self._decision(
            store,
            "deterministic_construction_failure",
        )
        self.assertEqual(first["action"], "reconstruct-same-admitted-bead")
        first_result = self._consume(store, self._issue(store, first))
        self.assertEqual(first_result["construction_attempt_count"], 1)
        self.assertFalse(first_result["terminal"])
        self.assertFalse(first_result["dispatch_authorized"])

        reopened = FixedCohortRecoveryActionStore.open(
            self.directory,
            root=self.controller_root,
        )
        persisted = reopened.read_state()
        bead_state = persisted["bead_states"][0]
        self.assertEqual(bead_state["construction_attempt_count"], 1)
        self.assertEqual(persisted["revision"], 1)

        second = self._decision(
            reopened,
            "deterministic_construction_failure",
        )
        self.assertEqual(
            second["action"],
            "return-same-admitted-bead-to-main-thread",
        )
        terminal_probe_evidence = self._evidence(reopened, second)
        second_result = self._consume(
            reopened,
            self._issue(reopened, second),
        )
        self.assertTrue(second_result["terminal"])
        self.assertEqual(reopened.read_state()["revision"], 2)
        with self.assertRaisesRegex(RecoveryAuthorityError, "bead-terminal"):
            reopened.issue(
                self.controller_root,
                self._decision(
                    reopened,
                    "deterministic_construction_failure",
                ),
                terminal_probe_evidence,
            )

    def test_replacement_once_then_policy_return_marks_terminal(self) -> None:
        store = self._create()
        first = self._decision(store, "pre_dispatch_transport_failure")
        self.assertEqual(first["action"], "replace-same-admitted-bead")
        first_result = self._consume(store, self._issue(store, first))
        self.assertEqual(first_result["replacement_count"], 1)
        self.assertFalse(first_result["terminal"])

        second = self._decision(store, "pre_dispatch_transport_failure")
        self.assertEqual(
            second["action"],
            "return-same-admitted-bead-to-main-thread",
        )
        second_result = self._consume(store, self._issue(store, second))
        self.assertTrue(second_result["terminal"])
        state = FixedCohortRecoveryActionStore.open(self.directory).read_state()
        self.assertEqual(state["bead_states"][0]["replacement_count"], 1)
        self.assertTrue(state["bead_states"][0]["terminal"])

    def test_exact_child_counters_and_resealed_decisions_are_revalidated(self) -> None:
        store = self._create()
        wrong_child = self._decision(
            store,
            "pre_dispatch_transport_failure",
            child_sha256=CHILD_B,
        )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "durable-binding-mismatch",
        ):
            store.issue(
                self.controller_root,
                wrong_child,
                self._evidence(
                    store,
                    self._decision(store, "pre_dispatch_transport_failure"),
                ),
            )

        wrong_cohort = build_recovery_audit_decision(
            _signals("pre_dispatch_transport_failure"),
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256=SOURCE_EVIDENCE,
            fixed_cohort_sha256="f" * 64,
            admitted_bead_id="bead-a",
            admitted_child_sha256=CHILD_A,
        )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "boundary-invalid",
        ):
            self._issue(store, wrong_cohort)

        valid = self._decision(store, "pre_dispatch_transport_failure")
        tampered = dict(valid)
        tampered["evidence_sha256"] = "d" * 64
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "decision-invalid",
        ):
            self._issue(store, tampered)

        type_confused = dict(valid)
        type_confused["replacement_budget"] = True
        type_confused.pop("decision_sha256")
        type_confused["decision_sha256"] = authority.canonical_recovery_sha256(
            type_confused,
            domain="native-recovery-audit-decision-v1",
        )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "exact-types-invalid",
        ):
            self._issue(store, type_confused)

        self._consume(store, self._issue(store, valid))
        stale_resealed = build_recovery_audit_decision(
            _signals("pre_dispatch_transport_failure"),
            replacement_count=0,
            construction_attempt_count=0,
            evidence_sha256=SOURCE_EVIDENCE,
            fixed_cohort_sha256=store.read_state()["fixed_cohort_sha256"],
            admitted_bead_id="bead-a",
            admitted_child_sha256=CHILD_A,
        )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "durable-binding-mismatch",
        ):
            self._issue(store, stale_resealed)

    def test_source_and_classification_evidence_are_distinct_bound_fields(self) -> None:
        store = self._create()
        decision = self._decision(
            store,
            "pre_dispatch_transport_failure",
            evidence_sha256="9" * 64,
        )
        result = self._consume(store, self._issue(store, decision))
        self.assertEqual(result["evidence_sha256"], "9" * 64)
        self.assertEqual(
            result["classification_evidence_sha256"],
            decision["classification_evidence_sha256"],
        )
        self.assertNotEqual(
            result["evidence_sha256"],
            result["classification_evidence_sha256"],
        )

    def test_control_ambiguous_and_operator_classes_never_issue_actions(self) -> None:
        store = self._create()
        for signal in (
            "failed_ambiguous_dispatch",
            "control_security_failure",
            "contradictory_authority_changing_validation",
        ):
            with self.subTest(signal=signal):
                decision = self._decision(store, signal)
                with self.assertRaisesRegex(
                    RecoveryAuthorityError,
                    "class-invalid",
                ):
                    store.register_controller_observation(
                        self.controller_root,
                        recovery_class=decision["recovery_class"],
                        bead_id=decision["admitted_bead_id"],
                        admitted_work_unit_id="work-unit-a",
                        admitted_child_sha256=decision[
                            "admitted_child_sha256"
                        ],
                        evidence_sha256=decision["evidence_sha256"],
                    )

    def test_untrusted_dict_is_snapshotted_once_before_validation(self) -> None:
        store = self._create()
        decision = self._decision(store, "pre_dispatch_transport_failure")

        class HostileDecision(dict):
            def __init__(self, source: dict) -> None:
                super().__init__(source)
                self.protocol_calls = 0

            def __getitem__(self, key: str) -> object:
                self.protocol_calls += 1
                if key == "admitted_bead_id":
                    return "attacker-bead"
                return super().__getitem__(key)

            def get(self, key: str, default: object = None) -> object:
                self.protocol_calls += 1
                if key == "admitted_bead_id":
                    return "attacker-bead"
                return super().get(key, default)

        hostile = HostileDecision(decision)
        evidence = self._evidence(store, decision)
        result = self._consume(
            store,
            store.issue(self.controller_root, hostile, evidence),
        )
        self.assertEqual(hostile.protocol_calls, 0)
        self.assertEqual(result["bead_id"], "bead-a")

    def test_identity_forgery_cross_store_reopen_replay_and_stale_actions_fail(self) -> None:
        store = self._create()
        decision = self._decision(store, "pre_dispatch_transport_failure")
        first = self._issue(store, decision)
        stale = self._issue(store, decision)

        class HostileAlias:
            def __init__(self) -> None:
                self.eq_calls = 0
                self.hash_calls = 0

            def __eq__(self, other: object) -> bool:
                self.eq_calls += 1
                raise AssertionError("attacker equality must not run")

            def __hash__(self) -> int:
                self.hash_calls += 1
                raise AssertionError("attacker hash must not run")

        hostile = HostileAlias()
        with self.assertRaisesRegex(RecoveryAuthorityError, "type-invalid"):
            store.consume(self.controller_root, hostile)
        self.assertEqual((hostile.eq_calls, hostile.hash_calls), (0, 0))

        forged = object.__new__(VerifiedFixedCohortRecoveryAction)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "not-registered-or-spent",
        ):
            store.consume(self.controller_root, forged)

        class ActionSubclass(VerifiedFixedCohortRecoveryAction):
            pass

        with self.assertRaisesRegex(RecoveryAuthorityError, "type-invalid"):
            store.consume(
                self.controller_root,
                object.__new__(ActionSubclass),
            )

        reopened = FixedCohortRecoveryActionStore.open(self.directory)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "root-store-mismatch",
        ):
            reopened.consume(self.controller_root, first)
        self._consume(store, first)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "not-registered-or-spent",
        ):
            store.consume(self.controller_root, first)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "stale-or-invalid",
        ):
            store.consume(self.controller_root, stale)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "not-registered-or-spent",
        ):
            store.consume(self.controller_root, stale)

    def test_two_open_stores_same_revision_have_one_cas_winner(self) -> None:
        first_store = self._create()
        second_store = FixedCohortRecoveryActionStore.open(
            self.directory,
            root=self.controller_root,
        )
        decision = self._decision(first_store, "pre_dispatch_transport_failure")
        first_action = self._issue(first_store, decision)
        second_action = self._issue(second_store, decision)
        barrier = Barrier(2)

        def consume(
            store: FixedCohortRecoveryActionStore,
            action: VerifiedFixedCohortRecoveryAction,
        ) -> str:
            barrier.wait()
            try:
                store.consume(self.controller_root, action)
            except RecoveryAuthorityError:
                return "rejected"
            return "persisted"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda pair: consume(*pair),
                    (
                        (first_store, first_action),
                        (second_store, second_action),
                    ),
                )
            )
        self.assertEqual(sorted(outcomes), ["persisted", "rejected"])
        state = first_store.read_state()
        self.assertEqual(state["revision"], 1)
        self.assertEqual(state["bead_states"][0]["replacement_count"], 1)

    def test_lock_inode_replacement_rejects_both_split_lock_consumers(self) -> None:
        first_store = self._create()
        second_store = FixedCohortRecoveryActionStore.open(
            self.directory,
            root=self.controller_root,
        )
        first_action = self._issue(
            first_store,
            self._decision(
                first_store,
                "pre_dispatch_transport_failure",
                bead_id="bead-a",
                child_sha256=CHILD_A,
            ),
        )
        second_action = self._issue(
            second_store,
            self._decision(
                second_store,
                "pre_dispatch_transport_failure",
                bead_id="bead-b",
                child_sha256=CHILD_B,
            ),
        )
        first_has_read = Event()
        release_first = Event()
        outcomes: dict[str, str] = {}
        unexpected: list[BaseException] = []
        atomic_write_threads: list[str] = []
        original_read = authority._read_controller_state
        original_atomic_write = authority._atomic_write_controller_state

        def gated_read(path: Path) -> dict:
            state = original_read(path)
            if current_thread().name == "consumer-a":
                first_has_read.set()
                if not release_first.wait(timeout=5):
                    raise AssertionError("consumer-a release timed out")
            return state

        def tracked_atomic_write(path: Path, state: dict) -> None:
            atomic_write_threads.append(current_thread().name)
            original_atomic_write(path, state)

        def consume(
            label: str,
            store: FixedCohortRecoveryActionStore,
            action: VerifiedFixedCohortRecoveryAction,
        ) -> None:
            try:
                store.consume(self.controller_root, action)
            except RecoveryAuthorityError as exc:
                outcomes[label] = str(exc)
            except BaseException as exc:  # pragma: no cover - assertion relay
                unexpected.append(exc)
            else:
                outcomes[label] = "persisted"

        with (
            mock.patch.object(
                authority,
                "_read_controller_state",
                side_effect=gated_read,
            ),
            mock.patch.object(
                authority,
                "_atomic_write_controller_state",
                side_effect=tracked_atomic_write,
            ),
        ):
            first_thread = Thread(
                target=consume,
                name="consumer-a",
                args=("consumer-a", first_store, first_action),
            )
            first_thread.start()
            self.assertTrue(first_has_read.wait(timeout=5))

            lock_path = self.directory / FIXED_COHORT_LOCK_FILE
            old_lock_path = self.directory / "controller.lock.old"
            os.rename(lock_path, old_lock_path)
            authority._create_private_file(lock_path)

            second_thread = Thread(
                target=consume,
                name="consumer-b",
                args=("consumer-b", second_store, second_action),
            )
            second_thread.start()
            second_thread.join(timeout=5)
            second_still_alive = second_thread.is_alive()
            release_first.set()
            first_thread.join(timeout=5)
            self.assertFalse(second_still_alive)
            self.assertFalse(first_thread.is_alive())

        self.assertEqual(unexpected, [])
        self.assertEqual(set(outcomes), {"consumer-a", "consumer-b"})
        for outcome in outcomes.values():
            self.assertIn("lock-identity", outcome)
        self.assertEqual(atomic_write_threads, [])
        state = FixedCohortRecoveryActionStore.open(self.directory).read_state()
        self.assertEqual(state["revision"], 0)
        self.assertEqual(
            [item["replacement_count"] for item in state["bead_states"]],
            [0, 0],
        )

    def test_json_root_and_evidence_forgery_cannot_issue_or_mutate(self) -> None:
        store = self._create()
        decision = self._decision(store, "pre_dispatch_transport_failure")
        before = store.read_state()

        class HostileAlias:
            def __init__(self) -> None:
                self.eq_calls = 0
                self.hash_calls = 0

            def __eq__(self, other: object) -> bool:
                self.eq_calls += 1
                raise AssertionError("attacker equality must not run")

            def __hash__(self) -> int:
                self.hash_calls += 1
                raise AssertionError("attacker hash must not run")

        hostile = HostileAlias()
        with self.assertRaisesRegex(RecoveryAuthorityError, "root-type-invalid"):
            store.issue(hostile, decision, hostile)
        with self.assertRaisesRegex(RecoveryAuthorityError, "evidence-type-invalid"):
            store.issue(self.controller_root, decision, hostile)
        self.assertEqual((hostile.eq_calls, hostile.hash_calls), (0, 0))

        with self.assertRaisesRegex(RecoveryAuthorityError, "root-type-invalid"):
            store.issue(None, decision, None)
        with self.assertRaisesRegex(RecoveryAuthorityError, "evidence-type-invalid"):
            store.issue(self.controller_root, decision, dict(decision))
        with self.assertRaisesRegex(RecoveryAuthorityError, "action-type-invalid"):
            store.consume(self.controller_root, dict(before))

        forged_root = object.__new__(FixedCohortControllerRoot)
        with self.assertRaisesRegex(RecoveryAuthorityError, "root-store-mismatch"):
            store.issue(forged_root, decision, object())

        other_store, other_root = FixedCohortRecoveryActionStore.create(
            self.root / "other-root-controller",
            self.cohort,
        )
        self.assertIsInstance(other_store, FixedCohortRecoveryActionStore)
        with self.assertRaisesRegex(RecoveryAuthorityError, "root-store-mismatch"):
            store.issue(other_root, decision, object())

        class RootSubclass(FixedCohortControllerRoot):
            pass

        with self.assertRaisesRegex(RecoveryAuthorityError, "root-type-invalid"):
            store.issue(object.__new__(RootSubclass), decision, object())

        forged_evidence = object.__new__(VerifiedRecoveryEvidence)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "evidence-not-registered-or-spent",
        ):
            store.issue(self.controller_root, decision, forged_evidence)

        class EvidenceSubclass(VerifiedRecoveryEvidence):
            pass

        with self.assertRaisesRegex(RecoveryAuthorityError, "evidence-type-invalid"):
            store.issue(
                self.controller_root,
                decision,
                object.__new__(EvidenceSubclass),
            )

        audit_only = FixedCohortRecoveryActionStore.open(self.directory)
        evidence = self._evidence(store, decision)
        with self.assertRaisesRegex(RecoveryAuthorityError, "root-store-mismatch"):
            audit_only.issue(self.controller_root, decision, evidence)
        action = store.issue(self.controller_root, decision, evidence)
        with self.assertRaisesRegex(RecoveryAuthorityError, "root-store-mismatch"):
            audit_only.consume(self.controller_root, action)
        self.assertEqual(store.read_state(), before)

    def test_cross_store_and_replayed_evidence_are_one_shot(self) -> None:
        store = self._create()
        peer = FixedCohortRecoveryActionStore.open(
            self.directory,
            root=self.controller_root,
        )
        decision = self._decision(store, "pre_dispatch_transport_failure")
        evidence = self._evidence(store, decision)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "evidence-not-registered-or-spent",
        ):
            peer.issue(self.controller_root, decision, evidence)
        action = store.issue(self.controller_root, decision, evidence)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "action-not-registered-or-spent",
        ):
            peer.consume(self.controller_root, action)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "evidence-not-registered-or-spent",
        ):
            store.issue(self.controller_root, decision, evidence)
        self._consume(store, action)

    def test_contained_decision_requires_exact_consumed_ledger_witness(self) -> None:
        store = self._create()
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "controller-recovery-evidence-class-invalid",
        ):
            store.register_controller_observation(
                self.controller_root,
                recovery_class="contained-semantic-no-op",
                bead_id="bead-a",
                admitted_work_unit_id="work-unit-a",
                admitted_child_sha256=CHILD_A,
                evidence_sha256=SOURCE_EVIDENCE,
            )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "ledger-recovery-evidence-store-type-invalid",
        ):
            store.register_contained_ledger_evidence(
                self.controller_root,
                recovery_class="contained-semantic-no-op",
                bead_id="bead-a",
                admitted_work_unit_id="work-unit-a",
                admitted_child_sha256=CHILD_A,
                ledger_store={},
                ledger_witness=object(),
                expected_thread_id="thread-1",
                expected_turn_intent_id="intent-1",
            )

        ledger_result = {
            "verification_grade": "ledger-chain-only",
            "dispatch_authorized": False,
            "bead_id": "bead-a",
            "work_unit_id": "work-unit-a",
            "thread_id": "thread-1",
            "turn_intent_id": "intent-1",
            "turn_id": "turn-1",
            "dispatch_record_sha256": "1" * 64,
            "dispatch_transport_binding_sha256": "2" * 64,
            "containment_evidence_sha256": "3" * 64,
            "containment_audit_event_hash": "4" * 64,
        }
        ledger_store = object.__new__(NativeLiveAllocationLedgerStore)
        ledger_witness = object.__new__(VerifiedContainedTurnDispatch)
        with mock.patch.object(
            NativeLiveAllocationLedgerStore,
            "consume_verified_contained_turn_dispatch",
            return_value=ledger_result,
        ) as consume_ledger:
            evidence = store.register_contained_ledger_evidence(
                self.controller_root,
                recovery_class="contained-semantic-no-op",
                bead_id="bead-a",
                admitted_work_unit_id="work-unit-a",
                admitted_child_sha256=CHILD_A,
                ledger_store=ledger_store,
                ledger_witness=ledger_witness,
                expected_thread_id="thread-1",
                expected_turn_intent_id="intent-1",
            )
        consume_ledger.assert_called_once_with(
            ledger_witness,
            expected_thread_id="thread-1",
            expected_turn_intent_id="intent-1",
        )
        decision = self._decision(
            store,
            "contained_semantic_no_op",
            evidence_sha256="3" * 64,
        )
        result = dict(
            store.consume(
                self.controller_root,
                store.issue(self.controller_root, decision, evidence),
            )
        )
        self.assertEqual(
            result["required_authority"],
            "pm-controller-plus-verified-containment",
        )
        self.assertEqual(result["stop_scope"], "child")
        self.assertEqual(result["evidence_kind"], "verified-contained-ledger-dispatch")
        self.assertRegex(result["ledger_result_sha256"], r"^[0-9a-f]{64}$")

    def test_same_bead_different_ledger_work_unit_is_rejected(self) -> None:
        store = self._create()
        before = store.read_state()
        ledger_store = NativeLiveAllocationLedgerStore(self.root / "ledger")
        ledger_bindings = bindings_v2()
        ledger_bindings["bead_id"] = "bead-a"
        ledger_bindings["work_unit_id"] = "totally-unrelated-work-unit"
        ledger_store.initialize(ledger_bindings, version=2)
        thread_id, turn_intent_id, _ = seed_contained_turn_dispatch(
            ledger_store,
            resolution="turn-bound",
        )
        ledger_witness = ledger_store.verify_contained_turn_dispatch(
            thread_id,
            turn_intent_id,
        )

        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "ledger-recovery-evidence-result-invalid",
        ):
            store.register_contained_ledger_evidence(
                self.controller_root,
                recovery_class="contained-semantic-no-op",
                bead_id="bead-a",
                admitted_work_unit_id="work-unit-a",
                admitted_child_sha256=CHILD_A,
                ledger_store=ledger_store,
                ledger_witness=ledger_witness,
                expected_thread_id=thread_id,
                expected_turn_intent_id=turn_intent_id,
            )
        self.assertEqual(store.read_state(), before)

    def test_live_root_head_rejects_validly_resealed_state(self) -> None:
        store = self._create()
        state = store.read_state()
        state["bead_states"][0]["replacement_count"] = 1
        state["revision"] = 1
        state["state_sha256"] = authority._state_sha256(state)
        state_path = self.directory / FIXED_COHORT_STATE_FILE
        state_path.write_text(
            authority._render_controller_state(state),
            encoding="utf-8",
        )
        state_path.chmod(0o600)
        self.assertEqual(
            FixedCohortRecoveryActionStore.open(self.directory).read_state(),
            state,
        )
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "root-head-mismatch",
        ):
            store.register_controller_observation(
                self.controller_root,
                recovery_class="pre-dispatch-transport-failure",
                bead_id="bead-a",
                admitted_work_unit_id="work-unit-a",
                admitted_child_sha256=CHILD_A,
                evidence_sha256=SOURCE_EVIDENCE,
            )

    def test_consume_pops_before_persist_failure_and_state_stays_unchanged(self) -> None:
        store = self._create()
        before = store.read_state()
        action = self._issue(
            store,
            self._decision(store, "pre_dispatch_transport_failure")
        )
        with mock.patch.object(
            authority,
            "_atomic_write_controller_state",
            side_effect=OSError("injected-write-failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected-write-failure"):
                store.consume(self.controller_root, action)
        self.assertEqual(store.read_state(), before)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "not-registered-or-spent",
        ):
            store.consume(self.controller_root, action)

    def test_corruption_permissions_and_symlinked_store_fail_closed(self) -> None:
        self._create()
        state_path = self.directory / FIXED_COHORT_STATE_FILE
        state_path.chmod(0o644)
        try:
            with self.assertRaisesRegex(RecoveryAuthorityError, "not-private"):
                FixedCohortRecoveryActionStore.open(self.directory)
        finally:
            state_path.chmod(0o600)

        hardlink = self.root / "state-hardlink.json"
        os.link(state_path, hardlink)
        try:
            with self.assertRaisesRegex(RecoveryAuthorityError, "not-private"):
                FixedCohortRecoveryActionStore.open(self.directory)
        finally:
            hardlink.unlink()

        state_path.write_text("{}\n", encoding="utf-8")
        state_path.chmod(0o600)
        with self.assertRaises(RecoveryAuthorityError):
            FixedCohortRecoveryActionStore.open(self.directory)

        other_directory = self.root / "other-controller"
        FixedCohortRecoveryActionStore.create(other_directory, self.cohort)
        symlink = self.root / "controller-link"
        os.symlink(other_directory, symlink)
        with self.assertRaisesRegex(
            RecoveryAuthorityError,
            "symlink-component",
        ):
            FixedCohortRecoveryActionStore.open(symlink)


if __name__ == "__main__":
    unittest.main()
