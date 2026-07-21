from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerError,
    NativeLiveAllocationLedgerStore,
    VerifiedContainedTurnDispatch,
    validate_live_allocation_ledger,
)
from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402
from cwo_core.native_turn_dispatch import (  # noqa: E402
    TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
    TurnDispatchReservation,
    evolve_turn_dispatch_record,
    seal_turn_absence_proof,
)
import cwo_core.native_live_allocation_ledger as LEDGER  # noqa: E402


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


def sha(label: str) -> str:
    return canonical_sha256({"label": label})


def bindings() -> dict:
    return {
        "bead_id": "complex-work-orchestration-18w.6.14.6",
        "authorization_id": str(uuid.uuid4()),
        "authorization_raw_sha256": sha("authorization-raw"),
        "authorization_canonical_sha256": sha("authorization-canonical"),
        "campaign_nonce": str(uuid.uuid4()),
        "live_generation": 4,
        "predecessor_generation": 3,
        "checkpoint_commit": "a" * 40,
        "guarded_primary_diff_sha256": sha("primary-diff"),
        "predecessor_containment_sha256": sha("predecessor-containment"),
        "pre_mutation_steering_receipt_sha256": sha("pre-mutation"),
        "pre_live_steering_receipt_sha256": sha("pre-live"),
        "certification_policy_sha256": sha("certification-policy"),
        "controller_identity": {
            "pid": os.getpid(),
            "start_ticks": 1,
            "boot_id_sha256": sha("boot"),
        },
        "connection_epoch_sha256": sha("connection"),
        "retention_class": "private-local-until-bead-closure",
        "expected_roles": list(EXPECTED_ROLES),
    }


def bindings_v2() -> dict:
    return {
        "bead_id": "complex-work-orchestration-18w",
        "work_unit_id": "complex-work-orchestration-18w.6.19",
        "authorization_id": str(uuid.uuid4()),
        "authorization_raw_sha256": sha("authorization-raw-v2"),
        "authorization_canonical_sha256": sha("authorization-canonical-v2"),
        "campaign_manifest_sha256": sha("campaign-manifest-v2"),
        "campaign_nonce": str(uuid.uuid4()),
        "live_generation": 5,
        "predecessor_generation": 4,
        "candidate_commit": "a" * 40,
        "candidate_tree": "b" * 40,
        "origin_main_commit": "c" * 40,
        "guarded_primary_diff_sha256": sha("primary-diff-v2"),
        "predecessor_containment_sha256": sha("predecessor-containment-v2"),
        "frozen_release_patch_sha256": sha("release-patch-v2"),
        "pre_mutation_steering_receipt_sha256": sha("pre-mutation-v2"),
        "pre_live_steering_receipt_sha256": sha("pre-live-v2"),
        "opus_review_sha256": sha("opus-v2"),
        "certification_policy_sha256": sha("certification-policy-v2"),
        "controller_identity": {
            "pid": os.getpid(),
            "start_ticks": 1,
            "boot_id_sha256": sha("boot-v2"),
        },
        "connection_epoch_sha256": sha("connection-v2"),
        "retention_class": "private-local-until-bead-closure",
        "expected_roles": list(EXPECTED_ROLES),
    }


CANONICAL_UUID_TEXT = "123e4567-e89b-12d3-a456-426614174000"
UUID_TEXT_ALIASES = (
    CANONICAL_UUID_TEXT.upper(),
    "{" + CANONICAL_UUID_TEXT + "}",
    uuid.UUID(CANONICAL_UUID_TEXT).hex,
    "urn:uuid:" + CANONICAL_UUID_TEXT,
    " " + CANONICAL_UUID_TEXT,
    CANONICAL_UUID_TEXT + " ",
    CANONICAL_UUID_TEXT + "\n",
)


def seed_contained_turn_dispatch(
    store: NativeLiveAllocationLedgerStore,
    *,
    resolution: str,
    include_archive: bool = True,
    include_containment_audit: bool = True,
    final_status: str = "failed-contained",
) -> tuple[str, str, str | None]:
    """Create a structural ledger-chain fixture without live dispatch."""

    allocation_id = store.allocation_intent("read-only-0")
    thread_id = "thread-contained"
    store.bind_thread(allocation_id, thread_id)
    turn_intent_id = store.turn_intent(thread_id)
    state = store.load()
    intent_entry = state["entries"][-1]
    epoch = state["bindings"]["connection_epoch_sha256"]
    reservation = TurnDispatchReservation(
        thread_id=thread_id,
        turn_intent_id=turn_intent_id,
        request_id=17,
        connection_epoch_sha256=epoch,
        notification_cursor=0,
        preexisting_turn_ids=(),
        ledger_id=state["ledger_id"],
        ledger_head_entry_sha256=intent_entry["entry_sha256"],
        turn_intent_entry_sha256=intent_entry["entry_sha256"],
        wire_request_sha256=sha("contained-wire-request"),
    )
    dispatch = evolve_turn_dispatch_record(
        reservation.prepared_record(),
        status="dispatching",
        wire_write_attempt_count=1,
    )
    ambiguity_reason = (
        "rpc-error-response" if resolution == "verified-absent" else "response-timeout"
    )
    ambiguous = evolve_turn_dispatch_record(
        dispatch,
        status="failed-ambiguous",
        ambiguity_reason=ambiguity_reason,
    )
    dispatch_directory = store.directory / "turn-dispatch"
    dispatch_directory.mkdir(mode=0o700)
    dispatch_path = dispatch_directory / f"{turn_intent_id}.json"
    LEDGER._atomic_private_write(dispatch_path, ambiguous)

    turn_id: str | None
    absence_proof_sha256: str | None = None
    if resolution == "turn-bound":
        turn_id = "turn-contained"
        store.bind_turn(thread_id, turn_intent_id, turn_id)
        discovered = [turn_id]
        terminal = {turn_id: "interrupted"}
    elif resolution == "verified-absent":
        turn_id = None
        proof = seal_turn_absence_proof(
            {
                "artifact_type": TURN_ABSENCE_PROOF_ARTIFACT_TYPE,
                "version": 1,
                "thread_id": thread_id,
                "turn_intent_id": turn_intent_id,
                "ledger_id": state["ledger_id"],
                "turn_intent_entry_sha256": intent_entry["entry_sha256"],
                "dispatch_record": ambiguous,
                "negative_response": {
                    "request_id": 17,
                    "connection_epoch_sha256": epoch,
                    "wire_request_sha256": ambiguous["wire_request_sha256"],
                    "code": -32603,
                    "response_sha256": sha("negative-response"),
                },
                "proof_sha256": "",
            }
        )
        absence_proof_sha256 = proof["proof_sha256"]
        proof_directory = store.directory / "turn-absence"
        proof_directory.mkdir(mode=0o700)
        proof_path = proof_directory / f"{turn_intent_id}.json"
        LEDGER._atomic_private_write(proof_path, proof)
        proof_identity = LEDGER._path_private_identity(
            proof_path, "turn-absence-proof"
        )
        binding = store._thread_binding(thread_id)[0]
        store._append(
            event="containment-audited",
            role=binding["role"],
            ordinal=binding["ordinal"],
            allocation_intent_id=binding["allocation_intent_id"],
            thread_id=thread_id,
            turn_intent_id=turn_intent_id,
            evidence_sha256=absence_proof_sha256,
            outcome="turn-intent-verified-absent",
            _pre_append_guard=lambda *_args: (str(proof_path), proof_identity),
        )
        discovered = []
        terminal = {}
    else:  # pragma: no cover - test helper contract
        raise AssertionError(f"unsupported fixture resolution: {resolution}")

    if include_archive:
        store.record_lifecycle(
            thread_id,
            "archive-observed",
            "archive-request-accepted",
        )
    final = evolve_turn_dispatch_record(
        ambiguous,
        status=final_status,
        ambiguity_reason=ambiguity_reason,
        notification_connection_epoch_sha256=epoch,
        discovered_turn_ids=discovered,
        terminal_status_by_turn=terminal,
        active_turn_ids_at_final_check=[],
        interrupt_failed_turn_ids=[],
        query_count=1,
        absence_verified=True,
        absence_proof_sha256=absence_proof_sha256,
        archived=True,
        ledger_resolution=resolution,
    )
    LEDGER._atomic_private_write(dispatch_path, final)
    if include_containment_audit:
        store.record_containment_audit(
            thread_id,
            outcome="contained",
            evidence={
                "dispatch_record_sha256": final["record_sha256"],
                "absence_proof_sha256": absence_proof_sha256,
                "discovered_turn_ids": discovered,
                "terminal_status_by_turn": terminal,
                "absence_verified": True,
                "archive_request_accepted": True,
            },
        )
    return thread_id, turn_intent_id, turn_id


class NativeLiveAllocationLedgerTests(unittest.TestCase):
    def test_contained_turn_dispatch_witness_is_one_shot_and_non_authorizing(
        self,
    ) -> None:
        expected_keys = {
            "verification_grade",
            "dispatch_authorized",
            "ledger_version",
            "bead_id",
            "work_unit_id",
            "ledger_id",
            "allocation_intent_id",
            "role",
            "ordinal",
            "thread_id",
            "turn_intent_id",
            "turn_id",
            "ledger_resolution",
            "request_id",
            "connection_epoch_sha256",
            "wire_request_sha256",
            "dispatch_transport_binding_sha256",
            "dispatch_record_sha256",
            "dispatch_file_sha256",
            "dispatch_ledger_head_entry_sha256",
            "turn_intent_entry_sha256",
            "turn_resolution_entry_sha256",
            "archive_entry_sha256",
            "containment_entry_sha256",
            "containment_evidence_sha256",
            "containment_audit_event_hash",
            "absence_proof_sha256",
            "absence_proof_file_sha256",
            "discovered_turn_ids",
            "terminal_status_by_turn",
            "ledger_head_entry_sha256",
            "ledger_state_sha256",
            "audit_head_sha256",
        }
        for resolution in ("turn-bound", "verified-absent"):
            with (
                self.subTest(resolution=resolution),
                tempfile.TemporaryDirectory() as temporary,
            ):
                store = NativeLiveAllocationLedgerStore(
                    Path(temporary) / "private-ledger"
                )
                store.initialize(bindings_v2(), version=2)
                thread_id, turn_intent_id, turn_id = seed_contained_turn_dispatch(
                    store, resolution=resolution
                )
                witness = store.verify_contained_turn_dispatch(
                    thread_id, turn_intent_id
                )
                self.assertIsInstance(witness, VerifiedContainedTurnDispatch)
                self.assertFalse(hasattr(witness, "__dict__"))
                result = store.consume_verified_contained_turn_dispatch(
                    witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=turn_intent_id,
                )
                self.assertEqual(set(result), expected_keys)
                self.assertEqual(result["verification_grade"], "ledger-chain-only")
                self.assertIs(result["dispatch_authorized"], False)
                self.assertEqual(result["ledger_version"], 2)
                self.assertEqual(
                    result["work_unit_id"],
                    store.load()["bindings"]["work_unit_id"],
                )
                self.assertEqual(result["thread_id"], thread_id)
                self.assertEqual(result["turn_intent_id"], turn_intent_id)
                self.assertEqual(result["turn_id"], turn_id)
                self.assertEqual(result["ledger_resolution"], resolution)
                with self.assertRaises(TypeError):
                    result["dispatch_authorized"] = True
                with self.assertRaisesRegex(
                    NativeLiveAllocationLedgerError, "witness-invalid"
                ):
                    store.consume_verified_contained_turn_dispatch(
                        witness,
                        expected_thread_id=thread_id,
                        expected_turn_intent_id=turn_intent_id,
                    )

    def test_contained_turn_dispatch_identity_registry_ignores_hostile_aliases(
        self,
    ) -> None:
        class HostileAlias:
            def __init__(self) -> None:
                self.hash_calls = 0
                self.equality_calls = 0

            def __hash__(self) -> int:
                self.hash_calls += 1
                raise AssertionError("hostile hash executed")

            def __eq__(self, _other: object) -> bool:
                self.equality_calls += 1
                raise AssertionError("hostile equality executed")

        class ForgedSubclass(VerifiedContainedTurnDispatch):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings_v2(), version=2)
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                store, resolution="turn-bound"
            )
            witness = store.verify_contained_turn_dispatch(thread_id, turn_intent_id)
            with self.assertRaisesRegex(TypeError, "mint-forbidden"):
                VerifiedContainedTurnDispatch()
            aliases = (
                object.__new__(VerifiedContainedTurnDispatch),
                object.__new__(ForgedSubclass),
                HostileAlias(),
            )
            for alias in aliases:
                with self.assertRaisesRegex(
                    NativeLiveAllocationLedgerError, "witness-invalid"
                ):
                    store.consume_verified_contained_turn_dispatch(
                        alias,
                        expected_thread_id=thread_id,
                        expected_turn_intent_id=turn_intent_id,
                    )
            hostile = aliases[-1]
            self.assertEqual(hostile.hash_calls, 0)
            self.assertEqual(hostile.equality_calls, 0)
            result = store.consume_verified_contained_turn_dispatch(
                witness,
                expected_thread_id=thread_id,
                expected_turn_intent_id=turn_intent_id,
            )
            self.assertIs(result["dispatch_authorized"], False)

    def test_contained_turn_dispatch_rejects_v1_archive_only_and_arbitrary_audit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings())
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                store, resolution="turn-bound"
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "work-unit-binding-missing"
            ):
                store.verify_contained_turn_dispatch(thread_id, turn_intent_id)

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings_v2(), version=2)
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                store,
                resolution="turn-bound",
                include_containment_audit=False,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "lifecycle-invalid"
            ):
                store.verify_contained_turn_dispatch(thread_id, turn_intent_id)

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings_v2(), version=2)
            allocation = store.allocation_intent("read-only-0")
            thread_id = "thread-contained"
            store.bind_thread(allocation, thread_id)
            turn_intent_id = store.turn_intent(thread_id)
            state = store.load()
            intent = state["entries"][-1]
            epoch = state["bindings"]["connection_epoch_sha256"]
            prepared = TurnDispatchReservation(
                thread_id=thread_id,
                turn_intent_id=turn_intent_id,
                request_id=1,
                connection_epoch_sha256=epoch,
                notification_cursor=0,
                preexisting_turn_ids=(),
                ledger_id=state["ledger_id"],
                ledger_head_entry_sha256=intent["entry_sha256"],
                turn_intent_entry_sha256=intent["entry_sha256"],
                wire_request_sha256=sha("forged-wire"),
            ).prepared_record()
            ambiguous = evolve_turn_dispatch_record(
                evolve_turn_dispatch_record(
                    prepared,
                    status="dispatching",
                    wire_write_attempt_count=1,
                ),
                status="failed-ambiguous",
                ambiguity_reason="response-timeout",
            )
            turn_id = "turn-contained"
            store.bind_turn(thread_id, turn_intent_id, turn_id)
            store.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
            store.record_containment_audit(
                thread_id,
                outcome="contained",
                evidence={"caller_fabricated": True},
            )
            final = evolve_turn_dispatch_record(
                ambiguous,
                status="failed-contained",
                notification_connection_epoch_sha256=epoch,
                discovered_turn_ids=[turn_id],
                terminal_status_by_turn={turn_id: "interrupted"},
                query_count=1,
                absence_verified=True,
                archived=True,
                ledger_resolution="turn-bound",
            )
            dispatch_directory = store.directory / "turn-dispatch"
            dispatch_directory.mkdir(mode=0o700)
            LEDGER._atomic_private_write(
                dispatch_directory / f"{turn_intent_id}.json", final
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "audit-evidence-invalid"
            ):
                store.verify_contained_turn_dispatch(thread_id, turn_intent_id)

    def test_contained_turn_dispatch_rejects_ambiguous_drift_reopen_and_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings_v2(), version=2)
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                store,
                resolution="turn-bound",
                final_status="failed-ambiguous",
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "final-state-invalid"
            ):
                store.verify_contained_turn_dispatch(thread_id, turn_intent_id)

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings_v2(), version=2)
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                store, resolution="turn-bound"
            )
            witness = store.verify_contained_turn_dispatch(thread_id, turn_intent_id)
            path = store.directory / "turn-dispatch" / f"{turn_intent_id}.json"
            record = json.loads(path.read_text(encoding="utf-8"))
            resealed = evolve_turn_dispatch_record(
                record, query_count=record["query_count"] + 1
            )
            LEDGER._atomic_private_write(path, resealed)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "binding-drift|audit-evidence-invalid",
            ):
                store.consume_verified_contained_turn_dispatch(
                    witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=turn_intent_id,
                )

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private-ledger"
            first = NativeLiveAllocationLedgerStore(directory)
            first.initialize(bindings_v2(), version=2)
            thread_id, turn_intent_id, _turn_id = seed_contained_turn_dispatch(
                first, resolution="turn-bound"
            )
            first_witness = first.verify_contained_turn_dispatch(
                thread_id, turn_intent_id
            )
            second_witness = first.verify_contained_turn_dispatch(
                thread_id, turn_intent_id
            )
            second = NativeLiveAllocationLedgerStore(directory)
            second.open()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "witness-invalid"
            ):
                second.consume_verified_contained_turn_dispatch(
                    first_witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=turn_intent_id,
                )
            for witness in (first_witness, second_witness):
                result = first.consume_verified_contained_turn_dispatch(
                    witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=turn_intent_id,
                )
                self.assertIs(result["dispatch_authorized"], False)
            reopened_witness = first.verify_contained_turn_dispatch(
                thread_id, turn_intent_id
            )
            first.open()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "witness-invalid"
            ):
                first.consume_verified_contained_turn_dispatch(
                    reopened_witness,
                    expected_thread_id=thread_id,
                    expected_turn_intent_id=turn_intent_id,
                )
            reminted = first.verify_contained_turn_dispatch(
                thread_id, turn_intent_id
            )
            result = first.consume_verified_contained_turn_dispatch(
                reminted,
                expected_thread_id=thread_id,
                expected_turn_intent_id=turn_intent_id,
            )
            self.assertIs(result["dispatch_authorized"], False)

    def test_v2_identity_bindings_reject_uuid_text_aliases(self) -> None:
        for field in ("authorization_id", "campaign_nonce"):
            for alias in UUID_TEXT_ALIASES:
                with (
                    self.subTest(field=field, alias=repr(alias)),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    value = bindings_v2()
                    value[field] = alias
                    store = NativeLiveAllocationLedgerStore(
                        Path(temporary) / "private-ledger-v2"
                    )
                    with self.assertRaisesRegex(
                        NativeLiveAllocationLedgerError,
                        f"ledger-binding-{field}-invalid",
                    ):
                        store.initialize(value, version=2)

    def test_v2_binds_successor_manifest_and_preserves_v1_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger-v2"
            )
            initial = store.initialize(bindings_v2(), version=2)
            self.assertEqual(
                validate_live_allocation_ledger(initial, audit_file=store.audit_file),
                [],
            )
            summary = store.summary()
            self.assertEqual(summary["version"], 2)
            self.assertEqual(summary["live_generation"], 5)
            self.assertEqual(
                summary["campaign_manifest_sha256"],
                initial["bindings"]["campaign_manifest_sha256"],
            )
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads(
                    (
                        ROOT / "schemas/native-live-allocation-ledger-v2.schema.json"
                    ).read_text(encoding="utf-8")
                )
                jsonschema.validate(initial, schema)

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "v1-as-v2")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "bindings-fields-invalid"
            ):
                store.initialize(bindings(), version=2)
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "v2-as-v1")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "bindings-fields-invalid"
            ):
                store.initialize(bindings_v2())
        with tempfile.TemporaryDirectory() as temporary:
            changed = bindings_v2()
            changed["live_generation"] = 6
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "skipped-generation"
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "generation-invalid"
            ):
                store.initialize(changed, version=2)

    def test_intent_bind_lifecycle_and_audit_anchor_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            initial = store.initialize(bindings())
            self.assertEqual(
                validate_live_allocation_ledger(initial, audit_file=store.audit_file),
                [],
            )
            allocation = store.allocation_intent("capability-calibration")
            store.bind_thread(allocation, "thread-1")
            turn_intent = store.turn_intent("thread-1")
            store.bind_turn("thread-1", turn_intent, "turn-1")
            store.record_lifecycle("thread-1", "interrupt-observed", "interrupted")
            store.record_lifecycle("thread-1", "archive-observed", "archived")
            store.record_containment_audit(
                "thread-1", outcome="contained", evidence={"status": "archived"}
            )
            store.bind_certification(sha("capability-receipt"))
            state = store.load()
            self.assertEqual(
                validate_live_allocation_ledger(state, audit_file=store.audit_file), []
            )
            self.assertEqual(state["sequence"], 8)
            self.assertEqual(
                state["head_entry_sha256"], state["entries"][-1]["entry_sha256"]
            )
            self.assertEqual(stat.S_IMODE(store.directory.stat().st_mode), 0o700)
            for path in (store.path, store.lock_path, store.audit_file):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads(
                    (
                        ROOT / "schemas/native-live-allocation-ledger.schema.json"
                    ).read_text(encoding="utf-8")
                )
                jsonschema.validate(state, schema)

    def test_unresolved_allocation_and_turn_intents_remain_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            allocation = store.allocation_intent("read-only-0")
            state = store.load()
            self.assertEqual(state["entries"][-1]["outcome"], "pending")
            self.assertEqual(state["entries"][-1]["allocation_intent_id"], allocation)
            store.bind_thread(allocation, "thread-0")
            turn_intent = store.turn_intent("thread-0")
            state = store.load()
            self.assertEqual(state["entries"][-1]["turn_intent_id"], turn_intent)
            self.assertEqual(state["entries"][-1]["outcome"], "pending")

    def test_successful_containment_audit_is_exactly_once_and_conflict_safe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(
                Path(temporary) / "private-ledger"
            )
            store.initialize(bindings())
            allocation = store.allocation_intent("capability-calibration")
            store.bind_thread(allocation, "thread-1")
            turn_intent = store.turn_intent("thread-1")
            store.bind_turn("thread-1", turn_intent, "turn-1")
            store.record_lifecycle(
                "thread-1", "archive-observed", "archive-request-accepted"
            )
            evidence = {"dispatch_record_sha256": "a" * 64}
            store.record_containment_audit(
                "thread-1", outcome="contained", evidence=evidence
            )
            before = store.load()
            before_audit = store.audit_file.read_bytes()

            store.record_containment_audit(
                "thread-1", outcome="contained", evidence=dict(evidence)
            )
            after = store.load()
            self.assertEqual(after, before)
            self.assertEqual(store.audit_file.read_bytes(), before_audit)

            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "containment-audit-success-conflict",
            ):
                store.record_containment_audit(
                    "thread-1",
                    outcome="contained",
                    evidence={"dispatch_record_sha256": "b" * 64},
                )
            store.open()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "containment-success-duplicate",
            ):
                store._append(
                    event="containment-audited",
                    role="capability-calibration",
                    ordinal=0,
                    allocation_intent_id=allocation,
                    thread_id="thread-1",
                    turn_intent_id=turn_intent,
                    turn_id="turn-1",
                    evidence_sha256=sha("duplicate-containment"),
                    outcome="already-contained",
                )

    def test_duplicate_role_identity_and_cross_generation_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            first = store.allocation_intent("read-only-0")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "transition-invalid"
            ):
                store.allocation_intent("read-only-0")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-not-open"
            ):
                store.bind_thread(first, "thread-a")
            store.open()
            store.bind_thread(first, "thread-a")
            second = store.allocation_intent("read-only-1")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "transition-invalid"
            ):
                store.bind_thread(second, "thread-a")

        with tempfile.TemporaryDirectory() as temporary:
            changed = bindings()
            changed["live_generation"] = 5
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "generation-invalid"
            ):
                store.initialize(changed)

    def test_concurrent_writers_serialize_without_losing_roles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            failures: list[BaseException] = []

            def allocate(role: str) -> None:
                try:
                    intent = store.allocation_intent(role)
                    store.bind_thread(intent, f"thread-{role}")
                except BaseException as exc:  # pragma: no cover - asserted below
                    failures.append(exc)

            threads = [
                threading.Thread(target=allocate, args=(role,))
                for role in ("read-only-0", "read-only-1")
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(failures, [])
            state = store.load()
            self.assertEqual(state["sequence"], 4)
            self.assertEqual(
                validate_live_allocation_ledger(state, audit_file=store.audit_file), []
            )

    def test_tamper_truncation_unknown_fields_permissions_and_symlink_fail(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = NativeLiveAllocationLedgerStore(root / "private-ledger")
            store.initialize(bindings())
            intent = store.allocation_intent("mutable-0")
            store.bind_thread(intent, "thread-mutable")
            original = json.loads(store.path.read_text(encoding="utf-8"))

            tampered = copy.deepcopy(original)
            tampered["entries"][0]["role"] = "mutable-1"
            store.path.write_text(json.dumps(tampered), encoding="utf-8")
            os.chmod(store.path, 0o600)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-invalid"
            ):
                store.load()

            store.path.write_text(json.dumps(original), encoding="utf-8")
            os.chmod(store.path, 0o644)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "permissions-invalid"
            ):
                store.load()

            os.chmod(store.path, 0o600)
            unknown = copy.deepcopy(original)
            unknown["unknown"] = True
            self.assertIn(
                "ledger-fields-invalid", validate_live_allocation_ledger(unknown)
            )

            audit_lines = store.audit_file.read_text(encoding="utf-8").splitlines()
            first_audit = json.loads(audit_lines[0])
            first_audit["phase"] = "archive-observed"
            audit_lines[0] = json.dumps(first_audit, sort_keys=True)
            store.audit_file.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
            os.chmod(store.audit_file, 0o600)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "audit-chain-invalid"
            ):
                store.load()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            ledger_dir = root / "private-ledger"
            ledger_dir.symlink_to(target, target_is_directory=True)
            store = NativeLiveAllocationLedgerStore(ledger_dir)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "already-exists"
            ):
                store.initialize(bindings())

    def test_append_metrics_separate_transition_checks_from_full_validation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            baseline = store.metrics()

            allocation = store.allocation_intent("read-only-0")
            store.bind_thread(allocation, "thread-0")
            turn_intent = store.turn_intent("thread-0")
            store.bind_turn("thread-0", turn_intent, "turn-0")
            store.record_lifecycle(
                "thread-0", "archive-observed", "archive-request-accepted"
            )

            appended = store.metrics()
            self.assertEqual(
                appended["full_validation_count"],
                baseline["full_validation_count"],
            )
            self.assertEqual(
                appended["full_validation_entry_count"],
                baseline["full_validation_entry_count"],
            )
            self.assertEqual(appended["incremental_transition_validation_count"], 5)
            self.assertEqual(
                appended["incremental_transition_validation_entry_count"], 5
            )
            self.assertEqual(appended["append_attempt_count"], 5)
            self.assertEqual(appended["append_success_count"], 5)
            self.assertGreaterEqual(appended["append_seconds"], 0.0)
            self.assertGreaterEqual(
                appended["incremental_transition_validation_seconds"], 0.0
            )

            store.load()
            loaded = store.metrics()
            self.assertEqual(
                loaded["full_validation_count"],
                baseline["full_validation_count"] + 1,
            )
            self.assertEqual(
                loaded["full_validation_entry_count"],
                baseline["full_validation_entry_count"] + 5,
            )
            store.checkpoint()
            checkpointed = store.metrics()
            self.assertEqual(
                checkpointed["full_validation_count"],
                loaded["full_validation_count"] + 1,
            )
            self.assertEqual(
                checkpointed["full_validation_entry_count"],
                loaded["full_validation_entry_count"] + 5,
            )

    def test_append_calls_one_transition_and_no_full_validator_at_any_length(
        self,
    ) -> None:
        for lifecycle_count in (0, 64):
            with (
                self.subTest(lifecycle_count=lifecycle_count),
                tempfile.TemporaryDirectory() as temporary,
            ):
                store = NativeLiveAllocationLedgerStore(
                    Path(temporary) / "private-ledger"
                )
                store.initialize(bindings())
                append_role = "read-only-0"
                if lifecycle_count:
                    allocation = store.allocation_intent("read-only-0")
                    store.bind_thread(allocation, "thread-history")
                    turn_intent = store.turn_intent("thread-history")
                    store.bind_turn("thread-history", turn_intent, "turn-history")
                    for index in range(lifecycle_count):
                        store.record_lifecycle(
                            "thread-history",
                            "archive-observed",
                            f"history-{index}",
                        )
                    append_role = "read-only-1"

                transition_helper = LEDGER._validate_entry_transition
                full_validator = LEDGER._validate_live_allocation_ledger_with_index
                with (
                    mock.patch.object(
                        LEDGER,
                        "_validate_entry_transition",
                        wraps=transition_helper,
                    ) as transition_spy,
                    mock.patch.object(
                        LEDGER,
                        "_validate_live_allocation_ledger_with_index",
                        wraps=full_validator,
                    ) as full_spy,
                ):
                    store.allocation_intent(append_role)

                self.assertEqual(transition_spy.call_count, 1)
                full_spy.assert_not_called()

    def test_open_validate_checkpoint_close_and_disarmed_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private-ledger"
            store = NativeLiveAllocationLedgerStore(directory)
            store.initialize(bindings())
            store.allocation_intent("read-only-0")
            final = store.close()
            self.assertEqual(final["sequence"], 1)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-not-open"
            ):
                store.allocation_intent("read-only-1")

            reopened = NativeLiveAllocationLedgerStore(directory)
            self.assertEqual(reopened.open()["sequence"], 1)
            self.assertEqual(reopened.validate()["sequence"], 1)
            self.assertEqual(reopened.checkpoint()["sequence"], 1)
            reopened.allocation_intent("read-only-1")
            self.assertEqual(reopened.close()["sequence"], 2)

    def test_corrupted_history_fails_every_full_validation_boundary(self) -> None:
        for method_name in ("open", "load", "validate", "checkpoint", "close"):
            with (
                self.subTest(method=method_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = Path(temporary) / "private-ledger"
                writer = NativeLiveAllocationLedgerStore(directory)
                writer.initialize(bindings())
                writer.allocation_intent("mutable-0")
                corrupted = json.loads(writer.path.read_text(encoding="utf-8"))
                corrupted["entries"][0]["role"] = "mutable-1"
                writer.path.write_text(json.dumps(corrupted), encoding="utf-8")
                os.chmod(writer.path, 0o600)

                target = (
                    writer
                    if method_name == "close"
                    else NativeLiveAllocationLedgerStore(directory)
                )
                with self.assertRaisesRegex(
                    NativeLiveAllocationLedgerError, "ledger-invalid"
                ):
                    getattr(target, method_name)()

    def test_stale_identity_blocks_append_before_audit_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            store.allocation_intent("mutable-0")
            audit_before = store.audit_file.read_bytes()
            corrupted = json.loads(store.path.read_text(encoding="utf-8"))
            corrupted["entries"][0]["role"] = "mutable-1"
            store.path.write_text(json.dumps(corrupted), encoding="utf-8")
            os.chmod(store.path, 0o600)

            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-stale"
            ):
                store.allocation_intent("read-only-0")
            self.assertEqual(store.audit_file.read_bytes(), audit_before)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-invalid"
            ):
                store.open()

    def test_independent_stale_store_cannot_overwrite_new_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private-ledger"
            first = NativeLiveAllocationLedgerStore(directory)
            first.initialize(bindings())
            second = NativeLiveAllocationLedgerStore(directory)
            second.open()

            first.allocation_intent("read-only-0")
            committed = first.path.read_bytes()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-stale"
            ):
                second.allocation_intent("read-only-1")
            self.assertEqual(first.path.read_bytes(), committed)
            self.assertEqual(
                len(first.audit_file.read_text(encoding="utf-8").splitlines()),
                1,
            )

            second.open()
            second.allocation_intent("read-only-1")
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-stale"
            ):
                first.allocation_intent("mutable-0")
            verifier = NativeLiveAllocationLedgerStore(directory)
            self.assertEqual(verifier.open()["sequence"], 2)

    def test_independent_concurrent_stores_admit_only_one_stale_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private-ledger"
            stores = (
                NativeLiveAllocationLedgerStore(directory),
                NativeLiveAllocationLedgerStore(directory),
            )
            stores[0].initialize(bindings())
            stores[1].open()
            barrier = threading.Barrier(2)
            results: list[str] = []

            def allocate(store: NativeLiveAllocationLedgerStore, role: str) -> None:
                barrier.wait()
                try:
                    store.allocation_intent(role)
                    results.append("committed")
                except NativeLiveAllocationLedgerError as exc:
                    results.append(str(exc))

            threads = [
                threading.Thread(
                    target=allocate,
                    args=(store, role),
                )
                for store, role in zip(
                    stores, ("read-only-0", "read-only-1"), strict=True
                )
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(results.count("committed"), 1)
            self.assertEqual(
                sum("ledger-store-stale" in result for result in results), 1
            )
            verifier = NativeLiveAllocationLedgerStore(directory)
            self.assertEqual(verifier.open()["sequence"], 1)

    def test_audit_and_ledger_crash_boundaries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "before-audit"
            store = NativeLiveAllocationLedgerStore(directory)
            initial = store.initialize(bindings())
            ledger_before = store.path.read_bytes()
            with mock.patch.object(
                LEDGER,
                "record_audit_event",
                side_effect=OSError("audit-write-failed"),
            ):
                with self.assertRaisesRegex(OSError, "audit-write-failed"):
                    store.allocation_intent("read-only-0")
            self.assertEqual(store.path.read_bytes(), ledger_before)
            self.assertEqual(store.audit_file.read_bytes(), b"")
            self.assertEqual(store.open(), initial)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "after-audit"
            store = NativeLiveAllocationLedgerStore(directory)
            store.initialize(bindings())
            ledger_before = store.path.read_bytes()
            with mock.patch.object(
                LEDGER,
                "_atomic_private_write",
                side_effect=OSError("ledger-write-failed"),
            ):
                with self.assertRaisesRegex(OSError, "ledger-write-failed"):
                    store.allocation_intent("read-only-0")
            self.assertEqual(store.path.read_bytes(), ledger_before)
            self.assertEqual(
                len(store.audit_file.read_text(encoding="utf-8").splitlines()),
                1,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "ledger-audit-entry-count-mismatch",
            ):
                store.open()

    def test_more_than_one_audit_tail_advance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            original_record = LEDGER.record_audit_event

            def record_twice(event: dict, audit_file: Path | None = None) -> dict:
                first = original_record(event, audit_file=audit_file)
                original_record(event, audit_file=audit_file)
                return first

            with mock.patch.object(
                LEDGER, "record_audit_event", side_effect=record_twice
            ):
                with self.assertRaisesRegex(
                    NativeLiveAllocationLedgerError,
                    "ledger-audit-transition-invalid",
                ):
                    store.allocation_intent("read-only-0")
            self.assertEqual(
                len(store.audit_file.read_text(encoding="utf-8").splitlines()),
                2,
            )
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError,
                "ledger-audit-entry-count-mismatch",
            ):
                store.open()

    def test_historical_multimap_semantics_and_candidate_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            allocation = store.allocation_intent("read-only-0")
            store.bind_thread(allocation, "thread-0")
            first_intent = store.turn_intent("thread-0")
            store.bind_turn("thread-0", first_intent, "turn-0")

            second_intent = str(uuid.uuid4())
            store._append(
                event="turn-intent",
                role="read-only-0",
                ordinal=EXPECTED_ROLES.index("read-only-0"),
                allocation_intent_id=allocation,
                thread_id="thread-0",
                turn_intent_id=second_intent,
                outcome="pending",
            )
            store._append(
                event="turn-bound",
                role="read-only-0",
                ordinal=EXPECTED_ROLES.index("read-only-0"),
                allocation_intent_id=allocation,
                thread_id="thread-0",
                turn_intent_id=second_intent,
                turn_id="turn-1",
                outcome="bound",
            )
            binding, latest_intent, latest_turn, duplicate = store._thread_binding(
                "thread-0"
            )
            self.assertEqual(binding["allocation_intent_id"], allocation)
            self.assertEqual(latest_intent, second_intent)
            self.assertEqual(latest_turn, "turn-1")
            self.assertFalse(duplicate)

            state_before = store.path.read_bytes()
            audit_before = store.audit_file.read_bytes()
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "turn-binding-invalid"
            ):
                store._append(
                    event="turn-bound",
                    role="read-only-0",
                    ordinal=EXPECTED_ROLES.index("read-only-0"),
                    allocation_intent_id=allocation,
                    thread_id="thread-0",
                    turn_intent_id=second_intent,
                    turn_id="turn-1",
                    outcome="bound",
                )
            self.assertEqual(store.path.read_bytes(), state_before)
            self.assertEqual(store.audit_file.read_bytes(), audit_before)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-not-open"
            ):
                store._thread_binding("thread-0")
            store.open()
            self.assertEqual(
                store._thread_binding("thread-0")[1:3], (second_intent, "turn-1")
            )
            self.assertEqual(store.checkpoint()["sequence"], 6)

    def test_lifecycle_turn_id_rejects_non_string_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            allocation = store.allocation_intent("read-only-0")
            store.bind_thread(allocation, "thread-0")
            turn_intent = store.turn_intent("thread-0")
            store.bind_turn("thread-0", turn_intent, "7")
            ledger_before = store.path.read_bytes()
            audit_before = store.audit_file.read_bytes()

            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "lifecycle-turn-invalid"
            ):
                store._append(
                    event="archive-observed",
                    role="read-only-0",
                    ordinal=EXPECTED_ROLES.index("read-only-0"),
                    allocation_intent_id=allocation,
                    thread_id="thread-0",
                    turn_intent_id=turn_intent,
                    turn_id=7,
                    outcome="archived",
                )
            self.assertEqual(store.path.read_bytes(), ledger_before)
            self.assertEqual(store.audit_file.read_bytes(), audit_before)
            with self.assertRaisesRegex(
                NativeLiveAllocationLedgerError, "ledger-store-not-open"
            ):
                store.has_lifecycle("thread-0", "archive-observed")

            store.open()
            store.record_lifecycle("thread-0", "archive-observed", "archived")
            self.assertTrue(store.has_lifecycle("thread-0", "archive-observed"))

    def test_legacy_wire_hash_and_summary_golden_vector(self) -> None:
        fixed_bindings = bindings()
        fixed_bindings["authorization_id"] = "123e4567-e89b-12d3-a456-426614174001"
        fixed_bindings["campaign_nonce"] = "123e4567-e89b-12d3-a456-426614174002"
        fixed_bindings["controller_identity"] = {
            "pid": 42,
            "start_ticks": 99,
            "boot_id_sha256": "b" * 64,
        }
        identifiers = iter(
            (
                uuid.UUID("123e4567-e89b-12d3-a456-426614174003"),
                uuid.UUID("123e4567-e89b-12d3-a456-426614174004"),
            )
        )

        def deterministic_audit(event: dict, audit_file: Path | None = None) -> dict:
            if audit_file is None:  # pragma: no cover - store always supplies it
                raise AssertionError("audit file required")
            enriched = {
                **event,
                "timestamp": "2026-07-20T00:00:00Z",
                "audit_lock_mode": "posix-flock",
            }
            enriched["event_hash"] = LEDGER.audit_event_payload_hash(enriched)
            with audit_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(enriched, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return enriched

        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            with (
                mock.patch.object(
                    LEDGER.uuid, "uuid4", side_effect=lambda: next(identifiers)
                ),
                mock.patch.object(
                    LEDGER,
                    "record_audit_event",
                    side_effect=deterministic_audit,
                ),
            ):
                store.initialize(fixed_bindings)
                allocation = store.allocation_intent("read-only-0")

            state = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertEqual(allocation, "123e4567-e89b-12d3-a456-426614174004")
            self.assertEqual(set(state), LEDGER.LEDGER_FIELDS)
            self.assertEqual(set(state["entries"][0]), LEDGER.ENTRY_FIELDS)
            self.assertEqual(
                state["entries"][0]["entry_sha256"],
                "e35d3482c75a70334a1d819acf0c053bcc76c2b57fbbdaf3d4bb0d3abc147334",
            )
            self.assertEqual(
                state["entries"][0]["audit_event_hash"],
                "a3e557a8ffb97f4a9cf7485dc83e9179b1b12723ea485a1e3ad7d0cd56f9efb3",
            )
            self.assertEqual(
                state["state_sha256"],
                "68ad13ac4ffdfa0372bbeaea70c34afdd69f745aca1f56bd380a6c13b643fcd8",
            )
            ledger_sha256 = hashlib.sha256(store.path.read_bytes()).hexdigest()
            self.assertEqual(
                ledger_sha256,
                "34e928ced03d39ac7bfddf417d7a2305cfb5c3440fbbc1cb317782a40fd05bc4",
            )
            self.assertEqual(
                hashlib.sha256(store.audit_file.read_bytes()).hexdigest(),
                "e215be7e1cc9fdd583dea3e6241c72c9feda18eea4e3232ed3dc56e70eaca0b5",
            )
            summary = store.summary()
            self.assertEqual(summary["ledger_file_sha256"], ledger_sha256)
            self.assertEqual(summary["head_entry_sha256"], state["head_entry_sha256"])
            self.assertEqual(summary["allocated_roles"], ["read-only-0"])


if __name__ == "__main__":
    unittest.main()
