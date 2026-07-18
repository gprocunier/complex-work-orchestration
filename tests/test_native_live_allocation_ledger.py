from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerError,
    NativeLiveAllocationLedgerStore,
    validate_live_allocation_ledger,
)
from cwo_core.native_pool_contracts import canonical_sha256  # noqa: E402


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


class NativeLiveAllocationLedgerTests(unittest.TestCase):
    def test_v2_identity_bindings_reject_uuid_text_aliases(self) -> None:
        for field in ("authorization_id", "campaign_nonce"):
            for alias in UUID_TEXT_ALIASES:
                with self.subTest(field=field, alias=repr(alias)), tempfile.TemporaryDirectory() as temporary:
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
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger-v2")
            initial = store.initialize(bindings_v2(), version=2)
            self.assertEqual(validate_live_allocation_ledger(initial, audit_file=store.audit_file), [])
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
                    (ROOT / "schemas/native-live-allocation-ledger-v2.schema.json").read_text(
                        encoding="utf-8"
                    )
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
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "skipped-generation")
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "generation-invalid"):
                store.initialize(changed, version=2)

    def test_intent_bind_lifecycle_and_audit_anchor_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            initial = store.initialize(bindings())
            self.assertEqual(validate_live_allocation_ledger(initial, audit_file=store.audit_file), [])
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
            self.assertEqual(validate_live_allocation_ledger(state, audit_file=store.audit_file), [])
            self.assertEqual(state["sequence"], 8)
            self.assertEqual(state["head_entry_sha256"], state["entries"][-1]["entry_sha256"])
            self.assertEqual(stat.S_IMODE(store.directory.stat().st_mode), 0o700)
            for path in (store.path, store.lock_path, store.audit_file):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            if HAS_JSONSCHEMA:
                import jsonschema

                schema = json.loads(
                    (ROOT / "schemas/native-live-allocation-ledger.schema.json").read_text(
                        encoding="utf-8"
                    )
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

    def test_duplicate_role_identity_and_cross_generation_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            store.initialize(bindings())
            first = store.allocation_intent("read-only-0")
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "transition-invalid"):
                store.allocation_intent("read-only-0")
            store.bind_thread(first, "thread-a")
            second = store.allocation_intent("read-only-1")
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "transition-invalid"):
                store.bind_thread(second, "thread-a")

        with tempfile.TemporaryDirectory() as temporary:
            changed = bindings()
            changed["live_generation"] = 5
            store = NativeLiveAllocationLedgerStore(Path(temporary) / "private-ledger")
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "generation-invalid"):
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
            self.assertEqual(validate_live_allocation_ledger(state, audit_file=store.audit_file), [])

    def test_tamper_truncation_unknown_fields_permissions_and_symlink_fail(self) -> None:
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
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "ledger-invalid"):
                store.load()

            store.path.write_text(json.dumps(original), encoding="utf-8")
            os.chmod(store.path, 0o644)
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "permissions-invalid"):
                store.load()

            os.chmod(store.path, 0o600)
            unknown = copy.deepcopy(original)
            unknown["unknown"] = True
            self.assertIn("ledger-fields-invalid", validate_live_allocation_ledger(unknown))

            audit_lines = store.audit_file.read_text(encoding="utf-8").splitlines()
            first_audit = json.loads(audit_lines[0])
            first_audit["phase"] = "archive-observed"
            audit_lines[0] = json.dumps(first_audit, sort_keys=True)
            store.audit_file.write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
            os.chmod(store.audit_file, 0o600)
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "audit-chain-invalid"):
                store.load()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            ledger_dir = root / "private-ledger"
            ledger_dir.symlink_to(target, target_is_directory=True)
            store = NativeLiveAllocationLedgerStore(ledger_dir)
            with self.assertRaisesRegex(NativeLiveAllocationLedgerError, "already-exists"):
                store.initialize(bindings())


if __name__ == "__main__":
    unittest.main()
