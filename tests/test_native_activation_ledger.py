from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_activation_ledger import (  # noqa: E402
    NativeActivationLedgerError,
    NativeActivationLedgerStore,
    read_private_json,
    validate_activation_ledger,
    write_exclusive_private_json,
)
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    validate_live_allocation_ledger,
)


def identifier() -> str:
    return str(uuid.uuid4())


HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


class NativeActivationLedgerTests(unittest.TestCase):
    def create_store(
        self,
        root: Path,
        *,
        profile: str = "n2-read-only",
    ) -> NativeActivationLedgerStore:
        root.chmod(0o700)
        return NativeActivationLedgerStore.create(
            root / "ledger",
            profile=profile,
            plan_sha256="a" * 64,
            claim_sha256="b" * 64,
            action_sha256="c" * 64,
            campaign_nonce=identifier(),
            created_at="2026-07-27T12:00:00.000Z",
        )

    def advance_authority(
        self,
        store: NativeActivationLedgerStore,
    ) -> None:
        store.append(
            "approval-consume-intent",
            recorded_at="2026-07-27T12:00:01.000Z",
        )
        store.append(
            "approval-verified",
            recorded_at="2026-07-27T12:00:02.000Z",
        )
        store.append(
            "activation-dispatch-intent",
            recorded_at="2026-07-27T12:00:03.000Z",
        )

    def test_fixed_n2_lifecycle_is_hash_chained_and_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = self.create_store(Path(temporary))
            self.advance_authority(store)
            threads: dict[str, str] = {}
            calibration = store.allocation_intent("calibration")
            threads["calibration"] = identifier()
            store.bind_thread(
                calibration,
                "calibration",
                threads["calibration"],
            )
            calibration_turn = store.turn_intent(
                "calibration",
                threads["calibration"],
                "fixed calibration",
            )
            store.bind_turn(
                "calibration",
                calibration_turn,
                identifier(),
            )
            for role in ("read-only-0", "read-only-1"):
                intent = store.allocation_intent(role)
                thread = identifier()
                store.bind_thread(intent, role, thread)
                threads[role] = thread
            for role in ("read-only-0", "read-only-1"):
                intent = store.turn_intent(role, threads[role], "fixed")
                store.bind_turn(role, intent, identifier())
            store.append("terminal", subject_id="d" * 64)

            ledger = store.load()
            self.assertEqual(validate_activation_ledger(ledger), [])
            self.assertEqual(ledger["profile"], "n2-read-only")
            self.assertEqual(
                [entry["sequence"] for entry in ledger["entries"]],
                list(range(len(ledger["entries"]))),
            )
            self.assertEqual(ledger["entries"][-1]["event"], "terminal")
            if HAS_JSONSCHEMA:
                from jsonschema import Draft202012Validator

                schema = json.loads(
                    (
                        ROOT
                        / "schemas/native-tool-activation-ledger.schema.json"
                    ).read_text(encoding="utf-8")
                )
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(ledger)
            with self.assertRaisesRegex(
                NativeActivationLedgerError,
                "event-after-terminal",
            ):
                store.append("terminal")

    def test_role_order_and_unpaired_bindings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = self.create_store(
                Path(temporary),
                profile="n1-mutable",
            )
            self.advance_authority(store)
            with self.assertRaisesRegex(
                NativeActivationLedgerError,
                "allocation-intent-sequence-invalid",
            ):
                store.allocation_intent("mutable-0")
            calibration = store.allocation_intent("calibration")
            with self.assertRaisesRegex(
                NativeActivationLedgerError,
                "thread-bind-sequence-invalid",
            ):
                store.bind_thread(
                    identifier(),
                    "calibration",
                    identifier(),
                )
            store.bind_thread(calibration, "calibration", identifier())
            self.assertEqual(
                store.summary()["phase"],
                "calibration-turning",
            )

    def test_activation_and_historical_ledgers_are_bidirectionally_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = self.create_store(
                Path(temporary),
                profile="n1-read-only",
            )
            activation = store.load()
            self.assertTrue(validate_live_allocation_ledger(activation))
            historical_header = {
                "ledger_type": "cwo-native-live-allocation-ledger:v2",
                "version": 2,
                "schema": "schemas/native-live-allocation-ledger-v2.schema.json",
            }
            self.assertTrue(validate_activation_ledger(historical_header))

    def test_owner_private_files_and_audit_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = self.create_store(Path(temporary))
            for path in (
                store.directory,
                store.ledger_path,
                store.audit_path,
                store.lock_path,
            ):
                if not path.exists():
                    continue
                expected = 0o700 if path.is_dir() else 0o600
                self.assertEqual(path.stat().st_mode & 0o777, expected)
            lines = store.audit_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["event"], "claim-acquired")

    def test_private_json_rejects_hardlinks_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            private = root / "private.json"
            write_exclusive_private_json(
                private,
                {"value": "fixed"},
                label="private-test",
            )
            os.link(private, root / "second-link.json")
            with self.assertRaisesRegex(
                NativeActivationLedgerError,
                "private-test-file-invalid",
            ):
                read_private_json(private, label="private-test")

            symlink = root / "symlink.json"
            symlink.symlink_to(private)
            with self.assertRaisesRegex(
                NativeActivationLedgerError,
                "activation-symlink-component-forbidden",
            ):
                read_private_json(symlink, label="private-test")


if __name__ == "__main__":
    unittest.main()
