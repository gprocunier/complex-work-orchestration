from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    NativeLiveAllocationLedgerStore,
)


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class Generation10ProtectedFaultContractTests(unittest.TestCase):
    def _ledger(self, root: Path) -> tuple[dict, dict[str, tuple[str, str]]]:
        store = NativeLiveAllocationLedgerStore(root / "ledger")
        store.initialize(
            {
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.43",
                "authorization_id": str(uuid.uuid4()),
                "authorization_raw_sha256": sha("authorization-raw"),
                "authorization_canonical_sha256": sha("authorization"),
                "campaign_manifest_sha256": sha("manifest"),
                "campaign_nonce": str(uuid.uuid4()),
                "live_generation": 9,
                "predecessor_generation": 8,
                "candidate_commit": "1" * 40,
                "candidate_tree": "2" * 40,
                "origin_main_commit": "3" * 40,
                "guarded_primary_diff_sha256": sha("primary"),
                "predecessor_containment_sha256": sha("predecessor"),
                "frozen_release_patch_sha256": sha("patch"),
                "pre_mutation_steering_receipt_sha256": sha("pre-mutation"),
                "pre_live_steering_receipt_sha256": sha("pre-live"),
                "opus_review_sha256": sha("opus"),
                "certification_policy_sha256": sha("certification-policy"),
                "controller_identity": {
                    "pid": 1,
                    "start_ticks": 1,
                    "boot_id_sha256": sha("boot"),
                },
                "connection_epoch_sha256": sha("connection"),
                "retention_class": "private-local-until-bead-closure",
                "expected_roles": list(CONTRACTS.EXPECTED_ROLES),
            },
            version=2,
        )
        identities: dict[str, tuple[str, str]] = {}

        def allocate(role: str, *, bind_turn: bool = True) -> tuple[str, str]:
            allocation_id = store.allocation_intent(role)
            session_id = str(uuid.uuid4())
            turn_id = str(uuid.uuid4())
            store.bind_thread(allocation_id, session_id)
            if bind_turn:
                turn_intent_id = store.turn_intent(session_id)
                store.bind_turn(session_id, turn_intent_id, turn_id)
            identities[role] = (session_id, turn_id)
            return session_id, turn_id

        calibration, _ = allocate("capability-calibration")
        store.record_lifecycle(
            calibration, "interrupt-observed", "interrupt-request-accepted"
        )
        store.record_lifecycle(
            calibration, "archive-observed", "archive-request-accepted"
        )
        store.bind_certification(sha("certification"))

        read_sessions: list[str] = []
        for role in ("read-only-0", "read-only-1"):
            allocation_id = store.allocation_intent(role)
            session_id = str(uuid.uuid4())
            store.bind_thread(allocation_id, session_id)
            identities[role] = (session_id, str(uuid.uuid4()))
            read_sessions.append(session_id)
        for role, session_id in zip(
            ("read-only-0", "read-only-1"), read_sessions, strict=True
        ):
            turn_id = identities[role][1]
            turn_intent_id = store.turn_intent(session_id)
            store.bind_turn(session_id, turn_intent_id, turn_id)
        for session_id in read_sessions:
            store.record_lifecycle(
                session_id, "archive-observed", "archive-request-accepted"
            )

        mutable_sessions: list[str] = []
        for role in ("mutable-0", "mutable-1"):
            allocation_id = store.allocation_intent(role)
            session_id = str(uuid.uuid4())
            store.bind_thread(allocation_id, session_id)
            identities[role] = (session_id, str(uuid.uuid4()))
            mutable_sessions.append(session_id)
        for role, session_id in zip(
            ("mutable-0", "mutable-1"), mutable_sessions, strict=True
        ):
            turn_id = identities[role][1]
            turn_intent_id = store.turn_intent(session_id)
            store.bind_turn(session_id, turn_intent_id, turn_id)
        for session_id in mutable_sessions:
            store.record_lifecycle(
                session_id, "interrupt-observed", "interrupt-request-accepted"
            )
            store.record_lifecycle(
                session_id, "archive-observed", "archive-request-accepted"
            )

        for role in CONTRACTS.EXPECTED_ROLES[:5]:
            session_id, _turn_id = identities[role]
            store.record_containment_audit(
                session_id,
                outcome="already-contained",
                evidence={"role": role, "outcome": "already-contained"},
            )
        return store.load(), identities

    def _failure_summary(self, ledger: dict) -> dict:
        bindings = ledger["bindings"]
        raw = (
            json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        return {
            "allocated_roles": list(CONTRACTS.EXPECTED_ROLES[:5]),
            "allocation_intent_count": 5,
            "available": True,
            "campaign_manifest_sha256": bindings["campaign_manifest_sha256"],
            "head_entry_sha256": ledger["head_entry_sha256"],
            "ledger_file_sha256": hashlib.sha256(raw).hexdigest(),
            "ledger_id": ledger["ledger_id"],
            "ledger_type": ledger["ledger_type"],
            "live_generation": 9,
            "sequence": 34,
            "state_sha256": ledger["state_sha256"],
            "thread_bound_count": 5,
            "turn_bound_count": 5,
            "turn_intent_count": 5,
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
            "version": 2,
        }

    def _session(
        self, role: str, session_id: str, turn_id: str
    ) -> tuple[bytes, dict]:
        records: list[dict] = [
            {
                "type": "session_meta",
                "payload": {"id": session_id, "session_id": session_id},
            },
            {
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": turn_id},
            },
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": turn_id,
                    "model": CONTRACTS.EXACT_OPERATIVE_MODEL,
                    "effort": CONTRACTS.EXACT_OPERATIVE_EFFORT,
                },
            },
        ]
        for index, (kind, name) in enumerate(
            CONTRACTS.CONTAINED_ROLE_TOOL_PREFIXES[role]
        ):
            call_id = f"{role}-call-{index}"
            call_type = "function_call" if kind == "function" else "custom_tool_call"
            output_type = (
                "function_call_output"
                if kind == "function"
                else "custom_tool_call_output"
            )
            records.extend(
                (
                    {
                        "type": "response_item",
                        "payload": {
                            "type": call_type,
                            "call_id": call_id,
                            "name": name,
                        },
                    },
                    {
                        "type": "response_item",
                        "payload": {"type": output_type, "call_id": call_id},
                    },
                )
            )
        terminal_type = (
            "task_complete" if role.startswith("read-only") else "turn_aborted"
        )
        records.append(
            {
                "type": "event_msg",
                "payload": {"type": terminal_type, "turn_id": turn_id},
            }
        )
        raw = b"".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            for record in records
        )
        accounting = {
            "active_match_count": 0,
            "archive_match_count": 1,
            "archive_request_outcome": "accepted",
            "archived_session_file_sha256": hashlib.sha256(raw).hexdigest(),
            "attested_effort": CONTRACTS.EXACT_OPERATIVE_EFFORT,
            "attested_model": CONTRACTS.EXACT_OPERATIVE_MODEL,
            "boundary_sha256": hashlib.sha256(raw).hexdigest(),
            "byte_offset": len(raw),
            "containment_outcome": "already-contained",
            "record_count": len(records),
            "role": role,
            "session_id": session_id,
            "terminal_event": {
                "count": 1,
                "event_type": terminal_type,
                "record_index": len(records) - 1,
                "status": (
                    "completed" if terminal_type == "task_complete" else "interrupted"
                ),
            },
            "trusted_turn_context_count": 1,
            "turn_id": turn_id,
        }
        return raw, accounting

    def test_exact_generation9_ledger_and_session_family_accept(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, identities = self._ledger(Path(temporary))
            self.assertEqual(
                CONTRACTS._validate_generation9_protected_fault_ledger(
                    ledger, self._failure_summary(ledger)
                ),
                [],
            )
            sessions_and_accounting = [
                self._session(role, *identities[role])
                for role in CONTRACTS.EXPECTED_ROLES[:5]
            ]
            raw_sessions = tuple(item[0] for item in sessions_and_accounting)
            accounting = [item[1] for item in sessions_and_accounting]
            family = CONTRACTS.contained_session_family_sha256(
                accounting, raw_sessions
            )
            self.assertEqual(
                CONTRACTS._validate_generation9_protected_fault_sessions(
                    raw_sessions,
                    accounting,
                    ledger,
                    expected_family_sha256=family,
                ),
                [],
            )

    def test_session_reorder_duplicate_and_missing_raw_attestation_reject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger, identities = self._ledger(Path(temporary))
            values = [
                self._session(role, *identities[role])
                for role in CONTRACTS.EXPECTED_ROLES[:5]
            ]
            raw = tuple(item[0] for item in values)
            accounting = [item[1] for item in values]
            family = CONTRACTS.contained_session_family_sha256(accounting, raw)
            variants = (
                ((raw[1], raw[0], *raw[2:]), accounting),
                ((raw[0], raw[0], *raw[2:]), accounting),
            )
            for changed_raw, changed_accounting in variants:
                with self.subTest(changed=hashlib.sha256(changed_raw[0]).hexdigest()):
                    self.assertNotEqual(
                        CONTRACTS._validate_generation9_protected_fault_sessions(
                            tuple(changed_raw),
                            changed_accounting,
                            ledger,
                            expected_family_sha256=family,
                        ),
                        [],
                    )
            records = [json.loads(line) for line in raw[3].splitlines()]
            records = [item for item in records if item["type"] != "turn_context"]
            without_context = b"".join(
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
                for item in records
            )
            changed_raw = (*raw[:3], without_context, raw[4])
            changed_accounting = copy.deepcopy(accounting)
            changed_accounting[3].update(
                {
                    "archived_session_file_sha256": hashlib.sha256(
                        without_context
                    ).hexdigest(),
                    "boundary_sha256": hashlib.sha256(without_context).hexdigest(),
                    "byte_offset": len(without_context),
                    "record_count": len(records),
                    "terminal_event": {
                        **changed_accounting[3]["terminal_event"],
                        "record_index": len(records) - 1,
                    },
                }
            )
            changed_family = CONTRACTS.contained_session_family_sha256(
                changed_accounting, tuple(changed_raw)
            )
            errors = CONTRACTS._validate_generation9_protected_fault_sessions(
                tuple(changed_raw),
                changed_accounting,
                ledger,
                expected_family_sha256=changed_family,
            )
            self.assertIn(
                "authorization-predecessor-v8-protected-session-turn-context-invalid",
                errors,
            )

    def test_malformed_nested_v9_v6_fields_return_errors_not_exceptions(self) -> None:
        for field in ("bindings", "mandatory_gates", "progress_gate"):
            errors = CONTRACTS.validate_full_auto_authorization(
                {"version": 9, field: "wrong-type"}
            )
            self.assertTrue(any(field.replace("_", "-") in item for item in errors))
        errors = CONTRACTS.validate_campaign_manifest(
            {"version": 6, "predecessor": "wrong-type"},
            authorization={"version": 9, "bindings": {}},
        )
        self.assertTrue(any("predecessor" in item for item in errors))

    def test_validator_contract_v4_adds_v9_v6_without_changing_v1_v2_v3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V4:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CWO Test",
                    "-c",
                    "user.email=cwo@example.invalid",
                    "commit",
                    "-qm",
                    "validator-v4",
                ],
                cwd=root,
                check=True,
            )
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            digests = {
                CONTRACTS.validator_contract_sha256(root, tree),
                CONTRACTS.validator_contract_sha256_v2(root, tree),
                CONTRACTS.validator_contract_sha256_v3(root, tree),
                CONTRACTS.validator_contract_sha256_v4(root, tree),
            }
            self.assertEqual(len(digests), 4)
            subprocess.run(
                ["git", "rm", "-q", "schemas/full-auto-run-authorization-v9.schema.json"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CWO Test",
                    "-c",
                    "user.email=cwo@example.invalid",
                    "commit",
                    "-qm",
                    "remove-v9",
                ],
                cwd=root,
                check=True,
            )
            changed_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            with self.assertRaisesRegex(ValueError, "validator-contract-path-invalid"):
                CONTRACTS.validator_contract_sha256_v4(root, changed_tree)


if __name__ == "__main__":
    unittest.main()
