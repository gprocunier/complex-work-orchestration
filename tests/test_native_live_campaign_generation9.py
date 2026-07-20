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
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class Generation9QuarantineContractTests(unittest.TestCase):
    def _ledger(self, root: Path) -> tuple[dict, dict, str, str]:
        store = NativeLiveAllocationLedgerStore(root / "ledger")
        store.initialize(
            {
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.38",
                "authorization_id": str(uuid.uuid4()),
                "authorization_raw_sha256": sha("authorization-raw"),
                "authorization_canonical_sha256": sha("authorization"),
                "campaign_manifest_sha256": sha("manifest"),
                "campaign_nonce": str(uuid.uuid4()),
                "live_generation": 8,
                "predecessor_generation": 7,
                "candidate_commit": "1" * 40,
                "candidate_tree": "2" * 40,
                "origin_main_commit": "3" * 40,
                "guarded_primary_diff_sha256": sha("primary"),
                "predecessor_containment_sha256": sha("predecessor"),
                "frozen_release_patch_sha256": sha("patch"),
                "pre_mutation_steering_receipt_sha256": sha("pre-mutation"),
                "pre_live_steering_receipt_sha256": sha("pre-live"),
                "opus_review_sha256": sha("opus"),
                "certification_policy_sha256": sha("certification"),
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
        allocation_id = store.allocation_intent("capability-calibration")
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        store.bind_thread(allocation_id, session_id)
        turn_intent_id = store.turn_intent(session_id)
        store.bind_turn(session_id, turn_intent_id, turn_id)
        prefix = store.load()
        prefix_raw = store.path.read_bytes()
        store.record_lifecycle(
            session_id, "archive-observed", "archive-request-accepted"
        )
        store.record_containment_audit(
            session_id,
            outcome="contained",
            evidence={
                "thread_id_sha256": hashlib.sha256(
                    session_id.encode("utf-8")
                ).hexdigest(),
                "turn_status": "interrupted",
                "outcome": "contained",
            },
        )
        final = store.load()
        failure_summary = {
            "allocated_roles": ["capability-calibration"],
            "allocation_intent_count": 1,
            "available": True,
            "campaign_manifest_sha256": final["bindings"][
                "campaign_manifest_sha256"
            ],
            "head_entry_sha256": prefix["head_entry_sha256"],
            "ledger_file_sha256": hashlib.sha256(prefix_raw).hexdigest(),
            "ledger_id": prefix["ledger_id"],
            "ledger_type": prefix["ledger_type"],
            "live_generation": 8,
            "sequence": 4,
            "state_sha256": prefix["state_sha256"],
            "thread_bound_count": 1,
            "turn_bound_count": 1,
            "turn_intent_count": 1,
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
            "version": 2,
        }
        return final, failure_summary, session_id, turn_id

    def _session(self, session_id: str, turn_id: str) -> bytes:
        records = (
            {
                "timestamp": "2026-07-18T07:35:44.181Z",
                "type": "session_meta",
                "payload": {"id": session_id, "session_id": session_id},
            },
            {
                "timestamp": "2026-07-18T07:35:44.181Z",
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": turn_id},
            },
        )
        return b"".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            for record in records
        )

    def _accounting(self, raw: bytes, session_id: str, turn_id: str) -> dict:
        return {
            "active_match_count": 0,
            "archive_match_count": 1,
            "archive_request_outcome": "accepted",
            "archived_session_file_sha256": hashlib.sha256(raw).hexdigest(),
            "attestation_status": "unavailable-quarantined-nonaccepting",
            "byte_offset": len(raw),
            "control_plane_projection_before_archive": "interrupted",
            "record_count": 2,
            "session_id": session_id,
            "terminal_event": None,
            "trusted_turn_context_count": 0,
            "turn_id": turn_id,
        }

    def test_exact_archive_only_ledger_and_cryptographic_failure_prefix_accept(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            final, failure_summary, _session_id, _turn_id = self._ledger(
                Path(temporary)
            )
            self.assertEqual(
                CONTRACTS._validate_generation8_quarantine_ledger(
                    final, failure_summary
                ),
                [],
            )
            prefix, prefix_raw = CONTRACTS._generation8_failure_ledger_prefix(final)
            self.assertEqual(prefix["state_sha256"], failure_summary["state_sha256"])
            self.assertEqual(
                hashlib.sha256(prefix_raw).hexdigest(),
                failure_summary["ledger_file_sha256"],
            )

    def test_quarantine_ledger_rejects_prefix_splice_and_accepting_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            final, failure_summary, _session_id, _turn_id = self._ledger(
                Path(temporary)
            )
            spliced = copy.deepcopy(failure_summary)
            spliced["ledger_file_sha256"] = sha("other-run-prefix")
            self.assertIn(
                "authorization-predecessor-v7-quarantine-ledger-prefix-binding-invalid",
                CONTRACTS._validate_generation8_quarantine_ledger(final, spliced),
            )
            changed_evidence = copy.deepcopy(final)
            changed_evidence["entries"][5]["evidence_sha256"] = sha(
                "accepting-or-unbound-containment"
            )
            self.assertIn(
                "authorization-predecessor-v7-quarantine-ledger-containment-evidence-invalid",
                CONTRACTS._validate_generation8_quarantine_ledger(
                    changed_evidence, failure_summary
                ),
            )
            for event, outcome in (
                ("interrupt-observed", "interrupt-request-accepted"),
                ("certification-bound", "bound"),
            ):
                changed = copy.deepcopy(final)
                changed["entries"].insert(
                    4,
                    {
                        **changed["entries"][3],
                        "event": event,
                        "outcome": outcome,
                    },
                )
                self.assertIn(
                    "authorization-predecessor-v7-quarantine-ledger-shape-invalid",
                    CONTRACTS._validate_generation8_quarantine_ledger(
                        changed, failure_summary
                    ),
                )

    def test_exact_two_record_nonattesting_session_accepts(self) -> None:
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        raw = self._session(session_id, turn_id)
        self.assertEqual(
            CONTRACTS._validate_generation8_quarantine_session(
                raw,
                self._accounting(raw, session_id, turn_id),
                expected_session_id=session_id,
                expected_turn_id=turn_id,
                expected_file_sha256=hashlib.sha256(raw).hexdigest(),
            ),
            [],
        )

    def test_quarantine_session_rejects_partial_extra_context_and_accepting_disposition(self) -> None:
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        raw = self._session(session_id, turn_id)
        accounting = self._accounting(raw, session_id, turn_id)
        variants = {
            "partial": raw[:-1],
            "extra": raw
            + json.dumps(
                {
                    "timestamp": "2026-07-18T07:35:45Z",
                    "type": "turn_context",
                    "payload": {"model": "gpt-5.3-codex-spark"},
                },
                separators=(",", ":"),
            ).encode()
            + b"\n",
        }
        for label, changed in variants.items():
            with self.subTest(label=label):
                self.assertNotEqual(
                    CONTRACTS._validate_generation8_quarantine_session(
                        changed,
                        accounting,
                        expected_session_id=session_id,
                        expected_turn_id=turn_id,
                        expected_file_sha256=hashlib.sha256(raw).hexdigest(),
                    ),
                    [],
                )
        accepting = copy.deepcopy(accounting)
        accepting["attestation_status"] = "accepted"
        self.assertIn(
            "authorization-predecessor-v7-quarantine-session-binding-invalid",
            CONTRACTS._validate_generation8_quarantine_session(
                raw,
                accepting,
                expected_session_id=session_id,
                expected_turn_id=turn_id,
                expected_file_sha256=hashlib.sha256(raw).hexdigest(),
            ),
        )

    def test_v8_v5_dispatch_rejects_missing_mixed_and_downgrade_proofs(self) -> None:
        v8 = {"version": 8}
        self.assertIn(
            "authorization-v8-predecessor-quarantine-proof-missing",
            CONTRACTS.validate_full_auto_authorization(
                v8,
                predecessor_proof=object(),
                recovery_cause_evidence=object(),
                recovery_cause_source_analysis=b"cause",
            ),
        )
        self.assertIn(
            "authorization-v9-predecessor-protected-proof-missing",
            CONTRACTS.validate_full_auto_authorization({"version": 9}),
        )
        self.assertIn(
            "campaign-manifest-v5-authorization-missing",
            CONTRACTS.validate_campaign_manifest(
                {"version": 5}, predecessor_proof=object()
            ),
        )
        self.assertIn(
            "campaign-manifest-v6-header-invalid",
            CONTRACTS.validate_campaign_manifest({"version": 6}),
        )

    def test_validator_contract_v3_adds_schema_blobs_without_changing_v1_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V3:
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
                    "validator-v3",
                ],
                cwd=root,
                check=True,
            )
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            v1 = CONTRACTS.validator_contract_sha256(root, tree)
            v2 = CONTRACTS.validator_contract_sha256_v2(root, tree)
            v3 = CONTRACTS.validator_contract_sha256_v3(root, tree)
            self.assertEqual(len({v1, v2, v3}), 3)
            subprocess.run(
                ["git", "rm", "-q", "schemas/full-auto-run-authorization-v8.schema.json"],
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
                    "remove-v8",
                ],
                cwd=root,
                check=True,
            )
            old_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            with self.assertRaisesRegex(ValueError, "validator-contract-path-invalid"):
                CONTRACTS.validator_contract_sha256_v3(root, old_tree)


if __name__ == "__main__":
    unittest.main()
