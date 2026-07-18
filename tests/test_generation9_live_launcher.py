from __future__ import annotations

import copy
from dataclasses import replace
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generation9_live_launcher",
    ROOT / "scripts" / "run_native_pool_live_canaries.py",
)
assert SPEC and SPEC.loader
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)


def snapshot(label: str, **value: object) -> LIVE.JsonArtifactSnapshot:
    return LIVE.JsonArtifactSnapshot(
        raw=(label + "\n").encode(),
        value={"label": label, **value},
    )


class Generation9LiveLauncherTests(unittest.TestCase):
    def inputs(self) -> LIVE.CampaignLaunchInputs:
        grandancestor = LIVE.HistoricalV4V1ProofInputs(
            authorization=snapshot("grandancestor-authorization"),
            manifest=snapshot("grandancestor-manifest"),
            authorization_state=snapshot("grandancestor-state"),
            failure_evidence=snapshot("grandancestor-failure"),
            original_containment=snapshot("grandancestor-original-containment"),
            containment=snapshot("grandancestor-containment"),
            allocation_ledger=snapshot("grandancestor-ledger"),
            allocation_audit_bytes=b"grandancestor-audit\n",
            cause_evidence=b"grandancestor-cause\n",
            contained_session_bytes=(b"grandancestor-session\n",),
        )
        ancestor = LIVE.Version5PredecessorProofInputs(
            authorization=snapshot("ancestor-authorization"),
            manifest=snapshot("ancestor-manifest"),
            authorization_state=snapshot("ancestor-state"),
            failure_evidence=snapshot("ancestor-failure"),
            containment=snapshot("ancestor-containment"),
            allocation_ledger=snapshot("ancestor-ledger"),
            allocation_audit_bytes=b"ancestor-audit\n",
            authorization_cause_evidence=b"ancestor-cause\n",
            outer_authority=snapshot("ancestor-outer"),
            independent_validation_receipt=snapshot("ancestor-validation"),
            independent_validation_session_bytes=b"ancestor-validation-session\n",
            ancestor=grandancestor,
            contained_session_bytes=(b"ancestor-contained-session\n",),
        )
        predecessor = LIVE.Version6PredecessorProofInputs(
            authorization=snapshot("predecessor-authorization"),
            manifest=snapshot("predecessor-manifest"),
            authorization_state=snapshot("predecessor-state"),
            failure_evidence=snapshot("predecessor-failure"),
            containment=snapshot("predecessor-containment"),
            allocation_ledger=snapshot("predecessor-ledger"),
            allocation_audit_bytes=b"predecessor-audit\n",
            authorization_recovery_cause_evidence=snapshot(
                "predecessor-recovery-cause"
            ),
            authorization_recovery_cause_source_analysis=b"predecessor-source\n",
            outer_authority=snapshot("predecessor-outer"),
            independent_validation_receipt=snapshot("predecessor-validation"),
            independent_validation_session_bytes=b"predecessor-validation-session\n",
            ancestor=ancestor,
            contained_session_bytes=(b"predecessor-contained-session\n",),
        )
        quarantine = LIVE.Version7QuarantinePredecessorProofInputs(
            authorization=snapshot("quarantine-authorization"),
            manifest=snapshot("quarantine-manifest"),
            authorization_state=snapshot("quarantine-state"),
            failure_evidence=snapshot("quarantine-failure"),
            containment=snapshot("quarantine-containment"),
            allocation_ledger=snapshot("quarantine-ledger"),
            allocation_audit_bytes=b"quarantine-audit\n",
            authorization_recovery_cause_evidence=snapshot(
                "quarantine-recovery-cause"
            ),
            authorization_recovery_cause_source_analysis=b"quarantine-source\n",
            outer_authority=snapshot("quarantine-outer"),
            independent_validation_receipt=snapshot("quarantine-validation"),
            independent_validation_session_bytes=b"quarantine-validation-session\n",
            ancestor=predecessor,
            quarantined_session_bytes=b"quarantined-nonattesting-session\n",
        )
        outputs = {
            "evidence_basename": "evidence.json",
            "authorization_state_basename": "state.json",
            "steering_registry_basename": "steering.json",
            "allocation_ledger_basename": "ledger",
        }
        return LIVE.CampaignLaunchInputs(
            authorization=snapshot(
                "authorization-v8",
                version=8,
                authorization_id="authorization-9",
                bindings={
                    "validator_contract_sha256": "a" * 64,
                    "predecessor_failure_ledger_prefix_file_sha256": "b" * 64,
                    "predecessor_failure_ledger_prefix_state_sha256": "c" * 64,
                    "predecessor_failure_ledger_prefix_head_entry_sha256": "d" * 64,
                },
            ),
            manifest=snapshot(
                "manifest-v5",
                version=5,
                manifest_id="manifest-9",
                manifest_sha256="e" * 64,
                authorization_id="authorization-9",
                candidate={"commit": "f" * 40, "tree": "1" * 40},
                outputs=outputs,
            ),
            outer_authority=snapshot("outer", authority_id="outer-9"),
            release_patch_bytes=b"release-patch\n",
            pre_mutation_receipt=snapshot(
                "pre-mutation", canonical_receipt_sha256="2" * 64
            ),
            pre_mutation_adjudication=snapshot("pre-mutation-adjudication"),
            pre_live_receipt=snapshot(
                "pre-live", canonical_receipt_sha256="3" * 64
            ),
            pre_live_adjudication=snapshot("pre-live-adjudication"),
            opus_review_evidence=snapshot(
                "opus-review",
                exact_model="claude-opus-4-6",
                glm_5_2_used=False,
                model_synthesis_used=False,
            ),
            opus_adjudication=snapshot(
                "opus-adjudication", main_architect_decision="go"
            ),
            spark_validation_receipt=snapshot(
                "spark-validation",
                canonical_receipt_sha256="4" * 64,
                session_id="spark-session",
            ),
            spark_validation_session_path=Path("/trusted/spark-session.jsonl"),
            spark_validation_session_bytes=b"spark-validation-session\n",
            predecessor_proof=quarantine,
            recovery_cause_evidence=snapshot("generation9-recovery-cause"),
            recovery_cause_source_analysis_bytes=b"generation9-source\n",
        )

    def claim_paths(self, root: Path) -> dict[str, Path]:
        return {
            "output": root / "evidence.json",
            "authorization_state": root / "state.json",
            "steering_registry": root / "steering.json",
            "allocation_ledger": root / "ledger",
        }

    def test_v8_v5_is_historical_after_v10_v7_activation(self) -> None:
        LIVE.require_operative_campaign_contract(10, 7)
        for authorization_version, manifest_version in (
            (7, 4),
            (8, 5),
            (8, 4),
            (9, 5),
            (8, 6),
            (9, 6),
            (6, 3),
        ):
            with self.subTest(
                authorization=authorization_version,
                manifest=manifest_version,
            ), self.assertRaises(LIVE.AppServerError):
                LIVE.require_operative_campaign_contract(
                    authorization_version, manifest_version
                )

    def test_generation9_path_set_requires_exact_quarantine_layer(self) -> None:
        paths = {
            label: Path("/") / label
            for label in LIVE.GENERATION9_REQUIRED_PROOF_PATHS
        }
        LIVE.require_generation9_proof_path_set(
            paths,
            predecessor_contained_sessions=1,
            ancestor_contained_sessions=1,
            grandancestor_contained_sessions=1,
        )
        for changed in (
            {
                key: value
                for key, value in paths.items()
                if key != "quarantined-predecessor-session"
            },
            {**paths, "ancestor-original-containment": Path("/legacy")},
        ):
            with self.assertRaisesRegex(
                LIVE.AppServerError, "generation9-proof-path-set-invalid"
            ):
                LIVE.require_generation9_proof_path_set(
                    changed,
                    predecessor_contained_sessions=1,
                    ancestor_contained_sessions=1,
                    grandancestor_contained_sessions=1,
                )

    def test_launch_claim_v3_binds_quarantine_and_complete_finite_dag(self) -> None:
        inputs = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.claim_paths(Path(temporary))
            payload = LIVE.campaign_launch_claim_payload_v3(inputs, **paths)
            self.assertEqual(payload["version"], 3)
            self.assertEqual(
                payload["successor_proof"]["proof_dag"],
                ["v8/v5", "v7/v4", "v6/v3", "v5/v2", "v4/v1"],
            )
            quarantine = payload["successor_proof"]["quarantined_predecessor"]
            self.assertFalse(quarantine["accepting_model_evidence"])
            self.assertEqual(
                quarantine["attestation_disposition"],
                "unavailable-quarantined-nonaccepting",
            )
            expected_sources = {
                **LIVE.generation9_private_source_snapshots(inputs),
                **LIVE.generation9_trusted_session_snapshots(inputs),
            }
            self.assertEqual(
                payload["source_file_sha256s"],
                {
                    label: LIVE.sha256_bytes(raw)
                    for label, raw in sorted(expected_sources.items())
                },
            )
            original = LIVE.campaign_launch_claim_sha256(inputs, **paths)
            for changed_proof in (
                replace(
                    inputs.predecessor_proof,
                    quarantined_session_bytes=b"changed-quarantine-session\n",
                ),
                replace(
                    inputs.predecessor_proof,
                    allocation_audit_bytes=b"changed-quarantine-audit\n",
                ),
                replace(
                    inputs.predecessor_proof,
                    ancestor=replace(
                        inputs.predecessor_proof.ancestor,
                        authorization_recovery_cause_source_analysis=(
                            b"changed-generation7-source\n"
                        ),
                    ),
                ),
            ):
                changed = copy.copy(inputs)
                changed.predecessor_proof = changed_proof
                self.assertNotEqual(
                    original,
                    LIVE.campaign_launch_claim_sha256(changed, **paths),
                )

    def test_mixed_authorization_and_quarantine_proof_is_rejected(self) -> None:
        inputs = self.inputs()
        changed = copy.copy(inputs)
        changed.authorization = snapshot("authorization-v7", version=7)
        with self.assertRaisesRegex(
            LIVE.AppServerError, "generation9-proof-input-invalid"
        ):
            LIVE.require_generation9_launch_inputs(changed)


if __name__ == "__main__":
    unittest.main()
