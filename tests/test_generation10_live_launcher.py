from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tests import test_generation9_live_launcher as generation9


LIVE = generation9.LIVE
snapshot = generation9.snapshot


class Generation10LiveLauncherTests(unittest.TestCase):
    def inputs(self) -> LIVE.CampaignLaunchInputs:
        prior = generation9.Generation9LiveLauncherTests().inputs()
        quarantine = prior.predecessor_proof
        self.assertIsInstance(
            quarantine, LIVE.Version7QuarantinePredecessorProofInputs
        )
        failed = LIVE.Version8ProtectedFaultPredecessorProofInputs(
            authorization=snapshot("failed-authorization"),
            manifest=snapshot("failed-manifest"),
            authorization_state=snapshot("failed-state"),
            failure_evidence=snapshot("failed-evidence"),
            containment=snapshot("failed-containment"),
            allocation_ledger=snapshot("failed-ledger"),
            allocation_audit_bytes=b"failed-audit\n",
            authorization_recovery_cause_evidence=snapshot(
                "failed-authorization-cause"
            ),
            authorization_recovery_cause_source_analysis=b"failed-source\n",
            outer_authority=snapshot("failed-outer"),
            independent_validation_receipt=snapshot("failed-validation"),
            independent_validation_session_bytes=b"failed-validation-session\n",
            ancestor=quarantine,
            contained_session_bytes=tuple(
                f"failed-contained-{index}\n".encode() for index in range(5)
            ),
        )
        outputs = dict(prior.manifest.value["outputs"])
        return LIVE.CampaignLaunchInputs(
            authorization=snapshot(
                "authorization-v9",
                version=9,
                authorization_id="authorization-10",
                run_generation=10,
                live_generation=10,
                predecessor_live_generation=9,
                bindings={
                    "campaign_nonce": "11111111-1111-4111-8111-111111111111",
                    "validator_contract_sha256": "a" * 64,
                    "predecessor_contained_session_family_sha256": "b" * 64,
                    "predecessor_contained_session_count": 5,
                },
            ),
            manifest=snapshot(
                "manifest-v6",
                version=6,
                manifest_id="manifest-10",
                manifest_sha256="c" * 64,
                authorization_id="authorization-10",
                candidate={"commit": "d" * 40, "tree": "e" * 40},
                outputs=outputs,
            ),
            outer_authority=prior.outer_authority,
            release_patch_bytes=prior.release_patch_bytes,
            pre_mutation_receipt=prior.pre_mutation_receipt,
            pre_mutation_adjudication=prior.pre_mutation_adjudication,
            pre_live_receipt=prior.pre_live_receipt,
            pre_live_adjudication=prior.pre_live_adjudication,
            opus_review_evidence=prior.opus_review_evidence,
            opus_adjudication=prior.opus_adjudication,
            spark_validation_receipt=prior.spark_validation_receipt,
            spark_validation_session_path=prior.spark_validation_session_path,
            spark_validation_session_bytes=prior.spark_validation_session_bytes,
            predecessor_proof=failed,
            recovery_cause_evidence=snapshot("generation10-recovery-cause"),
            recovery_cause_source_analysis_bytes=b"generation10-source\n",
        )

    def paths(self, root: Path) -> dict[str, Path]:
        return {
            "output": root / "evidence.json",
            "authorization_state": root / "state.json",
            "steering_registry": root / "steering.json",
            "allocation_ledger": root / "ledger",
        }

    def test_generation10_contract_is_historical_after_v11_v8_release(self) -> None:
        LIVE.require_operative_campaign_contract(12, 8, 6, 6)
        for pair in (
            (8, 5),
            (9, 5),
            (8, 6),
            (10, 6),
            (9, 7),
            (9, 6),
            (10, 7),
        ):
            with self.subTest(pair=pair), self.assertRaises(LIVE.AppServerError):
                LIVE.require_operative_campaign_contract(*pair)

    def test_generation10_path_set_requires_exact_five_session_leaf(self) -> None:
        paths = {
            label: Path("/") / label
            for label in LIVE.GENERATION10_REQUIRED_PROOF_PATHS
        }
        paths.update(
            {
                f"failed-predecessor-contained-session-{index}": Path("/")
                / f"failed-{index}"
                for index in range(5)
            }
        )
        kwargs = {
            "failed_predecessor_contained_sessions": 5,
            "predecessor_contained_sessions": 1,
            "ancestor_contained_sessions": 1,
            "grandancestor_contained_sessions": 1,
        }
        LIVE.require_generation10_proof_path_set(paths, **kwargs)
        for changed_paths, changed_kwargs in (
            ({k: v for k, v in paths.items() if not k.endswith("-4")}, kwargs),
            (paths, {**kwargs, "failed_predecessor_contained_sessions": 4}),
            (
                {**paths, "failed-predecessor-contained-session-5": Path("/x")},
                kwargs,
            ),
        ):
            with self.assertRaisesRegex(
                LIVE.AppServerError,
                "campaign-generation10-proof-path-set-invalid",
            ):
                LIVE.require_generation10_proof_path_set(
                    changed_paths, **changed_kwargs
                )

    def test_launch_claim_v4_binds_failed_leaf_and_complete_source_set(self) -> None:
        inputs = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.paths(Path(temporary))
            payload = LIVE.campaign_launch_claim_payload_v4(inputs, **paths)
            self.assertEqual(payload["version"], 4)
            self.assertEqual(
                payload["successor_proof"]["proof_dag"],
                ["v9/v6", "v8/v5", "v7/v4", "v6/v3", "v5/v2", "v4/v1"],
            )
            failed = payload["successor_proof"]["failed_predecessor"]
            self.assertFalse(failed["accepting_model_evidence"])
            self.assertFalse(failed["operative_authority"])
            self.assertEqual(failed["contained_session_count"], 5)
            self.assertIn(
                "failed-predecessor-contained-session-4",
                payload["source_file_sha256s"],
            )
            first = LIVE.campaign_launch_claim_sha256(inputs, **paths)
            proof = inputs.predecessor_proof
            self.assertIsInstance(
                proof, LIVE.Version8ProtectedFaultPredecessorProofInputs
            )
            changed_proof = LIVE.Version8ProtectedFaultPredecessorProofInputs(
                **{
                    **proof.__dict__,
                    "contained_session_bytes": (
                        *proof.contained_session_bytes[:-1],
                        b"changed-contained-session\n",
                    ),
                }
            )
            changed = self.inputs()
            changed.predecessor_proof = changed_proof
            self.assertNotEqual(
                first, LIVE.campaign_launch_claim_sha256(changed, **paths)
            )

    def test_mixed_generation10_inputs_fail_closed(self) -> None:
        inputs = self.inputs()
        inputs.predecessor_proof = inputs.predecessor_proof.ancestor
        with self.assertRaisesRegex(
            LIVE.AppServerError, "campaign-generation10-proof-input-invalid"
        ):
            LIVE.require_generation10_launch_inputs(inputs)


if __name__ == "__main__":
    unittest.main()
