from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from tests import test_generation10_live_launcher as generation10


LIVE = generation10.LIVE
snapshot = generation10.snapshot


class Generation11LiveLauncherTests(unittest.TestCase):
    def inputs(self) -> LIVE.CampaignLaunchInputs:
        prior = generation10.Generation10LiveLauncherTests().inputs()
        failed = prior.predecessor_proof
        self.assertIsInstance(
            failed, LIVE.Version8ProtectedFaultPredecessorProofInputs
        )
        preallocation = LIVE.Version9PreallocationFaultPredecessorProofInputs(
            authorization=snapshot("preallocation-authorization"),
            manifest=snapshot("preallocation-manifest"),
            authorization_state=snapshot("preallocation-state"),
            failure_evidence=snapshot("preallocation-failure"),
            containment=snapshot("preallocation-containment"),
            global_claim=snapshot(
                "preallocation-global-claim",
                launch_claim_sha256="f" * 64,
            ),
            authorization_marker=snapshot("preallocation-authorization-marker"),
            nonce_marker=snapshot("preallocation-nonce-marker"),
            scope_state=snapshot("preallocation-scope-state"),
            preflight=snapshot("preallocation-preflight"),
            pre_mutation_receipt=snapshot("preallocation-pre-mutation"),
            pre_live_receipt=snapshot("preallocation-pre-live"),
            authorization_recovery_cause_evidence=snapshot(
                "preallocation-recovery-cause"
            ),
            authorization_recovery_cause_source_analysis=(
                b"preallocation-source-analysis\n"
            ),
            outer_authority=snapshot("preallocation-outer"),
            independent_validation_receipt=snapshot(
                "preallocation-validation"
            ),
            independent_validation_session_bytes=(
                b"preallocation-validation-session\n"
            ),
            ancestor=failed,
        )
        return LIVE.CampaignLaunchInputs(
            authorization=snapshot(
                "authorization-v10",
                version=10,
                authorization_id="authorization-11",
                run_generation=11,
                live_generation=11,
                predecessor_live_generation=10,
                bindings={
                    "campaign_nonce": "22222222-2222-4222-8222-222222222222",
                    "validator_contract_sha256": "a" * 64,
                },
            ),
            manifest=snapshot(
                "manifest-v7",
                version=7,
                manifest_id="manifest-11",
                manifest_sha256="b" * 64,
                authorization_id="authorization-11",
                candidate={"commit": "c" * 40, "tree": "d" * 40},
                outputs=dict(prior.manifest.value["outputs"]),
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
            predecessor_proof=preallocation,
            recovery_cause_evidence=snapshot("generation11-recovery-cause"),
            recovery_cause_source_analysis_bytes=b"generation11-source\n",
        )

    @staticmethod
    def paths(root: Path) -> dict[str, Path]:
        return {
            "output": root / "evidence.json",
            "authorization_state": root / "state.json",
            "steering_registry": root / "steering.json",
            "allocation_ledger": root / "ledger",
        }

    def test_v10_v7_is_historical_after_v11_v8_activation(self) -> None:
        LIVE.require_operative_campaign_contract(11, 8, 6, 6)
        for pair in ((9, 6), (10, 6), (9, 7), (11, 7), (10, 8), (10, 7)):
            with self.subTest(pair=pair), self.assertRaises(LIVE.AppServerError):
                LIVE.require_operative_campaign_contract(*pair)

    def test_generation11_path_set_requires_zero_session_immediate_leaf(self) -> None:
        paths = {
            label: Path("/") / label
            for label in LIVE.GENERATION11_REQUIRED_PROOF_PATHS
        }
        paths.update(
            {
                f"failed-predecessor-contained-session-{index}": (
                    Path("/") / f"failed-{index}"
                )
                for index in range(5)
            }
        )
        kwargs = {
            "failed_predecessor_contained_sessions": 5,
            "predecessor_contained_sessions": 1,
            "ancestor_contained_sessions": 1,
            "grandancestor_contained_sessions": 1,
        }
        LIVE.require_generation11_proof_path_set(paths, **kwargs)
        changed = {
            **paths,
            "preallocation-failed-predecessor-contained-session-0": Path("/x"),
        }
        with self.assertRaisesRegex(
            LIVE.AppServerError, "campaign-generation11-proof-path-set-invalid"
        ):
            LIVE.require_generation11_proof_path_set(changed, **kwargs)

    def test_launch_claim_v5_binds_preallocation_leaf_and_complete_sources(self) -> None:
        inputs = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.paths(Path(temporary))
            payload = LIVE.campaign_launch_claim_payload_v5(inputs, **paths)
            self.assertEqual(payload["version"], 5)
            self.assertEqual(payload["successor_proof"]["proof_dag"][0], "v10/v7")
            leaf = payload["successor_proof"]["preallocation_failed_predecessor"]
            self.assertEqual(leaf["allocation_intent_count"], 0)
            self.assertEqual(leaf["session_count"], 0)
            self.assertFalse(leaf["operative_authority"])
            self.assertIn(
                "preallocation-failed-predecessor-scope-state",
                payload["source_file_sha256s"],
            )
            first = LIVE.campaign_launch_claim_sha256(inputs, **paths)
            proof = inputs.predecessor_proof
            self.assertIsInstance(
                proof, LIVE.Version9PreallocationFaultPredecessorProofInputs
            )
            changed = self.inputs()
            changed.predecessor_proof = LIVE.Version9PreallocationFaultPredecessorProofInputs(
                **{**proof.__dict__, "scope_state": snapshot("changed-scope-state")}
            )
            self.assertNotEqual(
                first, LIVE.campaign_launch_claim_sha256(changed, **paths)
            )

    def test_generation11_quarantine_prefix_comes_from_v8_failed_authority(
        self,
    ) -> None:
        inputs = self.inputs()
        proof = inputs.predecessor_proof
        self.assertIsInstance(
            proof, LIVE.Version9PreallocationFaultPredecessorProofInputs
        )
        failed = proof.ancestor
        expected = {
            "failure_ledger_prefix_file_sha256": "1" * 64,
            "failure_ledger_prefix_state_sha256": "2" * 64,
            "failure_ledger_prefix_head_entry_sha256": "3" * 64,
        }
        changed_failed = replace(
            failed,
            authorization=snapshot(
                "failed-v8-authorization",
                bindings={
                    f"predecessor_{field}": value
                    for field, value in expected.items()
                },
            ),
        )
        observed = LIVE.quarantined_predecessor_ledger_prefix_bindings(
            inputs.authorization.value, changed_failed
        )
        self.assertEqual(
            observed,
            {
                f"quarantined_predecessor_{field}": value
                for field, value in expected.items()
            },
        )
        self.assertTrue(all(value is not None for value in observed.values()))

    def test_mixed_generation11_inputs_fail_closed(self) -> None:
        inputs = self.inputs()
        inputs.predecessor_proof = inputs.predecessor_proof.ancestor
        with self.assertRaisesRegex(
            LIVE.AppServerError, "campaign-generation11-proof-input-invalid"
        ):
            LIVE.require_generation11_launch_inputs(inputs)


if __name__ == "__main__":
    unittest.main()
