from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from tests import test_generation11_live_launcher as generation11


LIVE = generation11.LIVE
snapshot = generation11.snapshot


class Generation12LiveLauncherTests(unittest.TestCase):
    def inputs(self) -> LIVE.CampaignLaunchInputs:
        prior = generation11.Generation11LiveLauncherTests().inputs()
        ancestor = prior.predecessor_proof
        self.assertIsInstance(
            ancestor, LIVE.Version9PreallocationFaultPredecessorProofInputs
        )
        interrupted = LIVE.Version10InterruptedEmptyBoundaryPredecessorProofInputs(
            authorization=snapshot(
                "interrupted-authorization", version=10
            ),
            manifest=snapshot("interrupted-manifest", version=7),
            authorization_state=snapshot("interrupted-state"),
            failure_evidence=snapshot("interrupted-failure"),
            global_claim=snapshot(
                "interrupted-global-claim", launch_claim_sha256="1" * 64
            ),
            authorization_marker=snapshot("interrupted-authorization-marker"),
            nonce_marker=snapshot("interrupted-nonce-marker"),
            scope_state=snapshot("interrupted-scope-state"),
            preflight=snapshot("interrupted-preflight"),
            pre_mutation_receipt=snapshot("interrupted-pre-mutation"),
            pre_mutation_adjudication=snapshot(
                "interrupted-pre-mutation-adjudication"
            ),
            pre_live_receipt=snapshot("interrupted-pre-live"),
            pre_live_adjudication=snapshot(
                "interrupted-pre-live-adjudication"
            ),
            allocation_ledger=snapshot("interrupted-allocation-ledger"),
            allocation_audit_bytes=b"interrupted-allocation-audit\n",
            steering_registry=snapshot("interrupted-steering-registry"),
            terminal_session_bytes=b"one-interrupted-terminal-session\n",
            containment=snapshot("interrupted-v32-containment"),
            terminal_facts=snapshot("interrupted-terminal-facts"),
            generation11_runner_source_bytes=(
                b"interrupted-generation11-runner-source\n"
            ),
            generation11_session_boundary_source_bytes=(
                b"interrupted-generation11-session-boundary-source\n"
            ),
            recovery_cause_analysis_bytes=(
                b"interrupted-recovery-cause-analysis\n"
            ),
            recovery_steering_receipt=snapshot(
                "interrupted-recovery-steering-receipt"
            ),
            recovery_steering_session_bytes=(
                b"interrupted-recovery-steering-session\n"
            ),
            authorization_recovery_cause_evidence=snapshot(
                "interrupted-authorization-recovery-cause"
            ),
            authorization_recovery_cause_source_analysis=(
                b"interrupted-authorization-recovery-source\n"
            ),
            outer_authority=snapshot("interrupted-outer"),
            independent_validation_receipt=snapshot(
                "interrupted-independent-validation"
            ),
            independent_validation_session_bytes=(
                b"interrupted-independent-validation-session\n"
            ),
            ancestor=ancestor,
        )
        bindings = {
            "campaign_nonce": "33333333-3333-4333-8333-333333333333",
            "validator_contract_sha256": "2" * 64,
            "predecessor_initial_empty_boundary_sha256": "3" * 64,
            "predecessor_recovery_entry_sha256": "4" * 64,
            "predecessor_interrupted_terminal_event_sha256": "5" * 64,
            "predecessor_no_replacement_read_sha256": "6" * 64,
        }
        return LIVE.CampaignLaunchInputs(
            authorization=snapshot(
                "authorization-v11",
                version=11,
                authorization_id="authorization-12",
                run_generation=12,
                live_generation=12,
                predecessor_live_generation=11,
                bindings=bindings,
            ),
            manifest=snapshot(
                "manifest-v8",
                version=8,
                manifest_id="manifest-12",
                manifest_sha256="7" * 64,
                authorization_id="authorization-12",
                candidate={"commit": "8" * 40, "tree": "9" * 40},
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
            predecessor_proof=interrupted,
            recovery_cause_evidence=snapshot("generation12-recovery-cause"),
            recovery_cause_source_analysis_bytes=b"generation12-source\n",
        )

    @staticmethod
    def paths(root: Path) -> dict[str, Path]:
        return {
            "output": root / "evidence.json",
            "authorization_state": root / "state.json",
            "steering_registry": root / "steering.json",
            "allocation_ledger": root / "ledger",
        }

    def test_only_v11_v8_v6_v6_is_operative(self) -> None:
        LIVE.require_operative_campaign_contract(11, 8, 6, 6)
        for observed in (
            (10, 7, 5, 5),
            (11, 7, 6, 6),
            (11, 8, 5, 6),
            (11, 8, 6, 5),
            (12, 8, 6, 6),
        ):
            with self.subTest(observed=observed), self.assertRaises(
                LIVE.AppServerError
            ):
                LIVE.require_operative_campaign_contract(*observed)

    def test_path_set_requires_complete_leaf_and_one_terminal_session(self) -> None:
        paths = {
            label: Path("/") / label
            for label in LIVE.GENERATION12_REQUIRED_PROOF_PATHS
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
        LIVE.require_generation12_proof_path_set(paths, **kwargs)
        cases = (
            {
                key: value
                for key, value in paths.items()
                if key != "interrupted-failed-predecessor-steering-registry"
            },
            {
                key: value
                for key, value in paths.items()
                if key != "interrupted-failed-predecessor-terminal-facts"
            },
            {
                key: value
                for key, value in paths.items()
                if key
                != "interrupted-failed-predecessor-recovery-steering-session"
            },
            {
                **paths,
                "interrupted-failed-predecessor-terminal-session-1": Path("/x"),
            },
            {
                **paths,
                "interrupted-failed-predecessor-contained-session-0": Path("/x"),
            },
        )
        for changed in cases:
            with self.subTest(changed=set(changed) ^ set(paths)), self.assertRaisesRegex(
                LIVE.AppServerError, "campaign-generation12-proof-path-set-invalid"
            ):
                LIVE.require_generation12_proof_path_set(changed, **kwargs)

    def test_source_set_is_complete_and_has_one_terminal_session(self) -> None:
        sources = LIVE.generation12_source_file_sha256s(self.inputs())
        required_immediate = set(LIVE.GENERATION12_INTERRUPTED_PROOF_PATHS)
        self.assertTrue(required_immediate.issubset(sources))
        terminal = {
            label
            for label in sources
            if label.startswith("interrupted-failed-predecessor-terminal-session")
        }
        self.assertEqual(
            terminal, {"interrupted-failed-predecessor-terminal-session"}
        )
        self.assertIn("preallocation-failed-predecessor-authorization", sources)
        self.assertIn("cause-evidence", sources)

    def test_launch_claim_v6_binds_every_immediate_source(self) -> None:
        inputs = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.paths(Path(temporary))
            payload = LIVE.campaign_launch_claim_payload_v6(inputs, **paths)
            self.assertEqual(payload["version"], 6)
            self.assertEqual(
                payload["operative_version_tuple"],
                {
                    "authorization_version": 11,
                    "manifest_version": 8,
                    "launch_claim_version": 6,
                    "validator_contract_version": 6,
                },
            )
            leaf = payload["successor_proof"]["interrupted_failed_predecessor"]
            self.assertEqual(leaf["terminal_session_count"], 1)
            self.assertFalse(leaf["accepting_completion"])
            first = LIVE.campaign_launch_claim_sha256(inputs, **paths)
            proof = inputs.predecessor_proof
            self.assertIsInstance(
                proof,
                LIVE.Version10InterruptedEmptyBoundaryPredecessorProofInputs,
            )
            for changed_proof in (
                replace(
                    proof,
                    steering_registry=snapshot("changed-steering-registry"),
                ),
                replace(proof, terminal_session_bytes=b"changed-terminal\n"),
                replace(
                    proof,
                    pre_mutation_adjudication=snapshot(
                        "changed-pre-mutation-adjudication"
                    ),
                ),
                replace(
                    proof,
                    pre_live_adjudication=snapshot(
                        "changed-pre-live-adjudication"
                    ),
                ),
                replace(
                    proof,
                    containment=snapshot("changed-v32-containment"),
                ),
                replace(
                    proof,
                    terminal_facts=snapshot("changed-terminal-facts"),
                ),
                replace(
                    proof,
                    generation11_runner_source_bytes=b"changed-runner-source\n",
                ),
                replace(
                    proof,
                    generation11_session_boundary_source_bytes=(
                        b"changed-session-boundary-source\n"
                    ),
                ),
                replace(
                    proof,
                    recovery_cause_analysis_bytes=(
                        b"changed-recovery-analysis\n"
                    ),
                ),
                replace(
                    proof,
                    recovery_steering_receipt=snapshot(
                        "changed-recovery-steering-receipt"
                    ),
                ),
                replace(
                    proof,
                    recovery_steering_session_bytes=(
                        b"changed-recovery-steering-session\n"
                    ),
                ),
            ):
                changed = self.inputs()
                changed.predecessor_proof = changed_proof
                self.assertNotEqual(
                    first, LIVE.campaign_launch_claim_sha256(changed, **paths)
                )

    def test_mixed_generation12_inputs_fail_closed(self) -> None:
        inputs = self.inputs()
        inputs.predecessor_proof = inputs.predecessor_proof.ancestor
        with self.assertRaisesRegex(
            LIVE.AppServerError, "campaign-generation12-proof-input-invalid"
        ):
            LIVE.require_generation12_launch_inputs(inputs)


if __name__ == "__main__":
    unittest.main()
