from __future__ import annotations

import copy
from dataclasses import replace
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generation8_live_launcher",
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


class Generation8LiveLauncherTests(unittest.TestCase):
    def inputs(self) -> LIVE.CampaignLaunchInputs:
        ancestor_cause = b"ancestor-authorization-cause\n"
        grandancestor_cause = b"grandancestor-authorization-cause\n"
        grandancestor = LIVE.HistoricalV4V1ProofInputs(
            authorization=snapshot("grandancestor-authorization"),
            manifest=snapshot("grandancestor-manifest"),
            authorization_state=snapshot("grandancestor-state"),
            failure_evidence=snapshot("grandancestor-failure"),
            original_containment=snapshot("grandancestor-original-containment"),
            containment=snapshot("grandancestor-containment"),
            allocation_ledger=snapshot("grandancestor-ledger"),
            allocation_audit_bytes=b"grandancestor-audit\n",
            cause_evidence=grandancestor_cause,
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
            authorization_cause_evidence=ancestor_cause,
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
            authorization_recovery_cause_source_analysis=(
                b"predecessor-recovery-source-analysis\n"
            ),
            outer_authority=snapshot("predecessor-outer"),
            independent_validation_receipt=snapshot("predecessor-validation"),
            independent_validation_session_bytes=(
                b"predecessor-validation-session\n"
            ),
            ancestor=ancestor,
            contained_session_bytes=(b"predecessor-contained-session\n",),
        )
        outputs = {
            "evidence_basename": "evidence.json",
            "authorization_state_basename": "state.json",
            "steering_registry_basename": "steering.json",
            "allocation_ledger_basename": "ledger",
        }
        return LIVE.CampaignLaunchInputs(
            authorization=snapshot(
                "authorization-v7",
                version=7,
                authorization_id="authorization-8",
                bindings={"validator_contract_sha256": "a" * 64},
            ),
            manifest=snapshot(
                "manifest-v4",
                version=4,
                manifest_id="manifest-8",
                manifest_sha256="b" * 64,
                authorization_id="authorization-8",
                candidate={"commit": "c" * 40, "tree": "d" * 40},
                outputs=outputs,
            ),
            outer_authority=snapshot("outer", authority_id="outer-8"),
            release_patch_bytes=b"release-patch\n",
            pre_mutation_receipt=snapshot(
                "pre-mutation", canonical_receipt_sha256="e" * 64
            ),
            pre_mutation_adjudication=snapshot("pre-mutation-adjudication"),
            pre_live_receipt=snapshot(
                "pre-live", canonical_receipt_sha256="f" * 64
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
                canonical_receipt_sha256="1" * 64,
                session_id="spark-session",
            ),
            spark_validation_session_path=Path("/trusted/spark-session.jsonl"),
            spark_validation_session_bytes=b"spark-validation-session\n",
            predecessor_proof=predecessor,
            recovery_cause_evidence=snapshot("generation8-recovery-cause"),
            recovery_cause_source_analysis_bytes=(
                b"generation8-recovery-source-analysis\n"
            ),
        )

    def test_old_pairs_are_historical_after_v11_v8_activation(self) -> None:
        LIVE.require_operative_campaign_contract(12, 8, 6, 6)
        for authorization_version, manifest_version in (
            (7, 4),
            (8, 5),
            (8, 4),
            (9, 5),
            (8, 6),
            (9, 6),
            (10, 7),
            (6, 3),
        ):
            with self.subTest(
                authorization=authorization_version, manifest=manifest_version
            ), self.assertRaises(LIVE.AppServerError):
                LIVE.require_operative_campaign_contract(
                    authorization_version, manifest_version
                )

    def test_fixed_proof_path_set_rejects_historical_or_missing_levels(self) -> None:
        paths = {label: Path("/") / label for label in LIVE.GENERATION8_REQUIRED_PROOF_PATHS}
        LIVE.require_generation8_proof_path_set(
            paths,
            predecessor_contained_sessions=1,
            ancestor_contained_sessions=1,
            grandancestor_contained_sessions=1,
        )
        for changed in (
            {key: value for key, value in paths.items() if key != "grandancestor-manifest"},
            {
                key: value
                for key, value in paths.items()
                if key != "grandancestor-authorization-cause-evidence"
            },
            {**paths, "ancestor-original-containment": Path("/legacy")},
        ):
            with self.assertRaisesRegex(
                LIVE.AppServerError, "generation8-proof-path-set-invalid"
            ):
                LIVE.require_generation8_proof_path_set(
                    changed,
                    predecessor_contained_sessions=1,
                    ancestor_contained_sessions=1,
                    grandancestor_contained_sessions=1,
                )

    def test_launch_claim_v2_binds_every_source_cause_session_and_model_ban(self) -> None:
        inputs = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "output": root / "evidence.json",
                "authorization_state": root / "state.json",
                "steering_registry": root / "steering.json",
                "allocation_ledger": root / "ledger",
            }
            payload = LIVE.campaign_launch_claim_payload(inputs, **paths)
            expected_sources = {
                **LIVE.generation8_private_source_snapshots(inputs),
                **LIVE.generation8_trusted_session_snapshots(inputs),
            }
            self.assertEqual(payload["version"], 2)
            self.assertEqual(
                payload["source_file_sha256s"],
                {
                    label: LIVE.sha256_bytes(raw)
                    for label, raw in sorted(expected_sources.items())
                },
            )
            self.assertEqual(
                payload["successor_proof"]["proof_dag"],
                ["v7/v4", "v6/v3", "v5/v2", "v4/v1"],
            )
            self.assertEqual(
                payload["outside_review"],
                {
                    "opus_evidence_raw_sha256": inputs.opus_review_evidence.raw_sha256,
                    "opus_adjudication_raw_sha256": inputs.opus_adjudication.raw_sha256,
                    "exact_model": "claude-opus-4-6",
                    "glm_5_2_used": False,
                    "model_synthesis_used": False,
                    "main_architect_decision": "go",
                },
            )
            self.assertTrue(
                payload["authority_semantics"][
                    "durable_one_shot_claim_is_launch_authority"
                ]
            )
            self.assertTrue(
                payload["authority_semantics"][
                    "bound_manifest_validation_is_evidence_only"
                ]
            )
            original = LIVE.campaign_launch_claim_sha256(inputs, **paths)
            changed_proof = replace(
                inputs.predecessor_proof,
                authorization_recovery_cause_source_analysis=b"changed\n",
            )
            changed_inputs = copy.copy(inputs)
            changed_inputs.predecessor_proof = changed_proof
            self.assertNotEqual(
                original,
                LIVE.campaign_launch_claim_sha256(
                    changed_inputs, **paths
                ),
            )
            changed_grandancestor = replace(
                inputs.predecessor_proof.ancestor.ancestor,
                contained_session_bytes=(b"changed-grandancestor-session\n",),
            )
            changed_ancestor = replace(
                inputs.predecessor_proof.ancestor, ancestor=changed_grandancestor
            )
            changed_inputs = copy.copy(inputs)
            changed_inputs.predecessor_proof = replace(
                inputs.predecessor_proof, ancestor=changed_ancestor
            )
            self.assertNotEqual(
                original,
                LIVE.campaign_launch_claim_sha256(
                    changed_inputs,
                    **paths,
                ),
            )

            for field, replacement in (
                ("ancestor", b"changed-ancestor-cause\n"),
                ("grandancestor", b"changed-grandancestor-cause\n"),
            ):
                if field == "ancestor":
                    changed_ancestor = replace(
                        inputs.predecessor_proof.ancestor,
                        authorization_cause_evidence=replacement,
                    )
                else:
                    changed_grandancestor = replace(
                        inputs.predecessor_proof.ancestor.ancestor,
                        cause_evidence=replacement,
                    )
                    changed_ancestor = replace(
                        inputs.predecessor_proof.ancestor,
                        ancestor=changed_grandancestor,
                    )
                changed_inputs = copy.copy(inputs)
                changed_inputs.predecessor_proof = replace(
                    inputs.predecessor_proof,
                    ancestor=changed_ancestor,
                )
                self.assertNotEqual(
                    original,
                    LIVE.campaign_launch_claim_sha256(changed_inputs, **paths),
                )

    def test_bound_gate_and_final_watermark_run_before_each_allocation(self) -> None:
        events: list[str] = []

        class FakeServer:
            def start_thread(self, _worktree: Path, **_kwargs: object):
                events.append("allocate")
                ordinal = events.count("allocate")
                return {
                    "thread": {"id": f"thread-{ordinal}", "turns": []},
                    "model": LIVE.EXACT_MODEL,
                }, 0.0

        def gate() -> dict[str, str]:
            events.append("gate")
            return {"validation": "evidence-only"}

        def final_watermark() -> None:
            events.append("watermark")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            integration = root / "integration"
            first = root / "first"
            second = root / "second"
            for path in (integration, first, second):
                path.mkdir()

            def fake_contract(request: dict[str, object], **_kwargs: object):
                return {"children": request["children"]}

            with mock.patch.object(
                LIVE, "validate_live_canary_manifest_gate", return_value=[]
            ), mock.patch.object(
                LIVE, "build_live_canary_pool_contract", side_effect=fake_contract
            ), mock.patch.object(LIVE, "PoolWorkspaceMonitor", return_value=object()):
                LIVE.build_pool_inputs(
                    FakeServer(),
                    {},
                    {"version": 4, "control_turn_id": LIVE.CONTROL_TURN_ID},
                    root=root,
                    integration=integration,
                    pool_name="generation8",
                    worktrees=[first, second],
                    mutable=False,
                    prompts=["one", "two"],
                    expected_tokens=["ONE", "TWO"],
                    pre_thread_start_check=gate,
                    pre_allocation_check=final_watermark,
                    expected_bound_manifest_validation={"expected": "receipt"},
                )
        self.assertEqual(
            events,
            [
                "gate",
                "watermark",
                "allocate",
                "gate",
                "watermark",
                "allocate",
            ],
        )


if __name__ == "__main__":
    unittest.main()
