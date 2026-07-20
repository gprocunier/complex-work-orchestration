from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from tests import test_generation11_live_launcher as LAUNCHER  # noqa: E402


def snapshot(value: dict) -> CONTRACTS.JsonArtifactSnapshot:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return CONTRACTS.JsonArtifactSnapshot(raw=raw, value=value)


class Generation11PreallocationContractTests(unittest.TestCase):
    def semantic_proof_fixture(
        self,
    ) -> tuple[
        CONTRACTS.Version9PreallocationFaultPredecessorProofInputs,
        dict,
        dict,
        dict,
    ]:
        prior_id = str(uuid.uuid4())
        prior_nonce = str(uuid.uuid4())
        outer_id = str(uuid.uuid4())
        launch_claim = "6" * 64
        candidate = {"commit": "a" * 40, "tree": "b" * 40}
        outputs = {
            "allocation_ledger_basename": "ledger.jsonl",
            "authorization_state_basename": "state.json",
            "evidence_basename": "evidence.json",
            "steering_registry_basename": "steering.json",
        }
        prior_authorization_value = {
            "authorization_id": prior_id,
            "version": 9,
            "run_generation": 10,
            "live_generation": 10,
            "predecessor_live_generation": 9,
            "canonical_authorization_sha256": "1" * 64,
            "bindings": {
                "campaign_nonce": prior_nonce,
                "outer_authority_id": outer_id,
                "origin_main_commit": "c" * 40,
                "guarded_primary_diff_sha256": "2" * 64,
                "validator_contract_sha256": "3" * 64,
                "predecessor_contained_session_family_sha256": "4" * 64,
                "predecessor_containment_file_sha256": "5" * 64,
                "predecessor_failure_evidence_file_sha256": "7" * 64,
                "predecessor_ancestor_lineage_sha256": "8" * 64,
            },
            "progress_gate": {
                "cause_evidence_sha256": "9" * 64,
                "predecessor_lineage_sha256": "d" * 64,
            },
            "supersession": {},
        }
        prior_authorization = snapshot(prior_authorization_value)
        prior_manifest = snapshot(
            {
                "version": 6,
                "manifest_id": str(uuid.uuid4()),
                "manifest_sha256": "e" * 64,
                "candidate": candidate,
                "outputs": outputs,
                "work_units": {
                    "epic_id": "epic",
                    "parent_work_unit_id": "parent",
                    "live_work_unit_id": "live",
                },
                "control_turn_id": "control",
                "release": {"patch_file_sha256": "f" * 64},
            }
        )
        state = snapshot(
            {
                "authorization_id": prior_id,
                "run_nonce": prior_nonce,
                "launch_claim_sha256": launch_claim,
                "state": "containment-only",
                "allowed_actions": ["inspect"],
                "revoked_actions": sorted(
                    {
                        "install",
                        "publish",
                        "push",
                        "relaunch",
                        "release-enable",
                        "replacement",
                        "retry",
                        "tracked-mutation",
                    }
                ),
                "state_sha256": "0" * 64,
            }
        )
        identity = {
            "authorization_id": prior_id,
            "run_generation": 10,
            "live_generation": 10,
            "campaign_nonce": prior_nonce,
        }
        claim_unsigned = {
            "claim_type": "cwo-native-live-campaign-global-claim",
            "version": 1,
            "identity": identity,
            "identity_sha256": CONTRACTS._domain_sha256(
                identity, domain="native-live-global-claim"
            ),
            "launch_claim_sha256": launch_claim,
            "outer_authority_id": outer_id,
            "candidate_commit": candidate["commit"],
            "candidate_tree": candidate["tree"],
            "output_paths": {
                "allocation_ledger": "/private/ledger.jsonl",
                "authorization_state": "/private/state.json",
                "evidence": "/private/evidence.json",
                "steering_registry": "/private/steering.json",
            },
            "claimed_at": "2026-07-18T12:00:00Z",
        }
        claim = snapshot(
            {
                **claim_unsigned,
                "canonical_claim_sha256": CONTRACTS._domain_sha256(
                    claim_unsigned, domain="native-live-global-claim-artifact"
                ),
            }
        )
        dummy = snapshot({"dummy": True})
        proof = CONTRACTS.Version9PreallocationFaultPredecessorProofInputs(
            authorization=prior_authorization,
            manifest=prior_manifest,
            authorization_state=state,
            failure_evidence=dummy,
            containment=dummy,
            global_claim=claim,
            authorization_marker=dummy,
            nonce_marker=dummy,
            scope_state=dummy,
            preflight=dummy,
            pre_mutation_receipt=dummy,
            pre_live_receipt=dummy,
            authorization_recovery_cause_evidence=dummy,
            authorization_recovery_cause_source_analysis=b"prior cause\n",
            outer_authority=snapshot(
                {
                    "authority_id": outer_id,
                    "canonical_outer_authority_sha256": "a" * 64,
                }
            ),
            independent_validation_receipt=dummy,
            independent_validation_session_bytes=b"validation session\n",
            ancestor=(
                LAUNCHER.Generation11LiveLauncherTests()
                .inputs()
                .predecessor_proof
                .ancestor
            ),
        )
        bindings = {
            "campaign_nonce": str(uuid.uuid4()),
            "predecessor_authorization_id": prior_id,
            "predecessor_authorization_file_sha256": prior_authorization.raw_sha256,
            "predecessor_authorization_canonical_sha256": (
                prior_authorization_value["canonical_authorization_sha256"]
            ),
            "predecessor_manifest_file_sha256": prior_manifest.raw_sha256,
            "predecessor_manifest_canonical_sha256": prior_manifest.value[
                "manifest_sha256"
            ],
            "predecessor_authorization_state_file_sha256": state.raw_sha256,
            "predecessor_authorization_state_canonical_sha256": state.value[
                "state_sha256"
            ],
            "predecessor_global_claim_file_sha256": claim.raw_sha256,
            "predecessor_global_claim_canonical_sha256": claim.value[
                "canonical_claim_sha256"
            ],
            "predecessor_launch_claim_sha256": launch_claim,
            "predecessor_ancestor_lineage_sha256": "d" * 64,
        }
        progress = {
            "predecessor_candidate_commit": candidate["commit"],
            "predecessor_candidate_tree": candidate["tree"],
        }
        supersession = {
            "prior_authorization_id": prior_id,
            "prior_terminal_state": "containment-only",
            "prior_live_generation": 10,
            "prior_allocations": 0,
            "prior_ambiguities": 0,
            "reuse_resume_retry_substitution_salvage_bridge": False,
        }
        return proof, bindings, progress, supersession

    def recovery_fixture(
        self,
        *,
        root_overrides: dict | None = None,
        pre_live_authorization_id: str | None = None,
    ) -> tuple[
        CONTRACTS.Version9PreallocationFaultPredecessorProofInputs,
        dict,
        dict,
        bytes,
        dict,
    ]:
        prior_id = str(uuid.uuid4())
        manifest_id = str(uuid.uuid4())
        source = b"generation-11 recovery source analysis\n"
        source_sha256 = hashlib.sha256(source).hexdigest()
        outer = snapshot(
            {
                "authority_id": str(uuid.uuid4()),
                "canonical_outer_authority_sha256": "1" * 64,
            }
        )
        prior_authorization = snapshot(
            {
                "authorization_id": prior_id,
                "live_generation": 10,
            }
        )
        prior_manifest = snapshot({"manifest_id": manifest_id})
        failure = snapshot(
            {
                "evidence_sha256": "2" * 64,
                "failure_code": "pre-mutation-steering-binding-invalid",
                "failure_message_sha256": "3" * 64,
            }
        )
        pre_mutation = snapshot(
            {
                "authorization_id": outer.value["authority_id"],
                "authorization_sha256": outer.raw_sha256,
            }
        )
        pre_live = snapshot(
            {
                "authorization_id": pre_live_authorization_id or prior_id,
                "authorization_sha256": prior_authorization.raw_sha256,
            }
        )
        root_cause = {
            "failure_class": "preflight-live-steering-authority-binding-gap",
            "failure_code": failure.value["failure_code"],
            "independent_reproduction": True,
            "pre_live_binding_correct": True,
            "pre_mutation_bound_authority_file_sha256": (
                pre_mutation.value["authorization_sha256"]
            ),
            "pre_mutation_bound_authority_id": pre_mutation.value[
                "authorization_id"
            ],
            "required_inner_authorization_file_sha256": (
                prior_authorization.raw_sha256
            ),
            "required_inner_authorization_id": prior_id,
            "source_analysis_sha256": source_sha256,
        }
        root_cause.update(root_overrides or {})
        containment_value = {
            "root_cause": root_cause,
            "canonical_recovery_sha256": "",
        }
        containment_value["canonical_recovery_sha256"] = (
            CONTRACTS.canonical_sha256(
                {"root_cause": root_cause}
            )
        )
        containment = snapshot(containment_value)
        ancestor = LAUNCHER.Generation11LiveLauncherTests().inputs().predecessor_proof.ancestor
        dummy = snapshot({"dummy": True})
        proof = CONTRACTS.Version9PreallocationFaultPredecessorProofInputs(
            authorization=prior_authorization,
            manifest=prior_manifest,
            authorization_state=dummy,
            failure_evidence=failure,
            containment=containment,
            global_claim=dummy,
            authorization_marker=dummy,
            nonce_marker=dummy,
            scope_state=dummy,
            preflight=dummy,
            pre_mutation_receipt=pre_mutation,
            pre_live_receipt=pre_live,
            authorization_recovery_cause_evidence=dummy,
            authorization_recovery_cause_source_analysis=b"prior cause\n",
            outer_authority=outer,
            independent_validation_receipt=dummy,
            independent_validation_session_bytes=b"validation session\n",
            ancestor=ancestor,
        )
        evidence = {
            "evidence_type": "cwo-native-live-campaign-cause-evidence",
            "version": 1,
            "schema": "schemas/native-live-campaign-cause-evidence.schema.json",
            "evidence_id": str(uuid.uuid4()),
            "recorded_at": "2026-07-18T12:00:00Z",
            "failed_authorization_id": prior_id,
            "failed_manifest_id": manifest_id,
            "live_generation": 10,
            "failure_evidence_file_sha256": failure.raw_sha256,
            "failure_evidence_canonical_sha256": failure.value[
                "evidence_sha256"
            ],
            "containment_file_sha256": containment.raw_sha256,
            "containment_canonical_sha256": containment.value[
                "canonical_recovery_sha256"
            ],
            "failure_class": "preflight-live-steering-authority-binding-gap",
            "failure_message_sha256": failure.value[
                "failure_message_sha256"
            ],
            "falsifiable_cause": "preclaim validates full inner steering",
            "source_analysis_sha256": source_sha256,
            "repair_commit": "a" * 40,
            "repair_tree": "b" * 40,
            "focused_tests_passed": 1,
            "repository_validation_passed": True,
            "compileall_passed": True,
            "diff_check_passed": True,
            "canonical_cause_evidence_sha256": "",
        }
        evidence["canonical_cause_evidence_sha256"] = (
            CONTRACTS.canonical_sha256(
                {
                    key: value
                    for key, value in evidence.items()
                    if key != "canonical_cause_evidence_sha256"
                }
            )
        )
        evidence_snapshot = snapshot(evidence)
        bindings = {
            "recovery_cause_evidence_file_sha256": evidence_snapshot.raw_sha256,
            "recovery_cause_evidence_canonical_sha256": evidence[
                "canonical_cause_evidence_sha256"
            ],
            "checkpoint_commit": evidence["repair_commit"],
            "checkpoint_tree": evidence["repair_tree"],
        }
        progress = {
            "cause_evidence_sha256": evidence_snapshot.raw_sha256,
            "predecessor_failure_class": evidence["failure_class"],
            "new_falsifiable_cause": evidence["falsifiable_cause"],
        }
        return proof, evidence, bindings, source, progress

    def test_v10_v7_schemas_match_strict_runtime_field_sets(self) -> None:
        authorization = json.loads(
            (ROOT / CONTRACTS.AUTHORIZATION_SCHEMA_V10).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (ROOT / CONTRACTS.MANIFEST_SCHEMA_V7).read_text(encoding="utf-8")
        )
        self.assertFalse(authorization["additionalProperties"])
        self.assertFalse(manifest["additionalProperties"])
        self.assertEqual(set(authorization["required"]), CONTRACTS.AUTHORIZATION_FIELDS)
        self.assertEqual(set(manifest["required"]), CONTRACTS.MANIFEST_FIELDS)
        self.assertEqual(
            set(authorization["$defs"]["bindings"]["required"]),
            CONTRACTS.BINDING_FIELDS_V10,
        )

    def test_malformed_nested_v10_v7_fields_return_errors_not_exceptions(self) -> None:
        for field in ("bindings", "mandatory_gates", "progress_gate"):
            errors = CONTRACTS.validate_full_auto_authorization(
                {"version": 10, field: "wrong-type"}
            )
            self.assertTrue(any(field.replace("_", "-") in item for item in errors))
        errors = CONTRACTS.validate_campaign_manifest(
            {"version": 7, "predecessor": "wrong-type"},
            authorization={"version": 10, "bindings": {}},
        )
        self.assertTrue(any("predecessor" in item for item in errors))

    def test_v4_recovery_cause_shape_accepts_and_root_bindings_reject(self) -> None:
        proof, evidence, bindings, source, progress = self.recovery_fixture()
        self.assertEqual(
            CONTRACTS._validate_recovery_cause_evidence(
                evidence,
                raw_sha256=bindings["recovery_cause_evidence_file_sha256"],
                bindings=bindings,
                progress=progress,
                predecessor=proof,
                source_analysis_bytes=source,
            ),
            [],
        )
        cases = (
            {"failure_code": "wrong"},
            {"required_inner_authorization_id": str(uuid.uuid4())},
            {"required_inner_authorization_file_sha256": "4" * 64},
            {"pre_mutation_bound_authority_id": str(uuid.uuid4())},
            {"source_analysis_sha256": "5" * 64},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                changed = self.recovery_fixture(root_overrides=overrides)
                changed_proof, changed_evidence, changed_bindings, changed_source, changed_progress = changed
                errors = CONTRACTS._validate_recovery_cause_evidence(
                    changed_evidence,
                    raw_sha256=changed_bindings[
                        "recovery_cause_evidence_file_sha256"
                    ],
                    bindings=changed_bindings,
                    progress=changed_progress,
                    predecessor=changed_proof,
                    source_analysis_bytes=changed_source,
                )
                self.assertIn(
                    "authorization-recovery-cause-evidence-binding-invalid",
                    errors,
                )

    def test_malformed_current_and_nested_generations_never_raise(self) -> None:
        proof = LAUNCHER.Generation11LiveLauncherTests().inputs().predecessor_proof
        for malformed in ({}, [], "10", True, None):
            with self.subTest(current=malformed):
                errors = CONTRACTS.validate_full_auto_authorization(
                    {"version": 10, "predecessor_live_generation": malformed},
                    predecessor_proof=proof,
                    recovery_cause_evidence=snapshot({}),
                    recovery_cause_source_analysis=b"source\n",
                )
                self.assertTrue(errors)
        for malformed in ({}, [], "9", True, None):
            with self.subTest(ancestor=malformed):
                changed_authorization = snapshot(
                    {
                        **proof.authorization.value,
                        "predecessor_live_generation": malformed,
                    }
                )
                changed = replace(proof, authorization=changed_authorization)
                with tempfile.TemporaryDirectory() as temporary:
                    errors = CONTRACTS.validate_full_auto_authorization(
                        {"version": 10, "predecessor_live_generation": 10},
                        predecessor_proof=changed,
                        recovery_cause_evidence=snapshot({}),
                        recovery_cause_source_analysis=b"source\n",
                        repo_root=Path(temporary),
                    )
                self.assertTrue(errors)

    def test_preallocation_leaf_semantics_reject_resealed_cross_binding_drift(
        self,
    ) -> None:
        proof, bindings, progress, supersession = self.semantic_proof_fixture()
        patches = (
            mock.patch.object(
                CONTRACTS, "_validate_full_auto_authorization_v9", return_value=[]
            ),
            mock.patch.object(
                CONTRACTS, "_validate_campaign_manifest_v6", return_value=[]
            ),
            mock.patch.object(
                CONTRACTS,
                "_validate_independent_validation_session_snapshot",
                return_value=[],
            ),
            mock.patch.object(CONTRACTS, "validate_authorization_state", return_value=[]),
            mock.patch.object(CONTRACTS, "validate_steering_receipt", return_value=[]),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            baseline = CONTRACTS._validate_v9_preallocation_fault_predecessor_proof(
                bindings=bindings,
                progress=progress,
                supersession=supersession,
                predecessor_live_generation=10,
                proof=proof,
                repo_root=None,
            )
            self.assertNotIn(
                "authorization-predecessor-v9-global-claim-binding-invalid",
                baseline,
            )
            self.assertNotIn(
                "authorization-predecessor-v9-state-binding-invalid", baseline
            )

            changed_claim_unsigned = {
                key: value
                for key, value in proof.global_claim.value.items()
                if key != "canonical_claim_sha256"
            }
            changed_claim_unsigned["launch_claim_sha256"] = "7" * 64
            changed_claim = snapshot(
                {
                    **changed_claim_unsigned,
                    "canonical_claim_sha256": CONTRACTS._domain_sha256(
                        changed_claim_unsigned,
                        domain="native-live-global-claim-artifact",
                    ),
                }
            )
            changed_claim_proof = replace(proof, global_claim=changed_claim)
            changed_claim_bindings = {
                **bindings,
                "predecessor_global_claim_file_sha256": changed_claim.raw_sha256,
                "predecessor_global_claim_canonical_sha256": (
                    changed_claim.value["canonical_claim_sha256"]
                ),
            }
            claim_errors = (
                CONTRACTS._validate_v9_preallocation_fault_predecessor_proof(
                    bindings=changed_claim_bindings,
                    progress=progress,
                    supersession=supersession,
                    predecessor_live_generation=10,
                    proof=changed_claim_proof,
                    repo_root=None,
                )
            )
            self.assertIn(
                "authorization-predecessor-v9-global-claim-binding-invalid",
                claim_errors,
            )

            changed_state_value = {
                **proof.authorization_state.value,
                "launch_claim_sha256": "7" * 64,
                "state_sha256": "8" * 64,
            }
            changed_state = snapshot(changed_state_value)
            changed_state_proof = replace(
                proof, authorization_state=changed_state
            )
            changed_state_bindings = {
                **bindings,
                "predecessor_authorization_state_file_sha256": (
                    changed_state.raw_sha256
                ),
                "predecessor_authorization_state_canonical_sha256": (
                    changed_state.value["state_sha256"]
                ),
            }
            state_errors = (
                CONTRACTS._validate_v9_preallocation_fault_predecessor_proof(
                    bindings=changed_state_bindings,
                    progress=progress,
                    supersession=supersession,
                    predecessor_live_generation=10,
                    proof=changed_state_proof,
                    repo_root=None,
                )
            )
            self.assertIn(
                "authorization-predecessor-v9-state-binding-invalid",
                state_errors,
            )

    def test_validator_contract_v5_adds_v10_v7_without_changing_v4(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V5:
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
                    "validator-v5",
                ],
                cwd=root,
                check=True,
            )
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            self.assertNotEqual(
                CONTRACTS.validator_contract_sha256_v4(root, tree),
                CONTRACTS.validator_contract_sha256_v5(root, tree),
            )
            subprocess.run(
                [
                    "git",
                    "rm",
                    "-q",
                    "schemas/full-auto-run-authorization-v10.schema.json",
                ],
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
                    "remove-v10",
                ],
                cwd=root,
                check=True,
            )
            changed_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            with self.assertRaisesRegex(
                ValueError, "validator-contract-path-invalid"
            ):
                CONTRACTS.validator_contract_sha256_v5(root, changed_tree)


if __name__ == "__main__":
    unittest.main()
