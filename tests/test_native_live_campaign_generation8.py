from __future__ import annotations

from dataclasses import replace
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
import test_run_native_pool_live_canaries as legacy_tests  # noqa: E402


LIVE = legacy_tests.LIVE


class Generation8FiniteDagContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = legacy_tests.FullAutoAuthorizationLauncherTests(
            methodName="runTest"
        )
        # The operative launcher intentionally imports only v2. Its historical
        # fixture helper still constructs v6/v3, so bind that helper explicitly
        # to the frozen v1 API without reopening an operative fallback.
        LIVE.VALIDATOR_CONTRACT_PATHS = CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1
        LIVE.validator_contract_sha256 = CONTRACTS.validator_contract_sha256

    def _snapshot(self, value: dict) -> CONTRACTS.JsonArtifactSnapshot:
        return self.helper.json_snapshot(value)

    def _seal(self, value: dict, field: str) -> dict:
        return self.helper.seal_field(value, field)

    def _contained_session(
        self, session_id: str, turn_id: str
    ) -> bytes:
        records = (
            {
                "type": "session_meta",
                "payload": {"id": session_id, "session_id": session_id},
            },
            {
                "type": "event_msg",
                "payload": {"type": "task_started", "turn_id": turn_id},
            },
            {
                "type": "event_msg",
                "payload": {"type": "turn_aborted", "turn_id": turn_id},
            },
        )
        return b"".join(
            json.dumps(
                item, sort_keys=True, separators=(",", ":")
            ).encode()
            + b"\n"
            for item in records
        )

    def _version6_failure_proof(
        self,
        root: Path,
        generation7: dict[str, object],
        ancestor: CONTRACTS.Version5PredecessorProofInputs,
    ) -> CONTRACTS.Version6PredecessorProofInputs:
        authorization = generation7["authorization"]
        manifest = generation7["manifest"]
        authorization_snapshot = generation7["authorization_snapshot"]
        manifest_snapshot = generation7["manifest_snapshot"]
        assert isinstance(authorization, dict)
        assert isinstance(manifest, dict)
        assert isinstance(
            authorization_snapshot, CONTRACTS.JsonArtifactSnapshot
        )
        assert isinstance(manifest_snapshot, CONTRACTS.JsonArtifactSnapshot)

        state_directory = root / (".v6-state-" + uuid.uuid4().hex)
        state_store = LIVE.CanaryAuthorizationStore(state_directory / "state.json")
        state_store.initialize(
            LIVE.new_authorization_state(
                authorization_id=authorization["authorization_id"],
                run_nonce=authorization["bindings"]["campaign_nonce"],
                now="2026-07-17T14:10:00Z",
            )
        )
        state_store.transition(
            "containment-only",
            reason="synthetic-v3-context-loss",
            now="2026-07-17T14:11:00Z",
        )
        state_snapshot = self.helper.file_snapshot(state_store.path)

        ledger_directory = root / (".v6-ledger-" + uuid.uuid4().hex)
        ledger = LIVE.NativeLiveAllocationLedgerStore(ledger_directory)
        reviews = manifest["reviews"]
        release = manifest["release"]
        ledger.initialize(
            {
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.35",
                "authorization_id": authorization["authorization_id"],
                "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                "authorization_canonical_sha256": authorization[
                    "canonical_authorization_sha256"
                ],
                "campaign_manifest_sha256": manifest["manifest_sha256"],
                "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                "live_generation": 7,
                "predecessor_generation": 6,
                "candidate_commit": manifest["candidate"]["commit"],
                "candidate_tree": manifest["candidate"]["tree"],
                "origin_main_commit": manifest["candidate"]["origin_main_commit"],
                "guarded_primary_diff_sha256": manifest["candidate"][
                    "guarded_primary_diff_sha256"
                ],
                "predecessor_containment_sha256": authorization["bindings"][
                    "predecessor_containment_canonical_sha256"
                ],
                "frozen_release_patch_sha256": release["patch_file_sha256"],
                "pre_mutation_steering_receipt_sha256": reviews[
                    "pre_mutation_receipt_canonical_sha256"
                ],
                "pre_live_steering_receipt_sha256": reviews[
                    "pre_live_receipt_canonical_sha256"
                ],
                "opus_review_sha256": reviews["opus_evidence_file_sha256"],
                "certification_policy_sha256": "c" * 64,
                "controller_identity": {
                    "pid": 1,
                    "start_ticks": 1,
                    "boot_id_sha256": "d" * 64,
                },
                "connection_epoch_sha256": "e" * 64,
                "retention_class": "private-local-until-bead-closure",
                "expected_roles": list(LIVE.EXPECTED_ROLES),
            },
            version=2,
        )
        allocation_intent_id = ledger.allocation_intent(
            "capability-calibration"
        )
        session_id = str(uuid.uuid4())
        turn_id = str(uuid.uuid4())
        ledger.bind_thread(allocation_intent_id, session_id)
        turn_intent_id = ledger.turn_intent(session_id)
        ledger.bind_turn(session_id, turn_intent_id, turn_id)
        ledger.record_lifecycle(
            session_id, "interrupt-observed", "interrupt-request-accepted"
        )
        ledger.record_lifecycle(
            session_id, "archive-observed", "archive-request-accepted"
        )
        ledger.bind_certification("b" * 64)
        ledger.record_containment_audit(
            session_id,
            outcome="already-contained",
            evidence={"contained": True, "already_contained": True},
        )
        ledger_snapshot = self.helper.file_snapshot(ledger.path)
        allocation_audit_bytes = ledger.audit_file.read_bytes()
        ledger_summary = ledger.summary()
        containment_summary = {
            "allocated_count": 1,
            "identified_thread_count": 1,
            "interrupted_count": 0,
            "archived_count": 0,
            "already_contained_count": 1,
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
            "ambiguous_count": 0,
            "all_contained": True,
            "ledger_consistent": True,
            "ledger_error_sha256": [],
        }
        failure_message_sha256 = LIVE.sha256_text(
            "campaign-manifest-v3-authorization-missing"
        )
        failure = self._seal(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": "complex-work-orchestration-18w",
                "work_unit_id": "complex-work-orchestration-18w.6.35",
                "control_turn_id": LIVE.CONTROL_TURN_ID,
                "started_at": "2026-07-17T14:09:00Z",
                "failed_at": "2026-07-17T14:12:00Z",
                "exact_model": LIVE.EXACT_MODEL,
                "campaign_bindings": {
                    "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                    "manifest_file_sha256": manifest_snapshot.raw_sha256,
                    "manifest_sha256": manifest["manifest_sha256"],
                    "candidate_commit": manifest["candidate"]["commit"],
                    "candidate_tree": manifest["candidate"]["tree"],
                    "spark_validation_session_file_sha256": LIVE.sha256_bytes(
                        generation7["session_raw"]
                    ),
                },
                "steering_consumptions": {},
                "allocation_ledger": {"available": True, **ledger_summary},
                "failure_class": "AppServerError",
                "failure_code": "campaign-manifest-v3-authorization-missing",
                "failure_message_sha256": failure_message_sha256,
                "first_protected_fault": None,
                "containment": containment_summary,
                "authorization_state_sha256": state_snapshot.value[
                    "state_sha256"
                ],
                "release_gate_passed": False,
                "validation_outcome": "rejected",
                "no_resume_or_salvage": True,
                "glm_5_2_used": False,
                "model_synthesis_used": False,
            },
            "evidence_sha256",
        )
        failure_snapshot = self._snapshot(failure)
        contained_session_bytes = self._contained_session(session_id, turn_id)
        falsifiable_cause = (
            "the pool renderer lost the full v3 authorization proof context"
        )
        containment = self._seal(
            {
                "schema": "cwo-live-campaign-containment-recovery:v2",
                "bead_id": "complex-work-orchestration-18w.6.35",
                "recorded_at": "2026-07-17T14:13:00Z",
                "failed_authorization": {
                    "authorization_id": authorization["authorization_id"],
                    "campaign_nonce": authorization["bindings"]["campaign_nonce"],
                    "canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "file_sha256": authorization_snapshot.raw_sha256,
                    "live_generation": 7,
                },
                "failed_manifest": {
                    "canonical_sha256": manifest["manifest_sha256"],
                    "file_sha256": manifest_snapshot.raw_sha256,
                    "manifest_id": manifest["manifest_id"],
                },
                "failed_evidence": {
                    "canonical_sha256": failure["evidence_sha256"],
                    "file_sha256": failure_snapshot.raw_sha256,
                    "authorization_state_canonical_sha256": state_snapshot.value[
                        "state_sha256"
                    ],
                    "authorization_state_file_sha256": state_snapshot.raw_sha256,
                },
                "root_cause": {
                    "exception_class": "AppServerError",
                    "failure_class": "v3-full-context-validation-loss",
                    "falsifiable_cause": falsifiable_cause,
                    "independent_reproduction": True,
                    "message": "campaign-manifest-v3-authorization-missing",
                    "message_sha256": failure_message_sha256,
                },
                "session_accounting": [
                    {
                        "session_id": session_id,
                        "active_match_count": 0,
                        "archive_match_count": 1,
                        "archived_session_file_sha256": LIVE.sha256_bytes(
                            contained_session_bytes
                        ),
                    }
                ],
                "allocation_ledger": {
                    "allocated_roles": ["capability-calibration"],
                    "allocation_intent_count": 1,
                    "audit_file_sha256": LIVE.sha256_bytes(
                        allocation_audit_bytes
                    ),
                    "head_entry_sha256": ledger_summary["head_entry_sha256"],
                    "ledger_file_sha256": ledger_snapshot.raw_sha256,
                    "sequence": ledger_summary["sequence"],
                    "state_sha256": ledger_summary["state_sha256"],
                    "thread_bound_count": 1,
                    "turn_bound_count": 1,
                    "turn_intent_count": 1,
                    "unresolved_allocation_intent_count": 0,
                    "unresolved_turn_intent_count": 0,
                    "validation_errors": [],
                },
                "containment": containment_summary,
                "control_plane_recheck": {
                    "authorization_state_validation_errors": [],
                    "campaign_process_alive": False,
                    "controller_pid": 1,
                    "disposable_workspace_present": False,
                    "evidence_canonical_hash_valid": True,
                    "isolated_checkout_head": manifest["candidate"]["commit"],
                    "isolated_checkout_tracked_clean": True,
                    "isolated_checkout_tree": manifest["candidate"]["tree"],
                    "operative_dispatch_authorized": False,
                    "origin_main_commit": manifest["candidate"][
                        "origin_main_commit"
                    ],
                    "protected_primary_diff_sha256": manifest["candidate"][
                        "guarded_primary_diff_sha256"
                    ],
                    "release_policy_status": "canary-gated",
                },
                "disposition": {
                    "authorization_state": "containment-only",
                    "outer_full_auto_recovery_permitted": True,
                    "release_gate_passed": False,
                    "requires_fresh_live_generation": 8,
                    "requires_validated_candidate_repair": True,
                    "reuse_resume_retry_substitution_salvage_bridge": False,
                },
            },
            "canonical_recovery_sha256",
        )
        return CONTRACTS.Version6PredecessorProofInputs(
            authorization=authorization_snapshot,
            manifest=manifest_snapshot,
            authorization_state=state_snapshot,
            failure_evidence=failure_snapshot,
            containment=self._snapshot(containment),
            allocation_ledger=ledger_snapshot,
            allocation_audit_bytes=allocation_audit_bytes,
            authorization_recovery_cause_evidence=generation7[
                "cause_snapshot"
            ],
            authorization_recovery_cause_source_analysis=generation7[
                "cause_source_analysis"
            ],
            outer_authority=generation7["outer_snapshot"],
            independent_validation_receipt=generation7["receipt_snapshot"],
            independent_validation_session_bytes=generation7["session_raw"],
            ancestor=ancestor,
            contained_session_bytes=(contained_session_bytes,),
        )

    def _reseal_v7_authorization(self, value: dict) -> None:
        bindings = value["bindings"]
        progress = value["progress_gate"]
        progress["predecessor_lineage_sha256"] = CONTRACTS.canonical_sha256(
            CONTRACTS._predecessor_lineage_v7(
                bindings, progress, value["predecessor_live_generation"]
            )
        )
        progress["independent_validation_binding_sha256"] = (
            CONTRACTS.canonical_sha256(
                CONTRACTS._independent_validation_binding(value, progress)
            )
        )
        progress.pop("qualification_sha256", None)
        progress["qualification_sha256"] = CONTRACTS.canonical_sha256(progress)
        value.pop("canonical_authorization_sha256", None)
        value["canonical_authorization_sha256"] = CONTRACTS.canonical_sha256(
            value
        )

    def _manifest_predecessor(self, authorization: dict) -> dict:
        bindings = authorization["bindings"]
        progress = authorization["progress_gate"]
        return {
            "authorization_id": bindings["predecessor_authorization_id"],
            "authorization_file_sha256": bindings[
                "predecessor_authorization_file_sha256"
            ],
            "authorization_canonical_sha256": bindings[
                "predecessor_authorization_canonical_sha256"
            ],
            "manifest_file_sha256": bindings["predecessor_manifest_file_sha256"],
            "manifest_canonical_sha256": bindings[
                "predecessor_manifest_canonical_sha256"
            ],
            "authorization_state_file_sha256": bindings[
                "predecessor_authorization_state_file_sha256"
            ],
            "authorization_state_canonical_sha256": bindings[
                "predecessor_authorization_state_canonical_sha256"
            ],
            "candidate_commit": progress["predecessor_candidate_commit"],
            "candidate_tree": progress["predecessor_candidate_tree"],
            "lineage_sha256": progress["predecessor_lineage_sha256"],
            "failure_evidence_file_sha256": bindings[
                "predecessor_failure_evidence_file_sha256"
            ],
            "failure_evidence_canonical_sha256": bindings[
                "predecessor_failure_evidence_canonical_sha256"
            ],
            "containment_file_sha256": bindings[
                "predecessor_containment_file_sha256"
            ],
            "containment_canonical_sha256": bindings[
                "predecessor_containment_canonical_sha256"
            ],
            "recovery_cause_evidence_file_sha256": bindings[
                "recovery_cause_evidence_file_sha256"
            ],
            "recovery_cause_evidence_canonical_sha256": bindings[
                "recovery_cause_evidence_canonical_sha256"
            ],
            "allocation_ledger_file_sha256": bindings[
                "predecessor_allocation_ledger_file_sha256"
            ],
            "allocation_ledger_state_sha256": bindings[
                "predecessor_allocation_ledger_state_sha256"
            ],
            "allocation_audit_file_sha256": bindings[
                "predecessor_allocation_audit_file_sha256"
            ],
            "ancestor_lineage_sha256": bindings[
                "predecessor_ancestor_lineage_sha256"
            ],
            "validator_contract_sha256": bindings["validator_contract_sha256"],
        }

    def _generation8_successor(
        self,
        root: Path,
        predecessor: CONTRACTS.Version6PredecessorProofInputs,
    ) -> dict[str, object]:
        (root / "generation8-repair.txt").write_text("repair", encoding="utf-8")
        subprocess.run(
            ["git", "add", "generation8-repair.txt"], cwd=root, check=True
        )
        subprocess.run(
            ["git", "commit", "-qm", "generation eight repair"],
            cwd=root,
            check=True,
        )
        for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        subprocess.run(
            ["git", "add", *CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "install generation eight contract"],
            cwd=root,
            check=True,
        )
        checkpoint = LIVE.run_git(root, "rev-parse", "HEAD")
        checkpoint_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
        validator_sha256 = CONTRACTS.validator_contract_sha256_v2(
            root, checkpoint_tree
        )

        prior_authorization = predecessor.authorization.value
        prior_manifest = predecessor.manifest.value
        prior_state = predecessor.authorization_state.value
        prior_failure = predecessor.failure_evidence.value
        prior_containment = predecessor.containment.value
        prior_ledger = predecessor.allocation_ledger.value
        authorization = json.loads(json.dumps(prior_authorization))
        authorization.update(
            {
                "version": 7,
                "schema": "schemas/full-auto-run-authorization-v7.schema.json",
                "authorization_id": str(uuid.uuid4()),
                "run_generation": 13,
                "live_generation": 8,
                "predecessor_live_generation": 7,
                "issued_at": "2026-07-17T16:00:00Z",
            }
        )
        authorization["scope"]["ordered_work_units"] = [
            "complex-work-orchestration-18w.6.35",
            "complex-work-orchestration-18w.6.36",
            "complex-work-orchestration-18w.7",
        ]
        bindings = authorization["bindings"]
        bindings.update(
            {
                "checkpoint_commit": checkpoint,
                "checkpoint_tree": checkpoint_tree,
                "campaign_nonce": str(uuid.uuid4()),
                "predecessor_authorization_id": prior_authorization[
                    "authorization_id"
                ],
                "predecessor_authorization_file_sha256": predecessor.authorization.raw_sha256,
                "predecessor_authorization_canonical_sha256": prior_authorization[
                    "canonical_authorization_sha256"
                ],
                "predecessor_manifest_file_sha256": predecessor.manifest.raw_sha256,
                "predecessor_manifest_canonical_sha256": prior_manifest[
                    "manifest_sha256"
                ],
                "predecessor_authorization_state_file_sha256": predecessor.authorization_state.raw_sha256,
                "predecessor_authorization_state_canonical_sha256": prior_state[
                    "state_sha256"
                ],
                "predecessor_failure_evidence_file_sha256": predecessor.failure_evidence.raw_sha256,
                "predecessor_failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "predecessor_containment_file_sha256": predecessor.containment.raw_sha256,
                "predecessor_containment_canonical_sha256": prior_containment[
                    "canonical_recovery_sha256"
                ],
                "predecessor_allocation_ledger_file_sha256": predecessor.allocation_ledger.raw_sha256,
                "predecessor_allocation_ledger_state_sha256": prior_ledger[
                    "state_sha256"
                ],
                "predecessor_allocation_audit_file_sha256": LIVE.sha256_bytes(
                    predecessor.allocation_audit_bytes
                ),
                "predecessor_ancestor_lineage_sha256": prior_authorization[
                    "progress_gate"
                ]["predecessor_lineage_sha256"],
                "validator_contract_sha256": validator_sha256,
                "outer_authority_id": str(uuid.uuid4()),
                "backup_ref": "refs/heads/backup/test-generation-eight",
            }
        )
        authorization["supersession"].update(
            {
                "prior_authorization_id": prior_authorization[
                    "authorization_id"
                ],
                "prior_terminal_state": "containment-only",
                "prior_live_generation": 7,
                "prior_allocations": 1,
                "prior_ambiguities": 0,
                "prior_allowed_actions": 0,
            }
        )
        progress = authorization["progress_gate"]
        root_cause = prior_containment["root_cause"]
        progress.update(
            {
                "predecessor_failure_class": root_cause["failure_class"],
                "predecessor_failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "predecessor_candidate_commit": prior_manifest["candidate"][
                    "commit"
                ],
                "predecessor_candidate_tree": prior_manifest["candidate"]["tree"],
                "new_falsifiable_cause": root_cause["falsifiable_cause"],
                "repair_commit": checkpoint,
                "repair_tree": checkpoint_tree,
                "independent_validation_session_id": str(uuid.uuid4()),
                "independent_validation_completed_at": "2026-07-17T15:59:00Z",
                "same_fault_without_new_evidence": False,
                "one_active_inner_campaign": True,
                "arbitrary_generation_cap": False,
                "fresh_exact_sol_pre_live_required": True,
            }
        )
        source_analysis = b"full-context manifest validation source analysis\n"
        cause = self._seal(
            {
                "evidence_type": "cwo-native-live-campaign-cause-evidence",
                "version": 1,
                "schema": "schemas/native-live-campaign-cause-evidence.schema.json",
                "evidence_id": str(uuid.uuid4()),
                "recorded_at": "2026-07-17T15:58:00Z",
                "failed_authorization_id": prior_authorization[
                    "authorization_id"
                ],
                "failed_manifest_id": prior_manifest["manifest_id"],
                "live_generation": 7,
                "failure_evidence_file_sha256": predecessor.failure_evidence.raw_sha256,
                "failure_evidence_canonical_sha256": prior_failure[
                    "evidence_sha256"
                ],
                "containment_file_sha256": predecessor.containment.raw_sha256,
                "containment_canonical_sha256": prior_containment[
                    "canonical_recovery_sha256"
                ],
                "failure_class": root_cause["failure_class"],
                "failure_message_sha256": prior_failure[
                    "failure_message_sha256"
                ],
                "falsifiable_cause": root_cause["falsifiable_cause"],
                "repair_commit": checkpoint,
                "repair_tree": checkpoint_tree,
                "source_analysis_sha256": LIVE.sha256_bytes(source_analysis),
                "focused_tests_passed": 4,
                "repository_validation_passed": True,
                "compileall_passed": True,
                "diff_check_passed": True,
            },
            "canonical_cause_evidence_sha256",
        )
        cause_snapshot = self._snapshot(cause)
        bindings["recovery_cause_evidence_file_sha256"] = (
            cause_snapshot.raw_sha256
        )
        bindings["recovery_cause_evidence_canonical_sha256"] = cause[
            "canonical_cause_evidence_sha256"
        ]
        progress["cause_evidence_sha256"] = cause_snapshot.raw_sha256

        outer_authority = self.helper.outer_authority(authorization)
        outer_snapshot = self._snapshot(outer_authority)
        bindings["outer_authority_canonical_sha256"] = outer_authority[
            "canonical_outer_authority_sha256"
        ]
        bindings["outer_authority_file_sha256"] = outer_snapshot.raw_sha256
        receipt, receipt_raw, _session_path, session_raw = (
            self.helper.bound_validation_receipt(root, authorization, checkpoint)
        )
        progress.update(
            {
                "independent_validation_receipt_canonical_sha256": receipt[
                    "canonical_receipt_sha256"
                ],
                "independent_validation_receipt_file_sha256": LIVE.sha256_bytes(
                    receipt_raw
                ),
                "independent_validation_session_id": receipt["session_id"],
                "independent_validation_completed_at": receipt["completed_at"],
            }
        )
        gates = authorization["mandatory_gates"]
        gates.pop("strict_authorization_v6", None)
        gates.pop("campaign_manifest_v3", None)
        gates.update(
            {
                "strict_authorization_v7": True,
                "campaign_manifest_v4": True,
            }
        )
        self._reseal_v7_authorization(authorization)
        authorization_snapshot = self._snapshot(authorization)

        manifest = self.helper.manifest(
            dict(predecessor.ancestor.authorization.value),
            checkpoint,
            checkpoint_tree,
        )
        manifest.update(
            {
                "version": 4,
                "schema": "schemas/native-live-campaign-manifest-v4.schema.json",
                "authorization_id": authorization["authorization_id"],
                "authorization_raw_sha256": authorization_snapshot.raw_sha256,
                "authorization_canonical_sha256": authorization[
                    "canonical_authorization_sha256"
                ],
                "run_generation": authorization["run_generation"],
                "live_generation": 8,
                "predecessor_live_generation": 7,
                "campaign_nonce": bindings["campaign_nonce"],
                "progress_qualification_sha256": progress["qualification_sha256"],
                "executors": json.loads(json.dumps(authorization["executors"])),
            }
        )
        manifest["work_units"]["live_work_unit_id"] = (
            "complex-work-orchestration-18w.6.36"
        )
        manifest["candidate"] = {
            "commit": checkpoint,
            "tree": checkpoint_tree,
            "origin_main_commit": bindings["origin_main_commit"],
            "guarded_primary_diff_sha256": bindings[
                "guarded_primary_diff_sha256"
            ],
        }
        manifest["predecessor"] = self._manifest_predecessor(authorization)
        manifest["outer_authority"] = {
            "authority_id": bindings["outer_authority_id"],
            "canonical_sha256": bindings["outer_authority_canonical_sha256"],
            "file_sha256": bindings["outer_authority_file_sha256"],
        }
        manifest["reviews"][
            "spark_validation_receipt_canonical_sha256"
        ] = receipt["canonical_receipt_sha256"]
        manifest["reviews"]["spark_validation_receipt_file_sha256"] = (
            LIVE.sha256_bytes(receipt_raw)
        )
        manifest["release"]["candidate_tree"] = checkpoint_tree
        manifest["outputs"] = {
            "evidence_basename": "generation8-evidence.json",
            "authorization_state_basename": "generation8-state.json",
            "steering_registry_basename": "generation8-steering.json",
            "allocation_ledger_basename": "generation8-ledger",
        }
        self.helper.reseal_manifest(manifest)
        return {
            "authorization": authorization,
            "authorization_snapshot": authorization_snapshot,
            "manifest": manifest,
            "cause_snapshot": cause_snapshot,
            "source_analysis": source_analysis,
            "outer_snapshot": outer_snapshot,
            "receipt": receipt,
            "receipt_snapshot": CONTRACTS.JsonArtifactSnapshot(
                raw=receipt_raw, value=receipt
            ),
            "validator_sha256": validator_sha256,
            "checkpoint_tree": checkpoint_tree,
            "session_raw": session_raw,
        }

    def _complete_chain(self, root: Path) -> tuple[
        CONTRACTS.Version5PredecessorProofInputs,
        CONTRACTS.Version6PredecessorProofInputs,
        dict[str, object],
    ]:
        generation6_checkpoint, _orphan = self.helper.make_repo(root)
        generation6 = self.helper.modern_predecessor_proof(
            root, generation6_checkpoint
        )
        generation7 = self.helper.generation7_successor(root, generation6)
        predecessor = self._version6_failure_proof(
            root, generation7, generation6
        )
        generation8 = self._generation8_successor(root, predecessor)
        return generation6, predecessor, generation8

    def _authorization_errors(
        self,
        root: Path,
        predecessor: object,
        generation8: dict[str, object],
    ) -> list[str]:
        authorization = generation8["authorization"]
        assert isinstance(authorization, dict)
        return CONTRACTS.validate_full_auto_authorization(
            authorization,
            expected_campaign_nonce=authorization["bindings"]["campaign_nonce"],
            predecessor_proof=predecessor,
            recovery_cause_evidence=generation8["cause_snapshot"],
            recovery_cause_source_analysis=generation8["source_analysis"],
            expected_validator_contract_sha256=generation8["validator_sha256"],
            repo_root=root,
        )

    def test_v1_digest_is_frozen_and_v2_requires_the_new_schema_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.helper.make_repo(root)
            self.helper.install_validator_contract_files(root)
            subprocess.run(
                ["git", "add", *CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install v1 contract"],
                cwd=root,
                check=True,
            )
            v1_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            v1_digest = CONTRACTS.validator_contract_sha256(root, v1_tree)
            with self.assertRaisesRegex(ValueError, "validator-contract-path-invalid"):
                CONTRACTS.validator_contract_sha256_v2(root, v1_tree)

            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            subprocess.run(
                ["git", "add", *CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install v2 contract"],
                cwd=root,
                check=True,
            )
            v2_tree = LIVE.run_git(root, "rev-parse", "HEAD^{tree}")
            self.assertEqual(
                CONTRACTS.validator_contract_sha256(root, v1_tree), v1_digest
            )
            self.assertNotEqual(
                CONTRACTS.validator_contract_sha256_v2(root, v2_tree),
                v1_digest,
            )

    def test_v7_v4_fixed_finite_dag_accepts_already_contained_predecessor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _generation6, predecessor, generation8 = self._complete_chain(root)
            self.assertEqual(
                self._authorization_errors(root, predecessor, generation8), []
            )
            manifest_errors = CONTRACTS.validate_campaign_manifest(
                generation8["manifest"],
                authorization=generation8["authorization"],
                authorization_raw_sha256=generation8[
                    "authorization_snapshot"
                ].raw_sha256,
                outer_authority=generation8["outer_snapshot"].value,
                outer_authority_raw_sha256=generation8[
                    "outer_snapshot"
                ].raw_sha256,
                predecessor_proof=predecessor,
                recovery_cause_evidence=generation8["cause_snapshot"],
                recovery_cause_source_analysis=generation8["source_analysis"],
                independent_validation_receipt=generation8["receipt"],
                independent_validation_receipt_raw_sha256=generation8[
                    "receipt_snapshot"
                ].raw_sha256,
                expected_validator_contract_sha256=generation8[
                    "validator_sha256"
                ],
                repo_root=root,
                expected_primary_diff_sha256=LIVE.sha256_bytes(b""),
            )
            self.assertEqual(manifest_errors, [])

    def test_v7_rejects_v5_shortcut_and_v6_identity_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation6, predecessor, generation8 = self._complete_chain(root)
            shortcut_errors = self._authorization_errors(
                root, generation6, generation8
            )
            self.assertIn(
                "authorization-v7-predecessor-proof-missing", shortcut_errors
            )

            changed = json.loads(json.dumps(predecessor.authorization.value))
            changed["version"] = 7
            changed_predecessor = CONTRACTS.Version6PredecessorProofInputs(
                authorization=CONTRACTS.JsonArtifactSnapshot(
                    raw=predecessor.authorization.raw, value=changed
                ),
                manifest=predecessor.manifest,
                authorization_state=predecessor.authorization_state,
                failure_evidence=predecessor.failure_evidence,
                containment=predecessor.containment,
                allocation_ledger=predecessor.allocation_ledger,
                allocation_audit_bytes=predecessor.allocation_audit_bytes,
                authorization_recovery_cause_evidence=(
                    predecessor.authorization_recovery_cause_evidence
                ),
                authorization_recovery_cause_source_analysis=(
                    predecessor.authorization_recovery_cause_source_analysis
                ),
                outer_authority=predecessor.outer_authority,
                independent_validation_receipt=(
                    predecessor.independent_validation_receipt
                ),
                independent_validation_session_bytes=(
                    predecessor.independent_validation_session_bytes
                ),
                ancestor=predecessor.ancestor,
                contained_session_bytes=predecessor.contained_session_bytes,
            )
            tamper_errors = self._authorization_errors(
                root, changed_predecessor, generation8
            )
            self.assertTrue(
                any(
                    "predecessor-v6-contract" in item
                    or item == "authorization-predecessor-v6-v3-binding-invalid"
                    for item in tamper_errors
                ),
                tamper_errors,
            )

    def test_v7_rejects_omitted_extra_mixed_and_recursive_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _generation6, predecessor, generation8 = self._complete_chain(root)
            authorization = generation8["authorization"]
            self.assertIn(
                "authorization-v7-recovery-cause-evidence-missing",
                CONTRACTS.validate_full_auto_authorization(
                    authorization,
                    predecessor_proof=predecessor,
                    recovery_cause_source_analysis=generation8[
                        "source_analysis"
                    ],
                ),
            )
            self.assertEqual(
                CONTRACTS.validate_full_auto_authorization(
                    authorization,
                    predecessor_proof=predecessor,
                    recovery_cause_evidence=generation8["cause_snapshot"],
                    recovery_cause_source_analysis=generation8[
                        "source_analysis"
                    ],
                    predecessor_extra_node={"version": 6},
                ),
                ["authorization-v7-legacy-proof-input-forbidden"],
            )

            recursive = replace(predecessor, ancestor=predecessor)
            recursive_errors = self._authorization_errors(
                root, recursive, generation8
            )
            self.assertIn(
                "authorization-predecessor-v6-ancestor-proof-type-invalid",
                recursive_errors,
            )
            mixed_ancestor = replace(
                predecessor.ancestor,
                ancestor=predecessor.ancestor,
            )
            mixed_errors = self._authorization_errors(
                root,
                replace(predecessor, ancestor=mixed_ancestor),
                generation8,
            )
            self.assertIn(
                "authorization-predecessor-v5-historical-proof-type-invalid",
                mixed_errors,
            )

    def test_v7_rejects_v1_digest_and_v4_cross_field_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _generation6, predecessor, generation8 = self._complete_chain(root)
            authorization = json.loads(json.dumps(generation8["authorization"]))
            authorization["bindings"]["validator_contract_sha256"] = (
                CONTRACTS.validator_contract_sha256(
                    root, generation8["checkpoint_tree"]
                )
            )
            self._reseal_v7_authorization(authorization)
            errors = CONTRACTS.validate_full_auto_authorization(
                authorization,
                expected_campaign_nonce=authorization["bindings"]["campaign_nonce"],
                predecessor_proof=predecessor,
                recovery_cause_evidence=generation8["cause_snapshot"],
                recovery_cause_source_analysis=generation8["source_analysis"],
                expected_validator_contract_sha256=generation8[
                    "validator_sha256"
                ],
                repo_root=root,
            )
            self.assertTrue(
                any("validator-contract-mismatch" in item for item in errors),
                errors,
            )

            manifest = json.loads(json.dumps(generation8["manifest"]))
            manifest["predecessor"]["ancestor_lineage_sha256"] = "0" * 64
            self.helper.reseal_manifest(manifest)
            manifest_errors = CONTRACTS.validate_campaign_manifest(
                manifest,
                authorization=generation8["authorization"],
                authorization_raw_sha256=generation8[
                    "authorization_snapshot"
                ].raw_sha256,
                outer_authority=generation8["outer_snapshot"].value,
                outer_authority_raw_sha256=generation8[
                    "outer_snapshot"
                ].raw_sha256,
                predecessor_proof=predecessor,
                recovery_cause_evidence=generation8["cause_snapshot"],
                recovery_cause_source_analysis=generation8["source_analysis"],
                independent_validation_receipt=generation8["receipt"],
                independent_validation_receipt_raw_sha256=generation8[
                    "receipt_snapshot"
                ].raw_sha256,
                expected_validator_contract_sha256=generation8[
                    "validator_sha256"
                ],
                repo_root=root,
                expected_primary_diff_sha256=LIVE.sha256_bytes(b""),
            )
            self.assertIn(
                "campaign-manifest-v4-predecessor-authorization-mismatch",
                manifest_errors,
            )

    def test_v7_rejects_predecessor_campaign_nonce_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _generation6, predecessor, generation8 = self._complete_chain(root)
            authorization = json.loads(json.dumps(generation8["authorization"]))
            predecessor_bindings = predecessor.authorization.value["bindings"]
            authorization["bindings"]["campaign_nonce"] = predecessor_bindings[
                "campaign_nonce"
            ]
            self._reseal_v7_authorization(authorization)
            errors = CONTRACTS.validate_full_auto_authorization(
                authorization,
                expected_campaign_nonce=authorization["bindings"][
                    "campaign_nonce"
                ],
                predecessor_proof=predecessor,
                recovery_cause_evidence=generation8["cause_snapshot"],
                recovery_cause_source_analysis=generation8["source_analysis"],
                expected_validator_contract_sha256=generation8[
                    "validator_sha256"
                ],
                repo_root=root,
            )
            self.assertIn(
                "authorization-v7-predecessor-campaign-nonce-reused",
                errors,
            )


if __name__ == "__main__":
    unittest.main()
