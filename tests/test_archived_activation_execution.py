"""Offline replay of the retired standalone calibration and activation executor."""

from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from tests.historical_campaign_launcher import run_archived_cases  # noqa: E402


PREVIEW_RELEASE = "7b2f3db802d7b1d1c4c555960d65d2502220f93b"  # v1.48.0
REVIEWED_SOURCE = "bd458b84e9ab1ef7161fe43f555c11f6ebac8c41"


class ArchivedActivationExecutionTests(unittest.TestCase):
    def test_archived_standalone_calibration_witnesses(self) -> None:
        run_archived_cases(
            self, REVIEWED_SOURCE,
            "tests.test_run_native_pool_live_canaries.LiveCanaryMaterializationTests",
        )

    def test_archived_standalone_calibration_recovery_witnesses(self) -> None:
        run_archived_cases(
            self, REVIEWED_SOURCE,
            "tests.test_generation12_empty_session_recovery.Generation12CalibrationRecoveryTests",
        )

    def test_archived_activation_entry_witnesses(self) -> None:
        run_archived_cases(
            self, REVIEWED_SOURCE,
            "tests.test_r1_activation_preview_hold.R1ActivationPreviewHoldTests",
            "tests.test_f5_native_live_holds.F5NativeLiveHoldTests."
            "test_r1_f5_held_preview_routes_zero_launch_and_independent_fake_controls",
            "tests.test_native_activation_preview.ActivationWorkspaceInspectionTests."
            "test_runner_monitor_uses_real_capture_for_clean_metadata_and_incomplete_controls",
        )

    @unittest.skipUnless(shutil.which("bd"), "disposable bd fixture unavailable")
    def test_archived_activation_execution_witnesses(self) -> None:
        prefix = "tests.test_native_activation_preview.NativeActivationPreviewTests."
        batches = (
            (
                "test_pool_capability_receipt_is_omitted_for_n1_and_preserved_for_n2",
                "test_activation_trace_artifact_binds_exact_ordered_receipts",
                "test_pool_receipt_must_be_exactly_accepting",
                "test_pool_failure_precedes_derivative_trace_incompleteness",
            ),
            (
                "test_activation_closes_only_exact_authorized_child_before_acceptance",
                "test_child_close_rejects_tampered_claim_receipt_before_command",
                "test_n2_partial_close_stops_without_rollback_or_parent_close",
            ),
            (
                "test_containment_requires_terminal_observation",
                "test_activation_containment_persists_proofs_and_pending_intent_wins",
                "test_activation_containment_deletes_fresh_never_turned_thread",
            ),
            (
                "test_transport_records_calibration_and_worker_intents_before_rpc",
                "test_failed_rpc_leaves_unresolved_durable_intent",
                "test_all_new_schemas_validate_emitted_artifacts",
            ),
        )
        for batch in batches:
            run_archived_cases(self, PREVIEW_RELEASE, *(prefix + test for test in batch))
