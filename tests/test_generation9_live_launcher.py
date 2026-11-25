"""Predecessor proof fixtures used by the retained Generation 11 contract tests."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402


def snapshot(label: str, **value: object) -> CONTRACTS.JsonArtifactSnapshot:
    return CONTRACTS.JsonArtifactSnapshot(
        raw=(label + "\n").encode(),
        value={"label": label, **value},
    )


def quarantine_proof() -> CONTRACTS.Version7QuarantinePredecessorProofInputs:
    grandancestor = CONTRACTS.HistoricalV4V1ProofInputs(
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
    ancestor = CONTRACTS.Version5PredecessorProofInputs(
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
    predecessor = CONTRACTS.Version6PredecessorProofInputs(
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
    return CONTRACTS.Version7QuarantinePredecessorProofInputs(
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
