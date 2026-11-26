"""Protected fault proof fixture used by the retained Generation 11 contract tests."""

from __future__ import annotations

from tests.test_generation9_live_launcher import CONTRACTS, quarantine_proof, snapshot


def protected_fault_proof() -> CONTRACTS.Version8ProtectedFaultPredecessorProofInputs:
    return CONTRACTS.Version8ProtectedFaultPredecessorProofInputs(
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
        ancestor=quarantine_proof(),
        contained_session_bytes=tuple(
            f"failed-contained-{index}\n".encode() for index in range(5)
        ),
    )
