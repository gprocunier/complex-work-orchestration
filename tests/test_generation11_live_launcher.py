"""Preallocation proof fixture used by the retained Generation 11 contract tests."""

from __future__ import annotations

from types import SimpleNamespace

from tests.test_generation10_live_launcher import protected_fault_proof
from tests.test_generation9_live_launcher import CONTRACTS, snapshot


class Generation11LiveLauncherTests:
    """Preserve the contract suite's existing fixture interface."""

    def inputs(self) -> SimpleNamespace:
        preallocation = CONTRACTS.Version9PreallocationFaultPredecessorProofInputs(
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
            ancestor=protected_fault_proof(),
        )
        return SimpleNamespace(predecessor_proof=preallocation)
