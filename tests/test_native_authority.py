from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_FIELDS,
    AuthorityProvenanceError,
    OPERATOR_APPROVAL_TYPE,
    OperatorApprovalVerifier,
    VerifiedAuthority,
    VerifiedOperatorApproval,
    canonical_authority_sha256,
    classify_operator_required_changes,
    policy_authority,
    trusted_actor_authority,
    validate_operator_approval_audit,
    validate_authority_provenance,
    verify_operator_directive,
)


def sha(label: str) -> str:
    return canonical_authority_sha256({"label": label})


def signed_directive(key: bytes) -> dict:
    body = {
        "version": 1,
        "directive_id": "directive-1",
        "action_sha256": sha("publication-stop"),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": "publication",
        "parent_receipt_sha256": None,
        "issued_at": "2026-07-20T00:00:00Z",
        "nonce": "directive-nonce-1",
    }
    body["signature"] = hmac.new(
        key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return body


def signed_approval(
    key: bytes,
    before: dict,
    after: dict,
    *,
    change_type: str = "objective-change",
    nonce: str = "approval-nonce-1",
    issued_at: str = "2026-07-20T00:00:00Z",
    expires_at: str = "2026-07-20T00:10:00Z",
    authorized_scope: str = "complete-task",
) -> dict:
    body = {
        "approval_type": OPERATOR_APPROVAL_TYPE,
        "version": 1,
        "approval_id": f"approval-{change_type}",
        "change_type": change_type,
        "before_sha256": canonical_authority_sha256(before),
        "after_sha256": canonical_authority_sha256(after),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": authorized_scope,
        "parent_receipt_sha256": None,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    body["signature"] = hmac.new(
        key,
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return body


class NativeAuthorityTest(unittest.TestCase):
    def test_policy_and_trusted_runtime_authority_are_verifiable(self) -> None:
        policy = policy_authority("policy-rule", authorized_scope="complete-task")
        worker = trusted_actor_authority(
            source_type="worker-discovery",
            source_id="session-1",
            source_sha256=sha("session"),
            actor_id="worker-1",
            actor_role="operative-worker",
            identity_source="trusted-session-jsonl",
        )
        self.assertEqual(validate_authority_provenance(policy.serialize()), [])
        self.assertEqual(validate_authority_provenance(worker.serialize()), [])
        self.assertEqual(worker.authorized_scope, "child")

    def test_verified_authority_cannot_be_caller_constructed(self) -> None:
        with self.assertRaisesRegex(
            AuthorityProvenanceError, "construction-forbidden"
        ):
            VerifiedAuthority({}, object())

    def test_free_text_role_cannot_create_operator_authority(self) -> None:
        with self.assertRaisesRegex(
            AuthorityProvenanceError, "requires-verified-directive"
        ):
            trusted_actor_authority(
                source_type="operator-directive",
                source_id="self-asserted",
                source_sha256=sha("self-asserted"),
                actor_id="operator-1",
                actor_role="operator",
                identity_source="free-text",
            )

    def test_operator_directive_is_signature_and_action_bound(self) -> None:
        key = b"test-only-authority-key"
        authority = verify_operator_directive(
            signed_directive(key),
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            expected_action_sha256=sha("publication-stop"),
        )
        self.assertEqual(authority.authorized_scope, "publication")
        tampered = signed_directive(key)
        tampered["action_sha256"] = sha("different-action")
        with self.assertRaisesRegex(AuthorityProvenanceError, "signature-invalid"):
            verify_operator_directive(
                tampered,
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
                expected_action_sha256=sha("different-action"),
            )

    def test_operator_approval_is_hash_time_scope_and_replay_bound(self) -> None:
        key = b"test-only-protected-change-key"
        before = {"objective": "repair CWO"}
        after = {"objective": "publish CWO"}
        consumed: set[str] = set()
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            consumed_nonces=consumed,
            now="2026-07-20T00:05:00Z",
        )
        approval = verifier.verify(
            signed_approval(key, before, after),
            expected_change_type="objective-change",
            before_artifact=before,
            after_artifact=after,
        )
        self.assertIsInstance(approval, VerifiedOperatorApproval)
        self.assertEqual(validate_operator_approval_audit(approval.audit_record()), [])
        self.assertNotIn("signature", approval.audit_record())
        self.assertIn("signature", approval.audit_record()["signed_receipt"])
        self.assertEqual(consumed, {"approval-nonce-1"})
        audit_verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        self.assertEqual(
            audit_verifier.verify_audit(
                approval.audit_record(),
                before_artifact=before,
                after_artifact=after,
            ).change_type,
            "objective-change",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            verifier.verify(
                signed_approval(key, before, after),
                expected_change_type="objective-change",
                before_artifact=before,
                after_artifact=after,
            )

    def test_operator_approval_rejects_expiry_and_different_after_artifact(self) -> None:
        key = b"test-only-protected-change-key"
        before = {"objective": "repair CWO"}
        after = {"objective": "publish CWO"}
        expired = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:10:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "expired"):
            expired.verify(
                signed_approval(key, before, after),
                expected_change_type="objective-change",
                before_artifact=before,
                after_artifact=after,
            )

        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "after-sha256-mismatch"):
            verifier.verify(
                signed_approval(key, before, after),
                expected_change_type="objective-change",
                before_artifact=before,
                after_artifact={"objective": "different"},
            )

    def test_operator_required_change_classification_and_atomic_authorization(self) -> None:
        before = {
            "objective": "repair",
            "requested_model": "model-a",
            "aggregate_allowance": {"tool_calls_hard": 10},
        }
        after = {
            "objective": "publish",
            "requested_model": "model-a",
            "aggregate_allowance": {"tool_calls_hard": 12},
        }
        configured = [
            "aggregate-budget-increase",
            "model-substitution",
            "objective-change",
        ]
        self.assertEqual(
            classify_operator_required_changes(before, after, configured),
            ["aggregate-budget-increase", "objective-change"],
        )
        key = b"test-only-protected-change-key"
        receipts = {
            "aggregate-budget-increase": signed_approval(
                key,
                before,
                after,
                change_type="aggregate-budget-increase",
                nonce="budget-nonce",
            ),
            "objective-change": signed_approval(
                key,
                before,
                after,
                change_type="objective-change",
                nonce="objective-nonce",
            ),
        }
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        approvals = verifier.authorize_changes(
            before,
            after,
            operator_required_for=configured,
            receipts=receipts,
        )
        self.assertEqual(
            [approval.change_type for approval in approvals],
            ["aggregate-budget-increase", "objective-change"],
        )
        self.assertEqual(
            verifier.consumed_nonces,
            frozenset({"budget-nonce", "objective-nonce"}),
        )
        fresh_verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            fresh_verifier.authorize_changes(
                before,
                after,
                operator_required_for=configured,
                receipts=receipts,
                prior_nonces={"budget-nonce"},
            )

    def test_operator_required_change_rejects_missing_or_insufficient_approval(self) -> None:
        before = {"requested_model": "model-a"}
        after = {"requested_model": "model-b"}
        key = b"test-only-protected-change-key"
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "required-for"):
            verifier.authorize_changes(
                before,
                after,
                operator_required_for=["model-substitution"],
                receipts=None,
            )
        receipt = signed_approval(
            key,
            before,
            after,
            change_type="model-substitution",
            authorized_scope="child",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "scope-insufficient"):
            verifier.authorize_changes(
                before,
                after,
                operator_required_for=["model-substitution"],
                receipts={"model-substitution": receipt},
            )

    def test_standalone_schema_matches_serialized_contract(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "native-authority-provenance.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["title"], "Native Authority Provenance")
        self.assertEqual(
            set(schema["required"]),
            set(policy_authority("schema-test", authorized_scope="child").serialize()),
        )
        approval_schema = json.loads(
            (ROOT / "schemas" / "native-operator-approval.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            approval_schema["title"],
            "Native Operator Protected Change Approval",
        )
        self.assertEqual(set(approval_schema["required"]), OPERATOR_APPROVAL_FIELDS)


if __name__ == "__main__":
    unittest.main()
