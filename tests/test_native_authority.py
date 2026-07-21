from __future__ import annotations

import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_FIELDS,
    OPERATOR_REQUIRED_CHANGE_TYPES,
    AuthorityProvenanceError,
    OPERATOR_APPROVAL_TYPE,
    OperatorApprovalVerifier,
    VerifiedAuthority,
    VerifiedOperatorApproval,
    assess_operator_required_changes,
    canonical_authority_sha256,
    classify_operator_required_changes,
    policy_authority,
    protected_change_identity,
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


def resign_approval(key: bytes, receipt: dict) -> dict:
    body = {name: value for name, value in receipt.items() if name != "signature"}
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


def assessment_identity(packet_id: str = "packet-1") -> dict:
    return protected_change_identity(
        artifact_type="test-protected-artifact",
        artifact_id="artifact-1",
        work_unit_id="work-1",
        bead_id="bead-1",
        packet_id=packet_id,
    )


class OneShotMapping(Mapping):
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.items_calls = 0

    def __getitem__(self, key):
        return self.payload[key]

    def __iter__(self):
        return iter(self.payload)

    def __len__(self):
        return len(self.payload)

    def items(self):
        self.items_calls += 1
        if self.items_calls > 1:
            raise RuntimeError("mapping was reread")
        return self.payload.items()


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
        configured = list(OPERATOR_REQUIRED_CHANGE_TYPES)
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
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
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
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                receipts={"model-substitution": receipt},
            )

    def test_assessment_classifies_all_six_categories_in_policy_order(self) -> None:
        cases = (
            (
                {"aggregate_allowance": {"tool_calls_hard": 1}},
                {"aggregate_allowance": {"tool_calls_hard": 2}},
                "aggregate-budget-increase",
            ),
            (
                {"requested_model": "a"},
                {"requested_model": "b"},
                "model-substitution",
            ),
            ({"objective": "a"}, {"objective": "b"}, "objective-change"),
            (
                {"security_context": {"mode": "a"}},
                {"security_context": {"mode": "b"}},
                "security-or-authority-change",
            ),
            (
                {"mutation": {"tainted": False}},
                {"mutation": {"tainted": True}},
                "tainted-mutation-acceptance",
            ),
            (
                {"contradictory_validation": False},
                {"contradictory_validation": True},
                "contradictory-validation",
            ),
        )
        for before, after, expected in cases:
            with self.subTest(expected=expected):
                assessment = assess_operator_required_changes(
                    before,
                    after,
                    operator_required_for=reversed(OPERATOR_REQUIRED_CHANGE_TYPES),
                    profile="native-replanning-refinement",
                    identity=assessment_identity(),
                )
                self.assertEqual(assessment.required_change_types, (expected,))
                self.assertTrue(assessment.changed_json_pointers)
                self.assertEqual(assessment.uncategorized_paths, ())
                if expected in {
                    "tainted-mutation-acceptance",
                    "contradictory-validation",
                }:
                    verifier = OperatorApprovalVerifier(
                        verification_key=b"terminal-key",
                        expected_actor_id="operator-1",
                        expected_identity_source="trusted-control-session",
                    )
                    with self.assertRaisesRegex(
                        AuthorityProvenanceError, "terminal-change-not-authorizable"
                    ):
                        verifier.authorize_assessment(assessment, receipts=None)

    def test_assessment_fails_closed_on_unknown_and_type_aliased_budget_paths(self) -> None:
        for before, after in (
            ({}, {"security_policy_bypass": True}),
            ({"unknown": {"nested": 1}}, {"unknown": {"nested": 2}}),
            (
                {"aggregate_allowance": {"tool_calls_hard": True}},
                {"aggregate_allowance": {"tool_calls_hard": 1}},
            ),
            (
                {"aggregate_allowance": {"tool_calls_hard": 1}},
                {"aggregate_allowance": {"tool_calls_hard": 1.0}},
            ),
            (
                {"aggregate_allowance": {}},
                {"aggregate_allowance": {"tool_calls_hard": None}},
            ),
        ):
            with self.subTest(before=before, after=after):
                with self.assertRaisesRegex(
                    AuthorityProvenanceError, "protected-change-uncategorized"
                ):
                    assess_operator_required_changes(
                        before,
                        after,
                        operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                        profile="native-replanning-refinement",
                        identity=assessment_identity(),
                    )
        for malformed in (
            {"objective": float("nan")},
            {"objective": ("not", "a", "json-array")},
        ):
            with self.assertRaisesRegex(
                AuthorityProvenanceError,
                "non-finite-number|json-type-invalid",
            ):
                assess_operator_required_changes(
                    {"objective": "before"},
                    malformed,
                    operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                    profile="native-replanning-refinement",
                    identity=assessment_identity(),
                )
        narrowed = assess_operator_required_changes(
            {"aggregate_allowance": {"tool_calls_hard": 2}},
            {"aggregate_allowance": {"tool_calls_hard": 1}},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        self.assertEqual(narrowed.required_change_types, ())

    def test_assessment_materializes_hostile_mapping_once_and_detaches_source(self) -> None:
        before_source = {"objective": "before"}
        after_source = {"objective": "after"}
        before = OneShotMapping(before_source)
        after = OneShotMapping(after_source)
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        before_source["objective"] = "mutated-after-assessment"
        after_source["objective"] = "also-mutated"
        self.assertEqual(before.items_calls, 1)
        self.assertEqual(after.items_calls, 1)
        self.assertEqual(
            assessment.before_subject["artifact"]["objective"], "before"
        )
        self.assertEqual(
            assessment.after_subject["artifact"]["objective"], "after"
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "assessment-sealed"):
            assessment._required_change_types = ()
        key = b"one-shot-receipt-key"
        hostile_receipt = OneShotMapping(
            signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
            )
        )
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        verifier.authorize_assessment(
            assessment, receipts={"objective-change": hostile_receipt}
        )
        self.assertEqual(hostile_receipt.items_calls, 1)

    def test_identity_retarget_swap_and_receipt_semantics_fail_closed(self) -> None:
        key = b"identity-bound-key"
        before = {"objective": "before"}
        after = {"objective": "after"}
        original = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("packet-1"),
        )
        receipt = signed_approval(
            key,
            original.before_subject,
            original.after_subject,
        )
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        retargeted = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("packet-2"),
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "sha256-mismatch"):
            verifier.authorize_assessment(
                retargeted, receipts={"objective-change": receipt}
            )
        swapped = assess_operator_required_changes(
            after,
            before,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("packet-1"),
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "sha256-mismatch"):
            verifier.authorize_assessment(
                swapped, receipts={"objective-change": receipt}
            )
        variants = (
            ("version", True, "version-invalid"),
            ("version", 1.0, "version-invalid"),
            ("change_type", "model-substitution", "change-type-mismatch"),
            ("actor_id", "operator-2", "actor-mismatch"),
            ("identity_source", "untrusted", "identity-source-mismatch"),
            ("authorized_scope", "child", "scope-insufficient"),
        )
        for field, value, message in variants:
            altered = dict(receipt)
            altered[field] = value
            altered = resign_approval(key, altered)
            with self.subTest(field=field), self.assertRaisesRegex(
                AuthorityProvenanceError, message
            ):
                verifier.authorize_assessment(
                    original, receipts={"objective-change": altered}
                )

    def test_approval_time_signature_atomicity_and_concurrent_replay(self) -> None:
        key = b"atomic-approval-key"
        before = {"objective": "before", "requested_model": "a"}
        after = {"objective": "after", "requested_model": "b"}
        receipts = {
            "model-substitution": signed_approval(
                key,
                before,
                after,
                change_type="model-substitution",
                nonce="model-nonce",
            ),
            "objective-change": signed_approval(
                key,
                before,
                after,
                change_type="objective-change",
                nonce="objective-nonce",
            ),
        }
        broken = json.loads(json.dumps(receipts))
        broken["objective-change"]["signature"] = "0" * 64
        verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "signature-invalid"):
            verifier.authorize_changes(
                before,
                after,
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                receipts=broken,
            )
        self.assertEqual(verifier.consumed_nonces, frozenset())

        duplicate_nonce = json.loads(json.dumps(receipts))
        duplicate_nonce["objective-change"]["nonce"] = "model-nonce"
        duplicate_nonce["objective-change"] = resign_approval(
            key, duplicate_nonce["objective-change"]
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            verifier.authorize_changes(
                before,
                after,
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                receipts=duplicate_nonce,
            )
        self.assertEqual(verifier.consumed_nonces, frozenset())

        duplicate_id = json.loads(json.dumps(receipts))
        duplicate_id["objective-change"]["approval_id"] = duplicate_id[
            "model-substitution"
        ]["approval_id"]
        duplicate_id["objective-change"] = resign_approval(
            key, duplicate_id["objective-change"]
        )
        with self.assertRaisesRegex(
            AuthorityProvenanceError, "duplicate-receipt"
        ):
            verifier.authorize_changes(
                before,
                after,
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                receipts=duplicate_id,
            )
        self.assertEqual(verifier.consumed_nonces, frozenset())

        future = signed_approval(
            key,
            {"objective": "before"},
            {"objective": "after"},
            issued_at="2026-07-20T00:06:00Z",
            expires_at="2026-07-20T00:10:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "not-yet-valid"):
            verifier.authorize_changes(
                {"objective": "before"},
                {"objective": "after"},
                operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                receipts={"objective-change": future},
            )

        single_before = {"objective": "before"}
        single_after = {"objective": "after"}
        single_receipt = signed_approval(key, single_before, single_after)
        replay_verifier = OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            now="2026-07-20T00:05:00Z",
        )

        def authorize_once() -> str:
            try:
                replay_verifier.authorize_changes(
                    single_before,
                    single_after,
                    operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                    receipts={"objective-change": single_receipt},
                )
                return "accepted"
            except AuthorityProvenanceError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: authorize_once(), range(2)))
        self.assertEqual(outcomes.count("accepted"), 1)
        self.assertEqual(
            sum("replayed" in outcome for outcome in outcomes), 1
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
