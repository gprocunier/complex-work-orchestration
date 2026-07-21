from __future__ import annotations

import hashlib
import hmac
import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


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


def _authorize_in_process(
    result_queue,
    start_event,
    replay_store: str,
    key: bytes,
    receipt: dict,
) -> None:
    assessment = assess_operator_required_changes(
        {"objective": "before"},
        {"objective": "after"},
        operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
        profile="native-replanning-refinement",
        identity=assessment_identity("process-packet"),
    )
    verifier = OperatorApprovalVerifier(
        verification_key=key,
        expected_actor_id="operator-1",
        expected_identity_source="trusted-control-session",
        replay_store_path=Path(replay_store),
        now="2026-07-20T00:05:00Z",
    )
    start_event.wait()
    try:
        verifier.authorize_assessment(
            assessment, receipts={"objective-change": receipt}
        )
    except AuthorityProvenanceError as exc:
        result_queue.put(str(exc))
    else:
        result_queue.put("accepted")


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
    def setUp(self) -> None:
        self._temporary = TemporaryDirectory()
        self.replay_root = Path(self._temporary.name)
        self._store_index = 0

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def replay_store(self, name: str | None = None) -> Path:
        self._store_index += 1
        return self.replay_root / (name or f"replay-{self._store_index}.json")

    def verifier(
        self,
        key: bytes,
        *,
        store: Path | None = None,
        now: str = "2026-07-20T00:05:00Z",
    ) -> OperatorApprovalVerifier:
        return OperatorApprovalVerifier(
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            replay_store_path=store or self.replay_store(),
            now=now,
        )

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
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        receipt = signed_approval(
            key, assessment.before_subject, assessment.after_subject
        )
        store = self.replay_store("shared.json")
        verifier = self.verifier(key, store=store)
        approval = verifier.authorize_assessment(
            assessment, receipts={"objective-change": receipt}
        )[0]
        self.assertIsInstance(approval, VerifiedOperatorApproval)
        self.assertEqual(validate_operator_approval_audit(approval.audit_record()), [])
        self.assertNotIn("signature", approval.audit_record())
        self.assertIn("signature", approval.audit_record()["signed_receipt"])
        self.assertEqual(verifier.consumed_nonces, frozenset({"approval-nonce-1"}))
        audit_verifier = self.verifier(key, store=store)
        audit_verifier.validate_assessment_audits(
            assessment,
            audits={"objective-change": approval.audit_record()},
            receipts={"objective-change": receipt},
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            audit_verifier.authorize_assessment(
                assessment, receipts={"objective-change": receipt}
            )

    def test_operator_approval_rejects_expiry_and_different_after_artifact(self) -> None:
        key = b"test-only-protected-change-key"
        before = {"objective": "repair CWO"}
        after = {"objective": "publish CWO"}
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        expired = self.verifier(key, now="2026-07-20T00:10:00Z")
        with self.assertRaisesRegex(AuthorityProvenanceError, "expired"):
            expired.authorize_assessment(
                assessment,
                receipts={
                    "objective-change": signed_approval(
                        key, assessment.before_subject, assessment.after_subject
                    )
                },
            )

        different = assess_operator_required_changes(
            before,
            {"objective": "different"},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        verifier = self.verifier(key)
        with self.assertRaisesRegex(AuthorityProvenanceError, "after-sha256-mismatch"):
            verifier.authorize_assessment(
                different,
                receipts={
                    "objective-change": signed_approval(
                        key, assessment.before_subject, assessment.after_subject
                    )
                },
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
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=configured,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        receipts = {
            "aggregate-budget-increase": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="aggregate-budget-increase",
                nonce="budget-nonce",
            ),
            "objective-change": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="objective-change",
                nonce="objective-nonce",
            ),
        }
        store = self.replay_store("atomic.json")
        verifier = self.verifier(key, store=store)
        approvals = verifier.authorize_assessment(assessment, receipts=receipts)
        self.assertEqual(
            [approval.change_type for approval in approvals],
            ["aggregate-budget-increase", "objective-change"],
        )
        self.assertEqual(
            verifier.consumed_nonces,
            frozenset({"budget-nonce", "objective-nonce"}),
        )
        fresh_verifier = self.verifier(key, store=store)
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            fresh_verifier.authorize_assessment(assessment, receipts=receipts)

    def test_operator_required_change_rejects_missing_or_insufficient_approval(self) -> None:
        before = {"requested_model": "model-a"}
        after = {"requested_model": "model-b"}
        key = b"test-only-protected-change-key"
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        verifier = self.verifier(key)
        with self.assertRaisesRegex(AuthorityProvenanceError, "required-for"):
            verifier.authorize_assessment(assessment, receipts=None)
        receipt = signed_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
            change_type="model-substitution",
            authorized_scope="child",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "scope-insufficient"):
            verifier.authorize_assessment(
                assessment, receipts={"model-substitution": receipt}
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
                    operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
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
                    verifier = self.verifier(b"terminal-key")
                    with self.assertRaisesRegex(
                        AuthorityProvenanceError, "terminal-change-not-authorizable"
                    ):
                        verifier.authorize_assessment(assessment, receipts=None)

        with self.assertRaisesRegex(
            AuthorityProvenanceError, "operator-required-for-invalid"
        ):
            assess_operator_required_changes(
                {"objective": "a"},
                {"objective": "b"},
                operator_required_for=reversed(OPERATOR_REQUIRED_CHANGE_TYPES),
                profile="native-replanning-refinement",
                identity=assessment_identity(),
            )

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
        verifier = self.verifier(key)
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
        verifier = self.verifier(key)
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
        assessment = assess_operator_required_changes(
            before,
            after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity(),
        )
        receipts = {
            "model-substitution": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="model-substitution",
                nonce="model-nonce",
            ),
            "objective-change": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="objective-change",
                nonce="objective-nonce",
            ),
        }
        broken = json.loads(json.dumps(receipts))
        broken["objective-change"]["signature"] = "0" * 64
        verifier = self.verifier(key)
        with self.assertRaisesRegex(AuthorityProvenanceError, "signature-invalid"):
            verifier.authorize_assessment(assessment, receipts=broken)
        self.assertEqual(verifier.consumed_nonces, frozenset())

        duplicate_nonce = json.loads(json.dumps(receipts))
        duplicate_nonce["objective-change"]["nonce"] = "model-nonce"
        duplicate_nonce["objective-change"] = resign_approval(
            key, duplicate_nonce["objective-change"]
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            verifier.authorize_assessment(assessment, receipts=duplicate_nonce)
        self.assertEqual(verifier.consumed_nonces, frozenset())

        duplicate_id = json.loads(json.dumps(receipts))
        duplicate_id["objective-change"]["approval_id"] = duplicate_id[
            "model-substitution"
        ]["approval_id"]
        duplicate_id["objective-change"] = resign_approval(
            key, duplicate_id["objective-change"]
        )
        with self.assertRaisesRegex(
            AuthorityProvenanceError, "replayed"
        ):
            verifier.authorize_assessment(assessment, receipts=duplicate_id)
        self.assertEqual(verifier.consumed_nonces, frozenset())

        future_assessment = assess_operator_required_changes(
            {"objective": "before"},
            {"objective": "after"},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("future-packet"),
        )
        future = signed_approval(
            key,
            future_assessment.before_subject,
            future_assessment.after_subject,
            issued_at="2026-07-20T00:06:00Z",
            expires_at="2026-07-20T00:10:00Z",
        )
        with self.assertRaisesRegex(AuthorityProvenanceError, "not-yet-valid"):
            verifier.authorize_assessment(
                future_assessment, receipts={"objective-change": future}
            )

        single_before = {"objective": "before"}
        single_after = {"objective": "after"}
        single_assessment = assess_operator_required_changes(
            single_before,
            single_after,
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("concurrent-packet"),
        )
        single_receipt = signed_approval(
            key, single_assessment.before_subject, single_assessment.after_subject
        )
        concurrent_store = self.replay_store("concurrent.json")

        def authorize_once() -> str:
            try:
                self.verifier(key, store=concurrent_store).authorize_assessment(
                    single_assessment,
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

    def test_only_identity_bound_assessment_can_mint_operator_authority(self) -> None:
        verifier = self.verifier(b"no-alternate-minting-key")
        self.assertFalse(hasattr(verifier, "verify"))
        self.assertFalse(hasattr(verifier, "verify_audit"))
        self.assertFalse(hasattr(verifier, "authorize_changes"))
        with self.assertRaisesRegex(
            AuthorityProvenanceError, "assessment-identity-required"
        ):
            verifier.authorize_assessment(
                assess_operator_required_changes(
                    {"objective": "before"},
                    {"objective": "after"},
                    operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
                    profile="generic",
                    identity=None,  # type: ignore[arg-type]
                ),
                receipts=None,
            )

    def test_replay_store_is_atomic_across_processes_and_restart(self) -> None:
        key = b"multiprocess-replay-key"
        assessment = assess_operator_required_changes(
            {"objective": "before"},
            {"objective": "after"},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("process-packet"),
        )
        receipt = signed_approval(
            key,
            assessment.before_subject,
            assessment.after_subject,
            nonce="process-race-nonce",
        )
        store = self.replay_store("process-race.json")
        context = multiprocessing.get_context("fork")
        result_queue = context.Queue()
        start_event = context.Event()
        processes = [
            context.Process(
                target=_authorize_in_process,
                args=(result_queue, start_event, str(store), key, receipt),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start_event.set()
        outcomes = [result_queue.get(timeout=10) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(outcomes.count("accepted"), 1)
        self.assertEqual(sum("replayed" in item for item in outcomes), 1)
        restarted = self.verifier(key, store=store)
        self.assertEqual(restarted.consumed_nonces, frozenset({"process-race-nonce"}))
        with self.assertRaisesRegex(AuthorityProvenanceError, "replayed"):
            restarted.authorize_assessment(
                assessment, receipts={"objective-change": receipt}
            )

    def test_replay_store_rejects_corruption_symlinks_links_and_relative_paths(self) -> None:
        key = b"replay-path-key"
        with self.assertRaisesRegex(AuthorityProvenanceError, "path-not-absolute"):
            OperatorApprovalVerifier(
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
                replay_store_path=Path("relative-replay.json"),
            )

        corrupt = self.replay_store("corrupt.json")
        corrupt.write_text("{broken", encoding="utf-8")
        corrupt.chmod(0o600)
        with self.assertRaisesRegex(AuthorityProvenanceError, "corrupt"):
            self.verifier(key, store=corrupt).consumed_nonces

        target = self.replay_store("target.json")
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        symlink = self.replay_store("symlink.json")
        symlink.symlink_to(target)
        with self.assertRaisesRegex(AuthorityProvenanceError, "symlink-forbidden"):
            self.verifier(key, store=symlink)

        assessment = assess_operator_required_changes(
            {"objective": "before"},
            {"objective": "after"},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("linked-store"),
        )
        receipt = signed_approval(
            key, assessment.before_subject, assessment.after_subject
        )
        linked_store = self.replay_store("linked.json")
        verifier = self.verifier(key, store=linked_store)
        verifier.authorize_assessment(
            assessment, receipts={"objective-change": receipt}
        )
        os.link(linked_store, self.replay_store("second-link.json"))
        with self.assertRaisesRegex(AuthorityProvenanceError, "file-invalid"):
            self.verifier(key, store=linked_store).consumed_nonces

    def test_failed_receipt_set_and_persistence_failure_grant_no_authority(self) -> None:
        key = b"persistence-failure-key"
        assessment = assess_operator_required_changes(
            {"objective": "before", "requested_model": "a"},
            {"objective": "after", "requested_model": "b"},
            operator_required_for=OPERATOR_REQUIRED_CHANGE_TYPES,
            profile="native-replanning-refinement",
            identity=assessment_identity("persistence-packet"),
        )
        receipts = {
            "model-substitution": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="model-substitution",
                nonce="persistence-model",
            ),
            "objective-change": signed_approval(
                key,
                assessment.before_subject,
                assessment.after_subject,
                change_type="objective-change",
                nonce="persistence-objective",
            ),
        }
        broken = json.loads(json.dumps(receipts))
        broken["objective-change"]["signature"] = "0" * 64
        store = self.replay_store("failed-set.json")
        verifier = self.verifier(key, store=store)
        with self.assertRaisesRegex(AuthorityProvenanceError, "signature-invalid"):
            verifier.authorize_assessment(assessment, receipts=broken)
        self.assertFalse(store.exists())
        self.assertEqual(verifier.consumed_nonces, frozenset())

        persist_store = self.replay_store("persist-error.json")
        persist_verifier = self.verifier(key, store=persist_store)
        with patch(
            "cwo_core.native_authority.os.replace",
            side_effect=OSError("simulated replace failure"),
        ), self.assertRaisesRegex(AuthorityProvenanceError, "persist-failed"):
            persist_verifier.authorize_assessment(assessment, receipts=receipts)
        self.assertFalse(persist_store.exists())
        self.assertEqual(persist_verifier.consumed_nonces, frozenset())

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
