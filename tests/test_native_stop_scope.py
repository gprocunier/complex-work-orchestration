from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_stop_scope import (  # noqa: E402
    STOP_METADATA_FIELDS,
    StopScopeError,
    build_stop_metadata,
    canonical_scope_sha256,
    continuation_path,
    merge_stop_metadata,
    policy_scope_authority,
    read_stop_metadata,
    trusted_actor_scope_authority,
    validate_stop_metadata,
    verify_operator_scope_directive,
)


def sha(label: str) -> str:
    return canonical_scope_sha256({"label": label})


def signed_operator_directive(key: bytes, *, scope: str = "publication") -> dict:
    body = {
        "version": 1,
        "directive_id": "operator-stop-1",
        "action_sha256": sha("publication-stop-action"),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": scope,
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


class NativeStopScopeTest(unittest.TestCase):
    def test_worker_publication_text_cannot_elevate_child_scope(self) -> None:
        authority = trusted_actor_scope_authority(
            source_type="worker-discovery",
            source_id="worker-return-1",
            source_sha256=sha("STOP 0.98 block publication"),
            actor_id="worker-1",
            actor_role="operative-worker",
            identity_source="trusted-runtime-session",
        )
        result = build_stop_metadata(
            "publication",
            authority=authority,
            authorized_continuation_paths=[
                continuation_path(
                    "replace-child",
                    target_id="child-1",
                    conditions=["fresh-attempt"],
                )
            ],
        )
        self.assertEqual(result["stop_scope"], "child")
        self.assertEqual(result["scope_authority"]["authorized_scope"], "child")
        self.assertEqual(result["authorized_continuation_paths"][0]["path"], "replace-child")

    def test_critic_recommendation_is_capped_at_cohort(self) -> None:
        authority = trusted_actor_scope_authority(
            source_type="worker-discovery",
            source_id="critic-steering-1",
            source_sha256=sha("critic-stop"),
            actor_id="critic-1",
            actor_role="critic",
            identity_source="trusted-runtime-session",
        )
        result = build_stop_metadata("publication", authority=authority)
        self.assertEqual(result["stop_scope"], "cohort")

    def test_verified_operator_publication_stop_is_enforced(self) -> None:
        key = b"test-only-operator-directive-key"
        authority = verify_operator_scope_directive(
            signed_operator_directive(key),
            verification_key=key,
            expected_actor_id="operator-1",
            expected_identity_source="trusted-control-session",
            expected_action_sha256=sha("publication-stop-action"),
        )
        result = build_stop_metadata(
            "publication",
            authority=authority,
            authorized_continuation_paths=[
                continuation_path(
                    "operator-adjudication",
                    conditions=["new-operator-directive"],
                )
            ],
        )
        self.assertEqual(result["stop_scope"], "publication")
        self.assertEqual(result["scope_authority"]["source_type"], "operator-directive")

    def test_unverified_or_mismatched_operator_directive_fails_closed(self) -> None:
        key = b"test-only-operator-directive-key"
        receipt = signed_operator_directive(key)
        receipt["signature"] = "0" * 64
        with self.assertRaisesRegex(StopScopeError, "signature-invalid"):
            verify_operator_scope_directive(
                receipt,
                verification_key=key,
                expected_actor_id="operator-1",
                expected_identity_source="trusted-control-session",
                expected_action_sha256=sha("publication-stop-action"),
            )
        with self.assertRaisesRegex(StopScopeError, "requires-verified-directive"):
            trusted_actor_scope_authority(
                source_type="operator-directive",
                source_id="fake",
                source_sha256=sha("fake"),
                actor_id="operator-1",
                actor_role="operator",
                identity_source="free-text",
            )

    def test_conflicts_choose_highest_authorized_scope_deterministically(self) -> None:
        child = build_stop_metadata(
            "child",
            authority=policy_scope_authority("child-fault", authorized_scope="child"),
            authorized_continuation_paths=[continuation_path("replace-child", target_id="child-1")],
        )
        cohort = build_stop_metadata(
            "cohort",
            authority=policy_scope_authority("cohort-budget", authorized_scope="cohort"),
            authorized_continuation_paths=[continuation_path("retry-cohort")],
        )
        self.assertEqual(merge_stop_metadata(child, cohort), merge_stop_metadata(cohort, child))
        merged = merge_stop_metadata(child, cohort)
        self.assertEqual(merged["stop_scope"], "cohort")
        self.assertEqual(
            merged["authorized_continuation_paths"],
            [continuation_path("retry-cohort")],
        )

    def test_legacy_read_is_conservative_and_new_metadata_is_strict(self) -> None:
        migrated = read_stop_metadata(
            {"status": "control-failed", "control_loss_scope": "pool", "reasons": []},
            legacy_source_id="legacy-pool-state-v1",
        )
        self.assertEqual(set(migrated), set(STOP_METADATA_FIELDS))
        self.assertEqual(migrated["stop_scope"], "cohort")
        self.assertEqual(
            migrated["scope_authority"]["verification"]["method"],
            "legacy-compatible-read-v1",
        )
        self.assertEqual(validate_stop_metadata(migrated), [])
        with self.assertRaisesRegex(StopScopeError, "partial-stop-metadata"):
            read_stop_metadata(
                {"status": "running", "stop_scope": "publication"},
                legacy_source_id="legacy-partial",
            )

    def test_authority_and_paths_are_tamper_evident_and_canonical(self) -> None:
        value = build_stop_metadata(
            "child",
            authority=policy_scope_authority("child-fault", authorized_scope="child"),
            authorized_continuation_paths=[
                continuation_path("retry-child", conditions=["z", "a"]),
            ],
        )
        self.assertEqual(value["authorized_continuation_paths"][0]["conditions"], ["a", "z"])
        value["scope_authority"]["authorized_scope"] = "publication"
        errors = validate_stop_metadata(value)
        self.assertIn("scope-authority-exceeds-role-cap", errors)
        self.assertIn("scope-authority-sha256-mismatch", errors)
        self.assertIn("publication-scope-requires-operator-directive", errors)
        with self.assertRaisesRegex(StopScopeError, "conditions-invalid"):
            continuation_path("retry-child", conditions="free text is not structured")


if __name__ == "__main__":
    unittest.main()
