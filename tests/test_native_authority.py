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
    AuthorityProvenanceError,
    VerifiedAuthority,
    canonical_authority_sha256,
    policy_authority,
    trusted_actor_authority,
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


if __name__ == "__main__":
    unittest.main()
