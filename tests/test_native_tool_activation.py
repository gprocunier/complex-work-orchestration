from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
from pathlib import Path
import pickle
import sys
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_authority import (  # noqa: E402
    OPERATOR_APPROVAL_TYPE,
    OperatorApprovalVerifier,
    canonical_authority_sha256,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    default_completion_evidence_policy,
)
from cwo_core.native_pool_preflight import (  # noqa: E402
    effective_child_packet_sha256,
    run_pool_preflight,
    validate_pool_preflight_result,
)
from cwo_core.native_tool_activation import (  # noqa: E402
    NativeToolEnforcementActivationError,
    consume_tool_enforcement_activation,
    tool_enforcement_activation_artifacts,
    tool_enforcement_activation_assessment,
    verify_tool_enforcement_activation,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    build_tool_surface_snapshot,
    default_tool_policy,
    prompt_preflight,
)
from tests.test_native_pool_preflight import (  # noqa: E402
    PreflightFixture,
    temporary_tool_override,
)


KEY = b"native-tool-activation-test-key"
NOW = "2026-07-27T12:05:00Z"


class MutableClock:
    def __init__(self, value: str = NOW) -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value


def temporary_request(fixture: PreflightFixture) -> dict[str, object]:
    request = fixture.preallocation_request()
    override = temporary_tool_override(fixture.campaign_nonce)
    request["aggregate_hard_budget"]["mutations"] = 0  # type: ignore[index]
    for child in request["children"]:  # type: ignore[union-attr]
        child["isolation_class"] = "read-only-shared"
        child["completion_evidence_policy"] = default_completion_evidence_policy(
            "read-only-shared"
        )
        child["tool_policy"] = default_tool_policy(
            mutable=False,
            enforcement_override=override,
        )
        child["prompt_preflight"] = prompt_preflight(
            child["prompt"],
            child["tool_policy"],
        )
        child["tool_surface"] = build_tool_surface_snapshot(
            child["tool_policy"],
            source="offline-test-surface",
            server_allowlist_supported=False,
            allowlist_parameter=None,
            effective_allowlist=None,
        )
        child["hard_budget"]["mutations"] = 0
        child["declared_write_paths"] = []
        child["integration_target_paths"] = []
        child["packet_sha256"] = effective_child_packet_sha256(child)
    return request


def signed_activation_approval(
    request: dict[str, object],
    *,
    key: bytes = KEY,
    nonce: str | None = None,
    issued_at: str = "2026-07-27T12:00:00Z",
    expires_at: str = "2026-07-27T12:10:00Z",
    authorized_scope: str = "complete-task",
) -> dict[str, object]:
    assessment = tool_enforcement_activation_assessment(request)
    body: dict[str, object] = {
        "approval_type": OPERATOR_APPROVAL_TYPE,
        "version": 1,
        "approval_id": str(uuid.uuid4()),
        "change_type": "security-or-authority-change",
        "before_sha256": canonical_authority_sha256(
            assessment.before_subject
        ),
        "after_sha256": canonical_authority_sha256(assessment.after_subject),
        "actor_id": "operator-1",
        "identity_source": "trusted-control-session",
        "authorized_scope": authorized_scope,
        "parent_receipt_sha256": None,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or str(uuid.uuid4()),
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


def verifier(
    root: Path,
    *,
    now: str | MutableClock = NOW,
) -> OperatorApprovalVerifier:
    root.chmod(0o700)
    return OperatorApprovalVerifier(
        verification_key=KEY,
        expected_actor_id="operator-1",
        expected_identity_source="trusted-control-session",
        replay_store_path=root / "activation-replay.json",
        now=now,
    )


def activation_for(
    request: dict[str, object],
    root: Path,
    *,
    receipt: dict[str, object] | None = None,
    now: str | MutableClock = NOW,
):
    return verify_tool_enforcement_activation(
        request,
        approval_receipt=receipt or signed_activation_approval(request),
        operator_approval_verifier=verifier(root, now=now),
    )


def finding_rules(result: dict[str, object]) -> set[str]:
    return {
        str(item["rule_id"]) for item in result["findings"]  # type: ignore[union-attr]
    }


class NativeToolActivationTests(unittest.TestCase):
    def test_raw_override_and_lookalike_capability_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = temporary_request(fixture)

            missing = run_pool_preflight(request)
            lookalike = run_pool_preflight(
                request,
                activation_capability={  # type: ignore[arg-type]
                    "action_sha256": "a" * 64,
                    "state": "available",
                },
            )

            for result in (missing, lookalike):
                self.assertFalse(result["accepted"])
                self.assertIn(
                    "tools.policy-enforcement-activation",
                    finding_rules(result),
                )
                self.assertIsNone(result["override_authority"])

    def test_verified_exact_activation_accepts_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            capability = activation_for(request, root)

            first = run_pool_preflight(
                request,
                activation_capability=capability,
            )
            second = run_pool_preflight(
                request,
                activation_capability=capability,
            )

            self.assertEqual(first, second)
            self.assertTrue(first["accepted"], first["findings"])
            self.assertEqual(
                first["override_authority"]["source_type"],  # type: ignore[index]
                "operator-directive",
            )
            self.assertEqual(
                first["override_authority"]["actor_role"],  # type: ignore[index]
                "operator",
            )
            self.assertEqual(
                validate_pool_preflight_result(
                    first,
                    expected_stage="pre-allocation",
                ),
                [],
            )

    def test_activation_is_bound_to_exact_pool_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            capability = activation_for(request, root)
            mismatched = copy.deepcopy(request)
            mismatched["pool_id"] = str(uuid.uuid4())

            result = run_pool_preflight(
                mismatched,
                activation_capability=capability,
            )

            self.assertFalse(result["accepted"])
            activation_findings = [
                item
                for item in result["findings"]
                if item["rule_id"] == "tools.policy-enforcement-activation"
            ]
            self.assertEqual(len(activation_findings), 1)
            self.assertIn(
                "tool-enforcement-activation-binding-mismatch",
                activation_findings[0]["evidence"]["errors"],
            )

    def test_activation_binding_is_stable_across_preflight_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            preallocation = temporary_request(fixture)
            predispatch = copy.deepcopy(preallocation)
            predispatch["stage"] = "pre-dispatch"
            for index, child in enumerate(predispatch["children"]):  # type: ignore[arg-type]
                session_id = fixture.effective_children[index]["session_id"]
                child["session_id"] = session_id
                child["agent_id"] = session_id

            self.assertEqual(
                tool_enforcement_activation_artifacts(preallocation),
                tool_enforcement_activation_artifacts(predispatch),
            )

    def test_activation_is_unrequested_on_exact_enforcement_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            capability = activation_for(request, root)
            exact_request = fixture.preallocation_request()
            baseline = run_pool_preflight(exact_request)

            result = run_pool_preflight(
                exact_request,
                activation_capability=capability,
            )

            self.assertTrue(baseline["accepted"], baseline["findings"])
            self.assertFalse(result["accepted"])
            self.assertIn(
                "tools.policy-enforcement-activation",
                finding_rules(result),
            )
            self.assertEqual(capability.state, "available")

    def test_invalid_signature_expiry_and_scope_do_not_mint_authority(self) -> None:
        cases = (
            ("signature", {}, "signature-invalid"),
            (
                "expiry",
                {
                    "issued_at": "2026-07-27T11:00:00Z",
                    "expires_at": "2026-07-27T11:10:00Z",
                },
                "expired",
            ),
            (
                "scope",
                {"authorized_scope": "execution-path"},
                "scope-insufficient",
            ),
        )
        for label, options, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = PreflightFixture(root)
                request = temporary_request(fixture)
                receipt = signed_activation_approval(request, **options)
                if label == "signature":
                    receipt["signature"] = "0" * 64
                with self.assertRaisesRegex(
                    NativeToolEnforcementActivationError,
                    expected,
                ):
                    activation_for(
                        request,
                        root,
                        receipt=receipt,
                    )

    def test_activation_expires_before_late_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            clock = MutableClock()
            capability = activation_for(request, root, now=clock)

            self.assertTrue(
                run_pool_preflight(
                    request,
                    activation_capability=capability,
                )["accepted"]
            )
            clock.value = "2026-07-27T12:10:00Z"

            expired = run_pool_preflight(
                request,
                activation_capability=capability,
            )

            self.assertFalse(expired["accepted"])
            activation_findings = [
                item
                for item in expired["findings"]
                if item["rule_id"]
                == "tools.policy-enforcement-activation"
            ]
            self.assertEqual(len(activation_findings), 1)
            self.assertIn(
                "tool-enforcement-activation-expired",
                activation_findings[0]["evidence"]["errors"],
            )
            self.assertEqual(capability.state, "retired")

    def test_operator_receipt_and_capability_each_consume_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            receipt = signed_activation_approval(request)
            approval_verifier = verifier(root)
            capability = verify_tool_enforcement_activation(
                request,
                approval_receipt=receipt,
                operator_approval_verifier=approval_verifier,
            )

            with self.assertRaisesRegex(
                NativeToolEnforcementActivationError,
                "replayed",
            ):
                verify_tool_enforcement_activation(
                    request,
                    approval_receipt=receipt,
                    operator_approval_verifier=approval_verifier,
                )

            consume_tool_enforcement_activation(capability, request)
            self.assertEqual(capability.state, "retired")
            retired_result = run_pool_preflight(
                request,
                activation_capability=capability,
            )
            self.assertFalse(retired_result["accepted"])
            self.assertIn(
                "tools.policy-enforcement-activation",
                finding_rules(retired_result),
            )
            with self.assertRaisesRegex(
                NativeToolEnforcementActivationError,
                "replayed",
            ):
                consume_tool_enforcement_activation(capability, request)

    def test_concurrent_consumption_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            capability = activation_for(request, root)

            def consume() -> str:
                try:
                    consume_tool_enforcement_activation(capability, request)
                except NativeToolEnforcementActivationError as error:
                    return str(error)
                return "consumed"

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = sorted(executor.map(lambda _index: consume(), range(2)))

            self.assertEqual(
                outcomes,
                ["consumed", "tool-enforcement-activation-replayed"],
            )

    def test_activation_cannot_be_copied_or_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = PreflightFixture(root)
            request = temporary_request(fixture)
            capability = activation_for(request, root)

            for operation in (
                lambda: copy.copy(capability),
                lambda: copy.deepcopy(capability),
            ):
                with self.assertRaisesRegex(
                    NativeToolEnforcementActivationError,
                    "copy-forbidden",
                ):
                    operation()
            with self.assertRaisesRegex(
                NativeToolEnforcementActivationError,
                "serialization-forbidden",
            ):
                pickle.dumps(capability)

    def test_caller_supplied_activation_artifacts_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PreflightFixture(Path(temporary))
            request = temporary_request(fixture)
            artifacts = tool_enforcement_activation_artifacts(request)
            artifacts["after_artifact"]["security_context"]["decision"] = (  # type: ignore[index]
                "caller-selected"
            )

            with self.assertRaisesRegex(
                NativeToolEnforcementActivationError,
                "artifacts-mismatch",
            ):
                tool_enforcement_activation_assessment(request, artifacts)


if __name__ == "__main__":
    unittest.main()
