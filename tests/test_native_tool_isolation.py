from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_tool_isolation import (  # noqa: E402
    NativeToolIsolationError,
    build_tool_surface_snapshot,
    default_tool_policy,
    forbidden_tool_activity,
    normalize_tool_policy,
    prompt_preflight,
    require_prompt_preflight,
    require_unchanged_tool_surface,
    seal_tool_enforcement_override,
    validate_tool_enforcement_override_binding,
    validate_tool_policy,
)


def temporary_override(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "override_type": "cwo-native-tool-enforcement-override",
        "version": 1,
        "schema": "schemas/native-tool-enforcement-override.schema.json",
        "authorization_id": "11111111-1111-4111-8111-111111111111",
        "authorization_canonical_sha256": "a" * 64,
        "outer_authority_id": "22222222-2222-4222-8222-222222222222",
        "outer_authority_file_sha256": "b" * 64,
        "outer_authority_canonical_sha256": "c" * 64,
        "campaign_nonce": "33333333-3333-4333-8333-333333333333",
        "candidate_commit": "d" * 40,
        "candidate_tree": "e" * 40,
        "max_workers": 2,
        "max_mutating_workers": 1,
        "single_use": True,
        "risk_acknowledgement": "unlisted-built-ins-may-act-before-detection",
    }
    value.update(updates)
    return seal_tool_enforcement_override(value)


class NativeToolIsolationTests(unittest.TestCase):
    def test_operative_policy_is_strict_and_server_enforced(self) -> None:
        policy = default_tool_policy(mutable=True)
        self.assertEqual(
            policy["permitted_tools"],
            ["apply_patch", "exec_command", "write_stdin"],
        )
        self.assertEqual(policy["enforcement_mode"], "server-allowlist-required")
        self.assertEqual(policy["workload_class"], "operative")
        self.assertIsNone(policy["override_provenance"])
        self.assertEqual(validate_tool_policy(policy), [])

        policy["enforcement_mode"] = "trusted-detect-and-contain"
        self.assertIn(
            "tool-policy-operative-detect-and-contain-requires-enforcement-override",
            validate_tool_policy(policy),
        )

    def test_policy_rejects_overlap_and_unproven_override(self) -> None:
        policy = default_tool_policy(mutable=False)
        policy["forbidden_tools"] = ["exec_command"]
        policy["override_provenance"] = {"authority": "self-report"}
        errors = validate_tool_policy(policy)
        self.assertIn("tool-policy-permitted-forbidden-overlap", errors)
        self.assertIn(
            "tool-policy-operative-unnecessary-tool-enforcement-override",
            errors,
        )

        expansion = default_tool_policy(mutable=False)
        expansion["permitted_tools"] = ["exec_command", "view_image"]
        expansion["forbidden_tools"] = []
        expansion_errors = validate_tool_policy(expansion)
        self.assertTrue(
            any("unproven-permitted-tool-expansion" in item for item in expansion_errors)
        )
        self.assertTrue(
            any("required-forbidden-tools-missing" in item for item in expansion_errors)
        )
        with self.assertRaisesRegex(
            NativeToolIsolationError, "contains-invalid-tool"
        ):
            default_tool_policy(
                mutable=False,
                forbidden_tools=[{"not": "a tool"}],  # type: ignore[list-item]
            )

    def test_temporary_operative_override_is_explicit_and_hash_bound(self) -> None:
        override = temporary_override()
        policy = default_tool_policy(
            mutable=True,
            enforcement_override=override,
        )
        self.assertEqual(
            policy["enforcement_mode"], "trusted-detect-and-contain"
        )
        self.assertEqual(normalize_tool_policy(policy), policy)
        self.assertEqual(validate_tool_policy(policy), [])

        snapshot = build_tool_surface_snapshot(
            policy,
            source="test-server",
            server_allowlist_supported=False,
            allowlist_parameter=None,
            effective_allowlist=None,
        )
        self.assertEqual(snapshot["override_provenance"], override)
        self.assertIsNone(snapshot["effective_allowlist"])

        tampered = dict(override)
        tampered["candidate_tree"] = "f" * 40
        policy["override_provenance"] = tampered
        self.assertTrue(
            any(
                error.endswith("canonical-hash-mismatch")
                for error in validate_tool_policy(policy)
            )
        )

    def test_temporary_override_must_match_live_campaign_and_capacity(self) -> None:
        override = temporary_override()
        expected = {
            "authorization_id": override["authorization_id"],
            "authorization_canonical_sha256": override[
                "authorization_canonical_sha256"
            ],
            "outer_authority_id": override["outer_authority_id"],
            "outer_authority_file_sha256": override[
                "outer_authority_file_sha256"
            ],
            "outer_authority_canonical_sha256": override[
                "outer_authority_canonical_sha256"
            ],
            "campaign_nonce": override["campaign_nonce"],
            "candidate_commit": override["candidate_commit"],
            "candidate_tree": override["candidate_tree"],
        }
        self.assertEqual(
            validate_tool_enforcement_override_binding(
                override,
                **expected,
                requested_workers=2,
                mutating_workers=1,
            ),
            [],
        )
        errors = validate_tool_enforcement_override_binding(
            override,
            **{**expected, "campaign_nonce": "44444444-4444-4444-8444-444444444444"},
            requested_workers=3,
            mutating_workers=2,
        )
        self.assertIn(
            "tool-enforcement-override-campaign-nonce-mismatch", errors
        )
        self.assertIn(
            "tool-enforcement-override-requested-workers-exceed-override",
            errors,
        )
        self.assertIn(
            "tool-enforcement-override-mutating-workers-exceed-override",
            errors,
        )

    def test_exact_capability_rejects_weaker_operative_override(self) -> None:
        policy = default_tool_policy(
            mutable=False,
            enforcement_override=temporary_override(),
        )
        with self.assertRaisesRegex(
            NativeToolIsolationError,
            "override-unnecessary-exact-capability-available",
        ):
            build_tool_surface_snapshot(
                policy,
                source="test-server",
                server_allowlist_supported=True,
                allowlist_parameter="nativeTools",
                effective_allowlist=["exec_command", "write_stdin"],
            )

    def test_prompt_preflight_reports_rule_and_location_without_rewriting(self) -> None:
        policy = default_tool_policy(
            mutable=False, workload_class="safety-canary"
        )
        prompt = "Inspect the file.\nInvoke $complex-work-orchestration now.\n"
        result = prompt_preflight(prompt, policy)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["findings"][0]["rule_id"], "explicit-skill-trigger")
        self.assertEqual(result["findings"][0]["line"], 2)
        self.assertGreater(result["findings"][0]["column"], 1)
        self.assertNotIn("complex-work-orchestration", str(result["findings"]))
        with self.assertRaisesRegex(
            NativeToolIsolationError, "prompt-trigger-conflict"
        ):
            require_prompt_preflight(prompt, policy)
        self.assertFalse(
            prompt_preflight("Use complex-work-orchestration now.", policy)[
                "accepted"
            ]
        )
        self.assertTrue(
            prompt_preflight(
                "Workdir: /srv/complex-work-orchestration-repair", policy
            )["accepted"]
        )

    def test_prompt_preflight_rejects_out_of_contract_tool_directive(self) -> None:
        policy = default_tool_policy(
            mutable=False, workload_class="safety-canary"
        )
        result = prompt_preflight("Use spawn_agent tool now.", policy)
        self.assertEqual(
            [item["rule_id"] for item in result["findings"]],
            ["out-of-contract-tool-directive"],
        )
        self.assertTrue(
            prompt_preflight("Do not use any other tool.", policy)["accepted"]
        )

        custom = default_tool_policy(
            mutable=False,
            workload_class="safety-canary",
            forbidden_tools=["custom_escape_tool"],
        )
        self.assertFalse(
            prompt_preflight("Run custom_escape_tool now.", custom)["accepted"]
        )

    def test_unsupported_surface_blocks_operative_but_not_safety_canary(self) -> None:
        operative = default_tool_policy(mutable=False)
        with self.assertRaisesRegex(
            NativeToolIsolationError, "operative-tool-restriction-unsupported"
        ):
            build_tool_surface_snapshot(
                operative,
                source="test-server",
                server_allowlist_supported=False,
                allowlist_parameter=None,
                effective_allowlist=None,
            )

        canary = default_tool_policy(
            mutable=False, workload_class="safety-canary"
        )
        snapshot = build_tool_surface_snapshot(
            canary,
            source="test-server",
            server_allowlist_supported=False,
            allowlist_parameter=None,
            effective_allowlist=None,
        )
        self.assertIsNone(snapshot["effective_allowlist"])
        self.assertFalse(snapshot["server_allowlist_supported"])

    def test_expanded_or_changed_surface_fails_closed(self) -> None:
        policy = default_tool_policy(mutable=False)
        with self.assertRaisesRegex(NativeToolIsolationError, "tool-surface-expanded"):
            build_tool_surface_snapshot(
                policy,
                source="test-server",
                server_allowlist_supported=True,
                allowlist_parameter="tools",
                effective_allowlist=["exec_command", "spawn_agent", "write_stdin"],
            )
        before = build_tool_surface_snapshot(
            policy,
            source="test-server-v1",
            server_allowlist_supported=True,
            allowlist_parameter="tools",
            effective_allowlist=["exec_command", "write_stdin"],
        )
        after = build_tool_surface_snapshot(
            policy,
            source="test-server-v2",
            server_allowlist_supported=True,
            allowlist_parameter="tools",
            effective_allowlist=["exec_command", "write_stdin"],
        )
        with self.assertRaisesRegex(
            NativeToolIsolationError, "tool-surface-changed-before-dispatch"
        ):
            require_unchanged_tool_surface(before, after)

    def test_forbidden_activity_preserves_only_tool_and_evidence_hash(self) -> None:
        policy = default_tool_policy(
            mutable=False, workload_class="safety-canary"
        )
        activity = [
            {"tool": "exec_command", "evidence_sha256": "a" * 64},
            {"tool": "spawn_agent", "evidence_sha256": "b" * 64},
        ]
        self.assertEqual(
            forbidden_tool_activity(activity, policy),
            [{"tool": "spawn_agent", "evidence_sha256": "b" * 64}],
        )


if __name__ == "__main__":
    unittest.main()
