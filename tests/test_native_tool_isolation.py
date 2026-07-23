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
    prompt_preflight,
    require_prompt_preflight,
    require_unchanged_tool_surface,
    validate_tool_policy,
)


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
            "tool-policy-operative-requires-server-allowlist",
            validate_tool_policy(policy),
        )

    def test_policy_rejects_overlap_and_unproven_override(self) -> None:
        policy = default_tool_policy(mutable=False)
        policy["forbidden_tools"] = ["exec_command"]
        policy["override_provenance"] = {"authority": "self-report"}
        errors = validate_tool_policy(policy)
        self.assertIn("tool-policy-permitted-forbidden-overlap", errors)
        self.assertIn("tool-policy-override-provenance-not-yet-authorized", errors)

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
