from __future__ import annotations

import sys
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_manual_dispatch_prompt import render_packet_prompt, render_prompt  # noqa: E402
from dispatch_work import local_executor_fallback  # noqa: E402
from build_contractor_packet import build_packet  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from cwo_core.packets import (  # noqa: E402
    require_valid_contractor_packet,
    validate_contractor_packet,
)


class DispatchTests(unittest.TestCase):
    def test_local_executor_fallback_resolves_historical_executor_aliases(self) -> None:
        fallback = local_executor_fallback("chatgpt_pro_5_5_extended_reasoning_browser")

        self.assertEqual(fallback["key"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(fallback["requested_key"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertEqual(fallback["dispatch_mode"], "browser_automation")

    def test_manual_prompt_contains_no_blind_acceptance_rule(self) -> None:
        task = "Security review the contractor redaction flow."
        route = classify_work(task, external_ok=True, share_boundary="redacted-packet", requested_roles=["security"])
        prompt = render_prompt(task, route)
        self.assertIn("outside model contractor", prompt)
        self.assertIn("scored by an evaluator", prompt)
        self.assertIn("Share boundary", prompt)
        self.assertIn("CONTRACTOR RETURN TEMPLATE - COPY EXACTLY", prompt)
        self.assertIn("Output only the contractor return", prompt)
        self.assertIn("Do not include a preamble", prompt)

    def test_raw_external_manual_prompt_cli_requires_degraded_flag(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_manual_dispatch_prompt.py"),
                "Security review the contractor redaction flow.",
                "--external-ok",
                "--share-boundary",
                "redacted-packet",
                "--requested-role",
                "security",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("external manual prompts require --packet", result.stderr)

    def test_raw_external_manual_prompt_cli_requires_rehearsal(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_manual_dispatch_prompt.py"),
                "Security review the contractor redaction flow.",
                "--external-ok",
                "--share-boundary",
                "redacted-packet",
                "--requested-role",
                "security",
                "--allow-raw-manual-prompt",
                "--waiver-reason",
                "test degraded manual prompt",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--allow-raw-manual-prompt requires --rehearsal", result.stderr)

    def test_dispatch_no_audit_requires_rehearsal(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "dispatch_work.py"),
                "Security review the contractor redaction flow.",
                "--no-audit",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--no-audit is allowed only with --rehearsal", result.stderr)

    def test_packet_prompt_contains_assignment_and_required_sections(self) -> None:
        packet = {
            "dispatch_id": "dispatch-test",
            "executor": "claude_code_manual",
            "bead_id": "cwo-1",
            "job_description_label": "contract-jd-security-reasoning",
            "share_boundary": "redacted-packet",
            "degraded_context_justification": "",
            "boundary_description": "Share only redacted snippets.",
            "bead_summary": {"id": "cwo-1", "title": "Security review"},
            "included_artifacts": [{"type": "assignment_summary", "sha256": "abc"}],
            "selected_snippets": [{"path": "policy/share-boundaries.yaml", "content": "token=[REDACTED]"}],
            "review_surface_contract": {
                "review_surface": "packet-only",
                "source_inspection": "packet-only",
                "allowed_actions": ["read this packet"],
                "forbidden_actions": ["shell execution"],
                "go_rule": "Do not return unconditional GO when source inspection is required but absent.",
                "required_disclosures": ["Review surface", "Source inspection"],
            },
            "required_return_sections": ["Status", "Evidence", "Recommended next bead"],
            "packet_sha256": "def",
        }
        prompt = render_packet_prompt(packet)
        self.assertIn("Dispatch ID: dispatch-test", prompt)
        self.assertIn("contract-jd-security-reasoning", prompt)
        self.assertIn("Recommended next bead", prompt)
        self.assertIn("CONTRACTOR RETURN TEMPLATE - COPY EXACTLY", prompt)
        self.assertIn("Patch authorization:", prompt)
        self.assertIn("Review surface contract:", prompt)
        self.assertIn("packet-only", prompt)
        self.assertIn("do not return an unconditional GO", prompt)
        self.assertIn("Do not mutate the active checkout", prompt)
        self.assertIn("do not claim peer review is unnecessary", prompt)
        self.assertIn("token=[REDACTED]", prompt)

    def test_packet_prompt_contains_degraded_justification(self) -> None:
        packet = {
            "dispatch_id": "dispatch-test",
            "executor": "claude_code_manual",
            "bead_id": "cwo-1",
            "job_description_label": "contract-jd-security-reasoning",
            "share_boundary": "redacted-packet",
            "degraded_context_justification": "The user explicitly requested a minimal packet.",
            "boundary_description": "Share only redacted snippets.",
            "bead_summary": {"id": "cwo-1", "title": "Security review"},
            "included_artifacts": [{"type": "assignment_summary", "sha256": "abc"}],
            "selected_snippets": [],
            "required_return_sections": ["Status", "Evidence", "Recommended next bead"],
            "packet_sha256": "def",
            "expert_profile": None,
            "expert_profile_included": False,
        }
        prompt = render_packet_prompt(packet)
        self.assertIn("Degraded-context justification:", prompt)
        self.assertIn("minimal packet", prompt)

    def test_dispatch_packet_validation_accepts_built_packet(self) -> None:
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={
                "id": "cwo-1",
                "title": "Security review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
            },
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=["token=[REDACTED]"],
            dispatch_id="dispatch-valid",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        require_valid_contractor_packet(packet)
        self.assertEqual(packet["review_surface_contract"]["review_surface"], "packet-only")
        self.assertEqual(packet["packet_version"], 2)
        self.assertEqual(packet["expected_return_language"], "en")
        self.assertIn("Review surface", packet["required_return_sections"])

    def test_gemini_agy_architecture_critic_packet_is_provider_bound(self) -> None:
        packet = build_packet(
            bead_id="cwo-arch-1",
            bead_json={
                "id": "cwo-arch-1",
                "title": "Gemini architect critique",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-architecture-reasoning"],
            },
            executor="gemini_architecture_critic",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-architecture-reasoning",
            allowed_files=[],
            inline_snippets=["Design scope: critique the proposed architecture, do not implement it."],
            dispatch_id="dispatch-gemini-critic",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        require_valid_contractor_packet(packet)
        self.assertEqual(packet["provider_key"], "google_gemini_manual")
        self.assertEqual(packet["provider_trust_tier"], "external-frontier")
        self.assertTrue(packet["expert_profile_included"])
        self.assertEqual(packet["expert_profile"]["path"], "experts/architecture.md")
        prompt = render_packet_prompt(packet)
        self.assertIn("gemini_architecture_critic", prompt)
        self.assertIn("contract-jd-architecture-reasoning", prompt)
        self.assertIn("Do not mutate the active checkout", prompt)
        self.assertIn("Output only the contractor return", prompt)

    def test_claude_opus_architecture_critic_prompt_and_packet_include_model_and_effort(self) -> None:
        route = classify_work(
            "Use Claude Opus 4.6 as a second opinion critique of the Codex architect design.",
            external_ok=True,
            share_boundary="redacted-packet",
            requested_roles=["architecture"],
        )
        prompt = render_prompt("Architecture critique", route)
        self.assertIn("Manual dispatch command: claude --model claude-opus-4-6 --effort high -p", prompt)
        self.assertIn("Architecture critic contracts:", prompt)

        packet = build_packet(
            bead_id="cwo-arch-2",
            bead_json={
                "id": "cwo-arch-2",
                "title": "Claude architect critique",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-architecture-reasoning"],
            },
            executor="claude_architecture_critic",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-architecture-reasoning",
            allowed_files=[],
            inline_snippets=["Design scope: critique the proposed architecture, do not implement it."],
            dispatch_id="dispatch-claude-critic",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        require_valid_contractor_packet(packet)
        self.assertEqual(packet["provider_key"], "anthropic_manual")
        self.assertEqual(packet["manual_command"], "claude --model claude-opus-4-6 --effort high -p")
        packet_prompt = render_packet_prompt(packet)
        self.assertIn("claude_architecture_critic", packet_prompt)
        self.assertIn("Manual dispatch command: claude --model claude-opus-4-6 --effort high -p", packet_prompt)
        self.assertIn("contract-jd-architecture-reasoning", packet_prompt)

    def test_chatgpt_pro_browser_reviewer_packet_is_provider_bound(self) -> None:
        packet = build_packet(
            bead_id="cwo-plan-1",
            bead_json={
                "id": "cwo-plan-1",
                "title": "ChatGPT Pro master plan review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
            },
            executor="chatgpt_pro_browser_master_reviewer",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-master-plan-review",
            allowed_files=[],
            inline_snippets=["Final plan scope: review execution readiness, do not implement it."],
            dispatch_id="dispatch-chatgpt-plan-review",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        require_valid_contractor_packet(packet)
        self.assertEqual(packet["provider_key"], "openai_manual")
        self.assertEqual(packet["provider_trust_tier"], "external-frontier")
        self.assertTrue(packet["expert_profile_included"])
        self.assertEqual(packet["expert_profile"]["path"], "experts/master-plan-review.md")
        prompt = render_packet_prompt(packet)
        self.assertIn("chatgpt_pro_browser_master_reviewer", prompt)
        self.assertIn("contract-jd-master-plan-review", prompt)
        self.assertIn("Output only the contractor return", prompt)

    def test_dispatch_packet_validation_rejects_tampering(self) -> None:
        packet = build_packet(
            bead_id="cwo-1",
            bead_json={
                "id": "cwo-1",
                "title": "Security review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
            },
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-tampered",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        packet["executor"] = "frontier_architect"
        errors = validate_contractor_packet(packet)
        self.assertTrue(any("packet_sha256" in error for error in errors))
        self.assertTrue(any("not an outside contractor" in error for error in errors))

    def test_degraded_packet_requires_explicit_override(self) -> None:
        with self.assertRaises(SystemExit):
            build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "Security review",
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
                },
                executor="claude_code_manual",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[],
                inline_snippets=[],
                dispatch_id="dispatch-degraded-missing-reason",
                include_expert_profile=False,
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )

        packet = build_packet(
            bead_id="cwo-1",
            bead_json={
                "id": "cwo-1",
                "title": "Security review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
            },
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-degraded",
            include_expert_profile=False,
            degraded_context_justification="The user requested a profile-free compatibility check.",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        self.assertTrue(validate_contractor_packet(packet))
        self.assertFalse(validate_contractor_packet(packet, allow_degraded_packet=True))


if __name__ == "__main__":
    unittest.main()
