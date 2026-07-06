from __future__ import annotations

import tempfile
import sys
import subprocess
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import validate_gate  # noqa: E402
from cwo_core.packets import validate_contractor_packet  # noqa: E402


class PacketGateTests(unittest.TestCase):
    def test_external_packet_requires_explicit_opt_in(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with self.assertRaises(SystemExit):
            validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=None,
            )

    def test_opt_in_record_is_accepted(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "project": "complex-work-orchestration",
                    "epic_id": "epic-1",
                    "bead_id": "epic-1.1",
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["claude_code_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "expires_at": "2999-01-01T00:00:00Z",
                    "scope": "test packet",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
                bead_id="epic-1.1",
                epic_id="epic-1",
            )
        self.assertEqual(basis, "audit-record")

    def test_opt_in_record_rejects_wrong_bead_or_epic_scope(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        cases = [
            {
                "allowed": True,
                "share_boundary": "redacted-packet",
                "allowed_external_executors": ["claude_code_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00Z",
                "scope": "wrong bead",
                "bead_id": "epic-1.2",
                "epic_id": "epic-1",
            },
            {
                "allowed": True,
                "share_boundary": "redacted-packet",
                "allowed_external_executors": ["claude_code_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00Z",
                "scope": "wrong epic",
                "bead_id": "epic-1.1",
                "epic_id": "epic-2",
            },
        ]
        for record in cases:
            with self.subTest(record=record["scope"]):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
                    json.dump(record, handle)
                    handle.flush()
                    with self.assertRaises(SystemExit):
                        validate_gate(
                            "claude_code_manual",
                            "redacted-packet",
                            labels,
                            "contract-jd-security-reasoning",
                            external_ok=False,
                            opt_in_record=handle.name,
                            bead_id="epic-1.1",
                            epic_id="epic-1",
                        )

    def test_legacy_allowed_executors_field_still_works(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_executors": ["claude_code_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "legacy packet",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def test_external_contracting_allowed_field_is_accepted(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "external_contracting_allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["claude_code_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "alternate opt-in field",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def test_opt_in_record_rejects_conflicting_authorization_fields(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        cases = [
            {"allowed": True, "external_contracting_allowed": False},
            {"allowed": False, "external_contracting_allowed": True},
        ]
        for auth_fields in cases:
            with self.subTest(auth_fields=auth_fields):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            **auth_fields,
                            "share_boundary": "redacted-packet",
                            "allowed_external_executors": ["claude_code_manual"],
                            "decision_source": "test",
                            "recorded_at": "2026-06-09T00:00:00Z",
                            "scope": "conflicting opt-in",
                        },
                        handle,
                    )
                    handle.flush()
                    with self.assertRaises(SystemExit):
                        validate_gate(
                            "claude_code_manual",
                            "redacted-packet",
                            labels,
                            "contract-jd-security-reasoning",
                            external_ok=False,
                            opt_in_record=handle.name,
                        )

    def test_opt_in_record_can_scope_to_provider(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["claude_code_manual"],
                    "allowed_providers": ["anthropic_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "provider scoped packet",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "claude_code_manual",
                "redacted-packet",
                labels,
                "contract-jd-security-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def test_gemini_agy_architecture_critic_accepts_scoped_opt_in_record(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-architecture-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["gemini_3_1_pro_preview_agy"],
                    "allowed_providers": ["google_gemini_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "architecture second-opinion critique",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "gemini_3_1_pro_preview_agy",
                "redacted-packet",
                labels,
                "contract-jd-architecture-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def test_claude_opus_architecture_critic_accepts_scoped_opt_in_record(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-architecture-reasoning"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["claude_opus_4_6_architecture_critic"],
                    "allowed_providers": ["anthropic_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "architecture second-opinion critique",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "claude_opus_4_6_architecture_critic",
                "redacted-packet",
                labels,
                "contract-jd-architecture-reasoning",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def test_chatgpt_pro_browser_reviewer_accepts_scoped_opt_in_record(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["chatgpt_pro_5_5_extended_reasoning_browser"],
                    "allowed_providers": ["openai_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "ChatGPT Pro master plan review",
                },
                handle,
            )
            handle.flush()
            basis = validate_gate(
                "chatgpt_pro_5_5_extended_reasoning_browser",
                "redacted-packet",
                labels,
                "contract-jd-master-plan-review",
                external_ok=False,
                opt_in_record=handle.name,
            )
        self.assertEqual(basis, "audit-record")

    def run_packet_builder(
        self,
        *,
        executor: str,
        external_ok: bool = True,
        opt_in_record: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as bead, tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
        ) as packet:
            json.dump({"id": "epic-1.1", "title": "Alias packet", "labels": labels}, bead)
            bead.flush()
            args = [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "build_contractor_packet.py"),
                "--bead",
                "epic-1.1",
                "--bead-json-file",
                bead.name,
                "--executor",
                executor,
                "--share-boundary",
                "redacted-packet",
                "--no-audit",
                "--rehearsal",
                "--no-include-expert-profile",
                "--degraded-context-justification",
                "test degraded packet",
                "--format",
                "json",
                "--output",
                packet.name,
            ]
            if external_ok:
                args.append("--external-ok")
            if opt_in_record:
                args.extend(["--opt-in-record", opt_in_record])
            result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                result.stdout = Path(packet.name).read_text(encoding="utf-8")
            return result

    def test_packet_build_cli_canonicalizes_executor_alias(self) -> None:
        result = self.run_packet_builder(executor="chatgpt_pro_browser_master_reviewer")

        self.assertEqual(result.returncode, 0, result.stderr)
        packet = json.loads(result.stdout)
        self.assertEqual(packet["executor"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertEqual(packet["requested_executor"], "chatgpt_pro_browser_master_reviewer")
        self.assertEqual(packet["canonical_executor"], "chatgpt_pro_5_5_extended_reasoning_browser")
        self.assertEqual(validate_contractor_packet(packet, allow_degraded_packet=True), [])

    def test_packet_validation_rejects_alias_executor_artifact(self) -> None:
        result = self.run_packet_builder(executor="chatgpt_pro_browser_master_reviewer")
        self.assertEqual(result.returncode, 0, result.stderr)
        packet = json.loads(result.stdout)
        packet["executor"] = "chatgpt_pro_browser_master_reviewer"

        errors = validate_contractor_packet(packet, allow_degraded_packet=True)

        self.assertIn("packet executor 'chatgpt_pro_browser_master_reviewer' is unknown", errors)

    def test_packet_build_cli_rejects_unknown_executor_alias(self) -> None:
        result = self.run_packet_builder(executor="totally_bogus_reviewer")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown executor 'totally_bogus_reviewer'", result.stderr)

    def test_opt_in_record_alias_authorizes_canonical_executor_cli(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["chatgpt_pro_browser_master_reviewer"],
                    "allowed_providers": ["openai_manual"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "ChatGPT Pro master plan review",
                },
                handle,
            )
            handle.flush()
            result = self.run_packet_builder(
                executor="chatgpt_pro_5_5_extended_reasoning_browser",
                external_ok=False,
                opt_in_record=handle.name,
            )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_opt_in_record_wrong_alias_rejects_canonical_executor_cli(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "allowed": True,
                    "share_boundary": "redacted-packet",
                    "allowed_external_executors": ["gemini_manual_reviewer"],
                    "decision_source": "test",
                    "recorded_at": "2026-06-09T00:00:00Z",
                    "scope": "wrong executor alias",
                },
                handle,
            )
            handle.flush()
            result = self.run_packet_builder(
                executor="chatgpt_pro_5_5_extended_reasoning_browser",
                external_ok=False,
                opt_in_record=handle.name,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not allow executor 'chatgpt_pro_5_5_extended_reasoning_browser'", result.stderr)

    def test_opt_in_record_rejects_expired_or_timezone_free_records(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        cases = [
            {
                "allowed": True,
                "share_boundary": "redacted-packet",
                "allowed_external_executors": ["claude_code_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00Z",
                "expires_at": "2000-01-01T00:00:00Z",
                "scope": "expired packet",
            },
            {
                "allowed": True,
                "share_boundary": "redacted-packet",
                "allowed_external_executors": ["claude_code_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00",
                "scope": "timezone-free packet",
            },
        ]
        for record in cases:
            with self.subTest(record=record["scope"]):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
                    json.dump(record, handle)
                    handle.flush()
                    with self.assertRaises(SystemExit):
                        validate_gate(
                            "claude_code_manual",
                            "redacted-packet",
                            labels,
                            "contract-jd-security-reasoning",
                            external_ok=False,
                            opt_in_record=handle.name,
                        )

    def test_opt_in_record_rejects_wrong_boundary_or_executor(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        cases = [
            {
                "allowed": True,
                "share_boundary": "repo-readonly",
                "allowed_external_executors": ["claude_code_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00Z",
                "scope": "wrong boundary",
            },
            {
                "allowed": True,
                "share_boundary": "redacted-packet",
                "allowed_external_executors": ["openai_deep_research_manual"],
                "decision_source": "test",
                "recorded_at": "2026-06-09T00:00:00Z",
                "scope": "wrong executor",
            },
        ]
        for record in cases:
            with self.subTest(record=record["scope"]):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8") as handle:
                    json.dump(record, handle)
                    handle.flush()
                    with self.assertRaises(SystemExit):
                        validate_gate(
                            "claude_code_manual",
                            "redacted-packet",
                            labels,
                            "contract-jd-security-reasoning",
                            external_ok=False,
                            opt_in_record=handle.name,
                        )

    def test_empty_opt_in_record_is_rejected(self) -> None:
        labels = ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"]
        with tempfile.NamedTemporaryFile() as handle:
            with self.assertRaises(SystemExit):
                validate_gate(
                    "claude_code_manual",
                    "redacted-packet",
                    labels,
                    "contract-jd-security-reasoning",
                    external_ok=False,
                    opt_in_record=handle.name,
                )


if __name__ == "__main__":
    unittest.main()
