from __future__ import annotations

import tempfile
import sys
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import validate_gate  # noqa: E402


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
            )
        self.assertEqual(basis, "audit-record")

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
