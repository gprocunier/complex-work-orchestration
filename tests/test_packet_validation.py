from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from build_contractor_packet import extract_labels  # noqa: E402
from orchestration_lib import packet_payload_hash, sanitize_bead, validate_contractor_packet  # noqa: E402


def base_packet() -> dict:
    return build_packet(
        bead_id="cwo-1",
        bead_json={"id": "cwo-1", "title": "Security review", "labels": ["contractor-only", "no-codex-exec"]},
        executor="claude_code_manual",
        share_boundary="redacted-packet",
        job_description_label="contract-jd-security-reasoning",
        allowed_files=[],
        inline_snippets=["token=[REDACTED]"],
        dispatch_id="dispatch-validation",
        external_opt_in=True,
        opt_in_basis="cli-flag",
    )


def rehash(packet: dict) -> dict:
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


class PacketValidationTests(unittest.TestCase):
    def test_rejects_forbidden_fields_in_bead_summary(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["comments"] = "raw comment thread"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("forbidden boundary fields" in error for error in errors))

    def test_rejects_missing_mandatory_exclusions(self) -> None:
        packet = base_packet()
        packet["excluded_artifacts"] = [
            item for item in packet["excluded_artifacts"] if item["type"] != "production_access"
        ]
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("mandatory exclusions" in error for error in errors))

    def test_rejects_snippet_over_boundary_limit(self) -> None:
        packet = base_packet()
        packet["selected_snippets"][0]["line_count"] = 81
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("exceeds boundary line limit" in error for error in errors))

    def test_rejects_snippet_hash_mismatch(self) -> None:
        packet = base_packet()
        packet["selected_snippets"][0]["content"] = "token=plain"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("sha256 does not match content" in error for error in errors))

    def test_rejects_included_snippet_without_matching_payload(self) -> None:
        packet = base_packet()
        for artifact in packet["included_artifacts"]:
            if artifact.get("type") == "inline_snippet":
                artifact["path"] = "wrong-path"
                break
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("has no matching selected snippet" in error for error in errors))

    def test_rejects_assignment_summary_hash_mismatch(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["title"] = "Changed title"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("assignment_summary sha256" in error for error in errors))

    def test_inline_snippet_build_rejects_boundary_overflow(self) -> None:
        too_long = "\n".join(str(index) for index in range(81))
        with self.assertRaises(SystemExit):
            build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "Security review",
                    "labels": ["contractor-only", "no-codex-exec"],
                },
                executor="claude_code_manual",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[],
                inline_snippets=[too_long],
                dispatch_id="dispatch-validation",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )

    def test_beads_show_list_shape_keeps_labels_and_summary(self) -> None:
        bead = [
            {
                "id": "cwo-1",
                "title": "Design review",
                "labels": ["contractor-only", "no-codex-exec", "contract-jd-domain-web-design"],
                "status": "open",
            }
        ]
        self.assertIn("contractor-only", extract_labels(bead))
        summary = sanitize_bead(bead, "patch-branch")
        self.assertEqual(summary["id"], "cwo-1")
        self.assertEqual(summary["title"], "Design review")


if __name__ == "__main__":
    unittest.main()
