from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from cwo_core.packets import validate_contractor_packet  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402
from generate_manual_dispatch_prompt import render_packet_prompt  # noqa: E402


def rehash(packet: dict) -> dict:
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


class PacketProfileInclusionTests(unittest.TestCase):
    def test_packet_includes_expert_profile_by_default(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-profile-test",
        )
        self.assertTrue(packet["expert_profile_included"])
        self.assertEqual(packet["expert_profile"]["path"], "experts/security.md")
        self.assertIn("Security Distinguished Engineer", packet["expert_profile"]["content"])
        artifact_types = {item["type"] for item in packet["included_artifacts"]}
        self.assertIn("expert_profile", artifact_types)

    def test_packet_can_explicitly_omit_expert_profile(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-no-profile-test",
            include_expert_profile=False,
            degraded_context_justification="The operator requested a minimal compatibility packet.",
        )
        self.assertFalse(packet["expert_profile_included"])
        self.assertIsNone(packet["expert_profile"])
        self.assertIn("minimal compatibility", packet["degraded_context_justification"])

    def test_managed_packet_requires_delivered_review_inputs(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        bead["labels"] = ["contractor-only", "no-codex-exec", "contract-jd-domain-web-design"]
        bead["metadata"] = {
            "expert": "web_design", "job_description_label": "contract-jd-domain-web-design",
            "private_context": "Private record behind a locator",
        }
        bead["description"] = "Review the public queue page."
        evidence = {
            "audience": "Queue operators opening a case for the first time",
            "screen states": "Missing owner, partial case, and a queue with 9000 entries",
            "content hierarchy": "Case summary precedes timing details",
            "accessibility constraints": "Case status has a spoken label",
            "responsive targets": "390px viewport with a single column",
            "reader journey": "See README.md#queue. Cases without owners appear first.",
        }

        def packet(**overrides):
            return build_packet(**{
                "bead_id": bead["id"], "bead_json": bead, "executor": "claude_code_manual",
                "share_boundary": "redacted-packet", "job_description_label": "contract-jd-domain-web-design",
                "allowed_files": [], "inline_snippets": [], "dispatch_id": "dispatch-review-inputs-test",
                "external_opt_in": True, "opt_in_basis": "cli-flag", **overrides,
            })

        def snippet(values):
            return ["\n".join(f"Review input [{name}]: {value}" for name, value in values.items())]

        with self.assertRaisesRegex(SystemExit, "review input.*blocked.*audience"):
            packet()
        for insufficient in (
            "token=abc123", "README.md#viewport", "[Private reviewer link](https://example.org/private)",
            "See docs/private-reader.md for details.", "Not supplied.", "Unknown!", "See attached.",
            "See private docs/reader flow.md for details.", 'Refer to "Reader flow.md".',
        ):
            with self.subTest(insufficient=insufficient), self.assertRaisesRegex(SystemExit, "responsive targets"):
                packet(inline_snippets=snippet({**evidence, "responsive targets": insufficient}))
        with self.assertRaisesRegex(SystemExit, "profile does not match the assigned job"):
            packet(inline_snippets=snippet(evidence), expert_profile_path="experts/security.md")
        complete = packet(inline_snippets=snippet(evidence))
        self.assertEqual(validate_contractor_packet(complete), [])
        prompt = render_packet_prompt(complete)
        self.assertIn("experts/web-design.md", prompt)
        self.assertNotIn("Private record behind a locator", prompt)
        for value in evidence.values():
            self.assertIn(value, prompt)
        substituted = {**complete, "expert_profile": {**complete["expert_profile"], "path": "experts/security.md"}}
        self.assertIn("profile does not match the assigned job", "; ".join(validate_contractor_packet(rehash(substituted))))
        substituted.update(expert_profile_included=False, degraded_context_justification="Omission approved.")
        errors = validate_contractor_packet(rehash(substituted), allow_degraded_packet=True)
        self.assertIn("profile does not match the assigned job", "; ".join(errors))
        reduced = {**complete, "review_surface_contract": {
            **complete["review_surface_contract"], "required_inputs": ["audience"],
        }}
        self.assertIn("do not match the assigned job", "; ".join(validate_contractor_packet(rehash(reduced))))
        complete["selected_snippets"] = []
        self.assertIn("required evidence is missing", "; ".join(validate_contractor_packet(rehash(complete))))
        bead["description"] += "\nExpert profile: experts/web-design.md"
        degraded = packet(inline_snippets=snippet(evidence), include_expert_profile=False,
                          degraded_context_justification="The operator approved a short review.")
        self.assertNotIn("experts/web-design.md", render_packet_prompt(degraded))
        bead["labels"][-1] = "contract-jd-editorial-reasoning"
        with self.assertRaisesRegex(SystemExit, "review identity does not match the assigned job"):
            packet(job_description_label="contract-jd-editorial-reasoning", inline_snippets=snippet(evidence))

    def test_caller_selected_profile_must_stay_under_experts(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        with self.assertRaises(SystemExit) as exc:
            build_packet(
                bead_id=bead["id"],
                bead_json=bead,
                executor="claude_code_manual",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[],
                inline_snippets=[],
                dispatch_id="dispatch-profile-test",
                expert_profile_path="README.md",
            )
        self.assertIn("expert profile must be", str(exc.exception))

    def test_packet_validation_rejects_missing_profile_content(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-profile-content-test",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        packet["expert_profile"].pop("content")
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("expert_profile.content" in error for error in errors))

    def test_packet_validation_rejects_profile_content_hash_mismatch(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=[],
            dispatch_id="dispatch-profile-hash-test",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        packet["expert_profile"]["content"] = "Different profile content"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("expert_profile sha256 does not match content" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
