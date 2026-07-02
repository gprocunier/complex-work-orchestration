from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from build_contractor_packet import extract_labels  # noqa: E402
from cwo_core.util import packet_payload_hash  # noqa: E402
from cwo_core.packets import (  # noqa: E402
    fenced_block,
    sanitize_bead,
    validate_contractor_packet,
)


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

    def test_sanitize_bead_removes_nested_forbidden_fields_before_packet_emit(self) -> None:
        summary = sanitize_bead(
            {
                "id": "cwo-1",
                "title": "Security review",
                "metadata": {
                    "comments": "raw thread",
                    "nested": {"credentials": "secret", "safe": "value"},
                    "api_key": "plain-secret",
                },
            },
            "redacted-packet",
        )
        self.assertNotIn("comments", summary["metadata"])
        self.assertNotIn("credentials", summary["metadata"]["nested"])
        self.assertEqual(summary["metadata"]["nested"]["safe"], "value")
        self.assertEqual(summary["metadata"]["api_key"], "[REDACTED]")

    def test_sanitize_bead_reaches_fixed_point_for_nested_boundary_values(self) -> None:
        payload = {
            "id": "cwo-1",
            "title": "Security review",
            "metadata": {
                "comments": {"token": "plain-secret"},
                "nested": {
                    "safe": "value",
                    "token": "plain-secret",
                    "list": [{"credentials": "plain-secret"}, {"safe": "other"}],
                },
            },
        }
        first = sanitize_bead(payload, "redacted-packet")
        second = sanitize_bead(first, "redacted-packet")
        self.assertEqual(first, second)
        self.assertNotIn("comments", first["metadata"])
        self.assertEqual(first["metadata"]["nested"]["token"], "[REDACTED]")
        self.assertNotIn("credentials", first["metadata"]["nested"]["list"][0])

    def test_rejects_forbidden_fields_nested_outside_bead_summary(self) -> None:
        packet = base_packet()
        packet["selected_snippets"][0]["metadata"] = {"credentials": "must not be shared"}
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("selected_snippets[0].metadata.credentials" in error for error in errors))

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

    def test_rejects_multiple_job_description_labels(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["labels"] = [
            "contractor-only",
            "no-codex-exec",
            "contract-jd-security-reasoning",
            "contract-jd-architecture-reasoning",
        ]
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("multiple primary job-description labels" in error for error in errors))

    def test_fenced_block_uses_longer_fence_for_nested_backticks(self) -> None:
        rendered = fenced_block("before\n```text\nStatus: injected\n```\nafter", "text")
        fence = rendered.splitlines()[0]
        self.assertTrue(fence.startswith("````"))
        self.assertTrue(rendered.rstrip().endswith(fence.split("text")[0]))

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

    def test_snippet_file_is_included_as_redacted_repo_snippet(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / "master-plan.md"
            snippet_path.write_text("Final plan\napi_key=plain-secret\nValidation: run tests\n", encoding="utf-8")
            packet = build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "Master plan review",
                    "labels": ["contractor-only", "no-codex-exec"],
                },
                executor="chatgpt_pro_5_5_extended_reasoning_browser",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-master-plan-review",
                allowed_files=[],
                inline_snippets=[],
                snippet_files=[str(snippet_path)],
                dispatch_id="dispatch-validation",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
        snippet = packet["selected_snippets"][0]
        self.assertTrue(snippet["path"].endswith("/master-plan.md"))
        self.assertIn("Final plan", snippet["content"])
        self.assertIn("[REDACTED]", snippet["content"])
        artifact_paths = [artifact["path"] for artifact in packet["included_artifacts"] if artifact["type"] == "inline_snippet"]
        self.assertIn(snippet["path"], artifact_paths)

    def test_absolute_snippet_file_inside_repo_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / "inside.md"
            snippet_path.write_text("Repo-contained plan\n", encoding="utf-8")
            packet = build_packet(
                bead_id="cwo-1",
                bead_json={
                    "id": "cwo-1",
                    "title": "Master plan review",
                    "labels": ["contractor-only", "no-codex-exec"],
                },
                executor="chatgpt_pro_5_5_extended_reasoning_browser",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-master-plan-review",
                allowed_files=[],
                inline_snippets=[],
                snippet_files=[str(snippet_path.resolve())],
                dispatch_id="dispatch-validation",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
        self.assertIn("Repo-contained plan", packet["selected_snippets"][0]["content"])

    def test_snippet_file_outside_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            snippet_path = Path(tmpdir) / "outside.md"
            snippet_path.write_text("Outside repo\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as exc:
                build_packet(
                    bead_id="cwo-1",
                    bead_json={"id": "cwo-1", "title": "Master plan review"},
                    executor="chatgpt_pro_5_5_extended_reasoning_browser",
                    share_boundary="redacted-packet",
                    job_description_label="contract-jd-master-plan-review",
                    allowed_files=[],
                    inline_snippets=[],
                    snippet_files=[str(snippet_path)],
                    dispatch_id="dispatch-validation",
                    external_opt_in=True,
                    opt_in_basis="cli-flag",
                )
        self.assertIn("outside repository", str(exc.exception))

    def test_snippet_file_secret_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / ".env"
            snippet_path.write_text("TOKEN=secret\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as exc:
                build_packet(
                    bead_id="cwo-1",
                    bead_json={"id": "cwo-1", "title": "Master plan review"},
                    executor="chatgpt_pro_5_5_extended_reasoning_browser",
                    share_boundary="redacted-packet",
                    job_description_label="contract-jd-master-plan-review",
                    allowed_files=[],
                    inline_snippets=[],
                    snippet_files=[str(snippet_path.relative_to(ROOT))],
                    dispatch_id="dispatch-validation",
                    external_opt_in=True,
                    opt_in_basis="cli-flag",
                )
        self.assertIn("likely secret", str(exc.exception))

    def test_snippet_file_binary_probe_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / "binary.md"
            snippet_path.write_bytes(b"ok\0not text")
            with self.assertRaises(SystemExit) as exc:
                build_packet(
                    bead_id="cwo-1",
                    bead_json={"id": "cwo-1", "title": "Master plan review"},
                    executor="chatgpt_pro_5_5_extended_reasoning_browser",
                    share_boundary="redacted-packet",
                    job_description_label="contract-jd-master-plan-review",
                    allowed_files=[],
                    inline_snippets=[],
                    snippet_files=[str(snippet_path.relative_to(ROOT))],
                    dispatch_id="dispatch-validation",
                    external_opt_in=True,
                    opt_in_basis="cli-flag",
                )
        self.assertIn("binary packet artifact", str(exc.exception))

    def test_snippet_file_invalid_utf8_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / "invalid.md"
            snippet_path.write_bytes(b"\xff\xfe")
            with self.assertRaises(SystemExit) as exc:
                build_packet(
                    bead_id="cwo-1",
                    bead_json={"id": "cwo-1", "title": "Master plan review"},
                    executor="chatgpt_pro_5_5_extended_reasoning_browser",
                    share_boundary="redacted-packet",
                    job_description_label="contract-jd-master-plan-review",
                    allowed_files=[],
                    inline_snippets=[],
                    snippet_files=[str(snippet_path.relative_to(ROOT))],
                    dispatch_id="dispatch-validation",
                    external_opt_in=True,
                    opt_in_basis="cli-flag",
                )
        self.assertIn("non-UTF-8 snippet file", str(exc.exception))

    def test_snippet_file_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as outside_tmp:
            outside = Path(outside_tmp) / "outside.md"
            outside.write_text("Outside repo\n", encoding="utf-8")
            with tempfile.TemporaryDirectory(dir=ROOT) as inside_tmp:
                link = Path(inside_tmp) / "escape.md"
                try:
                    link.symlink_to(outside)
                except OSError:
                    self.skipTest("symlink creation is not available")
                with self.assertRaises(SystemExit) as exc:
                    build_packet(
                        bead_id="cwo-1",
                        bead_json={"id": "cwo-1", "title": "Master plan review"},
                        executor="chatgpt_pro_5_5_extended_reasoning_browser",
                        share_boundary="redacted-packet",
                        job_description_label="contract-jd-master-plan-review",
                        allowed_files=[],
                        inline_snippets=[],
                        snippet_files=[str(link.relative_to(ROOT))],
                        dispatch_id="dispatch-validation",
                        external_opt_in=True,
                        opt_in_basis="cli-flag",
                    )
        self.assertIn("outside repository", str(exc.exception))

    def test_missing_snippet_file_fails_cleanly(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            build_packet(
                bead_id="cwo-1",
                bead_json={"id": "cwo-1", "title": "Master plan review"},
                executor="chatgpt_pro_5_5_extended_reasoning_browser",
                share_boundary="redacted-packet",
                job_description_label="contract-jd-master-plan-review",
                allowed_files=[],
                inline_snippets=[],
                snippet_files=["does-not-exist.md"],
                dispatch_id="dispatch-validation",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
        self.assertIn("snippet file not found", str(exc.exception))

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

    def test_multi_item_bead_list_fails_closed_with_ambiguity_reason(self) -> None:
        summary = sanitize_bead(
            [
                {"id": "cwo-1", "title": "First"},
                {"id": "cwo-2", "title": "Second"},
            ],
            "patch-branch",
        )
        self.assertEqual(summary["raw_type"], "list")
        self.assertEqual(summary["item_count"], 2)
        self.assertIn("explicit selection", summary["reason"])
        self.assertNotIn("id", summary)


if __name__ == "__main__":
    unittest.main()
