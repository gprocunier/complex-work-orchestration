from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from cwo_core.packets import (
    find_residual_private_context,
    redact_text,
)  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402


def sensitive_field_aliases() -> list[str]:
    policy = load_policy("share-boundaries")
    categories = policy.get("secret_field_policy", {}).get("categories", {})
    aliases: list[str] = []
    if isinstance(categories, dict):
        for values in categories.values():
            if not isinstance(values, list):
                continue
            aliases.extend(
                alias.strip().lower()
                for alias in values
                if isinstance(alias, str) and alias.strip()
            )
    if not aliases:
        aliases = ["token", "password", "secret"]
    return sorted(set(aliases))


class RedactionTests(unittest.TestCase):
    def test_redacted_packet_omits_full_bead_comments(self) -> None:
        bead = json.loads((ROOT / "examples" / "sample-bead.json").read_text(encoding="utf-8"))
        packet = build_packet(
            bead_id=bead["id"],
            bead_json=bead,
            executor="claude_code_manual",
            share_boundary="redacted-packet",
            job_description_label="contract-jd-security-reasoning",
            allowed_files=[],
            inline_snippets=["token=abc123 should be redacted"],
            dispatch_id="dispatch-test",
        )
        rendered = json.dumps(packet, sort_keys=True)
        self.assertNotIn("This comment must not appear", rendered)
        self.assertNotIn("token=abc123", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(packet["share_boundary"], "redacted-packet")
        self.assertTrue(packet["packet_sha256"])

    def test_redacted_packet_handles_multiline_comment_continuation(self) -> None:
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
            inline_snippets=[
                "token:\r\n  # explanatory comment\r\n  plaintextsecret",
                "x_access_key: safe",
            ],
            dispatch_id="dispatch-test",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        snippet = packet["selected_snippets"][0]["content"]
        self.assertNotIn("plaintextsecret", snippet)
        self.assertNotIn("safe", snippet)
        self.assertIn("[REDACTED]", snippet)
        self.assertIn("# explanatory comment", snippet)

    def test_comment_form_sensitive_assignments_redact_value_only(self) -> None:
        raw = "\n".join(
            [
                "# token: abc123",
                "# x-api-key = plaintextsecret",
                "# Plain explanatory comment",
            ]
        )
        redacted = redact_text(raw)
        self.assertIn("# token: [REDACTED]", redacted)
        self.assertIn("# x-api-key = [REDACTED]", redacted)
        self.assertIn("# Plain explanatory comment", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("plaintextsecret", redacted)

    def test_comment_assignment_while_multiline_scalar_is_pending(self) -> None:
        raw = "\n".join(
            [
                "token:",
                "  # x-api-key = plaintextsecret",
                "  # explanatory comment",
                "  secondsecret",
                "notes: visible",
            ]
        )
        redacted = redact_text(raw)
        self.assertIn("  # x-api-key = [REDACTED]", redacted)
        self.assertIn("  # explanatory comment", redacted)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertNotIn("secondsecret", redacted)
        self.assertIn("token:", redacted)
        self.assertIn("notes: visible", redacted)

    def test_nested_comment_assignments(self) -> None:
        raw = "\n".join(
            [
                "{",
                '  "section": "start",',
                "  # token: abc123",
                '  "notes": "visible"',
                "}",
            ]
        )
        redacted = redact_text(raw)
        self.assertIn('# token: [REDACTED]', redacted)
        self.assertIn('"notes": "visible"', redacted)
        self.assertNotIn("abc123", redacted)

    def test_multiline_inline_json_object_under_sensitive_key_is_whole_replaced(self) -> None:
        raw = "\n".join(
            [
                '{',
                '  "token": {',
                '    "password": "plaintextsecret",',
                '    "safe": "safe-value"',
                "  },",
                '  "notes": "ok"',
                "}",
            ]
        )
        redacted = redact_text(raw)
        redacted_payload = json.loads(redacted)
        self.assertEqual(redacted_payload["token"], "[REDACTED]")
        self.assertEqual(redacted_payload["notes"], "ok")
        self.assertNotIn("plaintextsecret", redacted)
        self.assertNotIn("safe-value", redacted)

    def test_multiline_inline_json_list_under_sensitive_key_is_whole_replaced(self) -> None:
        raw = "\n".join(
            [
                '{',
                '  "token": [',
                '    "firstsecret",',
                '    "safesecret"',
                "  ],",
                '  "notes": "keep"',
                "}",
            ]
        )
        redacted = redact_text(raw)
        redacted_payload = json.loads(redacted)
        self.assertEqual(redacted_payload["token"], "[REDACTED]")
        self.assertEqual(redacted_payload["notes"], "keep")
        self.assertNotIn("firstsecret", redacted)
        self.assertNotIn("safesecret", redacted)

    def test_multiline_container_with_nested_delimiters_in_quoted_strings(self) -> None:
        raw = "\n".join(
            [
                "token: {",
                '  "password": "literal with {braces} and [brackets] kept inside",',
                '  "safe": "value",',
                "  \"note\": \"text\"",
                "}"
            ]
        )
        redacted = redact_text(raw)
        self.assertEqual(redacted.count("[REDACTED]"), 1)
        self.assertNotIn("{braces}", redacted)
        self.assertNotIn("[brackets]", redacted)

    def test_multiline_container_with_escaped_quotes(self) -> None:
        raw = "\n".join(
            [
                'token: {"password":"before \\"inner\\" token",',
                '  "safe":"keep"',
                "}"
            ]
        )
        redacted = redact_text(raw)
        self.assertNotIn("before ", redacted)
        self.assertNotIn("safe", redacted)
        self.assertNotIn("inner", redacted)

    def test_inline_container_with_trailing_comma_context(self) -> None:
        raw = "\n".join(
            [
                '{',
                '  "token": {',
                '    "password": "plaintextsecret"',
                "  },",
                '  "safe": "keep"',
                "}"
            ]
        )
        redacted = redact_text(raw)
        redacted_payload = json.loads(redacted)
        self.assertEqual(redacted_payload["token"], "[REDACTED]")
        self.assertEqual(redacted_payload["safe"], "keep")
        self.assertNotIn("plaintextsecret", redacted)

    def test_yaml_flow_container_redaction_stays_parseable(self) -> None:
        raw = "\n".join(
            [
                "token: {password: plaintextsecret, safe: keep}",
                "list: [first, second]",
                'notes: "safe"',
            ]
        )
        redacted = redact_text(raw)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertIn('token: "[REDACTED]"', redacted)
        self.assertNotIn("safe: keep", redacted)

    def test_compact_aliases_are_covered(self) -> None:
        secret = "compactPolicySecret01"
        for raw in [
            f"accesskey: {secret}",
            f"api_accesskey={secret}",
            f"x-accesskey: {secret}",
            f'"accesskey": "{secret}"',
        ]:
            redacted = redact_text(raw)
            self.assertNotIn(secret, redacted)
            self.assertIn("[REDACTED]", redacted)
            self.assertFalse(find_residual_private_context(redacted))

    def test_policy_driven_sensitive_aliases_cover_structural_forms(self) -> None:
        aliases = sensitive_field_aliases()
        secret = "policySecret01"
        for alias in aliases:
            with self.subTest(alias=alias):
                alias_hyphen = alias.replace("_", "-")
                cases = [
                    f"{alias}: {secret}",
                    f"{alias.upper()}= {secret}",
                    f"x-{alias_hyphen}: {secret}",
                    f"{alias_hyphen}: {secret}",
                    f"\"{alias_hyphen}\": \"{secret}\"",
                    f"{alias}:\n  {secret}\nnotes: keep-this-safe",
                    f'{{"{alias_hyphen}": "{secret}"}}',
                ]
                for raw in cases:
                    redacted = redact_text(raw)
                    self.assertNotIn(secret, redacted, alias)
                    self.assertIn("[REDACTED]", redacted, alias)
                    self.assertFalse(find_residual_private_context(redacted), alias)
                redacted_multiline = redact_text(f"{alias}:\n  {secret}\nnotes: keep-this-safe")
                self.assertIn("notes: keep-this-safe", redacted_multiline, alias)

    def test_unbalanced_inline_container_fails_conservatively(self) -> None:
        raw = "\n".join(
            [
                "token: {",
                '  "password": "plaintextsecret",',
                '  "safe": "keep"',
                "notes: visible",
                "more_notes: safe",
            ]
        )
        redacted = redact_text(raw)
        self.assertIn("token: {", redacted)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertIn("notes: visible", redacted)
        self.assertIn("more_notes: safe", redacted)
        self.assertTrue(find_residual_private_context(redacted))

    def test_unbalanced_inline_container_does_not_consume_outer_close(self) -> None:
        raw = "\n".join(
            [
                "[",
                "  token: {",
                '    "password": "plaintextsecret"',
                "  notes: visible",
                "]",
            ]
        )
        redacted = redact_text(raw)
        self.assertIn("  token: {", redacted)
        self.assertIn("  notes: visible", redacted)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertTrue(find_residual_private_context(redacted))
        self.assertIn("]", redacted)

    def test_inline_container_redaction_is_idempotent(self) -> None:
        raw = "\n".join(
            [
                '{',
                '  "token": {',
                '    "password": "plaintextsecret"',
                "  },",
                '  "password": "othersecret",',
                "}"
            ]
        )
        redacted_once = redact_text(raw)
        redacted_twice = redact_text(redacted_once)
        self.assertEqual(redacted_once, redacted_twice)


if __name__ == "__main__":
    unittest.main()
