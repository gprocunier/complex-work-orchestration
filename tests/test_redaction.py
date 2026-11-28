from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from cwo_core import packets  # noqa: E402
from cwo_core.packets import (
    find_residual_private_context,
    redact_text,
)  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402
from cwo_core.util import artifact_hash, packet_payload_hash  # noqa: E402


# Generate AWS-shaped test values from fixed dummy material. Thirty bytes
# encode to 40 characters, and the binary suffix ensures slash coverage.
_AWS_ACCESS_ID, _AWS_TEMPORARY_ID = (
    f"{prefix}SYNTHETIC{number:07d}" for number, prefix in enumerate(("AKIA", "ASIA"), start=1)
)
_AWS_NUMERIC_ID = "AKIA" + "".join(str(index % 10) for index in range(16))
_AWS_SECRET_STEM = b"synthetic-aws-fixture".ljust(27, b"-")
_AWS_SECRET_ALNUM = base64.b64encode(_AWS_SECRET_STEM + b"002").decode("ascii")
_AWS_SECRET_WITH_SLASH = base64.b64encode(_AWS_SECRET_STEM + b"\xff\x00\x00").decode("ascii")

# Each synthetic probe records every private fragment whose survival would count as a leak.
PACKET_PROBES = {
    "database URL": (
        ("Connect with postgres://demo_owner:demo-pass%2B1@db.invalid:5432/project.",
         ("demo_owner", "demo-pass%2B1")),
        ("DATABASE_URL=mysql://sampleuser:sample-password@sql.invalid/main", ("sampleuser", "sample-password")),
        ("Try mongodb+srv://reader:p%40ssword@cluster.invalid/test?retryWrites=true",
         ("reader", "p%40ssword")),
        ("Endpoint `redis://:cache-credential@[::1]:6379/0` is down.", ("cache-credential",)),
        ('"dsn": "postgresql+psycopg://pipeline_user@db.invalid/db"', ("pipeline_user",)),
        ("Use JDBC jdbc:postgresql://robot%40trial:p%3Ass@db.invalid/app", ("robot%40trial", "p%3Ass")),
    ),
    "AWS key": (
        (f"Use {_AWS_ACCESS_ID} for access.", (_AWS_ACCESS_ID,)),
        (f"The temporary access ID ({_AWS_TEMPORARY_ID}) was supplied.", (_AWS_TEMPORARY_ID,)),
        (f"The key is {_AWS_SECRET_WITH_SLASH} here.", (_AWS_SECRET_WITH_SLASH,)),
        (f"An AWS secret access key {_AWS_SECRET_ALNUM} appeared.", (_AWS_SECRET_ALNUM,)),
        ("AWS_SECRET_ACCESS_KEY=SampleCredentialMaterial0123456789", ("SampleCredentialMaterial0123456789",)),
        (f"AWS_ACCESS_KEY_ID: {_AWS_NUMERIC_ID}", (_AWS_NUMERIC_ID,)),
    ),
    "email": (
        ("Send a note to jane.doe@example.invalid.", ("jane.doe@example.invalid",)),
        ("<trial+alias@example.com> was the sender.", ("trial+alias@example.com",)),
        ("Reply to mailto:person@example.net?subject=status", ("person@example.net",)),
        ('{"owner_email":"rene@example.org"}', ("rene@example.org",)),
        ("The mailbox was TEAM_123@SUB.EXAMPLE.INVALID; no reply arrived.", ("TEAM_123@SUB.EXAMPLE.INVALID",)),
    ),
    "phone": (
        ("Call (202) 555-0142 after lunch.", ("(202) 555-0142",)),
        ("Use 202.555.0143 for example calls.", ("202.555.0143",)),
        ("The callback was +1-202-555-0144.", ("+1-202-555-0144",)),
        ("Dial +44 20 7946 0958 for the demo.", ("+44 20 7946 0958",)),
        ("Use +442079460959 for the fixture.", ("+442079460959",)),
    ),
    "person name": (
        ("Contact Jane Doe for the report.", ("Jane Doe",)),
        ("Full name: Morgan Avery", ("Morgan Avery",)),
        ('{"name": "Élodie Martin"}', ("Élodie Martin",)),
        ("It was reviewed by Amina Rahman yesterday.", ("Amina Rahman",)),
        ("Signed by Casey J. O’Neil.", ("Casey J. O’Neil",)),
        ("Please ask Dr. Martín García-López to review.", ("Martín García-López",)),
    ),
}

PACKET_CONTROLS = (
    "postgresql://db.invalid:5432/project?connect_timeout=5",
    "https://example.invalid/docs/database-urls",
    "Git commit 2644bb55f5c64cb84fda708e96613929ff95dcbb",
    "AKIA-style identifiers are uppercase.",
    "The test started at 2026-11-27T09:20:37 and finished in 3 ms.",
    "Use /tmp/task-2026-11-27/replay.py with issue 2025550142.",
    "Contact Support Team for the public docs.",
    "Contact Customer Success Team for the public checklist.",
    "Release Notes: Database Reliability Improvements",
    "name: complex-work-orchestration",
    "FROM python:3.12-slim",
    "Review GitHub Actions and Debian Bookworm smoke tests.",
)


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
    def test_synthetic_leaks_by_class(self) -> None:
        leak_counts = {}
        missed_cases = []
        for category, rows in PACKET_PROBES.items():
            leak_counts[category] = 0
            for index, (raw, sensitive) in enumerate(rows):
                redacted = redact_text(raw)
                if any(fragment in redacted for fragment in sensitive):
                    leak_counts[category] += 1
                    missed_cases.append((category, index))
                self.assertEqual(redact_text(redacted), redacted)
                self.assertFalse(find_residual_private_context(redacted), (category, index))
        self.assertEqual(leak_counts, dict.fromkeys(PACKET_PROBES, 0), missed_cases)

    def test_residual_checks_raw_corpus_without_redaction_spans(self) -> None:
        disabled = Mock(side_effect=AssertionError("primary redaction detector called"))
        with patch.multiple(packets, _secret_spans=disabled, _person_word=disabled, _without_url_userinfo=disabled):
            for category, rows in PACKET_PROBES.items():
                for index, (raw, _sensitive) in enumerate(rows):
                    with self.subTest(category=category, index=index):
                        self.assertEqual(find_residual_private_context({"snippet": [raw]}), ["snippet[0]"])
            self.assertEqual(find_residual_private_context("Result one two three Jane Doe."), ["<root>"])

    def test_additional_contact_formats_keep_context(self) -> None:
        rows = (
            ("postgresql://fixture_user:synthetic_pw@/sample_database", "postgresql:///sample_database"),
            ("Jane Doe", "[REDACTED]"),
            ("Result one two three Jane Doe.", "Result one two three [REDACTED]."),
            ("Contact : Dinara Amos", "Contact : [REDACTED]"),
            ("Callback: `élodie@exämple.invalid`", "Callback: `[REDACTED]`"),
            ('{"phoneNumber": "2025550142"}', '{"phoneNumber": "[REDACTED]"}'),
            ("Phone: [REDACTED], mobile: 2025550142", "Phone: [REDACTED], mobile: [REDACTED]"),
            ("Dial 00 44 7700 900123 for the example.", "Dial [REDACTED] for the example."),
        )
        for raw, expected in rows:
            with self.subTest(expected=expected):
                self.assertEqual(redact_text(raw), expected)
                self.assertEqual(find_residual_private_context(raw), ["<root>"])
                self.assertFalse(find_residual_private_context(expected))

    def test_rehashed_packet_reports_profile_and_nested_private_keys_safely(self) -> None:
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
            inline_snippets=["Notes: retain this normal content."],
            dispatch_id="dispatch-test",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        self.assertEqual(packets.validate_contractor_packet(packet), [])
        profile_address = "profile-fixture@example.invalid"
        private_key_label = "mapping-fixture@example.invalid"
        private_key_value = "+1-202-555-0143"
        profile = packet["expert_profile"]
        profile["content"] += f"\nMailbox: {profile_address}"
        profile["sha256"] = artifact_hash(profile["content"])
        artifact = next(item for item in packet["included_artifacts"] if item["type"] == "expert_profile")
        artifact["sha256"] = profile["sha256"]
        packet["selected_snippets"][0]["metadata"] = {private_key_label: {"credentials": private_key_value}}
        packet["packet_sha256"] = packet_payload_hash(packet)

        errors = "\n".join(packets.validate_contractor_packet(packet))
        self.assertIn("residual private or secret-like context", errors)
        self.assertIn("expert_profile.content", errors)
        self.assertIn("packet contains forbidden boundary fields:", errors)
        self.assertIn("selected_snippets[0].metadata.<redacted-key>.credentials", errors)
        for private in (profile_address, private_key_label, private_key_value):
            self.assertNotIn(private, errors)

    def test_private_key_blocks_are_replaced_with_or_without_terminator(self) -> None:
        for label, closing in (
            ("PGP PRIVATE KEY BLOCK", "\n-----END PGP PRIVATE KEY BLOCK-----\nNext step: proceed."),
            ("PRIVATE KEY", "\n-----END PRIVATE KEY-----\nNext step: proceed."),
            ("RSA PRIVATE KEY", ""),
        ):
            with self.subTest(label=label):
                raw = f"Key material follows.\n-----BEGIN {label}-----\nSYNTHETIC-MATERIAL-123{closing}"
                redacted = redact_text(raw)
                expected = "Key material follows.\n[REDACTED]"
                self.assertEqual(redacted, expected + ("\nNext step: proceed." if closing else ""))
                self.assertTrue(find_residual_private_context(raw))
                self.assertFalse(find_residual_private_context(redacted))

    def test_rendered_redaction_keeps_normal_surrounding_content(self) -> None:
        for raw in PACKET_CONTROLS:
            with self.subTest(raw=raw):
                self.assertEqual(redact_text(raw), raw)
                self.assertFalse(find_residual_private_context(raw))
        for raw, expected in (
            (PACKET_PROBES["database URL"][0][0], "Connect with postgres://db.invalid:5432/project."),
            (PACKET_PROBES["email"][0][0], "Send a note to [REDACTED]."),
            (PACKET_PROBES["phone"][0][0], "Call [REDACTED] after lunch."),
            (PACKET_PROBES["person name"][0][0], "Contact [REDACTED] for the report."),
            (PACKET_PROBES["AWS key"][0][0], "Use [REDACTED] for access."),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(redact_text(raw), expected)
                self.assertFalse(find_residual_private_context(expected))

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

    def test_nested_sensitive_json_value_redaction_variants(self) -> None:
        variants = (
            ('test_multiline_inline_json_object_under_sensitive_key_is_whole_replaced',
             '  "token": {',
             '    "password": "plaintextsecret",',
             '    "safe": "safe-value"',
             '  },',
             '  "notes": "ok"',
             'ok',
             'plaintextsecret',
             'safe-value'),
            ('test_multiline_inline_json_list_under_sensitive_key_is_whole_replaced',
             '  "token": [',
             '    "firstsecret",',
             '    "safesecret"',
             '  ],',
             '  "notes": "keep"',
             'keep',
             'firstsecret',
             'safesecret'),
        )
        for original, opening, first_line, second_line, closing, notes_line, notes, first_secret, second_secret in variants:
            with self.subTest(original=original):
                raw = "\n".join(
                    [
                        '{',
                        opening,
                        first_line,
                        second_line,
                        closing,
                        notes_line,
                        "}",
                    ]
                )
                redacted = redact_text(raw)
                redacted_payload = json.loads(redacted)
                self.assertEqual(redacted_payload["token"], "[REDACTED]")
                self.assertEqual(redacted_payload["notes"], notes)
                self.assertNotIn(first_secret, redacted)
                self.assertNotIn(second_secret, redacted)


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
