from __future__ import annotations

import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cwo_core.policy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_contractor_packet import build_packet  # noqa: E402
from build_contractor_packet import extract_labels  # noqa: E402
from cwo_core.util import artifact_hash, packet_payload_hash  # noqa: E402
from cwo_core.policy import load_policy  # noqa: E402
import cwo_core.packets as packet_module  # noqa: E402
from cwo_core.packets import (  # noqa: E402
    find_residual_private_context,
    fenced_block,
    redact_text,
    sanitize_bead,
    validate_contractor_packet,
)


def base_packet() -> dict:
    return build_packet(
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
        dispatch_id="dispatch-validation",
        external_opt_in=True,
        opt_in_basis="cli-flag",
    )


def rehash(packet: dict) -> dict:
    packet["packet_sha256"] = packet_payload_hash(packet)
    return packet


def policy_sensitive_field_aliases() -> list[str]:
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
        return ["token", "password", "secret"]
    return sorted(set(aliases))


def policy_with_secret_aliases(aliases: list[str]) -> dict:
    return {
        "secret_field_policy": {
            "categories": {
                "credential_tokens": ["token"],
                "extensions": aliases,
            }
        },
        "redaction_patterns": [],
    }


class PacketValidationTests(unittest.TestCase):
    def test_import_does_not_eagerly_load_malformed_share_boundaries_policy(self) -> None:
        module_name = "cwo_core.packets"
        original_module = sys.modules.pop(module_name, None)
        try:
            with patch("cwo_core.policy.load_policy", side_effect=SystemExit("broken policy file")) as mock_load:
                importlib.import_module(module_name)
            mock_load.assert_not_called()
        finally:
            if original_module is not None:
                sys.modules[module_name] = original_module
            else:
                sys.modules.pop(module_name, None)

    def test_secret_field_policy_is_structural_and_machine_readable(self) -> None:
        policy = load_policy("share-boundaries")
        secret_policy = policy.get("secret_field_policy", {})
        self.assertEqual(secret_policy.get("parser_owner"), "scripts/cwo_core/packets.py")
        categories = secret_policy.get("categories")
        self.assertIsInstance(categories, dict)
        self.assertTrue(any(
            isinstance(values, list) and values
            for values in categories.values()
        ))

    @patch("cwo_core.packets.load_policy")
    def test_mandatory_secret_field_alias_floor_is_merged(self, load_policy_mock) -> None:
        load_policy_mock.return_value = {
            "secret_field_policy": {
                "categories": {
                    "credential_tokens": ["token"],
                    "access_keys": ["api_key"],
                }
            }
        }
        aliases = packet_module._load_secret_field_aliases()
        self.assertIn("session_token", aliases)
        self.assertIn("secret", aliases)

    def test_malformed_secret_field_policy_rejects_contract_validation(self) -> None:
        packet = base_packet()
        def mocked_load_policy(policy_name: str) -> dict:
            if policy_name == "share-boundaries":
                return {"secret_field_policy": {"categories": {"credential_tokens": "token"}}}
            return cwo_core.policy.load_policy(policy_name)
        with patch("cwo_core.packets.load_policy", side_effect=mocked_load_policy):
            errors = validate_contractor_packet(rehash(packet), allow_degraded_packet=True)
        self.assertTrue(any("invalid secret-field policy configuration" in error for error in errors))

    @patch("cwo_core.packets.load_policy")
    def test_inline_file_and_profile_construction_apply_custom_secret_field_aliases(self, load_policy_mock) -> None:
        custom_alias = "vaultcache"
        custom_value = "vaultSecret01"
        load_policy_mock.return_value = policy_with_secret_aliases([custom_alias])
        with tempfile.TemporaryDirectory(dir=ROOT) as tmpdir:
            snippet_path = Path(tmpdir) / "snippet.md"
            snippet_path.write_text(f"{custom_alias}: {custom_value}\n", encoding="utf-8")
            with tempfile.TemporaryDirectory(dir=ROOT / "experts") as profile_dir:
                profile_path = Path(profile_dir) / "profile.md"
                profile_path.write_text(f"{custom_alias}: {custom_value}\n", encoding="utf-8")
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
                    inline_snippets=[f"{custom_alias}: {custom_value}"],
                    snippet_files=[snippet_path.relative_to(ROOT).as_posix()],
                    dispatch_id="dispatch-validation",
                    expert_profile_path=profile_path.relative_to(ROOT).as_posix(),
                    external_opt_in=True,
                    opt_in_basis="cli-flag",
                )
        inline_snippet = packet["selected_snippets"][0]
        file_snippet = packet["selected_snippets"][1]
        self.assertNotIn(custom_value, inline_snippet["content"])
        self.assertNotIn(custom_value, file_snippet["content"])
        self.assertNotIn(custom_value, packet["expert_profile"]["content"])
        self.assertTrue(
            all(
                not find_residual_private_context(
                    snippet["content"], require_policy_patterns=True
                )
                for snippet in packet["selected_snippets"]
            )
        )
        self.assertNotIn(custom_value, packet["expert_profile"]["content"])
        self.assertFalse(find_residual_private_context(packet["expert_profile"]["content"], require_policy_patterns=True))

    @patch("cwo_core.packets.load_policy")
    def test_patched_secret_field_policies_do_not_cross_contaminate_one_process(self, load_policy_mock) -> None:
        custom_a = "custom_a"
        custom_b = "custom_b"
        value_a = "valueA01"
        value_b = "valueB01"
        load_policy_mock.return_value = policy_with_secret_aliases([custom_a])
        packet_a = build_packet(
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
            inline_snippets=[f"{custom_a}: {value_a}", f"{custom_b}: {value_b}"],
            dispatch_id="dispatch-validation",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        self.assertNotIn(value_a, packet_a["selected_snippets"][0]["content"])
        self.assertIn(value_b, packet_a["selected_snippets"][1]["content"])

        load_policy_mock.return_value = policy_with_secret_aliases([custom_b])
        packet_b = build_packet(
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
            inline_snippets=[f"{custom_a}: {value_a}", f"{custom_b}: {value_b}"],
            dispatch_id="dispatch-validation",
            external_opt_in=True,
            opt_in_basis="cli-flag",
        )
        self.assertNotIn(value_b, packet_b["selected_snippets"][0]["content"])
        self.assertIn(value_a, packet_b["selected_snippets"][0]["content"])

    @patch("cwo_core.packets.load_policy")
    def test_malformed_secret_field_policy_fails_packet_build(self, load_policy_mock) -> None:
        load_policy_mock.return_value = {
            "secret_field_policy": {"categories": {"credential_tokens": "token"}}
        }
        with self.assertRaises(SystemExit) as exc:
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
                inline_snippets=["token: should fail redaction if bad policy"],
                dispatch_id="dispatch-validation",
                external_opt_in=True,
                opt_in_basis="cli-flag",
            )
        self.assertIn("invalid secret-field policy configuration", str(exc.exception))

    def test_malformed_secret_field_policy_fails_without_packet_build(self) -> None:
        packet = base_packet()
        def mocked_load_policy(policy_name: str) -> dict:
            if policy_name == "share-boundaries":
                return {
                    "secret_field_policy": {
                        "categories": {"credential_tokens": "token"},
                    }
                }
            return cwo_core.policy.load_policy(policy_name)
        with patch("cwo_core.packets.load_policy", side_effect=mocked_load_policy):
            errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("invalid secret-field policy configuration" in error for error in errors))

    @patch("cwo_core.packets.load_policy")
    def test_compact_mandatory_aliases_remain(self, load_policy_mock) -> None:
        load_policy_mock.return_value = {
            "secret_field_policy": {"categories": {"credential_tokens": ["token"]}}
        }
        raw = "accesskey: stillsecret"
        redacted = redact_text(raw, require_policy_patterns=True)
        self.assertNotIn("stillsecret", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_rejects_forbidden_fields_in_bead_summary(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["comments"] = "raw comment thread"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("forbidden boundary fields" in error for error in errors))

    def test_sanitize_bead_does_not_share_metadata_for_external_boundaries(self) -> None:
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
        self.assertNotIn("metadata", summary)

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
        self.assertNotIn("metadata", first)

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
        self.assertTrue(any("exactly one primary job-description label" in error for error in errors))

    def test_rejects_missing_contractor_guard_labels_at_dispatch_validation(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["labels"] = ["contract-jd-security-reasoning"]
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("contractor guard labels" in error for error in errors))

    def test_rejects_missing_primary_job_description_label_at_dispatch_validation(self) -> None:
        packet = base_packet()
        packet["bead_summary"]["labels"] = ["contractor-only", "no-codex-exec"]
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("exactly one primary job-description label" in error for error in errors))

    def test_redaction_covers_common_secret_assignment_forms(self) -> None:
        raw = "\n".join(
            [
                "private_key=abc123",
                "AWS_SECRET_ACCESS_KEY=abc123",
                "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI",
                "client_secret: plain",
            ]
        )
        redacted = redact_text(raw)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("eyJhbGci", redacted)
        self.assertNotIn("plain", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_prose_secret_labels_preserve_ordinary_values(self) -> None:
        raw = "mixed-script token: 45; score, token: ordinary, and time remain visible"
        self.assertEqual(redact_text(raw), raw)
        self.assertFalse(find_residual_private_context(raw))

    def test_prose_secret_labels_redact_high_confidence_credentials(self) -> None:
        raw = "Use token: abc123 and password: 123456 only in this synthetic example."
        redacted = redact_text(raw)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("123456", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_structural_secret_fields_redact_short_and_multiword_values(self) -> None:
        raw = "\r\n".join(
            [
                "token: 45",
                "- password: ordinary words",
                '1. client_secret: "two words"',
                '{"token": 45, "safe": 1}',
                "export TOKEN=abc123",
                "password plaintextsecret",
            ]
        )
        redacted = redact_text(raw)
        for secret in ["45", "ordinary words", "two words", "abc123", "plaintextsecret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn('"safe": 1', redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_prefixed_sensitive_keys_are_redacted_with_structural_values(self) -> None:
        raw = "\n".join(
            [
                "x-api-key: abc123",
                "x-access-token=short",
                "my_access_key: safe",
                "x_access_token: safe",
            ]
        )
        redacted = redact_text(raw)
        for secret in ["abc123", "short", "safe"]:
            self.assertNotIn(secret, redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_policy_defined_sensitive_aliases_do_not_residual_in_validation_snippets(self) -> None:
        secret_value = "policySecret01"
        packet = base_packet()
        snippet = packet["selected_snippets"][0]
        artifact = next(
            item for item in packet["included_artifacts"] if item["type"] == "inline_snippet"
        )

        for alias in policy_sensitive_field_aliases():
            alias_hyphen = alias.replace("_", "-")
            forms = [
                f"{alias}: {secret_value}-{alias}",
                f"{alias_hyphen}= {secret_value}-{alias}",
                f"x-{alias_hyphen}: {secret_value}-{alias}",
                f'{{"{alias_hyphen}": "{secret_value}-{alias}"}}',
                f"{alias}:\n  {secret_value}-{alias}",
            ]
            redacted = redact_text("\n".join(forms))
            self.assertNotIn(f"{secret_value}-{alias}", redacted, alias)
            self.assertFalse(find_residual_private_context(redacted), alias)

            snippet["content"] = redacted
            snippet["sha256"] = artifact_hash(redacted)
            snippet["line_count"] = len(redacted.splitlines())
            artifact["sha256"] = snippet["sha256"]
            artifact["line_count"] = snippet["line_count"]
            self.assertEqual([], validate_contractor_packet(rehash(packet)), alias)

            raw = "\n".join(forms)
            snippet["content"] = raw
            snippet["sha256"] = artifact_hash(raw)
            snippet["line_count"] = len(raw.splitlines())
            artifact["sha256"] = snippet["sha256"]
            artifact["line_count"] = snippet["line_count"]
            errors = validate_contractor_packet(rehash(packet))
            self.assertTrue(any("residual private or secret-like context" in error for error in errors), alias)

    def test_compact_aliases_have_residual_validation(self) -> None:
        secret_value = "compactSecret01"
        alias = "accesskey"
        packet = base_packet()
        snippet = packet["selected_snippets"][0]
        artifact = next(
            item for item in packet["included_artifacts"] if item["type"] == "inline_snippet"
        )
        forms = [
            f"{alias}: {secret_value}",
            f"{alias}= {secret_value}",
            f"x-{alias}: {secret_value}",
            f'{{"{alias}": "{secret_value}"}}',
            f"{alias}:\n  {secret_value}",
        ]
        redacted = redact_text("\n".join(forms))
        self.assertNotIn(secret_value, redacted)
        self.assertFalse(find_residual_private_context(redacted))

        snippet["content"] = redacted
        snippet["sha256"] = artifact_hash(redacted)
        snippet["line_count"] = len(redacted.splitlines())
        artifact["sha256"] = snippet["sha256"]
        artifact["line_count"] = snippet["line_count"]
        self.assertEqual([], validate_contractor_packet(rehash(packet)))

        raw = "\n".join(forms)
        snippet["content"] = raw
        snippet["sha256"] = artifact_hash(raw)
        snippet["line_count"] = len(raw.splitlines())
        artifact["sha256"] = snippet["sha256"]
        artifact["line_count"] = snippet["line_count"]
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("residual private or secret-like context" in error for error in errors))

    def test_multiline_sensitive_key_skips_comment_and_blank_lines(self) -> None:
        raw = "\r\n".join(
            [
                "token:",
                "  # explanatory comment",
                "",
                "  plaintextsecret",
                "x-access-token:",
                "  # ignore this line",
                "  safe",
                "my_access_key:",
                "  ",
                "  # another comment",
                "  secondsecret",
            ]
        )
        redacted = redact_text(raw)
        for secret in ["plaintextsecret", "safe", "secondsecret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn("# explanatory comment", redacted)
        self.assertIn("# ignore this line", redacted)
        self.assertIn("# another comment", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_multiline_list_with_comment_lines_is_fully_redacted(self) -> None:
        raw = "\n".join(
            [
                "password:",
                "  # list header",
                "  - one",
                "  ",
                "  # inline separator",
                "  - safe",
                "  - # comment-only item",
                "  - secondsecret",
            ]
        )
        redacted = redact_text(raw)
        for secret in ["one", "safe", "secondsecret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn("# list header", redacted)
        self.assertIn("# inline separator", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_multiline_json_secret_scalars_are_redacted(self) -> None:
        raw = "\n".join(
            [
                "{",
                '  "token":',
                '    "plaintextsecret",',
                '  "password":',
                '    "secondsecret",',
                '  "safe": "keep-this"',
                "}"
            ]
        )
        redacted = redact_text(raw)
        for secret in ["plaintextsecret", "secondsecret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn('"safe": "keep-this"', redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_yaml_multiline_list_scalar_values_are_redacted(self) -> None:
        raw = "\n".join(
            [
                "token:",
                "  - plaintextsecret  # top item",
                '  - "quotedsecret"',
                "  - safe",
                "notes: safe",
            ]
        )
        redacted = redact_text(raw)
        for secret in ["plaintextsecret", "quotedsecret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn("notes: safe", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_nested_multiline_mapping_is_not_consumed_as_scalar(self) -> None:
        raw = "\n".join(
            [
                "token:",
                "  {",
                '    "password": "nestedsecret",',
                '    "safe": "safe"',
                "  }",
            ]
        )
        redacted = redact_text(raw)
        self.assertNotIn("nestedsecret", redacted)
        self.assertIn('"safe": "safe"', redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_multiline_nested_mapping_is_not_consumed_as_scalar(self) -> None:
        raw = "\n".join(
            [
                '{',
                '  "token":',
                "  {",
                '    "password": "nestedsecret",',
                '    "safe": "ok"',
                "  }",
                "}"
            ]
        )
        redacted = redact_text(raw)
        self.assertNotIn("nestedsecret", redacted)
        self.assertIn('"safe": "ok"', redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_markdown_headings_explanatory_text_and_inline_assignments(self) -> None:
        raw = "### Password: plaintextsecret\nIn docs, Password: plaintextsecret;\n"
        redacted = redact_text(raw)
        self.assertIn("### Password: plaintextsecret", redacted)
        self.assertIn("In docs, Password: [REDACTED];", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_plain_words_following_sensitive_terms_are_not_redacted(self) -> None:
        raw = "password management"
        self.assertEqual(redact_text(raw), raw)

    def test_empty_or_null_multiline_values(self) -> None:
        raw = "\n".join(["token:", "  ", "password:", "  null", "safe:", "  value"])
        redacted = redact_text(raw)
        self.assertIn("token:", redacted)
        self.assertIn("safe:", redacted)
        self.assertNotIn("null", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_repeated_redaction_is_fixed_point(self) -> None:
        raw = "\n".join(["In notes, Password: plaintextsecret", 'token:', '  "plaintextsecret"', ""])
        redacted_once = redact_text(raw)
        redacted_twice = redact_text(redacted_once)
        self.assertEqual(redacted_once, redacted_twice)
        self.assertFalse(find_residual_private_context(redacted_once))

    def test_comment_and_blank_continuation_is_idempotent(self) -> None:
        raw = "\r\n".join(
            [
                "token:",
                "  # explanatory comment",
                "  ",
                "  # ignored note",
                "  plaintextsecret",
            ]
        )
        redacted_once = redact_text(raw)
        redacted_twice = redact_text(redacted_once)
        self.assertEqual(redacted_once, redacted_twice)
        self.assertFalse(find_residual_private_context(redacted_once))

    def test_residual_scan_aligns_with_multiline_redaction(self) -> None:
        raw = "\r\n".join(
            [
                "token:",
                "  # explanatory comment",
                "  plaintextsecret",
            ]
        )
        self.assertTrue(find_residual_private_context(raw))
        self.assertFalse(find_residual_private_context(redact_text(raw)))

    def test_rejects_packet_with_residual_unbalanced_inline_container(self) -> None:
        packet = base_packet()
        packet["selected_snippets"][0]["content"] = "\n".join(
            [
                "[",
                "  token: {",
                '    "password": "plaintextsecret"',
                "  notes: visible",
                "]",
            ]
        )
        packet["selected_snippets"][0]["sha256"] = artifact_hash(packet["selected_snippets"][0]["content"])
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("residual private or secret-like context" in error for error in errors))

    def test_line_start_prose_is_not_a_whitespace_assignment(self) -> None:
        for raw in [
            "Token handling remains a policy concern.",
            "TOKEN handling remains a policy concern.",
            "# Token handling.",
        ]:
            self.assertEqual(redact_text(raw), raw)
            self.assertFalse(find_residual_private_context(raw))

    def test_structural_values_keep_comment_markers_inside_quotes_and_redact_semicolons(self) -> None:
        raw = 'token: "part one # part two" # note\nconnection_string: Server=host;User=name;Password=value'
        redacted = redact_text(raw)
        self.assertNotIn("part one", redacted)
        self.assertNotIn("part two", redacted)
        self.assertIn("# note", redacted)
        self.assertNotIn("Server=host", redacted)
        self.assertNotIn("User=name", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_yaml_block_and_multiline_quoted_values_are_fully_redacted(self) -> None:
        raw = (
            'token: |\n  plaintextsecret\n  second line\nsafe: ok\n'
            '- token: |\n    list secret\n  safe: preserved\n'
            'password: "first line\n  second secret"\n'
        )
        redacted = redact_text(raw)
        for secret in ["plaintextsecret", "second line", "list secret", "first line", "second secret"]:
            self.assertNotIn(secret, redacted)
        self.assertIn("safe: ok", redacted)
        self.assertIn("safe: preserved", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_malformed_inline_structure_fails_closed(self) -> None:
        raw = '{"token": "plaintextsecret"'
        redacted = redact_text(raw)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_markdown_blockquote_field_is_structural(self) -> None:
        raw = "> password: plaintextsecret\n> In prose, token: 45 remains ordinary."
        redacted = redact_text(raw)
        self.assertNotIn("plaintextsecret", redacted)
        self.assertIn("token: 45", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_redaction_sentinel_is_stable_only_as_complete_value(self) -> None:
        stable = "token=[REDACTED]"
        self.assertEqual(redact_text(stable), stable)
        tainted = "token=[REDACTED] trailing material"
        self.assertEqual(redact_text(tainted), stable)
        self.assertFalse(find_residual_private_context(stable))
        self.assertTrue(find_residual_private_context(tainted))

    def test_markdown_and_fenced_code_use_logical_line_field_position(self) -> None:
        raw = "```env\nTOKEN=abc123\n```\n> In prose, token: 45 remains ordinary.\n"
        redacted = redact_text(raw)
        self.assertNotIn("abc123", redacted)
        self.assertIn("token: 45", redacted)
        self.assertFalse(find_residual_private_context(redacted))

    def test_recursive_secret_key_with_non_string_value_is_residual(self) -> None:
        self.assertEqual(find_residual_private_context({"metadata": {"token": 42}}), ["metadata.token"])

    def test_rejects_residual_secret_like_assignments_in_packet_content(self) -> None:
        packet = base_packet()
        packet["selected_snippets"][0]["content"] = "private_key=abc123"
        packet["selected_snippets"][0]["sha256"] = "tampered"
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("residual private or secret-like context" in error for error in errors))

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
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
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
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
                },
                executor="chatgpt_pro_browser_master_reviewer",
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
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"],
                },
                executor="chatgpt_pro_browser_master_reviewer",
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
                    executor="chatgpt_pro_browser_master_reviewer",
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
                    executor="chatgpt_pro_browser_master_reviewer",
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
                    executor="chatgpt_pro_browser_master_reviewer",
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
                    executor="chatgpt_pro_browser_master_reviewer",
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
                        executor="chatgpt_pro_browser_master_reviewer",
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
                executor="chatgpt_pro_browser_master_reviewer",
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
