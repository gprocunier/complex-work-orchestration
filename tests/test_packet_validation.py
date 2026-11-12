from __future__ import annotations

import copy
import json
import importlib
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from typing import Literal, NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.policy  # noqa: E402
from build_contractor_packet import build_packet  # noqa: E402
from build_contractor_packet import extract_labels  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402
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


def canonical_json_bytes(value: object) -> int:
    return len(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )


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


class AliasPacketCase(NamedTuple):
    original: str
    aliases: list[str]
    secret: str
    suffix_alias: bool


class SnippetFileCase(NamedTuple):
    original: str
    filename: str
    payload: bytes
    inside: bool
    path_mode: Literal["absolute", "relative", "resolved"]
    diagnostic: str | None
    present: tuple[str, ...] = ()
    check_artifact: bool = False


class PacketMutation(NamedTuple):
    original: str
    path: tuple[str | int, ...]
    variants: tuple[tuple[str, object, str], ...]


class RedactionCase(NamedTuple):
    original: str
    raw: str
    absent: tuple[str, ...] = ()
    present: tuple[str, ...] = ()
    unchanged: bool = False
    repeat: bool = False
    scan_redacted: bool = True
    raw_residual: bool | None = None


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

    def test_packet_contract_mutation_rows(self) -> None:
        baseline = base_packet()
        rows = (
            PacketMutation("test_packet_summary_validation_refusal_variants", ("bead_summary", "comments"), (
                ("test_rejects_forbidden_fields_in_bead_summary", "raw comment thread", "forbidden boundary fields"),
            )),
            PacketMutation("test_packet_summary_validation_refusal_variants", ("bead_summary", "title"), (
                ("test_rejects_assignment_summary_hash_mismatch", "Changed title", "assignment_summary sha256"),
            )),
            PacketMutation("test_rejects_forbidden_fields_nested_outside_bead_summary", ("selected_snippets", 0, "metadata"), (
                ("nested credentials", {"credentials": "must not be shared"}, "selected_snippets[0].metadata.credentials"),
            )),
            PacketMutation("test_rejects_missing_mandatory_exclusions", ("excluded_artifacts",), (
                ("production access omitted", [item for item in baseline["excluded_artifacts"]
                                               if item["type"] != "production_access"], "mandatory exclusions"),
            )),
            PacketMutation("test_rejects_malformed_dependency_shape", ("bead_summary", "dependencies"), (
                ("non-list", "not-a-list", "dependencies must be a list"),
                ("non-object item", [123], "must be a shallow projection object"),
                ("non-string id", [{"id": 123, "title": "task", "status": "open", "dependency_type": "blocks"}],
                 "must be a string or null"),
            )),
            PacketMutation("test_rejects_dependency_with_extra_fields", ("bead_summary", "dependencies"), (
                ("extra field", [{"id": "task-001", "title": "Parent task", "status": "open",
                                  "dependency_type": "blocks", "extra": "not-allowed"}],
                 "must contain exactly id, title, status, and dependency_type"),
            )),
            PacketMutation("test_rejects_snippet_over_boundary_limit", ("selected_snippets", 0, "line_count"), (
                ("81 lines", 81, "exceeds boundary line limit"),
            )),
            PacketMutation("test_rejects_snippet_hash_mismatch", ("selected_snippets", 0, "content"), (
                ("changed content", "token=plain", "sha256 does not match content"),
            )),
            PacketMutation("test_rejects_multiple_job_description_labels", ("bead_summary", "labels"), (
                ("two primary labels", ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning",
                                        "contract-jd-architecture-reasoning"], "exactly one primary job-description label"),
            )),
            PacketMutation("test_rejects_missing_contractor_guard_labels_at_dispatch_validation", ("bead_summary", "labels"), (
                ("guard labels missing", ["contract-jd-security-reasoning"], "contractor guard labels"),
            )),
            PacketMutation("test_rejects_missing_primary_job_description_label_at_dispatch_validation", ("bead_summary", "labels"), (
                ("primary label missing", ["contractor-only", "no-codex-exec"], "exactly one primary job-description label"),
            )),
        )
        for row in rows:
            # Preserve sequential dependency mutations within their original case,
            # while every original case owns a fresh, complete packet tree.
            packet = copy.deepcopy(baseline)
            for case, value, diagnostic in row.variants:
                with self.subTest(original=row.original, case=case):
                    parent = packet
                    for key in row.path[:-1]:
                        parent = parent[key]
                    parent[row.path[-1]] = copy.deepcopy(value)
                    errors = validate_contractor_packet(rehash(packet))
                    self.assertTrue(any(diagnostic in error for error in errors))

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

    def test_sanitize_bead_projects_dependencies(self) -> None:
        summary = sanitize_bead(
            {
                "id": "cwo-1",
                "title": "Dependency check",
                "dependencies": [
                    "raw-dependency-id",
                    {
                        "id": "task-001",
                        "title": "Parent task",
                        "status": "open",
                        "dependency_type": "blocks",
                        "secret_payload": {"token": "redact-me"},
                    },
                    {
                        "id": "task-002",
                        "depends_on_id": "fallback-id",
                        "issue_id": "fallback-issue-id",
                        "dependency_type": "related",
                        "type": "fallback-type",
                    },
                ],
            },
            "repo-readonly",
        )
        self.assertEqual(
            summary["dependencies"],
            [
                {
                    "id": "raw-dependency-id",
                    "title": None,
                    "status": None,
                    "dependency_type": None,
                },
                {
                    "id": "task-001",
                    "title": "Parent task",
                    "status": "open",
                    "dependency_type": "blocks",
                },
                {
                    "id": "task-002",
                    "title": None,
                    "status": None,
                    "dependency_type": "related",
                },
            ],
        )

    def test_sanitize_bead_drops_nested_dependency_fields(self) -> None:
        summary = sanitize_bead(
            {
                "id": "cwo-1",
                "title": "Dependency check",
                "dependencies": [
                    {
                        "id": "task-001",
                        "title": "Parent task",
                        "status": "open",
                        "dependency_type": "blocks",
                        "metadata": {"extra": "nested"},
                    }
                ],
            },
            "repo-readonly",
        )
        self.assertEqual(summary["dependencies"][0].keys(), {"id", "title", "status", "dependency_type"})
        self.assertNotIn("metadata", summary["dependencies"][0])

    def test_sanitize_bead_rejects_malformed_dependency_inputs(self) -> None:
        invalid_dependencies = [
            "not-a-list",
            [123],
            [{"id": 123}],
            [{"id": "task-001", "title": ["not", "a", "string"]}],
        ]
        for dependencies in invalid_dependencies:
            with self.subTest(dependencies=dependencies):
                with self.assertRaises(CWOPolicyError):
                    sanitize_bead(
                        {
                            "id": "cwo-1",
                            "title": "Dependency check",
                            "dependencies": dependencies,
                        },
                        "repo-readonly",
                    )

    def test_redacted_boundary_still_excludes_malformed_dependencies(self) -> None:
        summary = sanitize_bead(
            {
                "id": "cwo-1",
                "title": "Dependency check",
                "dependencies": "not-a-list",
            },
            "redacted-packet",
        )
        self.assertNotIn("dependencies", summary)

    def test_sanitize_bead_enforces_exact_canonical_byte_cap(self) -> None:
        cap = 32768
        raw = {
            "id": "cwo-1",
            "title": "Dependency check",
            "labels": [],
            "description": "",
        }
        empty_summary = sanitize_bead(raw, "repo-readonly")
        raw["description"] = "x" * (cap - canonical_json_bytes(empty_summary))
        at_cap = sanitize_bead(raw, "repo-readonly")
        self.assertEqual(canonical_json_bytes(at_cap), cap)

        raw["description"] += "x"
        with self.assertRaisesRegex(CWOPolicyError, "exceeds boundary cap"):
            sanitize_bead(raw, "repo-readonly")

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


    def test_rejects_bead_summary_cap_overflow(self) -> None:
        packet = base_packet()
        packet["share_boundary"] = "repo-readonly"
        packet["disclosure_stage"] = "repo-readonly"
        packet["disclosure_escalation_approved"] = True
        filler = "x" * 32800
        packet["bead_summary"]["padding"] = filler
        errors = validate_contractor_packet(rehash(packet))
        self.assertTrue(any("bead_summary size" in error and "exceeds boundary cap" in error for error in errors))

    def test_allows_bead_summary_at_cap_edge(self) -> None:
        packet = base_packet()
        packet["share_boundary"] = "repo-readonly"
        packet["disclosure_stage"] = "repo-readonly"
        packet["disclosure_escalation_approved"] = True
        packet["bead_summary"].pop("padding", None)
        packet["bead_summary"]["padding"] = ""
        empty_size = canonical_json_bytes(packet["bead_summary"])
        packet["bead_summary"]["padding"] = "x" * (32768 - empty_size)
        self.assertEqual(canonical_json_bytes(packet["bead_summary"]), 32768)
        errors = validate_contractor_packet(rehash(packet))
        self.assertFalse(any("bead_summary size" in error for error in errors))


    def test_redaction_and_residual_rows(self) -> None:
        rows = (
            RedactionCase(
                'test_redaction_covers_common_secret_assignment_forms',
                raw="\n".join(
                    [
                        "private_key=abc123",
                        "AWS_SECRET_ACCESS_KEY=abc123",
                        "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI",
                        "client_secret: plain",
                    ]
                ),
                absent=('abc123', 'eyJhbGci', 'plain'),
            ),
            RedactionCase(
                'test_prose_secret_labels_preserve_ordinary_values',
                raw="mixed-script token: 45; score, token: ordinary, and time remain visible",
                unchanged=True, scan_redacted=False, raw_residual=False,
            ),
            RedactionCase(
                'test_prose_secret_labels_redact_high_confidence_credentials',
                raw="Use token: abc123 and password: 123456 only in this synthetic example.",
                absent=('abc123', '123456'),
            ),
            RedactionCase(
                'test_structural_secret_fields_redact_short_and_multiword_values',
                raw="\r\n".join(
                    [
                        "token: 45",
                        "- password: ordinary words",
                        '1. client_secret: "two words"',
                        '{"token": 45, "safe": 1}',
                        "export TOKEN=abc123",
                        "password plaintextsecret",
                    ]
                ),
                absent=('45', 'ordinary words', 'two words', 'abc123', 'plaintextsecret'), present=('"safe": 1',),
            ),
            RedactionCase(
                'test_prefixed_sensitive_keys_are_redacted_with_structural_values',
                raw="\n".join(
                    [
                        "x-api-key: abc123",
                        "x-access-token=short",
                        "my_access_key: safe",
                        "x_access_token: safe",
                    ]
                ),
                absent=('abc123', 'short', 'safe'),
            ),
            RedactionCase(
                'test_multiline_sensitive_key_skips_comment_and_blank_lines',
                raw="\r\n".join(
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
                ),
                absent=('plaintextsecret', 'safe', 'secondsecret'), present=('# explanatory comment', '# ignore this line', '# another comment'),
            ),
            RedactionCase(
                'test_multiline_list_with_comment_lines_is_fully_redacted',
                raw="\n".join(
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
                ),
                absent=('one', 'safe', 'secondsecret'), present=('# list header', '# inline separator'),
            ),
            RedactionCase(
                'test_multiline_json_secret_scalars_are_redacted',
                raw="\n".join(
                    [
                        "{",
                        '  "token":',
                        '    "plaintextsecret",',
                        '  "password":',
                        '    "secondsecret",',
                        '  "safe": "keep-this"',
                        "}"
                    ]
                ),
                absent=('plaintextsecret', 'secondsecret'), present=('"safe": "keep-this"',),
            ),
            RedactionCase(
                'test_yaml_multiline_list_scalar_values_are_redacted',
                raw="\n".join(
                    [
                        "token:",
                        "  - plaintextsecret  # top item",
                        '  - "quotedsecret"',
                        "  - safe",
                        "notes: safe",
                    ]
                ),
                absent=('plaintextsecret', 'quotedsecret'), present=('notes: safe',),
            ),
            RedactionCase(
                'test_nested_multiline_mapping_is_not_consumed_as_scalar',
                raw="\n".join(
                    [
                        "token:",
                        "  {",
                        '    "password": "nestedsecret",',
                        '    "safe": "safe"',
                        "  }",
                    ]
                ),
                absent=('nestedsecret',), present=('"safe": "safe"',),
            ),
            RedactionCase(
                'test_multiline_nested_mapping_is_not_consumed_as_scalar',
                raw="\n".join(
                    [
                        '{',
                        '  "token":',
                        "  {",
                        '    "password": "nestedsecret",',
                        '    "safe": "ok"',
                        "  }",
                        "}"
                    ]
                ),
                absent=('nestedsecret',), present=('"safe": "ok"',),
            ),
            RedactionCase(
                'test_markdown_headings_explanatory_text_and_inline_assignments',
                raw="### Password: plaintextsecret\nIn docs, Password: plaintextsecret;\n",
                present=('### Password: plaintextsecret', 'In docs, Password: [REDACTED];'),
            ),
            RedactionCase(
                'test_plain_words_following_sensitive_terms_are_not_redacted',
                raw="password management",
                unchanged=True, scan_redacted=False,
            ),
            RedactionCase(
                'test_empty_or_null_multiline_values',
                raw="\n".join(["token:", "  ", "password:", "  null", "safe:", "  value"]),
                absent=('null',), present=('token:', 'safe:'),
            ),
            RedactionCase(
                'test_repeated_redaction_is_fixed_point',
                raw="\n".join(["In notes, Password: plaintextsecret", 'token:', '  "plaintextsecret"', ""]),
                repeat=True,
            ),
            RedactionCase(
                'test_comment_and_blank_continuation_is_idempotent',
                raw="\r\n".join(
                    [
                        "token:",
                        "  # explanatory comment",
                        "  ",
                        "  # ignored note",
                        "  plaintextsecret",
                    ]
                ),
                repeat=True,
            ),
            RedactionCase(
                'test_residual_scan_aligns_with_multiline_redaction',
                raw="\r\n".join(
                    [
                        "token:",
                        "  # explanatory comment",
                        "  plaintextsecret",
                    ]
                ),
                raw_residual=True,
            ),
            RedactionCase(
                'test_structural_values_keep_comment_markers_inside_quotes_and_redact_semicolons',
                raw='token: "part one # part two" # note\nconnection_string: Server=host;User=name;Password=value',
                absent=('part one', 'part two', 'Server=host', 'User=name'), present=('# note',),
            ),
            RedactionCase(
                'test_yaml_block_and_multiline_quoted_values_are_fully_redacted',
                raw='token: |\n  plaintextsecret\n  second line\nsafe: ok\n'
                '- token: |\n    list secret\n  safe: preserved\n'
                'password: "first line\n  second secret"\n',
                absent=('plaintextsecret', 'second line', 'list secret', 'first line', 'second secret'), present=('safe: ok', 'safe: preserved'),
            ),
            RedactionCase(
                'test_malformed_inline_structure_fails_closed',
                raw='{"token": "plaintextsecret"',
                absent=('plaintextsecret',),
            ),
        )
        for row in rows:
            with self.subTest(original=row.original):
                if row.raw_residual is not None:
                    self.assertEqual(bool(find_residual_private_context(row.raw)), row.raw_residual)
                redacted = redact_text(row.raw)
                for secret in row.absent:
                    self.assertNotIn(secret, redacted)
                for fragment in row.present:
                    self.assertIn(fragment, redacted)
                if row.unchanged:
                    self.assertEqual(redacted, row.raw)
                if row.repeat:
                    self.assertEqual(redacted, redact_text(redacted))
                if row.scan_redacted:
                    self.assertFalse(find_residual_private_context(redacted))


    def test_packet_redaction_and_residual_alias_rows(self) -> None:
        rows = (
            AliasPacketCase("test_policy_defined_sensitive_aliases_do_not_residual_in_validation_snippets",
                            policy_sensitive_field_aliases(), "policySecret01", True),
            AliasPacketCase("test_compact_aliases_have_residual_validation", ["accesskey"], "compactSecret01", False),
        )
        baseline = base_packet()
        for row in rows:
            packet = copy.deepcopy(baseline)
            snippet = packet["selected_snippets"][0]
            artifact = next(item for item in packet["included_artifacts"] if item["type"] == "inline_snippet")
            for alias in row.aliases:
                with self.subTest(original=row.original, alias=alias):
                    alias_hyphen = alias.replace("_", "-")
                    secret = f"{row.secret}-{alias}" if row.suffix_alias else row.secret
                    forms = [
                        f"{alias}: {secret}",
                        f"{alias_hyphen}= {secret}",
                        f"x-{alias_hyphen}: {secret}",
                        f'{{"{alias_hyphen}": "{secret}"}}',
                        f"{alias}:\n  {secret}",
                    ]
                    raw = "\n".join(forms)
                    redacted = redact_text(raw)
                    self.assertNotIn(secret, redacted, alias)
                    self.assertFalse(find_residual_private_context(redacted), alias)
                    for control, content in (("redacted", redacted), ("raw", raw)):
                        with self.subTest(control=control):
                            snippet["content"] = content
                            snippet["sha256"] = artifact_hash(content)
                            snippet["line_count"] = len(content.splitlines())
                            artifact["sha256"] = snippet["sha256"]
                            artifact["line_count"] = snippet["line_count"]
                            errors = validate_contractor_packet(rehash(packet))
                            if control == "raw":
                                self.assertTrue(any("residual private or secret-like context" in error for error in errors), alias)
                            else:
                                self.assertEqual([], errors, alias)


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


    def test_redaction_preserves_benign_prose_across_markup_variants(self) -> None:
        variants = (
            ('test_markdown_blockquote_field_is_structural',
             '> password: plaintextsecret\n> In prose, token: 45 remains ordinary.',
             'plaintextsecret'),
            ('test_markdown_and_fenced_code_use_logical_line_field_position',
             '```env\nTOKEN=abc123\n```\n> In prose, token: 45 remains ordinary.\n',
             'abc123'),
        )
        for original, raw_text, secret in variants:
            with self.subTest(original=original):
                raw = raw_text
                redacted = redact_text(raw)
                self.assertNotIn(secret, redacted)
                self.assertIn("token: 45", redacted)
                self.assertFalse(find_residual_private_context(redacted))

    def test_redaction_sentinel_is_stable_only_as_complete_value(self) -> None:
        stable = "token=[REDACTED]"
        self.assertEqual(redact_text(stable), stable)
        tainted = "token=[REDACTED] trailing material"
        self.assertEqual(redact_text(tainted), stable)
        self.assertFalse(find_residual_private_context(stable))
        self.assertTrue(find_residual_private_context(tainted))


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

    def test_snippet_file_construction_rows(self) -> None:
        rows = (
            SnippetFileCase("test_snippet_file_is_included_as_redacted_repo_snippet", "master-plan.md",
                            b"Final plan\napi_key=plain-secret\nValidation: run tests\n",
                            True, "absolute", None, ("Final plan", "[REDACTED]"), True),
            SnippetFileCase("test_absolute_snippet_file_inside_repo_is_allowed", "inside.md", b"Repo-contained plan\n",
                            True, "resolved", None, ("Repo-contained plan",)),
            SnippetFileCase("test_snippet_file_outside_repo_is_rejected", "outside.md", b"Outside repo\n",
                            False, "absolute", "outside repository"),
            SnippetFileCase("test_snippet_file_secret_name_is_rejected", ".env", b"TOKEN=secret\n",
                            True, "relative", "likely secret"),
            SnippetFileCase("test_snippet_file_binary_probe_is_rejected", "binary.md", b"ok\0not text",
                            True, "relative", "binary packet artifact"),
            SnippetFileCase("test_snippet_file_invalid_utf8_is_rejected", "invalid.md", b"\xff\xfe",
                            True, "relative", "non-UTF-8 snippet file"),
        )
        for row in rows:
            with self.subTest(original=row.original):
                with tempfile.TemporaryDirectory(dir=ROOT if row.inside else None) as tmpdir:
                    snippet_path = Path(tmpdir) / row.filename
                    snippet_path.write_bytes(row.payload)
                    selected = str(snippet_path)
                    if row.path_mode == "relative":
                        selected = str(snippet_path.relative_to(ROOT))
                    elif row.path_mode == "resolved":
                        selected = str(snippet_path.resolve())
                    bead = {"id": "cwo-1", "title": "Master plan review"}
                    if row.diagnostic is None:
                        bead["labels"] = ["contractor-only", "no-codex-exec", "contract-jd-master-plan-review"]
                    expected = self.assertRaises(SystemExit) if row.diagnostic else nullcontext()
                    with expected as raised:
                        packet = build_packet(
                            bead_id="cwo-1", bead_json=bead,
                            executor="chatgpt_pro_browser_master_reviewer", share_boundary="redacted-packet",
                            job_description_label="contract-jd-master-plan-review", allowed_files=[], inline_snippets=[],
                            snippet_files=[selected], dispatch_id="dispatch-validation",
                            external_opt_in=True, opt_in_basis="cli-flag",
                        )
                if row.diagnostic:
                    self.assertIn(row.diagnostic, str(raised.exception))
                else:
                    snippet = packet["selected_snippets"][0]
                    for fragment in row.present:
                        self.assertIn(fragment, snippet["content"])
                    if row.check_artifact:
                        self.assertTrue(snippet["path"].endswith("/master-plan.md"))
                        artifact_paths = [artifact["path"] for artifact in packet["included_artifacts"]
                                          if artifact["type"] == "inline_snippet"]
                        self.assertIn(snippet["path"], artifact_paths)


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
