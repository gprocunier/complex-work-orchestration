"""Share-boundary configuration is checked at canonical load before coercive consumers."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_contractor_packet as builder  # noqa: E402
from cwo_core import packets, policy  # noqa: E402
from cwo_core.errors import CWOPolicyError  # noqa: E402
from cwo_core.policy_schema import PolicySchemaError  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402
from tests.test_policy_schema import malformed_policy  # noqa: E402

FLAGS = ("allows_external", "allows_repo_access", "allows_patches", "requires_disclosure_escalation")
COMMON_FIELDS = (
    "allows_external", "allows_repo_access", "allows_patches",
    "disclosure_stage", "requires_disclosure_escalation",
    "artifact_whitelist", "field_whitelist", "snippet_line_limit", "description",
)
OPTIONAL_FIELDS = ("forbidden_fields", "redaction_profile", "bead_summary_max_bytes", "patch_prerequisites")


def change_at(path: tuple[str, ...], value: Any, *, remove: bool = False) -> Callable[[dict[str, Any]], None]:
    def mutate(document: dict[str, Any]) -> None:
        parent = document
        for step in path[:-1]:
            parent = parent[step]
        if remove:
            del parent[path[-1]]
        else:
            parent[path[-1]] = value
    return mutate


class ShareBoundaryRegistrySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        policy.clear_policy_cache()
        self.addCleanup(policy.clear_policy_cache)
        self.document = json.loads(
            (ROOT / "policy" / "share-boundaries.yaml").read_text(encoding="utf-8")
        )

    def assert_good_false(self) -> None:
        with malformed_policy("share-boundaries"):
            self.assertEqual(policy.load_policy("share-boundaries"), self.document)
            self.assertIs(policy.boundary_allows_external("no-outside-sharing"), False)

    def assert_refused(self, mutate: Callable[[dict[str, Any]], None] | None = None, *,
                       raw: str | None = None, fragment: str = "", schema_error: bool = True) -> None:
        self.assert_good_false()
        consumers = (
            ("external", lambda: policy.boundary_allows_external("no-outside-sharing")),
            ("suffixed load", lambda: policy.load_policy("share-boundaries.yaml")),
            ("sanitize", lambda: packets.sanitize_bead({"id": "schema-test"}, "redacted-packet",
                                                       require_policy_patterns=True)),
            ("default", lambda: builder.resolve_share_boundary(None)),
        )
        with malformed_policy("share-boundaries", mutate, raw):
            for name, consume in consumers:
                with self.subTest(consumer=name):
                    policy.clear_policy_cache()
                    try:
                        with self.assertRaises(SystemExit) as raised:
                            result = consume()
                            self.fail(f"malformed share-boundaries accepted; {name} returned {result!r}")
                        message = str(raised.exception)
                        self.assertIn("policy/share-boundaries.yaml", message)
                        self.assertIn(fragment, message)
                        if schema_error:
                            self.assertIsInstance(raised.exception, PolicySchemaError)
                    finally:
                        policy.clear_policy_cache()

    def test_string_false_cannot_enable_no_outside_sharing(self) -> None:
        # On the exact predecessor, the real helper returns True after the good-False control.
        self.assert_refused(
            change_at(("boundaries", "no-outside-sharing", "allows_external"), "false"),
            fragment="allows_external: expected boolean, found string",
        )

    def test_flags_require_exact_booleans(self) -> None:
        for flag in FLAGS:
            for value in (0, 1, "false", "true", None, [], {}):
                with self.subTest(flag=flag, value=value):
                    self.assert_refused(change_at(("boundaries", "no-outside-sharing", flag), value), fragment=flag)

    def test_version_and_schema_marker(self) -> None:
        for version in (False, True, 2.0, 1, 3, "2", None, [], {}):
            with self.subTest(version=version):
                self.assert_refused(change_at(("version",), version), fragment="$.version")
        self.assert_refused(change_at(("schema",), "yaml"), fragment="$.schema")

    def test_integer_limits(self) -> None:
        for value in (False, True, -1, 0.0, 80.0, "80", None, [], {}):
            with self.subTest(snippet_limit=value):
                self.assert_refused(change_at(("boundaries", "redacted-packet", "snippet_line_limit"), value),
                                    fragment="snippet_line_limit")
        for value in (False, True, -1, 0, 1.0, "32768", [], {}):
            with self.subTest(summary_cap=value):
                self.assert_refused(change_at(("boundaries", "repo-readonly", "bead_summary_max_bytes"), value),
                                    fragment="bead_summary_max_bytes")

    def test_all_known_strings_are_typed(self) -> None:
        paths = (
            ("schema",),
            ("boundaries", "redacted-packet", "disclosure_stage"),
            ("boundaries", "redacted-packet", "description"),
            ("boundaries", "redacted-packet", "redaction_profile"),
            ("secret_field_policy", "parser_owner"),
            ("secret_field_policy", "parser_notes", "source"),
            ("secret_field_policy", "parser_notes", "notes"),
        )
        for path in paths:
            for value in (False, 7, None, [], {}):
                with self.subTest(path=path, value=value):
                    self.assert_refused(change_at(path, value), fragment=".".join(path))

    def test_known_containers_are_objects(self) -> None:
        paths = (
            ("boundaries",),
            ("boundaries", "redacted-packet"),
            ("secret_field_policy",),
            ("secret_field_policy", "categories"),
            ("secret_field_policy", "parser_notes"),
        )
        for path in paths:
            for value in ([], False, 7, "object", None):
                with self.subTest(path=path, value=value):
                    self.assert_refused(change_at(path, value), fragment=".".join(path))

    def test_arrays_and_their_items_are_typed(self) -> None:
        paths = (
            ("redaction_patterns",), ("never_share",),
            ("boundaries", "redacted-packet", "artifact_whitelist"),
            ("boundaries", "redacted-packet", "field_whitelist"),
            ("boundaries", "redacted-packet", "forbidden_fields"),
            ("boundaries", "patch-branch", "patch_prerequisites"),
            ("secret_field_policy", "categories", "credential_tokens"),
        )
        for path in paths:
            for value in ("item", False, 7, {}, None, [False], [7], [None], [[]], [{}]):
                with self.subTest(path=path, value=value):
                    self.assert_refused(change_at(path, value), fragment=".".join(path))

    def test_closed_records_refuse_unknown_fields(self) -> None:
        for path in ((), ("boundaries", "redacted-packet"), ("secret_field_policy",),
                     ("secret_field_policy", "parser_notes")):
            with self.subTest(path=path):
                self.assert_refused(change_at(path + ("zz_unexpected",), True), fragment="zz_unexpected: unexpected field")

    def test_required_fields(self) -> None:
        groups = (
            ((), ("version", "schema", "boundaries", "redaction_patterns", "secret_field_policy", "never_share")),
            (("boundaries", "no-outside-sharing"), COMMON_FIELDS),
            (("secret_field_policy",), ("parser_owner", "categories", "parser_notes")),
            (("secret_field_policy", "parser_notes"), ("source", "notes")),
        )
        for path, fields in groups:
            for field in fields:
                with self.subTest(path=path, field=field):
                    self.assert_refused(change_at(path + (field,), None, remove=True), fragment=f"missing required field {field!r}")

    def test_duplicate_keys_and_nonfinite_numbers(self) -> None:
        raw = json.dumps(self.document)
        cases = [
            (raw.replace('"version": 2', '"version": 2, "version": 2', 1), "duplicate key 'version'"),
            (raw.replace('"allows_external": false', '"allows_external": false, "allows_external": true', 1),
             "duplicate key 'allows_external'"),
            (raw.replace('"credential_tokens": [', '"credential_tokens": [], "credential_tokens": [', 1),
             "duplicate key 'credential_tokens'"),
        ]
        for token in ("NaN", "Infinity", "-Infinity", "1e309", "-1e309", "1" + "0" * 400):
            cases.append((raw.replace('"version": 2', '"version": ' + token, 1), "not JSON-compatible YAML"))
        for text, fragment in cases:
            with self.subTest(fragment=fragment, raw=text[:60]):
                self.assertNotEqual(text, raw)
                self.assert_refused(raw=text, fragment=fragment, schema_error=False)

    def test_nonobject_documents(self) -> None:
        for raw in ("[]", "false", "2", "null", '"boundary"'):
            with self.subTest(raw=raw):
                self.assert_refused(raw=raw, fragment="top-level object", schema_error=False)

    def test_optional_fields_empty_arrays_and_dynamic_ids(self) -> None:
        def mutate(document: dict[str, Any]) -> None:
            for boundary in document["boundaries"].values():
                for field in OPTIONAL_FIELDS:
                    boundary.pop(field, None)
                boundary["artifact_whitelist"] = []
                boundary["field_whitelist"] = []
            document["boundaries"]["custom:boundary"] = document["boundaries"].pop("patch-branch")
            document["secret_field_policy"]["categories"] = {"custom:category": [], "extra": ["vaultcache"]}
            document["redaction_patterns"] = []
            document["never_share"] = []
        with malformed_policy("share-boundaries", mutate):
            loaded = policy.load_policy("share-boundaries")
            self.assertIs(policy.boundary_allows_external("custom:boundary"), True)
            for boundary in loaded["boundaries"].values():
                self.assertFalse(set(OPTIONAL_FIELDS) & set(boundary))
                self.assertEqual(boundary["artifact_whitelist"], [])
                self.assertEqual(boundary["field_whitelist"], [])
            self.assertIn("vaultcache", packets._load_secret_field_aliases())
            self.assertIn("session_token", packets._load_secret_field_aliases())
            self.assertEqual(loaded["never_share"], [])
            self.assertEqual(loaded["redaction_patterns"], [])

    def test_no_required_roster_or_invented_string_enums(self) -> None:
        def mutate(document: dict[str, Any]) -> None:
            document["boundaries"] = {}
            document["secret_field_policy"]["categories"] = {}
            document["redaction_patterns"] = ["["]  # Data at schema load, not a regex to execute.
            document["never_share"] = ["", "same", "same"]
        with malformed_policy("share-boundaries", mutate):
            self.assertEqual(policy.load_policy("share-boundaries")["boundaries"], {})
            self.assertIn("session_token", packets._load_secret_field_aliases())

    def test_zero_snippet_limit_and_optional_uncapped_summary(self) -> None:
        for limit, cap in ((0, None), (1, 1), (100001, 100001)):
            with self.subTest(limit=limit, cap=cap):
                mutate = lambda d: d["boundaries"]["redacted-packet"].update(
                    snippet_line_limit=limit, bead_summary_max_bytes=cap,
                    disclosure_stage="custom-stage", redaction_profile="custom-profile",
                    patch_prerequisites=["", "same", "same"],
                )
                with malformed_policy("share-boundaries", mutate):
                    boundary = policy.boundary_config("redacted-packet")
                    self.assertEqual(boundary["snippet_line_limit"], limit)
                    self.assertEqual(packets._bead_summary_max_bytes(boundary), cap)
                    self.assertEqual(policy.share_boundary_disclosure_stage("redacted-packet"), "custom-stage")

    def test_current_consumers_and_boundary_decisions(self) -> None:
        expected = {
            "no-outside-sharing": (False, False, False, "none", False),
            "redacted-packet": (True, False, False, "redacted", False),
            "repo-readonly": (True, True, False, "repo-readonly", True),
            "patch-branch": (True, True, True, "patch-branch", True),
        }
        with malformed_policy("share-boundaries"):
            self.assertEqual(policy.load_policy("share-boundaries"), self.document)
            for name, values in expected.items():
                with self.subTest(boundary=name):
                    boundary = policy.boundary_config(name)
                    actual = tuple(boundary[field] for field in (
                        "allows_external", "allows_repo_access", "allows_patches", "disclosure_stage",
                        "requires_disclosure_escalation",
                    ))
                    self.assertEqual(actual, values)
                    self.assertIs(policy.boundary_allows_external(name), values[0])
                    self.assertEqual(policy.share_boundary_disclosure_stage(name), values[3])
                    self.assertIs(policy.share_boundary_requires_escalation(name), values[4])
            with self.assertRaisesRegex(SystemExit, "does not allow outside disclosure"):
                builder.resolve_share_boundary(None)
            self.assertEqual(builder.resolve_share_boundary("redacted-packet"), "redacted-packet")
            args = ("claude_code_manual", "redacted-packet",
                    ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
                    "contract-jd-security-reasoning")
            self.assertEqual(builder.validate_gate(*args, external_ok=True, opt_in_record=None), "cli-flag")
            for boundary in ("repo-readonly", "patch-branch"):
                with self.subTest(boundary=boundary):
                    gate_args = (args[0], boundary, *args[2:])
                    with self.assertRaisesRegex(SystemExit, "requires --allow-disclosure-escalation"):
                        builder.validate_gate(*gate_args, external_ok=True, opt_in_record=None)
                    self.assertEqual(builder.validate_gate(
                        *gate_args, external_ok=True, opt_in_record=None, allow_disclosure_escalation=True,
                    ), "cli-flag")

    def test_packet_sanitization_build_and_validation_still_work(self) -> None:
        with malformed_policy("share-boundaries"):
            summary = packets.sanitize_bead(
                {"id": "shape-test", "title": "Notes", "comments": "private", "metadata": {"safe": "extra"}},
                "redacted-packet", require_policy_patterns=True,
            )
            self.assertEqual(summary, {"id": "shape-test", "title": "Notes"})
            self.assertEqual(packets.redact_text("token=abc123", require_policy_patterns=True), "token=[REDACTED]")
            packet = builder.build_packet(
                bead_id="shape-test", bead_json={
                    "id": "shape-test", "title": "Notes",
                    "labels": ["contractor-only", "no-codex-exec", "contract-jd-security-reasoning"],
                },
                executor="claude_code_manual", share_boundary="redacted-packet",
                job_description_label="contract-jd-security-reasoning",
                allowed_files=[], inline_snippets=["Plain notes."], dispatch_id="dispatch-schema",
                include_expert_profile=False, degraded_context_justification="Configuration regression fixture.",
                external_opt_in=True, opt_in_basis="cli-flag",
            )
            self.assertEqual(packets.validate_contractor_packet(packet, allow_degraded_packet=True), [])

    def test_known_routing_outcomes_remain_conservative(self) -> None:
        with malformed_policy("share-boundaries"):
            benign = classify_work("Fix the typo in README", file_paths=["README.md"])
            self.assertEqual(benign["risk_level"], "low")
            self.assertFalse(benign["operative_route"]["dispatch_authorized"])
            oidc = classify_work("Inspect OIDC")
            self.assertEqual(oidc["risk_assessment"]["floor"], "high")
            self.assertIn("security", {expert["name"] for expert in oidc["ranked_experts"]})
            self.assertFalse(oidc["operative_route"]["dispatch_authorized"])

    def test_unknown_boundary_still_uses_digest(self) -> None:
        unknown = "unknown\ncaller boundary"
        digest = hashlib.sha256(unknown.encode("utf-8")).hexdigest()[:12]
        with malformed_policy("share-boundaries"):
            with self.assertRaises(SystemExit) as raised:
                policy.boundary_config(unknown)
            message = str(raised.exception)
            self.assertIn(f"unknown share boundary (sha256 {digest})", message)
            self.assertNotIn(unknown, message)
            self.assertIn(", ".join(sorted(self.document["boundaries"])), message)

    def test_cache_aliases_copies_and_refusal_before_insertion(self) -> None:
        with malformed_policy("share-boundaries") as directory:
            self.assertIs(policy.boundary_allows_external("no-outside-sharing"), False)
            loaded = policy.load_policy("share-boundaries.yaml")
            loaded["boundaries"]["no-outside-sharing"]["allows_external"] = True
            self.assertIs(policy.boundary_allows_external("no-outside-sharing"), False)
            self.assertEqual(policy._load_policy_cached.cache_info().currsize, 1)
            path = directory / "share-boundaries.yaml"
            malformed = json.loads(path.read_text(encoding="utf-8"))
            malformed["boundaries"]["no-outside-sharing"]["allows_external"] = "false"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            # An already cached disk load remains cached until explicit invalidation.
            self.assertIs(policy.boundary_allows_external("no-outside-sharing"), False)
            policy.clear_policy_cache()
            with self.assertRaises(PolicySchemaError):
                policy.boundary_allows_external("no-outside-sharing")
            self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)
            with self.assertRaises(PolicySchemaError):
                policy.load_policy("share-boundaries.yaml")
            self.assertEqual(policy._load_policy_cached.cache_info().currsize, 0)
            path.write_text(json.dumps(self.document), encoding="utf-8")
            self.assertIs(policy.boundary_allows_external("no-outside-sharing"), False)

    def test_direct_dictionary_contracts_remain_additional_checks(self) -> None:
        with mock.patch.object(policy, "boundary_config", return_value={"allows_external": "false"}):
            self.assertIs(policy.boundary_allows_external("dictionary-fixture"), True)
        with mock.patch.object(packets, "load_policy", return_value={
            "secret_field_policy": {"categories": {"extension": "not-a-list"}},
        }):
            with self.assertRaises(CWOPolicyError):
                packets._load_secret_field_aliases()
        with self.assertRaises(CWOPolicyError):
            packets._bead_summary_max_bytes({"bead_summary_max_bytes": 0})


if __name__ == "__main__":
    unittest.main()
