"""Unit tests for the advisory hook allowlist and the enforcement disposition."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import configure_codex_beads_hooks as writer  # noqa: E402
from cwo_core.codex_hook_enforcement import (  # noqa: E402
    ADVISORY_HOOK_ALLOWLIST,
    ADVISORY_HOOK_EVENTS,
    ADVISORY_HOOK_KEYS,
    ADVISORY_HOOK_TYPES,
    ENFORCEMENT_HOOK_EVENTS,
    check_pinned_versions_ineligible,
    validate_advisory_hook_configuration,
    validate_profile_hooks,
)
from cwo_core.errors import CWOValidationError  # noqa: E402

PINNED = (
    "hook-based enforcement is unsupported on pinned Codex versions ['0.163.0', '0.162.0']; "
    "PreToolUse leaves should_block=false on execution/JSON failures, stdin skips PreToolUse, "
    "and PermissionRequest fallthrough is not equivalent to PreToolUse; enforcement mode refused"
)
CTX = "hook configuration"


def writer_outputs() -> dict[str, dict]:
    outputs = {}
    for mode, supported in (("full-context", False), ("quiet", True), ("verbose", True), ("compact-degraded", False)):
        managed, _ = writer.build_managed_hooks(
            mode=mode, visibility_hint_supported=supported, allow_degraded_context=True
        )
        outputs[mode] = {"hooks": managed}
    return outputs


def session_hook(**hook) -> dict:
    return {"hooks": {"SessionStart": [{"matcher": "startup|resume|clear", "hooks": [hook]}]}}


class EnforcementRefusalTests(unittest.TestCase):
    def test_pinned_versions_always_refuse_enforcement(self) -> None:
        with self.assertRaises(CWOValidationError) as context:
            check_pinned_versions_ineligible()
        self.assertEqual(str(context.exception), PINNED)

    def test_enforcement_events_are_refused_by_name_before_contents(self) -> None:
        cases = {
            "PreToolUse list": ({"PreToolUse": [{"hooks": [{"type": "command", "command": "guard"}]}]}, "PreToolUse"),
            "PreToolUse garbage": ({"PreToolUse": "garbage"}, "PreToolUse"),
            "PermissionRequest null": ({"PermissionRequest": None}, "PermissionRequest"),
            "case variant": ({"pretooluse": []}, "pretooluse"),
            "listed after an unknown event": ({"Stop": 1, "PreToolUse": []}, "PreToolUse"),
        }
        for name, (events, refused) in cases.items():
            with self.subTest(name):
                with self.assertRaises(CWOValidationError) as context:
                    validate_advisory_hook_configuration({"hooks": events})
                self.assertEqual(str(context.exception), f"{CTX}: hook event(s) {[refused]} refused: {PINNED}")

    def test_enforcement_and_advisory_events_are_disjoint(self) -> None:
        self.assertFalse(ENFORCEMENT_HOOK_EVENTS & ADVISORY_HOOK_EVENTS)


class AllowlistMatchesWriterTests(unittest.TestCase):
    def test_every_writer_mode_output_validates(self) -> None:
        for mode, payload in writer_outputs().items():
            with self.subTest(mode):
                validate_advisory_hook_configuration(payload)

    def test_allowlist_is_exactly_what_the_writer_can_write(self) -> None:
        written = set()
        types = set()
        keys = set()
        for payload in writer_outputs().values():
            for event, groups in payload["hooks"].items():
                for group in groups:
                    for hook in group["hooks"]:
                        written.add((event, group.get("matcher"), hook["command"]))
                        types.add(hook["type"])
                        keys.update(hook)
        allowed = {
            (event, spec["matcher"], cmd)
            for event, spec in ADVISORY_HOOK_ALLOWLIST.items()
            for cmd in spec["commands"]
        }
        self.assertEqual(written, allowed)
        self.assertEqual(types, set(ADVISORY_HOOK_TYPES))
        self.assertEqual(keys, set(ADVISORY_HOOK_KEYS))
        self.assertEqual(set(writer.MANAGED_EVENTS), set(ADVISORY_HOOK_EVENTS))


class AllowlistRefusalTests(unittest.TestCase):
    def assert_refused(self, payload, expected: str) -> None:
        with self.assertRaises(CWOValidationError) as context:
            validate_advisory_hook_configuration(payload)
        self.assertEqual(str(context.exception), expected)

    def test_structure_refusals(self) -> None:
        group0 = f"{CTX} event 'SessionStart' group 0"
        cases = {
            "None": (None, f"{CTX}: hook configuration must be a JSON object, not NoneType; refused"),
            "hooks null": ({"hooks": None}, f"{CTX}: 'hooks' must be an object mapping event names to hook groups, not NoneType; refused"),
            "groups object": (
                {"hooks": {"SessionStart": {}}},
                f"{CTX} event 'SessionStart': hook groups must be a list, not dict; refused",
            ),
            "group string": ({"hooks": {"SessionStart": ["x"]}}, f"{group0}: hook group must be an object, not str; refused"),
            "unknown group key": (
                {"hooks": {"SessionStart": [{"matcher": "startup|resume|clear", "hooks": [], "enabled": True}]}},
                f"{group0}: unsupported key(s) ['enabled']; allowed keys are ['hooks', 'matcher']; refused",
            ),
            "empty hooks": (
                {"hooks": {"SessionStart": [{"matcher": "startup|resume|clear", "hooks": []}]}},
                f"{group0}: 'hooks' must be a non-empty list of hook entries; refused",
            ),
            "missing matcher": (
                {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "bd codex-hook SessionStart"}]}]}},
                f"{group0}: matcher (absent) does not match the allowlisted matcher 'startup|resume|clear'; refused",
            ),
            "matcher where none is written": (
                {"hooks": {"UserPromptSubmit": [{"matcher": None, "hooks": [{"type": "command", "command": "bd codex-hook UserPromptSubmit"}]}]}},
                f"{CTX} event 'UserPromptSubmit' group 0: matcher None does not match the allowlisted matcher (absent); refused",
            ),
            "entry string": (
                {"hooks": {"SessionStart": [{"matcher": "startup|resume|clear", "hooks": ["bd codex-hook SessionStart"]}]}},
                f"{group0} hook 0: hook entry must be an object, not str; refused",
            ),
        }
        for name, (payload, expected) in cases.items():
            with self.subTest(name):
                self.assert_refused(payload, expected)

    def test_entry_refusals(self) -> None:
        hook0 = f"{CTX} event 'SessionStart' group 0 hook 0"
        allowed = "['bd codex-hook SessionStart', 'bd prime --memories-only --hook-json']"
        good = {"type": "command", "command": "bd codex-hook SessionStart"}
        cases = {
            "trailing space": (
                {**good, "command": "bd codex-hook SessionStart "},
                f"{hook0}: command 'bd codex-hook SessionStart ' is not an allowlisted advisory command for SessionStart; allowed: {allowed}; refused",
            ),
            "argv list": (
                {**good, "command": ["bd", "codex-hook", "SessionStart"]},
                f"{hook0}: command ['bd', 'codex-hook', 'SessionStart'] is not an allowlisted advisory command for SessionStart; allowed: {allowed}; refused",
            ),
            "semicolon chain": (
                {**good, "command": "bd codex-hook SessionStart; untrusted-helper"},
                f"{hook0}: command 'bd codex-hook SessionStart; untrusted-helper' is not an allowlisted advisory command for SessionStart; allowed: {allowed}; refused",
            ),
            "missing type": (
                {"command": "bd codex-hook SessionStart"},
                f"{hook0}: hook type None is not an allowlisted advisory hook type ['command']; refused",
            ),
            "unknown key": (
                {**good, "timeout": 5},
                f"{hook0}: unsupported key(s) ['timeout']; allowed keys are ['command', 'statusMessage', 'type', 'visibilityHint']; refused",
            ),
            "several permission fields": (
                {**good, "allow": True, "bypassReview": True},
                f"{hook0}: hook contains permission-granting field(s) ['allow', 'bypassReview']; advisory hooks cannot issue authority; refused",
            ),
            "status message not a string": (
                {**good, "statusMessage": {"decision": "allow"}},
                f"{hook0}: statusMessage must be a string; refused",
            ),
            "unknown visibility hint": (
                {**good, "visibilityHint": "hidden"},
                f"{hook0}: visibilityHint 'hidden' is not one of ['quiet', 'verbose']; refused",
            ),
        }
        for name, (hook, expected) in cases.items():
            with self.subTest(name):
                self.assert_refused(session_hook(**hook), expected)

    def test_empty_configurations_are_accepted(self) -> None:
        validate_advisory_hook_configuration({})
        validate_advisory_hook_configuration({"hooks": {}})


class ProfileHookTests(unittest.TestCase):
    def test_profile_without_hooks_validates(self) -> None:
        validate_profile_hooks({"display_name": "Test", "status": "available"}, profile_name="test")

    def test_profile_with_allowlisted_hooks_validates(self) -> None:
        validate_profile_hooks({"hooks": writer_outputs()["quiet"]["hooks"]}, profile_name="test")

    def test_profile_refusals(self) -> None:
        cases = {
            "not an object": (["hooks"], "access profile 'test' must be an object; refused"),
            "enforcement_hooks": (
                {"enforcement_hooks": {}},
                "access profile 'test' declares enforcement_hooks; hook-based enforcement is unsupported on pinned Codex versions",
            ),
            "hooks null": (
                {"hooks": None},
                "access profile 'test' hooks: 'hooks' must be an object mapping event names to hook groups, not NoneType; refused",
            ),
            "permission field": (
                {"hooks": session_hook(type="command", command="bd codex-hook SessionStart", grant_permission=True)["hooks"]},
                "access profile 'test' hooks event 'SessionStart' group 0 hook 0: hook contains permission-granting field(s) ['grant_permission']; advisory hooks cannot issue authority; refused",
            ),
        }
        for name, (profile, expected) in cases.items():
            with self.subTest(name):
                with self.assertRaises(CWOValidationError) as context:
                    validate_profile_hooks(profile, profile_name="test")
                self.assertEqual(str(context.exception), expected)


class DispositionRecordTests(unittest.TestCase):
    """Test that disposition record is present and accurate."""

    def test_disposition_document_exists(self):
        """Disposition document references/codex-hook-enforcement-disposition.md exists."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        disposition_file = repo_root / "references" / "codex-hook-enforcement-disposition.md"

        self.assertTrue(disposition_file.exists(),
                       f"Disposition record not found at {disposition_file}")

    def test_disposition_document_contract_terms(self):
        variants = (
            # Disposition document mentions the pinned Codex versions.
            ('test_disposition_mentions_pinned_versions', '0.163.0', '0.162.0'),
            # Disposition cites PreToolUse should_block=false on failures.
            ('test_disposition_cites_pretooluse_should_block_false', 'should_block=false', 'PreToolUse'),
        )
        for original, first_term, second_term in variants:
            with self.subTest(original=original):
                from pathlib import Path
                repo_root = Path(__file__).parent.parent
                disposition_file = repo_root / "references" / "codex-hook-enforcement-disposition.md"

                content = disposition_file.read_text(encoding="utf-8")
                self.assertIn(first_term, content)
                self.assertIn(second_term, content)

    def test_disposition_states_unsupported(self):
        """Disposition document states enforcement is unsupported."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        disposition_file = repo_root / "references" / "codex-hook-enforcement-disposition.md"

        content = disposition_file.read_text(encoding="utf-8")
        self.assertIn("unsupported", content.lower())
        self.assertIn("ineligible", content.lower())


    def test_disposition_cites_stdin_skips_pretooluse(self):
        """Disposition cites that stdin skips PreToolUse."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        disposition_file = repo_root / "references" / "codex-hook-enforcement-disposition.md"

        content = disposition_file.read_text(encoding="utf-8")
        self.assertIn("stdin", content.lower())
        self.assertIn("skips", content.lower())
        self.assertIn("PreToolUse", content)

    def test_disposition_distinguishes_permissionrequest_from_pretooluse(self):
        """Disposition states PermissionRequest is not equivalent to PreToolUse."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        disposition_file = repo_root / "references" / "codex-hook-enforcement-disposition.md"

        content = disposition_file.read_text(encoding="utf-8")
        self.assertIn("PermissionRequest", content)
        self.assertIn("not equivalent", content.lower())


class CapabilityMatrixTests(unittest.TestCase):
    """Test that capability matrix correctly describes hook behavior."""

    def test_capability_matrix_does_not_claim_pretooluse_permissionrequest_equivalent(self):
        """Capability matrix does not describe PermissionRequest as equivalent to PreToolUse."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        matrix_file = repo_root / "references" / "codex-protocol-capability-matrix.md"

        content = matrix_file.read_text(encoding="utf-8")

        # Should have a row distinguishing them
        self.assertIn("PermissionRequest", content)
        self.assertIn("PreToolUse", content)
        self.assertIn("not equivalent", content.lower())

    def test_capability_matrix_mentions_should_block_false(self):
        """Capability matrix mentions PreToolUse should_block=false behavior."""
        from pathlib import Path
        repo_root = Path(__file__).parent.parent
        matrix_file = repo_root / "references" / "codex-protocol-capability-matrix.md"

        content = matrix_file.read_text(encoding="utf-8")
        self.assertIn("should_block=false", content)


if __name__ == "__main__":
    unittest.main()
