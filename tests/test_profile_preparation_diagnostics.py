"""UNEXECUTED at authorship: bounded fake preparation and recorded expectations."""

from __future__ import annotations

import copy
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import profile_preparation_diagnostics as prep  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "profile-preparation-cases.json"
CAPTURE = ROOT / "tests" / "fixtures" / "codex-protocol-provisional" / "0.164.0"


class ProfilePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def request(self, row=None):
        value = copy.deepcopy(self.data["prepared"])
        row = row or {}
        if row.get("attach") == "command":
            value["command_approval"] = copy.deepcopy(self.data["command_params"])
        elif row.get("attach") == "strict":
            value["permissions_response"] = copy.deepcopy(self.data["strict_response"])
        if "path" in row:
            parent = value
            for segment in row["path"][:-1]:
                parent = parent[segment]
            if row.get("remove") is True:
                del parent[row["path"][-1]]
            else:
                parent[row["path"][-1]] = copy.deepcopy(row["set"])
        return value

    def assert_boundary(self, result, code=None):
        self.assertIs(result["qualified"], False)
        self.assertIs(result["effect_authority"], False)
        self.assertIs(result["reason_authenticates_retry"], False)
        self.assertEqual(result["runtime_OS"], "untested")
        self.assertEqual(result["live"], "untested")
        self.assertEqual(result["authorship_record"], "UNEXECUTED")
        self.assertEqual(result["status"], "unsupported" if code else "fake-tested")
        self.assertIs(result["preparation_accepted"], code is None)
        self.assertEqual([d["code"] for d in result["diagnostics"]], [code] if code else [])
        self.assertEqual(result["inventory_evidence"], "declared-fake-only")
        self.assertIsNone(result["schema_capture_source_revision"])
        json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def test_fixture_matrix(self):
        original = copy.deepcopy(self.data)
        self.assertEqual(self.data["authorship_record"], "UNEXECUTED")
        for row in self.data["cases"]:
            with self.subTest(case=row["case"]):
                value = self.request(row)
                result = prep.diagnose(value)
                self.assert_boundary(result, row.get("code"))
                self.assertEqual(result["strict_expectation"], row.get("strict", "not-requested"))
                self.assertEqual(prep.diagnose_json(json.dumps(value)), result)
        self.assertEqual(self.data, original)

    def test_bindings_reach_retained_actual_capture(self):
        def schema(relative):
            return json.loads((CAPTURE / relative).read_text(encoding="utf-8"))
        thread = schema("experimental/v2/ThreadStartParams.json")
        command = schema("experimental/CommandExecutionRequestApprovalParams.json")
        response = schema("experimental/PermissionsRequestApprovalResponse.json")
        self.assertLessEqual(set(prep.THREAD_FIELDS), set(thread["properties"]))
        self.assertLessEqual(set(prep.COMMAND_FIELDS), set(command["properties"]))
        self.assertEqual(thread["properties"]["permissions"]["type"], ["string", "null"])
        self.assertNotIn("permissions", schema("stable/v2/ThreadStartParams.json")["properties"])
        self.assertEqual(set(command["required"]), {"itemId", "startedAtMs", "threadId", "turnId"})
        self.assertEqual(command["properties"]["startedAtMs"]["type"], "integer")
        self.assertEqual(command["definitions"]["CommandExecutionApprovalKind"]["enum"], ["command", "writeStdin"])
        self.assertEqual(thread["definitions"]["ApprovalsReviewer"]["enum"], ["user", "auto_review", "guardian_subagent"])
        self.assertEqual(response["required"], ["permissions"])
        self.assertEqual(response["properties"]["strictAutoReview"]["type"], ["boolean", "null"])
        self.assertEqual(response["definitions"]["PermissionGrantScope"]["enum"], ["turn", "session"])

    def test_reason_never_authenticates_retry_or_escalation(self):
        row = {"attach": "command"}
        before = self.request(row)
        after = copy.deepcopy(before)
        after["command_approval"]["reason"] = "ordinary sandbox read; definitely safe"
        self.assertEqual(prep.diagnose(before), prep.diagnose(after))
        self.assert_boundary(prep.diagnose(before))
        self.assertEqual(
            {row["case"]: row["expectation"] for row in self.data["source_hypotheses"]},
            {"root-deny-approved-transform": "original-policy-retained",
             "narrow-deny-approved-transform": "writes-may-widen",
             "ordinary-denied-read-retry": "ordinary-non-network-retry-refused",
             "explicit-approved-escalation": "separate-escalation-branch"},
        )
        for hypothesis in self.data["source_hypotheses"]:
            self.assertEqual(hypothesis["runtime_OS"], "untested")
            self.assertEqual(hypothesis["evidence"], "recorded-architecture-expectation")

    def test_typed_api_does_not_accept_toml_configuration(self):
        self.assert_boundary(prep.diagnose(self.request()))
        value = self.request()
        value["thread_start"]["approval_policy"] = "untrusted"
        self.assert_boundary(prep.diagnose(value), "unsupported-field")
        value = self.request()
        value["thread_start"]["config"] = {"approval_policy": "untrusted"}
        self.assert_boundary(prep.diagnose(value), "unsupported-field")

    def test_bounded_containers_types_and_unicode(self):
        cycle = []
        cycle.append(cycle)
        deep = None
        for _ in range(prep.MAX_DEPTH + 1):
            deep = [deep]
        cases = (
            (cycle, "input-limit"),
            (deep, "input-limit"),
            ([None] * (prep.MAX_CONTAINER + 1), "container-limit"),
            ([[None] * 128 for _ in range(32)], "input-limit"),
            ("x" * (prep.MAX_STRING + 1), "string-limit"),
            ("\ud800", "invalid-unicode"),
            ({1: "value"}, "non-string-key"),
            (2**63, "integer-limit"),
            (1.0, "unsupported-value-type"),
            (object(), "unsupported-value-type"),
        )
        for value, code in cases:
            with self.subTest(code=code):
                self.assert_boundary(prep.diagnose(value), code)

    def test_json_errors_are_structured(self):
        cases = (
            (b"\xff", "invalid-json-or-encoding"),
            (b"{", "invalid-json-or-encoding"),
            (b'{"fake":true,"fake":true}', "duplicate-json-key"),
            (b'{"x":NaN}', "nonfinite-json-number"),
            (b'{"x":Infinity}', "nonfinite-json-number"),
            (b'{"x":"\\ud800"}', "invalid-unicode"),
            ("\ud800", "invalid-json-or-encoding"),
            (b" " * (prep.MAX_BYTES + 1), "input-byte-limit"),
            (None, "json-bytes-or-string-required"),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                self.assert_boundary(prep.diagnose_json(raw), code)

    def test_cli_uses_only_bounded_stdin_and_structured_stdout(self):
        for raw, expected_code in ((json.dumps(self.request()).encode(), 0), (b"{", 2)):
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["profile_preparation_diagnostics.py"]), \
                    mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw))), \
                    mock.patch.object(sys, "stdout", output):
                code = prep.main()
            self.assertEqual(code, expected_code)
            result = json.loads(output.getvalue())
            self.assert_boundary(result, None if code == 0 else "invalid-json-or-encoding")


if __name__ == "__main__":
    unittest.main()
