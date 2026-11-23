"""Schema capabilities checked at native App Server startup and in CI."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.codex_protocol_capabilities import CapabilityError, check_codex_capabilities


FIXTURE = ROOT / "tests/fixtures/codex-protocol-provisional/0.164.0"
PROTOCOL = "codex_app_server_protocol.schemas.json"
PROTOCOL_V2 = "codex_app_server_protocol.v2.schemas.json"


class CodexProtocolCapabilitiesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for mode in ("stable", "experimental"):
            (self.root / mode).mkdir()
            for filename in (PROTOCOL, PROTOCOL_V2):
                shutil.copyfile(FIXTURE / mode / filename, self.root / mode / filename)
        self.binary = self.root / "codex-fixture"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, shutil, sys\n"
            "assert sys.argv[1:3] == ['app-server', 'generate-json-schema']\n"
            "flags = sys.argv[3:-2]\n"
            "assert flags in ([], ['--experimental']) and sys.argv[-2] == '--out'\n"
            "mode = 'experimental' if flags else 'stable'\n"
            "output = pathlib.Path(sys.argv[-1])\n"
            "assert output.parent == pathlib.Path.cwd()\n"
            "for key in ('HOME', 'CODEX_HOME'):\n"
            "    assert pathlib.Path(os.environ[key]).parent == output.parent\n"
            "assert 'OPENAI_API_KEY' not in os.environ\n"
            f"for filename in {(PROTOCOL, PROTOCOL_V2)!r}:\n"
            "    shutil.copyfile(pathlib.Path(__file__).parent / mode / filename, output / filename)\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o700)

    def edit_schema(self, filename, schema, edit, *, mode="experimental"):
        path = self.root / mode / filename
        document = json.loads(path.read_text(encoding="utf-8"))
        selected = document["definitions"]
        for key in schema.split("."):
            selected = selected[key]
        edit(selected)
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_intact_schema_is_supported(self):
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "unused-fixture-value"}):
            check_codex_capabilities(self.binary)

    def test_n1_qualification_schema_is_supported(self):
        check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_requires_namespace_registration(self):
        def remove_namespace(schema):
            schema["oneOf"] = [
                branch for branch in schema["oneOf"]
                if branch["properties"]["type"]["enum"] != ["namespace"]
            ]

        self.edit_schema(PROTOCOL, "v2.DynamicToolSpec", remove_namespace)
        check_codex_capabilities(self.binary)
        with self.assertRaisesRegex(CapabilityError, r"thread/start.*dynamicTools"):
            check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_keeps_the_original_history_contract(self):
        self.edit_schema(PROTOCOL, "v2.ThreadHistoryMode",
                         lambda schema: schema["enum"].remove("paginated"))
        check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_requires_history_mode_readback(self):
        self.edit_schema(PROTOCOL_V2, "Thread",
                         lambda schema: schema["properties"].pop("historyMode"))
        check_codex_capabilities(self.binary)
        with self.assertRaisesRegex(CapabilityError, r"thread/start.*thread\.historyMode"):
            check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_requires_string_request_namespace(self):
        self.edit_schema(PROTOCOL, "DynamicToolCallParams.properties.namespace",
                         lambda schema: schema["type"].remove("string"))
        check_codex_capabilities(self.binary)
        with self.assertRaisesRegex(CapabilityError, r"item/tool/call.*params\.namespace"):
            check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_requires_typed_completion(self):
        def remove_success(schema):
            completion, = (branch for branch in schema["oneOf"]
                           if branch["properties"]["type"]["enum"] == ["dynamicToolCall"])
            completion["properties"].pop("success")

        self.edit_schema(PROTOCOL, "v2.ThreadItem", remove_success)
        check_codex_capabilities(self.binary)
        with self.assertRaisesRegex(CapabilityError, r"item/completed.*dynamicToolCall\.success"):
            check_codex_capabilities(self.binary, n1_qualification=True)

    def test_n1_qualification_requires_a_refused_tool_result(self):
        self.edit_schema(PROTOCOL, "DynamicToolCallResponse.properties.success",
                         lambda schema: schema.update(const=True))
        check_codex_capabilities(self.binary)
        with self.assertRaisesRegex(CapabilityError, r"item/tool/call.*success"):
            check_codex_capabilities(self.binary, n1_qualification=True)

    def test_missing_method_names_the_capability(self):
        check_codex_capabilities(self.binary)

        def remove_thread_read(schema):
            schema["oneOf"] = [
                branch for branch in schema["oneOf"]
                if branch["properties"]["method"]["enum"] != ["thread/read"]
            ]

        self.edit_schema(PROTOCOL, "ClientRequest", remove_thread_read)
        with self.assertRaisesRegex(CapabilityError, "thread/read"):
            check_codex_capabilities(self.binary)

    def test_diagnostic_requires_method_without_experimental_negotiation(self):
        check_codex_capabilities(self.binary)

        def remove_command_exec(schema):
            schema["oneOf"] = [
                branch for branch in schema["oneOf"]
                if branch["properties"]["method"]["enum"] != ["command/exec"]
            ]

        self.edit_schema(PROTOCOL, "ClientRequest", remove_command_exec, mode="stable")
        with self.assertRaisesRegex(CapabilityError, "command/exec"):
            check_codex_capabilities(self.binary)

    def test_missing_nested_request_field_names_the_gap(self):
        self.edit_schema(PROTOCOL, "v2.ThreadReadParams",
                         lambda schema: schema["properties"].pop("includeTurns"))
        with self.assertRaisesRegex(CapabilityError, r"thread/read.*params\.includeTurns"):
            check_codex_capabilities(self.binary)

    def test_changed_nested_reply_type_names_the_gap(self):
        self.edit_schema(PROTOCOL_V2, "Thread",
                         lambda schema: schema["properties"].update(path={"type": "integer"}))
        with self.assertRaisesRegex(CapabilityError, r"thread/read.*ThreadReadResponse\.thread\.path"):
            check_codex_capabilities(self.binary)

    def test_new_required_request_field_refuses(self):
        def add_field(schema):
            schema["properties"]["newField"] = {"type": "boolean"}
            schema["required"].append("newField")

        self.edit_schema(PROTOCOL, "v2.ThreadReadParams", add_field)
        with self.assertRaisesRegex(CapabilityError, r"thread/read.*params\.newField"):
            check_codex_capabilities(self.binary)

    def test_missing_refusal_reply_names_callback_and_field(self):
        self.edit_schema(PROTOCOL, "FileChangeRequestApprovalResponse",
                         lambda schema: schema["properties"].pop("decision"))
        with self.assertRaisesRegex(CapabilityError, r"item/fileChange/requestApproval.*decision"):
            check_codex_capabilities(self.binary)

    def test_an_additive_method_and_optional_fields_pass(self):
        self.edit_schema(PROTOCOL, "ClientRequest", lambda schema: schema["oneOf"].append({
            "type": "object",
            "properties": {"method": {"const": "new/additive"}, "params": {"type": "object"}},
            "required": ["method"],
        }))
        self.edit_schema(PROTOCOL, "v2.ThreadReadParams",
                         lambda schema: schema["properties"].update(newField={"type": "boolean"}))
        self.edit_schema(PROTOCOL_V2, "ThreadReadResponse",
                         lambda schema: schema["properties"].update(newField={"type": "boolean"}))
        check_codex_capabilities(self.binary)

    def test_launch_prefix_receives_isolated_workspace(self):
        workspaces = []

        def launcher(workspace):
            workspaces.append(workspace)
            self.assertTrue((workspace / "home").is_dir())
            self.assertTrue((workspace / "codex-home").is_dir())
            return [sys.executable, "-c", "import os, sys; os.execv(sys.argv[1], sys.argv[1:])"]

        check_codex_capabilities(self.binary, launcher=launcher)
        self.assertEqual(len(set(workspaces)), 2)
        self.assertTrue(all(not workspace.exists() for workspace in workspaces))
