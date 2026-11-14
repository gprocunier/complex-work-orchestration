"""Selected protocol response contracts at the registered fake-child boundary."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from tests import test_registered_server_requests as requests
from cwo_core import codex_protocol_pin as pins, qualification_target as target


class RegisteredTransportContractTests(unittest.TestCase):
    def setUp(self):
        self.fixture = requests.RegisteredRequestsTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(requests.family.cleanup_helper, self, self.fixture)

    def response_schema(self, bundle, name):
        version = target.selected_target()["selection"]["pin_version"]
        pin = pins.pin_for(version)
        manifest = pins.load_manifest(pin, requests.family.ROOT)
        relative = name + ".json"
        path = requests.family.ROOT / "tests/fixtures/codex-protocol" / version / bundle / relative
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest[bundle][relative])
        return json.loads(raw)

    def assert_response_contract(self, reply, name):
        result = reply["result"]
        for bundle in ("stable", "experimental"):
            with self.subTest(bundle=bundle, response=name):
                schema = self.response_schema(bundle, name)
                self.assertEqual(schema["type"], "object")
                self.assertEqual(set(result), set(schema["required"]))
                field = schema["required"][0]
                definition = schema["properties"][field]["$ref"].rsplit("/", 1)[1]
                value_schema = schema["definitions"][definition]
                if field == "permissions":
                    self.assertEqual(result[field], {})
                    self.assertEqual(value_schema["type"], "object")
                    self.assertEqual(value_schema.get("required", []), [])
                else:
                    strings = {value for option in value_schema["oneOf"]
                               if option.get("type") == "string" for value in option["enum"]}
                    self.assertIn(result[field], strings)

    def test_selected_schemas_match_registered_refusals_then_useful_acceptance(self):
        protocol = requests.runtime.protocol
        case = self.fixture.pipe_case(archive_schedule="settled", request_probes=[
            (7, protocol.FILE, {"reason": "EXAMPLE rename destination is not path evidence"}),
            ("7", protocol.PERMISSIONS,
             {"cwd": "EXAMPLE-cwd", "permissions": {"network": {"enabled": True}}}),
        ])
        factory = self.fixture.fixture.factory(case)
        factory.run()
        replies = self.fixture.fixture.spawned[0].replies
        self.assertEqual(replies, [
            {"id": 7, "result": {"decision": "decline"}},
            {"id": "7", "result": {"permissions": {}}},
            {"id": "EXAMPLE-request", "result": {"decision": "accept"}},
        ])
        for reply, name in zip(replies, (
                "FileChangeRequestApprovalResponse", "PermissionsRequestApprovalResponse",
                "CommandExecutionRequestApprovalResponse"), strict=True):
            self.assert_response_contract(reply, name)
        self.assertIsNotNone(factory.token)

    def test_selected_schema_matches_registered_command_cancellation(self):
        case = self.fixture.pipe_case(archive_schedule="settled")
        factory = self.fixture.fixture.factory(case)
        with patch.object(requests.runtime._RegisteredServer, "_decision", return_value="cancel"):
            with self.assertRaises(ValueError):
                factory.run()
        replies = self.fixture.fixture.spawned[0].replies
        self.assertEqual(replies, [{"id": "EXAMPLE-request", "result": {"decision": "cancel"}}])
        self.assert_response_contract(replies[0], "CommandExecutionRequestApprovalResponse")
        self.assertIsNone(factory.token)
        self.assertTrue(factory.server.lifetime.contained)


if __name__ == "__main__":
    unittest.main()
