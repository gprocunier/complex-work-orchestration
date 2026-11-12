"""Bounded canonical 0.164 schema concordance with the inert server-request consumer."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import server_request_preparation as prep  # noqa: E402

CORPUS = ROOT / "tests" / "fixtures" / "codex-protocol-0164-corpus"
BUNDLES = ("stable", "experimental")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _local(schema, node):
    prefix = "#/definitions/"
    reference = node["$ref"]
    if set(node) != {"$ref"} or not reference.startswith(prefix):
        raise AssertionError("expected a bare local definition reference")
    name = reference[len(prefix):]
    if "/" in name:
        raise AssertionError("expected one definition name")
    return schema["definitions"][name]


def _variant(branches, field, value):
    matches = [
        branch for branch in branches
        if branch.get("properties", {}).get(field, {}).get("enum") == [value]
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one {field} discriminator for {value!r}")
    return matches[0]


def _frame(method, request_id=7, **changes):
    params = {"threadId": "thread", "turnId": "turn", "itemId": "item",
              "startedAtMs": 100}
    if method == prep.COMMAND:
        params.update(command="inspect fixture", cwd="/fixture")
    if method == prep.PERMISSIONS:
        params.update(cwd="/fixture", permissions={})
    params.update(changes)
    return {"id": request_id, "method": method, "params": params}


def _context(frame):
    values = {"epoch": "fixture", "thread_id": "thread", "turn_id": "turn",
              "item_id": frame["params"]["itemId"], "method": frame["method"]}
    if frame["method"] == prep.COMMAND:
        values.update(command="inspect fixture", cwd="/fixture")
    if frame["method"] == prep.FILE:
        values.update(paths=("/fixture/a",))
    return prep.FakeItemContext(**values)


class W130164CorpusCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.capture = _read(CORPUS / "capture.json")
        self.manifest = _read(CORPUS / "manifest.json")
        for bundle in BUNDLES:
            self.assertEqual(len(self.manifest[bundle]),
                             self.capture["canonical_corpus"][bundle]["files"])

    def schema(self, bundle, name):
        self.assertIn(name, self.manifest[bundle])
        self.assertIn(f"{bundle}/{name}", self.capture["original_raw_sha256"])
        return _read(CORPUS / bundle / name)

    def contract(self, bundle, method):
        server = self.schema(bundle, "ServerRequest.json")
        branch = _variant(server["oneOf"], "method", method)
        self.assertEqual(branch["required"], ["id", "method", "params"])
        ids = _local(server, branch["properties"]["id"])
        self.assertEqual(ids["anyOf"], [{"type": "string"},
                                       {"format": "int64", "type": "integer"}])
        node = branch["properties"]["params"]
        params = _local(server, node)
        name = node["$ref"].rsplit("/", 1)[-1]
        if method != prep.PERMISSIONS:
            standalone = self.schema(bundle, name + ".json")
            for key in ("type", "properties", "required"):
                self.assertEqual(standalone[key], params[key])
            params = standalone
        required = ["itemId", "startedAtMs", "threadId", "turnId"]
        if method == prep.PERMISSIONS:
            required = ["cwd", "itemId", "permissions", "startedAtMs", "threadId", "turnId"]
        self.assertEqual(params["required"], required)
        self.assertEqual(params["type"], "object")
        for key in ("threadId", "turnId", "itemId"):
            self.assertEqual(params["properties"][key]["type"], "string")
        self.assertEqual(params["properties"]["startedAtMs"]["type"], "integer")
        response = self.schema(bundle, name.removesuffix("Params") + "Response.json")
        return server, params, response

    def registered(self, frames):
        adapter = prep.FakeRequestPreparer(
            "fixture", allowed_paths=("/fixture/a",), max_pending=2)
        adapter.open_turn("thread", "turn", now=0)
        for frame in frames:
            adapter.observe_item(_context(frame), now=0)
        return adapter

    def receive(self, adapter, frame):
        typed = prep.classify_message(frame)
        self.assertIsInstance(typed, prep.ServerRequest)
        self.assertEqual((typed.request_id, typed.method), (frame["id"], frame["method"]))
        self.assertIs(type(typed.request_id), type(frame["id"]))
        self.assertEqual(json.loads(typed.params_json), frame["params"])
        self.assertEqual(adapter.receive(frame, epoch="fixture", now=0), typed)

    def work(self, adapter, frame):
        work = adapter.next_decision(now=0)
        self.assertIsNotNone(work)
        self.assertEqual(work.method, frame["method"])
        self.assertEqual(work.correlation, prep.Correlation(
            "fixture", frame["id"], "thread", "turn", frame["params"]["itemId"],
            frame["params"].get("approvalId")))
        self.assertIs(type(work.correlation.request_id), type(frame["id"]))
        self.assertEqual(work.context, _context(frame))
        self.assertEqual(json.loads(work.params_json), frame["params"])
        return work

    def pending(self, bundle, frame):
        _, _, response = self.contract(bundle, frame["method"])
        adapter = self.registered([frame])
        self.receive(adapter, frame)
        self.assertEqual(adapter.drain_replies(now=0), ())
        return adapter, self.work(adapter, frame), response

    def assert_reply(self, reply, frame, response, result, *, interrupt=False):
        wire = json.loads(reply.frame_json)
        self.assertEqual(wire, {"id": frame["id"], "result": result})
        self.assertIs(type(wire["id"]), type(frame["id"]))
        self.assertLessEqual(len(reply.frame_json), 65536)
        self.assertEqual(response["type"], "object")
        self.assertEqual(reply.interruption_required, interrupt)
        self.assertIs(reply.experimental, True)
        self.assertIs(reply.qualified, False)
        self.assertEqual(self.capture["captured_executable"]["version_text"],
                         f"codex-cli {reply.captured_version}")
        if frame["method"] == prep.PERMISSIONS:
            self.assertEqual(response["required"], ["permissions"])
            self.assertEqual(result, {"permissions": {}})
            granted = _local(response, response["properties"]["permissions"])
            self.assertEqual(granted["type"], "object")
            self.assertEqual(granted.get("required", []), [])
        else:
            self.assertEqual(response["required"], ["decision"])
            union = _local(response, response["properties"]["decision"])
            matches = [node for node in union["oneOf"]
                       if node.get("enum") == [result["decision"]]]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["type"], "string")

    def finish(self, adapter, work, frame, response, decision, result):
        adapter.prepare(work.correlation, decision, now=0)
        replies = adapter.drain_replies(now=0)
        self.assertEqual(len(replies), 1)
        self.assert_reply(replies[0], frame, response, result, interrupt=decision == "cancel")
        self.assertEqual(adapter.drain_replies(now=0), ())

    def test_01_command_file_acceptance_has_typed_ordered_one_action_frames(self):
        for bundle in BUNDLES:
            for method in (prep.COMMAND, prep.FILE):
                with self.subTest(bundle=bundle, method=method):
                    frames = [_frame(method, 7, itemId="integer"),
                              _frame(method, "7", itemId="string")]
                    _, _, response = self.contract(bundle, method)
                    adapter = self.registered(frames)
                    for frame in frames:
                        self.receive(adapter, frame)
                    for frame in frames:
                        work = self.work(adapter, frame)
                        other_id = str(frame["id"]) if type(frame["id"]) is int else int(frame["id"])
                        with self.assertRaisesRegex(prep.PreparationError, "correlation-mismatch"):
                            adapter.prepare(replace(work.correlation, request_id=other_id),
                                            "accept", now=0)
                        adapter.prepare(work.correlation, "accept", now=0)
                        with self.assertRaisesRegex(prep.PreparationError, "decision-stale-or-duplicate"):
                            adapter.prepare(work.correlation, "accept", now=0)
                    replies = adapter.drain_replies(now=0)
                    self.assertEqual(len(replies), 2)
                    for frame, reply in zip(frames, replies, strict=True):
                        self.assert_reply(reply, frame, response, {"decision": "accept"})
                    self.assertEqual(adapter.drain_replies(now=0), ())
                    self.assertIsNone(adapter.next_decision(now=0))
                    with self.assertRaisesRegex(prep.PreparationError, "duplicate-request-id"):
                        adapter.receive(frames[0], epoch="fixture", now=0)

    def test_02_captured_required_fields_pair_with_type_and_correlation_refusals(self):
        for bundle in BUNDLES:
            for method in (prep.COMMAND, prep.FILE, prep.PERMISSIONS):
                with self.subTest(bundle=bundle, method=method):
                    frame = _frame(method)
                    adapter, work, response = self.pending(bundle, frame)
                    decision = "decline" if method == prep.PERMISSIONS else "accept"
                    result = {"permissions": {}} if method == prep.PERMISSIONS else {"decision": decision}
                    self.finish(adapter, work, frame, response, decision, result)
                    bad = []
                    for key, value in (("startedAtMs", True), ("startedAtMs", "100"),
                                       ("threadId", False)):
                        changed = deepcopy(frame)
                        changed["params"][key] = value
                        bad.append(changed)
                    missing = deepcopy(frame)
                    del missing["params"]["startedAtMs"]
                    bad.append(missing)
                    boolean_id = deepcopy(frame)
                    boolean_id["id"] = True
                    bad.append(boolean_id)
                    for changed in bad:
                        with self.subTest(changed=changed):
                            with self.assertRaises(prep.PreparationError):
                                prep.classify_message(changed)
                            with self.assertRaises(prep.PreparationError):
                                adapter.receive(changed, epoch="fixture", now=0)
                    self.assertEqual(adapter.drain_replies(now=0), ())
                    changed = deepcopy(frame)
                    changed["params"]["turnId"] = "other"
                    self.assertIsInstance(prep.classify_message(changed), prep.ServerRequest)
                    fresh = self.registered([frame])
                    with self.assertRaisesRegex(prep.PreparationError, "inactive-or-cross-thread-turn"):
                        fresh.receive(changed, epoch="fixture", now=0)
                    self.assertIsNone(fresh.next_decision(now=0))
                    self.assertEqual(fresh.drain_replies(now=0), ())

    def permission_paths(self, server, params):
        profile = _local(server, params["properties"]["permissions"])
        self.assertIs(profile["additionalProperties"], False)
        filesystem = _local(server, profile["properties"]["fileSystem"]["anyOf"][0])
        network = _local(server, profile["properties"]["network"]["anyOf"][0])
        self.assertEqual(network["properties"]["enabled"]["type"], ["boolean", "null"])
        entry = _local(server, filesystem["properties"]["entries"]["items"])
        self.assertEqual(entry["required"], ["access", "path"])
        self.assertEqual(_local(server, entry["properties"]["access"])["enum"],
                         ["read", "write", "deny"])
        paths = _local(server, entry["properties"]["path"])
        literal = _variant(paths["oneOf"], "type", "path")
        glob = _variant(paths["oneOf"], "type", "glob_pattern")
        self.assertEqual(literal["required"], ["path", "type"])
        self.assertEqual(_local(server, literal["properties"]["path"])["type"], "string")
        self.assertEqual(glob["required"], ["pattern", "type"])
        self.assertEqual(glob["properties"]["pattern"]["type"], "string")
        special = _variant(paths["oneOf"], "type", "special")
        self.assertEqual(special["required"], ["type", "value"])
        special_paths = _local(server, special["properties"]["value"])
        cases = [{"type": "path", "path": "/fixture/a"},
                 {"type": "glob_pattern", "pattern": "src/*"}]
        for kind in ("root", "minimal", "project_roots", "tmpdir", "slash_tmp", "unknown"):
            branch = _variant(special_paths["oneOf"], "kind", kind)
            value = {"kind": kind}
            self.assertEqual(branch["required"], ["kind", "path"] if kind == "unknown" else ["kind"])
            if kind == "unknown":
                self.assertEqual(branch["properties"]["path"]["type"], "string")
                value["path"] = "/fixture/a"
            if kind in {"project_roots", "unknown"}:
                self.assertNotIn("additionalProperties", branch)
                subpath = branch["properties"]["subpath"]["anyOf"]
                self.assertEqual(_local(server, subpath[0])["type"], "string")
                self.assertEqual(subpath[1], {"type": "null"})
                value["subpath"] = "src"
            cases.append({"type": "special", "value": value})
        return cases

    def test_03_permission_path_variants_prepare_only_empty_denial(self):
        for bundle in BUNDLES:
            server, params, response = self.contract(bundle, prep.PERMISSIONS)
            for path in self.permission_paths(server, params):
                with self.subTest(bundle=bundle, path=path):
                    permissions = {"fileSystem": {"entries": [{"access": "read", "path": path}]},
                                   "network": {"enabled": True}}
                    frame = _frame(prep.PERMISSIONS, permissions=permissions)
                    adapter, work, response = self.pending(bundle, frame)
                    for decision in ("accept", "cancel"):
                        with self.assertRaisesRegex(prep.PreparationError, "permission-grants"):
                            adapter.prepare(work.correlation, decision, now=0)
                    self.finish(adapter, work, frame, response, "decline", {"permissions": {}})
                    changed = deepcopy(frame)
                    changed["params"]["permissions"]["network"]["enabled"] = "true"
                    with self.assertRaises(prep.PreparationError):
                        prep.classify_message(changed)
            project = next(path for path in self.permission_paths(server, params)
                           if path.get("value", {}).get("kind") == "project_roots")
            frame = _frame(prep.PERMISSIONS, permissions={"fileSystem": {"entries": [
                {"access": "read", "path": project}]}})
            self.receive(self.registered([frame]), frame)
            for key, value in (("subpath", True), ("extension", True)):
                changed = deepcopy(frame)
                changed["params"]["permissions"]["fileSystem"]["entries"][0]["path"]["value"][key] = value
                with self.assertRaises(prep.PreparationError):
                    prep.classify_message(changed)

    def test_04_session_decisions_refuse_without_losing_decline_or_cancel(self):
        for bundle in BUNDLES:
            for method in (prep.COMMAND, prep.FILE):
                _, params, response = self.contract(bundle, method)
                union = _local(response, response["properties"]["decision"])
                enums = [node["enum"] for node in union["oneOf"] if "enum" in node]
                self.assertIn(["acceptForSession"], enums)
                for final in ("decline", "cancel"):
                    frame = _frame(method)
                    if method == prep.COMMAND and bundle == "experimental":
                        choices = ["cancel", "acceptForSession", "accept", "decline"]
                        self.assertEqual(_local(params, params["properties"]["availableDecisions"]["items"]),
                                         union)
                        frame["params"]["availableDecisions"] = choices
                    adapter, work, response = self.pending(bundle, frame)
                    with self.assertRaisesRegex(prep.PreparationError, "one-action-decision-required"):
                        adapter.prepare(work.correlation, "acceptForSession", now=0)
                    self.finish(adapter, work, frame, response, final, {"decision": final})
                if method == prep.FILE:
                    self.assertEqual(params["properties"]["grantRoot"]["type"], ["string", "null"])
                    frame = _frame(method, grantRoot="/fixture")
                    adapter, work, response = self.pending(bundle, frame)
                    self.finish(adapter, work, frame, response, "accept", {"decision": "decline"})

    def rule_decisions(self, response):
        branches = _local(response, response["properties"]["decision"])["oneOf"]
        exec_branch = next(node for node in branches
                           if node.get("required") == ["acceptWithExecpolicyAmendment"])
        amendment = exec_branch["properties"]["acceptWithExecpolicyAmendment"]
        self.assertEqual(amendment["required"], ["execpolicy_amendment"])
        self.assertEqual(amendment["properties"]["execpolicy_amendment"],
                         {"items": {"type": "string"}, "type": "array"})
        network_branch = next(node for node in branches
                              if node.get("required") == ["applyNetworkPolicyAmendment"])
        amendment = network_branch["properties"]["applyNetworkPolicyAmendment"]
        self.assertEqual(amendment["required"], ["network_policy_amendment"])
        rule = _local(response, amendment["properties"]["network_policy_amendment"])
        self.assertEqual(rule["required"], ["action", "host"])
        self.assertEqual(rule["properties"]["host"]["type"], "string")
        self.assertEqual(_local(response, rule["properties"]["action"])["enum"], ["allow", "deny"])
        return ({"acceptWithExecpolicyAmendment": {"execpolicy_amendment": ["inspect"]}},
                {"applyNetworkPolicyAmendment": {"network_policy_amendment": {
                    "action": "allow", "host": "fixture.invalid"}}})

    def test_05_command_rules_network_and_remote_overlays_cannot_grant(self):
        for bundle in BUNDLES:
            _, params, response = self.contract(bundle, prep.COMMAND)
            frame = _frame(prep.COMMAND)
            adapter, work, response = self.pending(bundle, frame)
            self.finish(adapter, work, frame, response, "accept", {"decision": "accept"})
            for decision in self.rule_decisions(response):
                adapter, work, response = self.pending(bundle, frame)
                with self.assertRaisesRegex(prep.PreparationError, "one-action-decision-required"):
                    adapter.prepare(work.correlation, decision, now=0)
                self.finish(adapter, work, frame, response, "decline", {"decision": "decline"})
            properties = params["properties"]
            network = _local(params, properties["networkApprovalContext"]["anyOf"][0])
            self.assertEqual(network["required"], ["host", "protocol"])
            self.assertEqual(_local(params, network["properties"]["protocol"])["enum"],
                             ["http", "https", "socks5Tcp", "socks5Udp"])
            self.assertEqual(properties["environmentId"]["type"], ["string", "null"])
            self.assertEqual(properties["proposedExecpolicyAmendment"]["items"], {"type": "string"})
            rule = _local(params, properties["proposedNetworkPolicyAmendments"]["items"])
            self.assertEqual(rule["required"], ["action", "host"])
            overlays = [("environmentId", "remote"),
                        ("proposedExecpolicyAmendment", ["inspect"]),
                        ("proposedNetworkPolicyAmendments", [{"action": "allow", "host": "fixture.invalid"}]),
                        ("networkApprovalContext", {"host": "fixture.invalid", "protocol": "https"})]
            if bundle == "experimental":
                profile = _local(params, properties["additionalPermissions"]["anyOf"][0])
                enabled = _local(params, profile["properties"]["network"]["anyOf"][0])
                self.assertEqual(enabled["properties"]["enabled"]["type"], ["boolean", "null"])
                overlays.append(("additionalPermissions", {"network": {"enabled": True}}))
            for field, value in overlays:
                with self.subTest(bundle=bundle, field=field):
                    changed = deepcopy(frame)
                    changed["params"][field] = value
                    adapter, work, response = self.pending(bundle, changed)
                    self.finish(adapter, work, changed, response, "accept", {"decision": "decline"})

    def test_06_captured_unsupported_branches_emit_only_bounded_protocol_errors(self):
        cases = (
            ("item/tool/call", {"threadId": "thread", "turnId": "turn", "callId": "call",
                                "tool": "fixture", "arguments": {}},
             ["arguments", "callId", "threadId", "tool", "turnId"]),
            ("item/tool/requestUserInput", {"threadId": "thread", "turnId": "turn",
                                            "itemId": "item", "isBlocking": True, "questions": []},
             ["isBlocking", "itemId", "questions", "threadId", "turnId"]),
            ("mcpServer/elicitation/request", {"threadId": "thread", "serverName": "fixture",
                                               "mode": "form", "message": "fixture", "requestedSchema": {
                                                   "type": "object", "properties": {}}}, ["serverName", "threadId"]),
        )
        for bundle in BUNDLES:
            server = self.schema(bundle, "ServerRequest.json")
            adapter = prep.FakeRequestPreparer("fixture", max_pending=1)
            for message, kind in (
                ({"method": "item/updated", "params": {"threadId": "thread"}}, prep.Notification),
                ({"id": "response", "result": {"unchanged": True}}, prep.Response),
            ):
                typed = adapter.receive(message, epoch="fixture", now=0)
                self.assertIsInstance(typed, kind)
                self.assertEqual(json.loads(typed.frame_json), message)
            self.assertIsNone(adapter.next_decision(now=0))
            self.assertEqual(adapter.drain_replies(now=0), ())
            for number, (method, params, required) in enumerate(cases, 1):
                branch = _variant(server["oneOf"], "method", method)
                self.assertEqual(branch["required"], ["id", "method", "params"])
                schema = _local(server, branch["properties"]["params"])
                self.assertEqual(schema["required"], required)
                if method == "item/tool/call":
                    self.assertIs(schema["properties"]["arguments"], True)
                if method == "item/tool/requestUserInput":
                    self.assertEqual(schema["properties"]["isBlocking"]["type"], "boolean")
                    self.assertEqual(schema["properties"]["questions"]["type"], "array")
                if method == "mcpServer/elicitation/request":
                    form = _variant(schema["oneOf"], "mode", "form")
                    self.assertEqual(form["required"], ["message", "mode", "requestedSchema"])
                    requested = _local(server, form["properties"]["requestedSchema"])
                    self.assertEqual(requested["required"], ["properties", "type"])
                    self.assertEqual(_local(server, requested["properties"]["type"])["enum"], ["object"])
                frame = {"id": number, "method": method, "params": params}
                self.receive(adapter, frame)
                self.assertIsNone(adapter.next_decision(now=0))
                replies = adapter.drain_replies(now=0)
                self.assertEqual(len(replies), 1)
                reply = replies[0]
                self.assertEqual(json.loads(reply.frame_json), {
                    "id": number, "error": {"code": -32601, "message": "Unsupported server request"}})
                self.assertLessEqual(len(reply.frame_json), 65536)
                self.assertIs(reply.interruption_required, True)
                self.assertIsNone(reply.correlation)
                self.assertIs(reply.qualified, False)
                self.assertEqual(adapter.drain_replies(now=0), ())
            self.assertIsNone(adapter.next_decision(now=0))


if __name__ == "__main__":
    unittest.main()
