from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Iterator, NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.codex_protocol_pin as pins  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "codex-protocol"


def fixture_root(pin: dict) -> Path:
    return FIXTURES / pin["version"]


class PinPolicyTests(unittest.TestCase):
    def test_exactly_one_current_pin_and_a_historical_one(self) -> None:
        loaded = pins.load_pins()
        self.assertEqual({pin["version"]: pin["status"] for pin in loaded}, {"0.163.0": "current", "0.162.0": "historical"})
        self.assertEqual(pins.pin_for("0.163.0")["executable"]["version_text"], "codex-cli 0.163.0")
        with self.assertRaises(pins.PinError):
            pins.pin_for("0.164.0")

    def test_manifests_and_vendored_schemas_match_the_pins(self) -> None:
        for pin in pins.load_pins():
            with self.subTest(version=pin["version"]):
                manifest = pins.load_manifest(pin, ROOT)
                vendored = [path for path in fixture_root(pin).rglob("*.json") if path.name != "manifest.json"]
                self.assertGreaterEqual(len(vendored), 16)
                for path in vendored:
                    bundle, relative = path.relative_to(fixture_root(pin)).parts[0], "/".join(path.relative_to(fixture_root(pin)).parts[1:])
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), manifest[bundle][relative], relative)

    def test_every_fact_holds_for_each_pinned_version(self) -> None:
        for pin in pins.load_pins():
            with self.subTest(version=pin["version"]):
                self.assertEqual(pins.check_facts(pin, fixture_root(pin), pins.load_manifest(pin, ROOT)), [])

    def test_a_malformed_pin_policy_is_refused(self) -> None:
        good = pins.load_policy(pins.PIN_POLICY)
        cases = {
            "no pins": {"pins": []},
            "bad hash": {"pins": [{**good["pins"][0], "executable": {**good["pins"][0]["executable"], "sha256": "x"}}]},
            "unknown fact kind": {"pins": [{**good["pins"][0], "facts": [{**good["pins"][0]["facts"][0], "kind": "trust-me"}]}]},
            "repeated fact": {"pins": [{**good["pins"][0], "facts": [good["pins"][0]["facts"][0]] * 2}]},
            "two current": {"pins": [good["pins"][0], {**good["pins"][1], "status": "current"}]},
            "missing bundle": {"pins": [{**good["pins"][0], "bundles": {"stable": good["pins"][0]["bundles"]["stable"]}}]},
        }
        for label, data in cases.items():
            with self.subTest(label=label), patch.object(pins, "load_policy", return_value=data):
                with self.assertRaises(pins.PinError):
                    pins.load_pins()

    def test_a_manifest_that_drifted_from_its_pin_is_refused(self) -> None:
        pin = pins.pin_for("0.163.0")
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = json.loads((ROOT / pin["manifest"]).read_text(encoding="utf-8"))
            manifest["stable"]["v2/ThreadStartParams.json"] = "0" * 64
            target = Path(tmpdir) / pin["manifest"]
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(pins.PinError, "bundle stable does not match the pin"):
                pins.load_manifest(pin, Path(tmpdir))


class FactMutationCase(NamedTuple):
    original: str
    path: str
    mutate: Callable[[dict], None]
    expected: set[str]


def _fact_mutation_rows() -> Iterator[FactMutationCase]:
    yield FactMutationCase('test_a_structured_retry_field_breaks_the_no_retry_class_fact', "stable/CommandExecutionRequestApprovalParams.json", lambda data: data["properties"].update(retryReason={"type": "string"}), {"no-structured-retry-class-CommandExecutionRequestApprovalParams-stable"})

    def drop(data: dict) -> None:
        options = data["definitions"]["CommandExecutionApprovalDecision"]["oneOf"]
        data["definitions"]["CommandExecutionApprovalDecision"]["oneOf"] = [
            option for option in options if option.get("enum") != ["acceptForSession"]]
    yield FactMutationCase('test_losing_session_scoped_approval_breaks_the_decisions_fact', "stable/CommandExecutionRequestApprovalResponse.json", drop, {"command-approval-decisions", "command-approval-decision-union-stable"})

    yield FactMutationCase('test_a_stable_profile_selector_breaks_the_experimental_only_fact', "stable/v2/ThreadStartParams.json", lambda data: data["properties"].update(permissions={"type": "string"}), {"named-profile-selector-experimental-only"})

    def add(data: dict) -> None:
        data["oneOf"].append({"properties": {"method": {"enum": ["item/commandExecution/stdinApproval"]},
                                             "params": {"$ref": "#/definitions/CommandExecutionStdinApprovalParams"}}})
    yield FactMutationCase('test_a_new_server_request_breaks_the_method_set_and_needs_a_response', "stable/ServerRequest.json", add, {"server-requests-stable", "server-requests-answerable-stable"})

    yield FactMutationCase('test_an_uncorrelated_approval_breaks_the_correlation_fact', "experimental/CommandExecutionRequestApprovalParams.json", lambda data: data["required"].remove("turnId"), {"command-approval-correlation-experimental"})

    yield FactMutationCase('test_a_changed_reason_description_breaks_the_free_text_fact', "stable/CommandExecutionRequestApprovalParams.json", lambda data: data["properties"]["reason"].update(description="Structured retry class."), {"command-approval-reason-is-free-text"})

    yield FactMutationCase('test_a_removed_configuration_request_breaks_the_readable_fact', "stable/ClientRequest.json", lambda data: data.update(oneOf=[
        variant for variant in data["oneOf"] if variant["properties"]["method"]["enum"] != ["configRequirements/read"]]), {"configuration-readable-without-a-turn"})

    def drop(data: dict) -> None:
        data["definitions"]["CommandExecutionApprovalKind"]["enum"] = ["command"]
    yield FactMutationCase('test_losing_writeStdin_breaks_the_approval_kind_fact', "stable/CommandExecutionRequestApprovalParams.json", drop, {"command-approval-kind-stable"})

    yield FactMutationCase('test_changing_approval_id_description_breaks_the_correlation_fact', "experimental/CommandExecutionRequestApprovalParams.json", lambda data: data["properties"]["approvalId"].update(description="Just an id."), {"command-approval-id-correlation-experimental"})

    def add_turn_required(data: dict) -> None:
        for variant in data.get("oneOf", []):
            if variant.get("properties", {}).get("method", {}).get("enum") == ["config/read"]:
                params_ref = variant.get("properties", {}).get("params", {}).get("$ref", "")
                params_def = params_ref.split("/")[-1]
                if params_def in data.get("definitions", {}):
                    data["definitions"][params_def].setdefault("required", []).append("turnId")
    yield FactMutationCase('test_adding_turnId_required_to_config_read_breaks_the_no_turn_fact', "stable/ClientRequest.json", add_turn_required, {"config-read-no-turn-required-stable"})

    def change_to_integer(data: dict) -> None:
        decision_def = data["definitions"]["CommandExecutionApprovalDecision"]
        decision_def.clear()
        decision_def["type"] = "integer"
    yield FactMutationCase('test_changing_approval_decision_to_integer_breaks_the_decision_union_fact', "stable/CommandExecutionRequestApprovalResponse.json", change_to_integer, {"command-approval-decision-union-stable", "command-approval-decisions"})


class FactNegativeTests(unittest.TestCase):
    """Each fact is checked against the vendored schema with one value changed at a time."""

    def setUp(self) -> None:
        self.pin = pins.pin_for("0.163.0")
        self.manifest = pins.load_manifest(self.pin, ROOT)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copytree(fixture_root(self.pin), self.root, dirs_exist_ok=True)

    def edit(self, relative: str, change) -> None:
        path = self.root / relative
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data), encoding="utf-8")

    def failing(self) -> set[str]:
        return {problem.split(":", 1)[0] for problem in pins.check_facts(self.pin, self.root, self.manifest)}

    def test_schema_fact_mutation_rows(self) -> None:
        for row in _fact_mutation_rows():
            with self.subTest(original=row.original):
                path = self.root / row.path
                original = path.read_bytes()
                try:
                    self.edit(row.path, row.mutate)
                    self.assertEqual(self.failing(), row.expected)
                finally:
                    path.write_bytes(original)


    def test_a_missing_response_schema_breaks_the_answerable_fact(self) -> None:
        manifest = {name: dict(entries) for name, entries in self.manifest.items()}
        del manifest["experimental"]["CurrentTimeReadResponse.json"]
        failing = {problem.split(":", 1)[0] for problem in pins.check_facts(self.pin, self.root, manifest)}
        self.assertEqual(failing, {"server-requests-answerable-experimental"})


    def test_an_unreadable_schema_fails_its_facts(self) -> None:
        (self.root / "stable" / "v2" / "ThreadStartParams.json").write_text("{not json", encoding="utf-8")
        self.assertEqual(self.failing(), {"named-profile-selector-experimental-only", "approvals-reviewer-routing"})


def _failing_after(version: str, relative: str, change) -> set[str]:
    """Fact ids that fail for ``version`` once ``change`` is applied to one copied schema file."""
    pin = pins.pin_for(version)
    manifest = pins.load_manifest(pin, ROOT)
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        shutil.copytree(fixture_root(pin), root, dirs_exist_ok=True)
        path = root / relative
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data), encoding="utf-8")
        return {problem.split(":", 1)[0] for problem in pins.check_facts(pin, root, manifest)}


def _branch(union: dict, name: str) -> dict:
    return next(branch for branch in union["oneOf"] if branch.get("enum") == [name] or name in branch.get("properties", {}))


def _without(union: dict, name: str) -> None:
    union["oneOf"].remove(_branch(union, name))


class StructuralFactTests(unittest.TestCase):
    """Facts that follow references and check complete unions, changed one way at a time in both pins and bundles."""

    VERSIONS = ("0.163.0", "0.162.0")

    DECISION_CHANGES = {
        # label: (change to the decision union, also fails the stable-only decisions fact)
        "integer branch added": (lambda union: union["oneOf"].append({"type": "integer", "enum": [1]}), False),
        "untyped branch added": (lambda union: union["oneOf"].append({"description": "Anything."}), False),
        "type removed from a string branch": (lambda union: _branch(union, "accept").pop("type"), False),
        "string branch widened to integer": (lambda union: _branch(union, "decline").update(type=["string", "integer"]), False),
        "string branch replaced by integer": (lambda union: _branch(union, "cancel").update(type="integer", enum=[3]), True),
        "string branch removed": (lambda union: _without(union, "cancel"), True),
        "amendment branch removed": (lambda union: _without(union, "applyNetworkPolicyAmendment"), True),
        "unpinned string added": (lambda union: union["oneOf"].append({"type": "string", "enum": ["acceptAll"]}), False),
        "amendment opened to other properties": (
            lambda union: _branch(union, "acceptWithExecpolicyAmendment").pop("additionalProperties"), False),
        "amendment shape changed": (
            lambda union: _branch(union, "acceptWithExecpolicyAmendment")["properties"]["acceptWithExecpolicyAmendment"]
            ["properties"]["execpolicy_amendment"]["items"].update(type="integer"), False),
        "unpinned amendment added": (lambda union: union["oneOf"].append(
            {"type": "object", "additionalProperties": False, "properties": {"grantAll": {"type": "object"}},
             "required": ["grantAll"]}), False),
        "type beside the union": (lambda union: union.update(type="integer"), False),
    }

    def test_each_decision_union_change_breaks_the_union_fact(self) -> None:
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                for label, (change, breaks_decisions) in self.DECISION_CHANGES.items():
                    with self.subTest(version=version, bundle=bundle, change=label):
                        expected = {f"command-approval-decision-union-{bundle}"}
                        if breaks_decisions and bundle == "stable":
                            expected.add("command-approval-decisions")
                        failing = _failing_after(version, f"{bundle}/CommandExecutionRequestApprovalResponse.json",
                                                 lambda data: change(data["definitions"]["CommandExecutionApprovalDecision"]))
                        self.assertEqual(failing, expected)

    def test_an_optional_decision_breaks_the_union_fact(self) -> None:
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                with self.subTest(version=version, bundle=bundle):
                    failing = _failing_after(version, f"{bundle}/CommandExecutionRequestApprovalResponse.json",
                                             lambda data: data.update(required=[]))
                    self.assertEqual(failing, {f"command-approval-decision-union-{bundle}"})

    def test_the_experimental_decision_is_checked_from_vendored_files(self) -> None:
        for version in self.VERSIONS:
            with self.subTest(version=version):
                ids = {fact["id"]: fact for fact in pins.pin_for(version)["facts"]}
                fact = ids["command-approval-decision-union-experimental"]
                self.assertEqual((fact["schema"], fact["bundle"]), ("experimental/ServerRequest.json", "experimental"))

    def test_each_reachable_kind_change_breaks_the_reachable_kind_fact(self) -> None:
        def params(data: dict) -> dict:
            return data["definitions"]["CommandExecutionRequestApprovalParams"]

        def retarget(data: dict, name: str, definition: dict | None) -> None:
            if definition is not None:
                data["definitions"][name] = definition
            params(data)["properties"]["kind"]["allOf"][0]["$ref"] = f"#/definitions/{name}"

        changes = {
            "kind removed from the reachable params": lambda data: params(data)["properties"].pop("kind"),
            "kind retargeted to a narrower enum": lambda data: retarget(
                data, "CommandExecutionApprovalKindNarrow", {"enum": ["command"], "type": "string"}),
            "kind retargeted to an identical copy": lambda data: retarget(
                data, "CommandExecutionApprovalKindCopy", dict(data["definitions"]["CommandExecutionApprovalKind"])),
            "kind reference dangling": lambda data: retarget(data, "CommandExecutionApprovalKindMissing", None),
            "writeStdin removed from the reachable definition": lambda data: data["definitions"]
            ["CommandExecutionApprovalKind"].update(enum=["command"]),
            "kind value added": lambda data: data["definitions"]["CommandExecutionApprovalKind"].update(
                enum=["command", "writeStdin", "applyPatch"]),
            "default changed": lambda data: params(data)["properties"]["kind"].update(default="writeStdin"),
        }
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                for label, change in changes.items():
                    with self.subTest(version=version, bundle=bundle, change=label):
                        self.assertEqual(_failing_after(version, f"{bundle}/ServerRequest.json", change),
                                         {f"command-approval-kind-reachable-{bundle}"})

    def test_retargeting_the_approval_params_breaks_the_facts_that_follow_them(self) -> None:
        def retarget(data: dict) -> None:
            for variant in data["oneOf"]:
                if variant["properties"]["method"]["enum"] == ["item/commandExecution/requestApproval"]:
                    variant["properties"]["params"]["$ref"] = "#/definitions/FileChangeRequestApprovalParams"
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                with self.subTest(version=version, bundle=bundle):
                    self.assertEqual(_failing_after(version, f"{bundle}/ServerRequest.json", retarget),
                                     {f"command-approval-kind-reachable-{bundle}", f"command-approval-decision-union-{bundle}"})

    def test_the_standalone_kind_fact_follows_the_params_kind_property(self) -> None:
        changes = {
            "kind removed from the params": lambda data: data["properties"].pop("kind"),
            "default changed": lambda data: data["properties"]["kind"].update(default="writeStdin"),
            "kind retargeted": lambda data: data["properties"]["kind"]["allOf"][0].update(
                {"$ref": "#/definitions/CommandExecutionApprovalKindMissing"}),
        }
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                for label, change in changes.items():
                    with self.subTest(version=version, bundle=bundle, change=label):
                        self.assertEqual(
                            _failing_after(version, f"{bundle}/CommandExecutionRequestApprovalParams.json", change),
                            {f"command-approval-kind-{bundle}"})

    def test_adding_constraint_keywords_beside_allOf_reference_breaks_the_fact(self) -> None:
        """Constraints added alongside an allOf reference must be rejected or evaluated."""
        def add_enum_to_kind_wrapper(data: dict) -> None:
            # Add enum: ["command"] to the params kind property, alongside the allOf reference.
            # This excludes writeStdin but should break the fact by being unsupported.
            params = data["definitions"]["CommandExecutionRequestApprovalParams"]
            params["properties"]["kind"]["enum"] = ["command"]

        def wrap_decision_with_conflicting_type(data: dict) -> None:
            # Wrap the decision reference in allOf alongside type: integer, making it unsatisfiable.
            response = data
            decision_ref = response["properties"]["decision"]
            response["properties"]["decision"] = {
                "allOf": [decision_ref, {"type": "integer"}]
            }

        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                with self.subTest(version=version, bundle=bundle, constraint="enum beside kind ref"):
                    self.assertEqual(
                        _failing_after(version, f"{bundle}/ServerRequest.json", add_enum_to_kind_wrapper),
                        {f"command-approval-kind-reachable-{bundle}"})

                with self.subTest(version=version, bundle=bundle, constraint="type beside decision ref"):
                    self.assertEqual(
                        _failing_after(version, f"{bundle}/CommandExecutionRequestApprovalResponse.json",
                                       wrap_decision_with_conflicting_type),
                        {f"command-approval-decision-union-{bundle}"})

    def test_response_root_type_must_be_exactly_object(self) -> None:
        """The response root must be exactly object type with decision required."""
        changes = {
            "root type widened to include integer": lambda data: data.update(type=["object", "integer"]),
            "root type removed": lambda data: data.pop("type", None),
            "decision removed from required": lambda data: data.update(required=[]),
        }
        for version in self.VERSIONS:
            for bundle in pins.BUNDLES:
                for label, change in changes.items():
                    with self.subTest(version=version, bundle=bundle, change=label):
                        self.assertEqual(
                            _failing_after(version, f"{bundle}/CommandExecutionRequestApprovalResponse.json", change),
                            {f"command-approval-decision-union-{bundle}"})


class BundleAndExecutableTests(unittest.TestCase):
    def bundle(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "v2").mkdir()
        for name, text in (("A.json", "{}"), ("B.json", "[]"), ("v2/C.json", '{"x": 1}')):
            (root / name).write_text(text, encoding="utf-8")
        return root

    def test_a_matching_bundle_has_no_problems(self) -> None:
        root = self.bundle()
        manifest = pins.bundle_manifest(root)
        self.assertEqual(sorted(manifest), ["A.json", "B.json", "v2/C.json"])
        self.assertEqual(pins.verify_bundle(root, manifest, pins.bundle_digest(manifest)), [])

    def test_each_kind_of_drift_is_reported(self) -> None:
        root = self.bundle()
        manifest = pins.bundle_manifest(root)
        digest = pins.bundle_digest(manifest)
        (root / "A.json").write_text('{"changed": true}', encoding="utf-8")
        (root / "B.json").unlink()
        (root / "D.json").write_text("{}", encoding="utf-8")
        self.assertEqual(pins.verify_bundle(root, manifest, digest),
                         ["missing: B.json", "unexpected: D.json", "changed: A.json", "bundle digest differs from the pin"])

    def test_a_wrong_digest_alone_is_reported(self) -> None:
        root = self.bundle()
        manifest = pins.bundle_manifest(root)
        self.assertEqual(pins.verify_bundle(root, manifest, "0" * 64), ["bundle digest differs from the pin"])

    def test_a_symlink_in_the_bundle_is_refused(self) -> None:
        root = self.bundle()
        manifest = pins.bundle_manifest(root)
        os.symlink(root / "A.json", root / "E.json")
        problems = pins.verify_bundle(root, manifest, pins.bundle_digest(manifest))
        self.assertEqual(len(problems), 1)
        self.assertIn("not a regular file in the bundle: E.json", problems[0])

    def test_the_executable_must_match_version_and_hash(self) -> None:
        pin = pins.pin_for("0.163.0")
        sha = pin["executable"]["sha256"]
        self.assertEqual(pins.executable_matches(pin, "codex-cli 0.163.0\n", sha), [])
        self.assertEqual(len(pins.executable_matches(pin, "codex-cli 0.163.1", sha)), 1)
        self.assertEqual(pins.executable_matches(pin, "codex-cli 0.163.0", "1" * 64), ["executable hash differs from the pin"])
        self.assertEqual(len(pins.executable_matches(pins.pin_for("0.162.0"), "codex-cli 0.163.0", sha)), 2)


if __name__ == "__main__":
    unittest.main()
