"""Offline checks of the selected canonical 0.164 corpus; no pin registration."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.codex_protocol_pin as pins  # noqa: E402

CORPUS = ROOT / "tests" / "fixtures" / "codex-protocol-0164-corpus"
SELECTED = {
    "stable": {
        "files": 19,
        "digest": "70d08b76e8eb335017c35c9ec5a0bc1eaada140ba914e7641c6b2559ef8e5f60",
    },
    "experimental": {
        "files": 22,
        "digest": "6f73c310cd7f85bf7e558374c4d0b176b39b9634c85bdc3594d48e1cd518a36b",
    },
}
METADATA_SHA256 = {
    "capture.json": "09b98b71c43e2e1a574eb060695e1a515e1059144454dff7c39cd9f3fb44982d",
    "facts.json": "ff9fd96d6bc2ee3bb2523b436d580a5a8a8675269dc05c0a00bc707aaf2f0dee",
    "manifest.json": "7defda338948631f68b49453fab42900c0e8b2d937927461b71095ed3064aacf",
}
RESPONSE = "CommandExecutionRequestApprovalResponse.json"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n",
                    encoding="utf-8")


def _manifest_wrapper() -> dict:
    return {"manifest": "manifest.json", "bundles": deepcopy(SELECTED)}


@contextmanager
def _record_reads() -> Iterator[list[Path]]:
    original = Path.read_text
    reads: list[Path] = []

    def observed(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)

    with patch.object(Path, "read_text", observed):
        yield reads


def _change_amendment(data: dict) -> None:
    branches = data["definitions"]["CommandExecutionApprovalDecision"]["oneOf"]
    branch = next(item for item in branches if "acceptWithExecpolicyAmendment" in item.get("properties", {}))
    branch["properties"]["acceptWithExecpolicyAmendment"]["properties"]["execpolicy_amendment"]["items"]["type"] = "integer"


class Codex0164SchemaCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capture = _read(CORPUS / "capture.json")
        self.subject = _read(CORPUS / "facts.json")
        self.facts = {fact["id"]: fact for fact in self.subject["facts"]}
        self.manifest = pins.load_manifest(_manifest_wrapper(), CORPUS)

    def _copy(self, *relatives: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for relative in relatives:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(CORPUS / relative, target)
        return root

    def _holds(self, identity: str, root: Path = CORPUS, manifest=None) -> None:
        entries = self.manifest if manifest is None else manifest
        self.assertIsNone(pins.evaluate_fact(self.facts[identity], root, entries))

    def _reject(self, identity: str, root: Path, fragment: str, manifest=None) -> None:
        entries = self.manifest if manifest is None else manifest
        problem = pins.evaluate_fact(self.facts[identity], root, entries)
        self.assertIsInstance(problem, str)
        self.assertTrue(problem.startswith(identity + ":"), problem)
        self.assertIn(fragment, problem)

    def test_selected_canonical_bytes_and_historical_metadata(self) -> None:
        for filename, digest in METADATA_SHA256.items():
            with self.subTest(metadata=filename):
                self.assertEqual(hashlib.sha256((CORPUS / filename).read_bytes()).hexdigest(), digest)
        self.assertEqual(self.capture["canonical_corpus"], SELECTED)
        self.assertEqual(set(self.manifest), set(SELECTED))
        for bundle, expected in SELECTED.items():
            with self.subTest(bundle=bundle):
                self.assertIs(type(self.capture["canonical_corpus"][bundle]["files"]), int)
                self.assertEqual(len(self.manifest[bundle]), expected["files"])
                self.assertEqual(pins.bundle_digest(self.manifest[bundle]), expected["digest"])
                self.assertEqual(pins.verify_bundle(CORPUS / bundle, self.manifest[bundle], expected["digest"]), [])
        selected_paths = {f"{bundle}/{name}" for bundle, entries in self.manifest.items() for name in entries}
        self.assertEqual(set(self.capture["original_raw_sha256"]), selected_paths)
        for field in ("operative", "qualified", "effect_authority", "full_pin_registered"):
            self.assertIs(self.capture[field], False)

    def test_all_32_frozen_facts_read_the_actual_selected_schemas(self) -> None:
        self.assertEqual(len(self.subject["facts"]), 32)
        self.assertEqual(len(self.facts), 32)
        with _record_reads() as reads:
            self.assertEqual(pins.check_facts(self.subject, CORPUS, self.manifest), [])
            self.assertTrue(reads)
            for fact in self.subject["facts"]:
                self.assertIn(CORPUS / fact["schema"], reads)
            for bundle in SELECTED:
                self.assertIn(CORPUS / bundle / RESPONSE, reads)

    def test_selected_manifest_wrapper_reads_before_malformed_count_controls(self) -> None:
        root = self._copy("manifest.json")
        with _record_reads() as reads:
            self.assertEqual(pins.load_manifest(_manifest_wrapper(), root), self.manifest)
            self.assertEqual(reads, [root / "manifest.json"])
            for value in (True, False, 19.0, "19"):
                with self.subTest(count=repr(value)):
                    bad = _manifest_wrapper()
                    bad["bundles"]["stable"]["files"] = value
                    reads.clear()
                    with self.assertRaisesRegex(pins.PinError, "file count"):
                        pins.load_manifest(bad, root)
                    self.assertEqual(reads, [])

    def test_captured_executable_metadata_has_version_and_hash_controls(self) -> None:
        version = "codex-cli 0.164.0"
        digest = "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
        self.assertEqual(self.subject["executable"], self.capture["captured_executable"])
        self.assertEqual(self.subject["executable"]["version_text"], version)
        self.assertEqual(self.subject["executable"]["sha256"], digest)
        self.assertEqual(pins.executable_matches(self.subject, version + "\n", digest), [])
        wrong_version = pins.executable_matches(self.subject, "codex-cli 0.164.1", digest)
        self.assertEqual(len(wrong_version), 1)
        self.assertIn("version", wrong_version[0])
        self.assertEqual(pins.executable_matches(self.subject, version, "0" * 64),
                         ["executable hash differs from the pin"])
        self.assertEqual(len(pins.executable_matches(self.subject, "codex-cli 0.164.1", "0" * 64)), 2)

    def test_each_actual_server_request_has_a_physical_selected_response(self) -> None:
        for bundle in SELECTED:
            schema = _read(CORPUS / bundle / "ServerRequest.json")
            methods = {}
            for variant in schema["oneOf"]:
                properties = variant["properties"]
                method = properties["method"]["enum"][0]
                methods[method] = properties["params"]["$ref"].rsplit("/", 1)[-1]
            self.assertEqual(set(methods), set(self.facts[f"server-requests-{bundle}"]["values"]))
            self._holds(f"server-requests-{bundle}")
            self._holds(f"server-requests-answerable-{bundle}")
            for method, params in methods.items():
                with self.subTest(bundle=bundle, method=method):
                    self.assertTrue(params.endswith("Params"))
                    response = params[:-len("Params")] + "Response.json"
                    self.assertIn(response, self.manifest[bundle])
                    path = CORPUS / bundle / response
                    self.assertTrue(path.is_file(), str(path))
                    self.assertIsInstance(_read(path), dict)

    def test_method_set_rejects_a_changed_real_request_method(self) -> None:
        for bundle in SELECTED:
            with self.subTest(bundle=bundle):
                relative = f"{bundle}/ServerRequest.json"
                root = self._copy(relative)
                self._holds(f"server-requests-{bundle}", root)
                schema = _read(root / relative)
                schema["oneOf"][0]["properties"]["method"]["enum"] = ["corpus/control"]
                _write(root / relative, schema)
                self._reject(f"server-requests-{bundle}", root, "methods are")
                self._holds(f"server-requests-answerable-{bundle}", root)

    def test_response_manifest_membership_uses_keys_even_when_file_exists(self) -> None:
        for bundle in SELECTED:
            with self.subTest(bundle=bundle):
                root = self._copy(f"{bundle}/ServerRequest.json", f"{bundle}/{RESPONSE}")
                self._holds(f"server-requests-answerable-{bundle}", root)
                self._holds(f"command-approval-decision-union-{bundle}", root)
                missing = deepcopy(self.manifest)
                del missing[bundle][RESPONSE]
                missing[bundle]["DecoyResponse.json"] = RESPONSE
                self.assertTrue((root / bundle / RESPONSE).is_file())
                self._reject(f"server-requests-answerable-{bundle}", root, "no response schema", missing)
                self._reject(f"command-approval-decision-union-{bundle}", root, "not in manifest", missing)

    def test_missing_physical_response_is_distinct_from_missing_manifest_key(self) -> None:
        for bundle in SELECTED:
            with self.subTest(bundle=bundle):
                root = self._copy(f"{bundle}/ServerRequest.json", f"{bundle}/{RESPONSE}")
                expected = {name: self.manifest[bundle][name] for name in ("ServerRequest.json", RESPONSE)}
                digest = pins.bundle_digest(expected)
                self.assertEqual(pins.verify_bundle(root / bundle, expected, digest), [])
                self._holds(f"server-requests-answerable-{bundle}", root)
                self._holds(f"command-approval-decision-union-{bundle}", root)
                (root / bundle / RESPONSE).unlink()
                self.assertEqual(pins.verify_bundle(root / bundle, expected, digest),
                                 [f"missing: {RESPONSE}", "bundle digest differs from the pin"])
                self._holds(f"server-requests-answerable-{bundle}", root)
                self._reject(f"command-approval-decision-union-{bundle}", root, "unreadable")

    def test_standalone_and_reachable_kind_defaults_and_enums_are_consumed(self) -> None:
        for bundle in SELECTED:
            for reachable in (False, True):
                for change in ("default", "enum"):
                    with self.subTest(bundle=bundle, reachable=reachable, change=change):
                        filename = "ServerRequest.json" if reachable else "CommandExecutionRequestApprovalParams.json"
                        prefix = "command-approval-kind-reachable" if reachable else "command-approval-kind"
                        identity = f"{prefix}-{bundle}"
                        relative = f"{bundle}/{filename}"
                        root = self._copy(relative)
                        expected = {filename: self.manifest[bundle][filename]}
                        digest = pins.bundle_digest(expected)
                        self.assertEqual(pins.verify_bundle(root / bundle, expected, digest), [])
                        self._holds(identity, root)
                        schema = _read(root / relative)
                        params = schema["definitions"]["CommandExecutionRequestApprovalParams"] if reachable else schema
                        kind = params["properties"]["kind"]
                        self.assertEqual(kind["allOf"][0]["$ref"], "#/definitions/CommandExecutionApprovalKind")
                        self.assertEqual(kind["default"], "command")
                        if change == "default":
                            kind["default"] = "writeStdin"
                            fragment = "defaults to"
                        else:
                            schema["definitions"]["CommandExecutionApprovalKind"]["enum"] = ["command"]
                            fragment = "allows"
                        _write(root / relative, schema)
                        self._reject(identity, root, fragment)
                        self.assertEqual(pins.verify_bundle(root / bundle, expected, digest),
                                         [f"changed: {filename}", "bundle digest differs from the pin"])

    def test_referenced_decision_union_rejects_real_schema_corruption(self) -> None:
        changes = (
            ("integer branch", lambda data: data["definitions"]["CommandExecutionApprovalDecision"]["oneOf"].append(
                {"type": "integer", "enum": [1]}), "neither"),
            ("constraint beside reference", lambda data: data["properties"]["decision"].update(type="integer"),
             "does not resolve"),
            ("amendment shape", _change_amendment, "changes the shape"),
        )
        for bundle in SELECTED:
            for label, change, fragment in changes:
                with self.subTest(bundle=bundle, change=label):
                    root = self._copy(f"{bundle}/ServerRequest.json", f"{bundle}/{RESPONSE}")
                    identity = f"command-approval-decision-union-{bundle}"
                    self._holds(identity, root)
                    response = _read(root / bundle / RESPONSE)
                    self.assertEqual(response["properties"]["decision"]["$ref"], "#/definitions/CommandExecutionApprovalDecision")
                    change(response)
                    _write(root / bundle / RESPONSE, response)
                    self._reject(identity, root, fragment)

    def test_named_selector_and_stable_experimental_approval_gates(self) -> None:
        permissions = _read(CORPUS / "experimental/v2/ThreadStartParams.json")["properties"]["permissions"]
        cases = (
            ("named-profile-selector-experimental-only", "stable/v2/ThreadStartParams.json",
             lambda data: data["properties"].update(permissions=deepcopy(permissions)), "unexpected properties"),
            ("named-profile-selector-in-experimental", "experimental/v2/ThreadStartParams.json",
             lambda data: data["properties"]["permissions"].update(description="Changed selector."), "description"),
            ("additional-permissions-experimental-only", "stable/CommandExecutionRequestApprovalParams.json",
             lambda data: data["properties"].update(additionalPermissions={"type": "object"}), "unexpected properties"),
            ("additional-permissions-in-experimental", "experimental/CommandExecutionRequestApprovalParams.json",
             lambda data: data["properties"].pop("availableDecisions"), "missing properties"),
        )
        for identity, relative, change, fragment in cases:
            with self.subTest(fact=identity):
                root = self._copy(relative)
                self._holds(identity, root)
                schema = _read(root / relative)
                change(schema)
                _write(root / relative, schema)
                self._reject(identity, root, fragment)

    def test_thread_source_fields_are_schema_claims_with_a_removal_control(self) -> None:
        for bundle in SELECTED:
            with self.subTest(bundle=bundle):
                relative = f"{bundle}/v2/ThreadStartParams.json"
                root = self._copy(relative)
                schema = _read(root / relative)
                fact = {"id": f"corpus-thread-source-fields-{bundle}", "kind": "properties-present", "schema": relative,
                        "names": ["sessionStartSource", "threadSource", "approvalsReviewer", "approvalPolicy", "sandbox"]}
                self.assertIsNone(pins.evaluate_fact(fact, root, self.manifest))
                self.assertEqual(schema["definitions"]["ThreadStartSource"]["enum"], ["startup", "clear"])
                self.assertEqual(schema["definitions"]["ThreadSource"], {"type": "string"})
                for field, definition in (("sessionStartSource", "ThreadStartSource"), ("threadSource", "ThreadSource")):
                    self.assertEqual(schema["properties"][field]["anyOf"],
                                     [{"$ref": f"#/definitions/{definition}"}, {"type": "null"}])
                del schema["properties"]["threadSource"]
                _write(root / relative, schema)
                self.assertEqual(pins.evaluate_fact(fact, root, self.manifest),
                                 f"{fact['id']}: missing properties ['threadSource']")


if __name__ == "__main__":
    unittest.main()
