"""Unregistered protocol pin proposal checks; offline data APIs only, no qualification."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import codex_hook_enforcement as hooks  # noqa: E402
from cwo_core import codex_protocol_pin as pins  # noqa: E402
from cwo_core.errors import CWOValidationError  # noqa: E402

FIXTURE = ROOT / "tests/fixtures/codex-0164-pin-proposal"
CORPUS = ROOT / "tests/fixtures/codex-protocol-0164-corpus"
POLICY = ROOT / "policy/codex-protocol-pins.yaml"
VERSION = "codex-cli 0.164.0"
EXECUTABLE = "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
FULL = {
    "stable": (320, "bb9b9746d0ecb050ea3e5b0d5e8acb89141a148a35fe7c6c987d48b9338c8c7a"),
    "experimental": (458, "3fdb06b2010e8885f842792f9da899db41ac56d21238b6d45f2a50f834161b80"),
}
POSTIMAGES = {
    "base-policy.json": "0085fbb1dee5ed093e1133d848130f130f3ab382ab4219aead4906d4c469cc21",
    "manifest.json": "9dbf022ca359ef662061d489e72470076108bdcb0e59d397589c8e205c7f7901",
    "preparation.json": "c7575c87e3887c613aeed73579e7434fe62f1e3e75be21fb267e6a5ac77749e0",
    "proposal.json": "e4259f32da26c67cd10e2f6659b36c4d16247e7b5e6a8e65463dea2a73c46417",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class Codex0164PinProposalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshots = {path: path.read_bytes() for path in (POLICY, *(FIXTURE / name for name in POSTIMAGES))}
        self.loader = pins.load_policy
        self.addCleanup(self.assert_unchanged)
        self.defaults = deepcopy(pins.load_pins())
        self.proposal = read_json(FIXTURE / "proposal.json")
        self.base = read_json(FIXTURE / "base-policy.json")
        self.manifest = read_json(FIXTURE / "manifest.json")
        self.capture = read_json(CORPUS / "capture.json")
        self.selected = read_json(CORPUS / "manifest.json")

    def assert_unchanged(self) -> None:
        self.assertIs(pins.load_policy, self.loader)
        self.assertEqual(pins.load_pins(), self.defaults)
        for pin in self.defaults:
            self.assertEqual(pins.pin_for(pin["version"]), pin)
        for path, before in self.snapshots.items():
            self.assertEqual(path.read_bytes(), before, str(path.relative_to(ROOT)))

    def prospective_policy(self) -> dict:
        document = deepcopy(self.base)
        for pin in document["pins"]:
            pin["status"] = "historical"
        document["pins"].append(deepcopy(self.proposal))
        return document

    def observed_manifest(self, subject, root: Path, expected: dict) -> dict:
        reader_method = Path.read_text
        with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
            result = pins.load_manifest(subject, root)
            self.assertEqual(result, expected)
            reader.assert_called_once_with(root / subject["manifest"], encoding="utf-8")
        return result

    def refused_before_io(self, subject) -> None:
        reader_method = Path.read_text
        with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
            with self.assertRaises(pins.PinError):
                pins.load_manifest(subject, ROOT)
            reader.assert_not_called()

    def observed_error(self, subject, root: Path, error: type[Exception]) -> str:
        reader_method = Path.read_text
        with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
            with self.assertRaises(error) as raised:
                pins.load_manifest(subject, root)
            reader.assert_called_once_with(root / subject["manifest"], encoding="utf-8")
        return str(raised.exception)

    def private_manifest(self) -> tuple[Path, Path]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        target = root / self.proposal["manifest"]
        target.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE / "manifest.json", target)
        return root, target

    def test_prepared_postimages_and_full_manifest(self) -> None:
        for name, expected in POSTIMAGES.items():
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256(self.snapshots[FIXTURE / name]).hexdigest(), expected)
        self.assertEqual((self.proposal["version"], self.proposal["status"]), ("0.164.0", "current"))
        self.assertEqual(set(self.manifest), set(pins.BUNDLES))
        loaded = self.observed_manifest(self.proposal, ROOT, self.manifest)
        for name, (count, digest) in FULL.items():
            with self.subTest(bundle=name):
                self.assertIs(type(self.proposal["bundles"][name]["files"]), int)
                self.assertEqual(self.proposal["bundles"][name], {"files": count, "digest": digest})
                self.assertEqual(len(loaded[name]), count)
                self.assertEqual(pins.bundle_digest(loaded[name]), digest)
        for relative, digest in self.capture["original_raw_sha256"].items():
            bundle, filename = relative.split("/", 1)
            self.assertEqual(loaded[bundle][filename], digest, relative)

    def test_minimal_metadata_and_refusal_before_reads(self) -> None:
        minimal = MappingProxyType({"manifest": self.proposal["manifest"],
                                    "bundles": deepcopy(self.proposal["bundles"])})
        self.observed_manifest(minimal, ROOT, self.manifest)
        for name in pins.BUNDLES:
            for field, value in (("files", True), ("files", False), ("digest", "A" * 64)):
                with self.subTest(bundle=name, field=field, value=value):
                    bad = deepcopy(self.proposal)
                    bad["bundles"][name][field] = value
                    self.refused_before_io(bad)
        bad = deepcopy(self.proposal)
        bad["manifest"] = ""
        self.refused_before_io(bad)

    def test_well_formed_manifest_metadata_drift_reads_then_refuses(self) -> None:
        self.observed_manifest(self.proposal, ROOT, self.manifest)
        for name in pins.BUNDLES:
            for field, value in (("files", 0), ("digest", "0" * 64)):
                with self.subTest(bundle=name, field=field):
                    bad = deepcopy(self.proposal)
                    bad["bundles"][name][field] = value
                    self.assertIn(f"bundle {name} does not match the pin",
                                  self.observed_error(bad, ROOT, pins.PinError))

    def test_private_physical_manifest_failures_follow_real_read(self) -> None:
        for mode, error in (("syntax", json.JSONDecodeError), ("missing", FileNotFoundError),
                            ("digest", pins.PinError)):
            with self.subTest(mode=mode):
                root, target = self.private_manifest()
                self.observed_manifest(self.proposal, root, self.manifest)
                if mode == "syntax":
                    target.write_text("{not json", encoding="utf-8")
                elif mode == "missing":
                    target.unlink()
                else:
                    changed = deepcopy(self.manifest)
                    changed["stable"]["ServerRequest.json"] = "0" * 64
                    target.write_text(json.dumps(changed), encoding="utf-8")
                self.observed_error(self.proposal, root, error)

    def test_executable_identity_and_minimal_mapping(self) -> None:
        self.assertEqual(self.proposal["executable"]["version_text"], VERSION)
        self.assertEqual(self.proposal["executable"]["sha256"], EXECUTABLE)
        minimal = MappingProxyType({"executable": MappingProxyType(self.proposal["executable"])})
        for subject in (self.proposal, minimal):
            with self.subTest(minimal=subject is minimal):
                self.assertEqual(pins.executable_matches(subject, VERSION + "\n", EXECUTABLE), [])
                self.assertEqual(pins.executable_matches(subject, "codex-cli 0.164.1", EXECUTABLE),
                                 ["version 'codex-cli 0.164.1' is not the pinned 'codex-cli 0.164.0'"])
                self.assertEqual(pins.executable_matches(subject, VERSION, "0" * 64),
                                 ["executable hash differs from the pin"])
                self.assertEqual(len(pins.executable_matches(subject, "codex-cli 0.164.1", "0" * 64)), 2)
        for field, value in (("version_text", ""), ("sha256", "invalid")):
            bad = deepcopy(self.proposal)
            bad["executable"][field] = value
            with self.subTest(field=field), self.assertRaises(pins.PinError):
                pins.executable_matches(bad, VERSION, EXECUTABLE)

    def test_historical_fixture_registration_lookup_and_restoration(self) -> None:
        document = self.prospective_policy()
        with patch.object(pins, "load_policy", return_value=document) as loader:
            loaded = pins.load_pins()
            self.assertEqual({pin["version"]: pin["status"] for pin in loaded},
                             {"0.162.0": "historical", "0.163.0": "historical", "0.164.0": "current"})
            proposed = pins.pin_for("0.164.0")
            self.assertEqual(proposed["executable"]["sha256"], EXECUTABLE)
            self.assertEqual(proposed["bundles"], {name: {"files": count, "digest": digest}
                                                   for name, (count, digest) in FULL.items()})
            self.assertEqual(pins.load_manifest(proposed, ROOT), self.manifest)
            for historical in self.base["pins"]:
                self.assertEqual(pins.pin_for(historical["version"])["executable"], historical["executable"])
            with self.assertRaisesRegex(pins.PinError, "no Codex protocol pin"):
                pins.pin_for("fixture-only-unknown-version")
            loader.assert_called_with(pins.PIN_POLICY)
        self.assertEqual(self.base, read_json(FIXTURE / "base-policy.json"))

    def test_two_current_fixture_refuses_both_load_and_lookup(self) -> None:
        document = self.prospective_policy()
        with patch.object(pins, "load_policy", return_value=document):
            self.assertEqual(pins.pin_for("0.164.0")["executable"]["sha256"], EXECUTABLE)
            document["pins"][0]["status"] = "current"
            with self.assertRaisesRegex(pins.PinError, "exactly one pin must be current"):
                pins.load_pins()
            with self.assertRaisesRegex(pins.PinError, "exactly one pin must be current"):
                pins.pin_for("0.164.0")

    def test_malformed_prospective_policy_metadata(self) -> None:
        for section, field, value in (("stable", "files", True), ("experimental", "files", False),
                                      ("stable", "digest", "invalid"), ("executable", "sha256", "invalid"),
                                      ("executable", "version_text", "")):
            with self.subTest(section=section, field=field, value=value):
                document = self.prospective_policy()
                with patch.object(pins, "load_policy", return_value=document):
                    self.assertEqual(pins.pin_for("0.164.0")["executable"]["sha256"], EXECUTABLE)
                    target = document["pins"][-1]
                    if section != "executable":
                        target = target["bundles"]
                    target[section][field] = value
                    with self.assertRaises(pins.PinError):
                        pins.load_pins()
                    with self.assertRaises(pins.PinError):
                        pins.pin_for("0.164.0")

    def test_hook_enforcement_consumer_still_refuses_prospective_pin(self) -> None:
        with patch.object(pins, "load_policy", return_value=self.prospective_policy()):
            self.assertEqual(pins.pin_for("0.164.0")["executable"]["sha256"], EXECUTABLE)
            for event in ("PreToolUse", "PermissionRequest"):
                with self.subTest(event=event):
                    with self.assertRaises(CWOValidationError) as raised:
                        hooks.validate_advisory_hook_configuration({"hooks": {event: []}})
                    self.assertIn("0.164.0", str(raised.exception))
                    self.assertIn("enforcement mode refused", str(raised.exception))
                    self.assertIn("should_block=false", str(raised.exception))

    def test_canonical_selected_positive_precedes_full_raw_mismatch(self) -> None:
        wrapper = {"manifest": "manifest.json", "bundles": deepcopy(self.capture["canonical_corpus"])}
        self.observed_manifest(wrapper, CORPUS, self.selected)
        self.assertEqual({name: len(entries) for name, entries in self.selected.items()},
                         {"stable": 19, "experimental": 22})
        for name, (count, digest) in FULL.items():
            with self.subTest(bundle=name):
                self.assertEqual(pins.verify_bundle(CORPUS / name, self.selected[name],
                                                    wrapper["bundles"][name]["digest"]), [])
                problems = pins.verify_bundle(CORPUS / name, self.manifest[name], digest)
                self.assertIn("missing: AttestationGenerateParams.json", problems)
                self.assertIn("changed: ServerRequest.json", problems)
                self.assertEqual(sum(problem.startswith("missing: ") for problem in problems),
                                 count - len(self.selected[name]))
                self.assertIn("bundle digest differs from the pin", problems)

    def test_all_proposal_hypotheses_consume_canonical_json_only(self) -> None:
        self.assertEqual(len(self.proposal["facts"]), 32)
        self.assertEqual(len({fact["id"] for fact in self.proposal["facts"]}), 32)
        self.assertEqual(self.proposal["facts"], self.base["pins"][0]["facts"])
        self.assertEqual(self.proposal["facts"], read_json(CORPUS / "facts.json")["facts"])
        reader_method = Path.read_text
        with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
            self.assertEqual(pins.check_facts(self.proposal, CORPUS, self.selected), [])
            reads = [call.args[0] for call in reader.call_args_list]
            for fact in self.proposal["facts"]:
                self.assertIn(CORPUS / fact["schema"], reads)
            for name in pins.BUNDLES:
                self.assertIn(CORPUS / name / "CommandExecutionRequestApprovalResponse.json", reads)

    def test_private_schema_mutation_breaks_proposal_fact(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name) / "corpus"
        shutil.copytree(CORPUS, root)
        self.assertEqual(pins.check_facts(self.proposal, root, self.selected), [])
        path = root / "stable/CommandExecutionRequestApprovalParams.json"
        data = read_json(path)
        data["required"].remove("turnId")
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(pins.check_facts(self.proposal, root, self.selected),
                         ["command-approval-correlation-stable: not required: ['turnId']"])
        self.assertEqual(pins.verify_bundle(root / "stable", self.selected["stable"],
                                            self.capture["canonical_corpus"]["stable"]["digest"]),
                         ["changed: CommandExecutionRequestApprovalParams.json", "bundle digest differs from the pin"])


if __name__ == "__main__":
    unittest.main()
