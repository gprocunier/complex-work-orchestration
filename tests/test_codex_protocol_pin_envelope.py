"""Offline envelope-data regressions; synthetic metadata confers no qualification."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import codex_protocol_pin as pins, policy  # noqa: E402
from tests.test_codex_protocol_pin_counts import BAD_COUNTS, copied_policy, synthetic_manifest  # noqa: E402

MISSING = object()
BAD_STRING = (None, False, 0, 1.0, [], {})
BAD_NONEMPTY = ("",) + BAD_STRING
BAD_MAPPING = (MISSING, None, False, 0, 1.0, "1", [])
BAD_DIGEST = (
    MISSING, None, False, True, 0, int("1" * 64), 1.0, [], {}, "", "1",
    "A" * 64, "g" * 64, "1" * 63, "1" * 65, " " + "1" * 64,
)


def changes(data, fields):
    """Single-field mutations, with omission distinct from an explicit null."""
    for path, replacements in fields:
        for index, value in enumerate(replacements):
            changed = copy.deepcopy(data)
            target = changed
            for name in path[:-1]:
                target = target[name]
            if value is MISSING:
                target.pop(path[-1], None)
            else:
                target[path[-1]] = copy.deepcopy(value)
            yield (path, index), changed


def pin_fields():
    fields = [
        (("version",), (MISSING,) + BAD_NONEMPTY),
        (("status",), (MISSING, "unknown", "1") + BAD_NONEMPTY),
        (("manifest",), (MISSING,) + BAD_NONEMPTY),
        (("executable",), BAD_MAPPING),
        (("executable", "version_text"), (MISSING,) + BAD_NONEMPTY),
        (("executable", "sha256"), BAD_DIGEST),
        (("executable", "target"), BAD_STRING),
        (("executable", "package_json_sha256"), BAD_DIGEST[1:]),
        (("generation",), BAD_MAPPING),
        (("generation", "commands"), BAD_MAPPING),
        (("generation", "environment"), BAD_STRING),
        (("generation", "reproducibility"), BAD_STRING),
        (("package_json_note",), BAD_STRING),
        (("bundles",), BAD_MAPPING),
    ]
    for name in pins.BUNDLES:
        fields.extend([
            (("generation", "commands", name), (MISSING,) + BAD_STRING),
            (("bundles", name), BAD_MAPPING),
            (("bundles", name, "files"), (MISSING,) + BAD_COUNTS),
            (("bundles", name, "digest"), BAD_DIGEST),
        ])
    for prefix in ((), ("executable",), ("generation",), ("generation", "commands"),
                   ("bundles",), ("bundles", "stable"), ("bundles", "experimental")):
        fields.append((prefix + ("private/envelope-value",), ({"secret": True},)))
    return fields


def manifest_fields():
    fields = [(("manifest",), (MISSING,) + BAD_NONEMPTY), (("bundles",), BAD_MAPPING)]
    for name in pins.BUNDLES:
        fields.extend([
            (("bundles", name), BAD_MAPPING),
            (("bundles", name, "files"), (MISSING,) + BAD_COUNTS),
            (("bundles", name, "digest"), BAD_DIGEST),
        ])
    return fields


class EnvelopePolicyTests(unittest.TestCase):
    def tearDown(self):
        policy.clear_policy_cache()

    def controls(self):
        loaded = pins.load_pins()
        self.assertEqual({pin["version"]: pin["status"] for pin in loaded},
                         {"0.163.0": "current", "0.162.0": "historical"})
        self.assertEqual(sum(len(pin["facts"]) for pin in loaded), 64)
        for pin in loaded:
            manifest = pins.load_manifest(pin, ROOT)
            fixture = ROOT / "tests/fixtures/codex-protocol" / pin["version"]
            self.assertEqual(pins.check_facts(pin, fixture, manifest), [])
            self.assertEqual(pins.executable_matches(
                pin, pin["executable"]["version_text"] + "\n", pin["executable"]["sha256"]), [])
        with self.assertRaisesRegex(pins.PinError, "no Codex protocol pin"):
            pins.pin_for("0.164.0")
        return loaded

    def write_policy(self, path, document):
        path.write_text(json.dumps(document), encoding="utf-8")
        policy.clear_policy_cache()

    def test_root_fields_through_canonical_file_loading(self):
        fields = [
            (("version",), (MISSING, None, False, True, 0, 2, 1.0, "1", [], {})),
            (("description",), BAD_STRING),
            (("bundle_digest",), BAD_STRING),
            (("pins",), (MISSING, None, False, 0, "1", {}, [], [None], [False], [[]])),
            (("private/envelope-value",), (True,)),
        ]
        with copied_policy() as path:
            original = json.loads(path.read_text(encoding="utf-8"))
            self.controls()
            for label, changed in changes(original, fields):
                with self.subTest(case=label):
                    self.write_policy(path, original)
                    self.assertEqual(pins.load_pins(), original["pins"])
                    self.write_policy(path, changed)
                    with self.assertRaises(pins.PinError):
                        pins.load_pins()

    def test_each_pin_field_through_canonical_file_loading(self):
        for pin_index in range(2):
            with copied_policy() as path:
                original = json.loads(path.read_text(encoding="utf-8"))
                self.controls()
                for label, changed in changes(original["pins"][pin_index], pin_fields()):
                    with self.subTest(pin=pin_index, case=label):
                        self.write_policy(path, original)
                        self.assertEqual(pins.load_pins(), original["pins"])
                        document = copy.deepcopy(original)
                        document["pins"][pin_index] = changed
                        self.write_policy(path, document)
                        with self.assertRaises(pins.PinError):
                            pins.load_pins()

    def test_unexpected_fields_and_raw_mapping_shapes(self):
        original = pins.load_policy(pins.PIN_POLICY)
        prefixes = [()]
        for index in range(2):
            prefixes += [("pins", index) + suffix for suffix in (
                (), ("executable",), ("generation",), ("generation", "commands"),
                ("bundles",), ("bundles", "stable"), ("bundles", "experimental"))]
        for prefix in prefixes:
            for key in ("private/envelope-value", 7):
                with self.subTest(path=prefix, key=key):
                    changed = copy.deepcopy(original)
                    target = changed
                    for name in prefix:
                        target = target[name]
                    target[key] = {"secret": True}
                    with patch.object(pins, "load_policy", return_value=changed):
                        with self.assertRaises(pins.PinError) as raised:
                            pins.load_pins()
                    self.assertNotIn("private/envelope-value", str(raised.exception))
        for bad in (None, False, 0, [], "1"):
            with self.subTest(root=bad), patch.object(pins, "load_policy", return_value=bad):
                with self.assertRaises(pins.PinError):
                    pins.load_pins()

    def test_current_pin_cardinality(self):
        original = pins.load_policy(pins.PIN_POLICY)
        for statuses in (("historical", "historical"), ("current", "current")):
            document = copy.deepcopy(original)
            for pin, status in zip(document["pins"], statuses):
                pin["status"] = status
            with patch.object(pins, "load_policy", return_value=document):
                with self.assertRaisesRegex(pins.PinError, "exactly one pin must be current"):
                    pins.load_pins()

    def test_optional_annotations_and_unrestricted_version_strings(self):
        document = pins.load_policy(pins.PIN_POLICY)
        del document["description"]
        del document["bundle_digest"]
        for pin in document["pins"]:
            pin.pop("package_json_note", None)
            pin["executable"].pop("target", None)
            pin["executable"].pop("package_json_sha256", None)
            pin["generation"] = {"commands": dict.fromkeys(pins.BUNDLES, "")}
            pin["version"] = "synthetic/" + pin["version"]
        with patch.object(pins, "load_policy", return_value=document):
            self.assertEqual(pins.load_pins(), document["pins"])
        document["description"] = ""
        document["bundle_digest"] = ""
        for pin in document["pins"]:
            pin["package_json_note"] = ""
            pin["executable"]["target"] = ""
            pin["executable"]["package_json_sha256"] = "1" * 64
            pin["generation"].update(environment="", reproducibility="")
        with patch.object(pins, "load_policy", return_value=document):
            self.assertEqual(pins.load_pins(), document["pins"])


class DirectEnvelopeTests(unittest.TestCase):
    def observed_manifest(self, pin, root, expected):
        reader_method = Path.read_text
        with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
            self.assertEqual(pins.load_manifest(pin, root), expected)
            reader.assert_called_once_with(root / pin["manifest"], encoding="utf-8")

    def refused_manifest(self, pin, root):
        with patch.object(Path, "read_text", side_effect=AssertionError("invalid metadata reached I/O")) as reader:
            with self.assertRaises(pins.PinError):
                pins.load_manifest(pin, root)
            reader.assert_not_called()

    def test_manifest_minimal_mapping_and_ignored_unconsumed_fields(self):
        for count in (0, 1):
            with self.subTest(count=count), synthetic_manifest(count) as (root, pin, manifest):
                self.observed_manifest(pin, root, manifest)
                wrapped = MappingProxyType({
                    **pin, "generation": [], "executable": None, "facts": None,
                    "bundles": MappingProxyType({
                        **{name: MappingProxyType({**data, "unused": None}) for name, data in pin["bundles"].items()},
                        "unused": None,
                    }),
                })
                self.observed_manifest(wrapped, root, manifest)

    def test_manifest_metadata_refuses_before_io(self):
        for count in (0, 1):
            with synthetic_manifest(count) as (root, pin, manifest):
                self.observed_manifest(pin, root, manifest)
                for label, bad in changes(pin, manifest_fields()):
                    with self.subTest(count=count, case=label):
                        self.refused_manifest(bad, root)
                for bad in (None, False, 0, [], "1", {}):
                    self.refused_manifest(bad, root)

    def test_manifest_mismatch_and_unreadable_controls(self):
        with synthetic_manifest(1) as (root, pin, manifest):
            self.observed_manifest(pin, root, manifest)
            for name in pins.BUNDLES:
                for field, value in (("files", 0), ("digest", "0" * 64)):
                    changed = copy.deepcopy(pin)
                    changed["bundles"][name][field] = value
                    reader_method = Path.read_text
                    with patch.object(Path, "read_text", autospec=True, side_effect=reader_method) as reader:
                        with self.assertRaisesRegex(pins.PinError, f"bundle {name} does not match the pin"):
                            pins.load_manifest(changed, root)
                        reader.assert_called_once()
            (root / pin["manifest"]).write_text("{not json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                pins.load_manifest(pin, root)
            (root / pin["manifest"]).unlink()
            with self.assertRaises(FileNotFoundError):
                pins.load_manifest(pin, root)

    def test_minimal_executable_mapping_and_drift(self):
        executable = {"version_text": "synthetic executable", "sha256": "1" * 64}
        pin = MappingProxyType({"executable": MappingProxyType({
            **executable, "target": [], "package_json_sha256": 0,
        }), "generation": [], "facts": None})
        self.assertEqual(pins.executable_matches(pin, "synthetic executable\n", "1" * 64), [])
        self.assertEqual(len(pins.executable_matches(pin, "other executable", "1" * 64)), 1)
        self.assertEqual(pins.executable_matches(pin, "synthetic executable", "2" * 64), ["executable hash differs from the pin"])
        self.assertEqual(len(pins.executable_matches(pin, "other executable", "2" * 64)), 2)

    def test_executable_metadata_refuses_controlled(self):
        good = {"executable": {"version_text": "synthetic executable", "sha256": "1" * 64}}
        fields = [
            (("executable",), BAD_MAPPING),
            (("executable", "version_text"), (MISSING,) + BAD_NONEMPTY),
            (("executable", "sha256"), BAD_DIGEST),
        ]
        self.assertEqual(pins.executable_matches(good, "synthetic executable", "1" * 64), [])
        for label, bad in changes(good, fields):
            with self.subTest(case=label):
                with self.assertRaises(pins.PinError):
                    pins.executable_matches(bad, "synthetic executable", "1" * 64)
        for bad in (None, False, 0, [], "1", {}):
            with self.subTest(wrapper=bad), self.assertRaises(pins.PinError):
                pins.executable_matches(bad, "synthetic executable", "1" * 64)


if __name__ == "__main__":
    unittest.main()
