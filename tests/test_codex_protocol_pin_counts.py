"""Offline count metadata regressions; synthetic manifests are not trusted pins."""

from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import codex_protocol_pin as pins, policy  # noqa: E402

POLICY_FILE = "codex-protocol-pins.yaml"
BAD_COUNTS = (True, False, 1.0, 0.0, -1, "1", "0", "private/count-value", None, [], {})
COUNT_ERROR = r"^codex-protocol-pins: file count must be a nonnegative integer$"


@contextmanager
def copied_policy() -> Iterator[Path]:
    """Copy the canonical policy file; redirect only its directory, never its validator."""
    with tempfile.TemporaryDirectory() as directory:
        policy_dir = Path(directory) / "policy"
        policy_dir.mkdir()
        target = policy_dir / POLICY_FILE
        shutil.copyfile(ROOT / "policy" / POLICY_FILE, target)
        policy.clear_policy_cache()
        try:
            with patch.object(policy, "POLICY_DIR", policy_dir):
                yield target
        finally:
            policy.clear_policy_cache()


@contextmanager
def synthetic_manifest(count: int) -> Iterator[tuple[Path, dict[str, Any], dict[str, dict[str, str]]]]:
    """Minimal direct API input with genuine scratch inventories, not executable evidence."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = {}
        for name in pins.BUNDLES:
            bundle_root = root / name
            bundle_root.mkdir()
            if count:
                (bundle_root / "one.json").write_text("{}\n", encoding="utf-8")
            manifest[name] = pins.bundle_manifest(bundle_root)
        pin = {
            "manifest": "manifest.json",
            "bundles": {
                name: {"files": count, "digest": pins.bundle_digest(entries)}
                for name, entries in manifest.items()
            },
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        yield root, pin, manifest


class ProtocolPinCountTests(unittest.TestCase):
    def tearDown(self) -> None:
        policy.clear_policy_cache()

    def test_real_policy_manifests_facts_and_version_selection_remain_readable(self) -> None:
        with copied_policy() as path:
            expected = json.loads(path.read_text(encoding="utf-8"))
            loaded = pins.load_pins()
            self.assertEqual(loaded, expected["pins"])
            self.assertEqual({pin["version"]: pin["status"] for pin in loaded},
                             {"0.163.0": "current", "0.162.0": "historical"},
                             )
            for pin in loaded:
                with self.subTest(version=pin["version"]):
                    manifest = pins.load_manifest(pin, ROOT)
                    for name in pins.BUNDLES:
                        self.assertIs(type(pin["bundles"][name]["files"]), int)
                        self.assertEqual(len(manifest[name]), pin["bundles"][name]["files"])
                    self.assertEqual(pins.check_facts(pin, ROOT / "tests/fixtures/codex-protocol" / pin["version"], manifest), [])
            self.assertEqual(pins.pin_for("0.163.0")["status"], "current")
            with self.assertRaisesRegex(pins.PinError, "no Codex protocol pin"):
                pins.pin_for("0.164.0")

    def test_real_policy_reader_rejects_each_invalid_count_independently(self) -> None:
        for pin_index in range(2):
            for bundle in pins.BUNDLES:
                for bad in BAD_COUNTS:
                    with self.subTest(pin=pin_index, bundle=bundle, bad=bad):
                        with copied_policy() as path:
                            document = json.loads(path.read_text(encoding="utf-8"))
                            self.assertEqual(pins.load_pins(), document["pins"])
                            document["pins"][pin_index]["bundles"][bundle]["files"] = bad
                            path.write_text(json.dumps(document), encoding="utf-8")
                            policy.clear_policy_cache()
                            with self.assertRaisesRegex(pins.PinError, COUNT_ERROR):
                                pins.load_pins()

    def test_policy_count_contract_accepts_zero_and_one(self) -> None:
        for count in (0, 1):
            for pin_index in range(2):
                for bundle in pins.BUNDLES:
                    with self.subTest(count=count, pin=pin_index, bundle=bundle):
                        with copied_policy() as path:
                            document = json.loads(path.read_text(encoding="utf-8"))
                            self.assertEqual(pins.load_pins(), document["pins"])
                            document["pins"][pin_index]["bundles"][bundle]["files"] = count
                            path.write_text(json.dumps(document), encoding="utf-8")
                            policy.clear_policy_cache()
                            self.assertEqual(pins.load_pins(), document["pins"])

    def test_minimal_synthetic_empty_and_one_file_manifests_match(self) -> None:
        for count in (0, 1):
            with self.subTest(count=count), synthetic_manifest(count) as (root, pin, manifest):
                self.assertEqual(pins.load_manifest(pin, root), manifest)
                for name in pins.BUNDLES:
                    self.assertIs(type(pin["bundles"][name]["files"]), int)
                    self.assertEqual(len(manifest[name]), count)

    def test_direct_reader_rejects_invalid_counts_before_manifest_io(self) -> None:
        for count in (0, 1):
            for bundle in pins.BUNDLES:
                for bad in BAD_COUNTS:
                    with self.subTest(count=count, bundle=bundle, bad=bad):
                        with synthetic_manifest(count) as (root, pin, manifest):
                            self.assertEqual(pins.load_manifest(pin, root), manifest)
                            invalid = copy.deepcopy(pin)
                            invalid["bundles"][bundle]["files"] = copy.deepcopy(bad)
                            with self.assertRaisesRegex(pins.PinError, COUNT_ERROR):
                                pins.load_manifest(invalid, root)
                            (root / "manifest.json").unlink()
                            with self.assertRaisesRegex(pins.PinError, COUNT_ERROR):
                                pins.load_manifest(invalid, root)

    def test_direct_reader_controls_malformed_bundle_shapes(self) -> None:
        cases = (
            None,
            [],
            {},
            {"stable": None, "experimental": {}},
            {"stable": [], "experimental": {}},
            {"stable": {}, "experimental": {}},
        )
        for bundles in cases:
            with self.subTest(bundles=bundles):
                with synthetic_manifest(1) as (root, pin, manifest):
                    self.assertEqual(pins.load_manifest(pin, root), manifest)
                    invalid = copy.deepcopy(pin)
                    invalid["bundles"] = bundles
                    with self.assertRaises(pins.PinError):
                        pins.load_manifest(invalid, root)

    def test_direct_reader_controls_missing_count_or_digest(self) -> None:
        for name in pins.BUNDLES:
            for field in ("files", "digest"):
                with self.subTest(bundle=name, field=field), synthetic_manifest(1) as (root, pin, manifest):
                    self.assertEqual(pins.load_manifest(pin, root), manifest)
                    invalid = copy.deepcopy(pin)
                    del invalid["bundles"][name][field]
                    with self.assertRaises(pins.PinError):
                        pins.load_manifest(invalid, root)

    def test_valid_integer_count_and_digest_mismatches_still_fail(self) -> None:
        for name in pins.BUNDLES:
            for field, replacement in (("files", 0), ("digest", "0" * 64)):
                with self.subTest(bundle=name, field=field), synthetic_manifest(1) as (root, pin, manifest):
                    self.assertEqual(pins.load_manifest(pin, root), manifest)
                    invalid = copy.deepcopy(pin)
                    invalid["bundles"][name][field] = replacement
                    with self.assertRaisesRegex(pins.PinError, f"bundle {name} does not match the pin"):
                        pins.load_manifest(invalid, root)


if __name__ == "__main__":
    unittest.main()
