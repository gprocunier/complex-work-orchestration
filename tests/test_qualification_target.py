"""Selected qualification metadata does not grant execution authority."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import codex_protocol_pin as pins, qualification_target as target
from cwo_core.policy import load_policy
from cwo_core.policy_schema import policy_document_errors
import validate_repository


class QualificationTargetTests(unittest.TestCase):
    def arguments(self):
        selected = load_policy("qualification-target")["selection"]
        return {
            "profile": selected["profile"],
            "version_text": "codex-cli 0.163.0",
            "executable_sha256": selected["executable_sha256"],
            "package_json_sha256": selected["package"]["sha256"],
            "configuration": copy.deepcopy(selected["configuration"]),
        }

    def test_selected_target_resolves_existing_pin_and_profile(self):
        document = target.selected_target()
        selected = document["selection"]
        pin = pins.pin_for(selected["pin_version"])
        self.assertEqual(selected["executable_sha256"], pin["executable"]["sha256"])
        self.assertEqual(selected["package"]["sha256"], pin["executable"]["package_json_sha256"])
        self.assertEqual(target.target_for(**self.arguments()), selected)
        self.assertEqual(document["profiles"]["constrained-integrity"]["status"], "selected-unqualified")
        self.assertEqual(document["profiles"]["confidential"]["status"], "unsupported")
        self.assertIs(document["execution_authorized"], False)

    def test_other_hash_version_package_and_profile_refuse_at_resolution(self):
        for field, value in (
            ("executable_sha256", "1" * 64),
            ("version_text", "codex-cli 0.162.0"),
            ("package_json_sha256", "2" * 64),
            ("profile", "confidential"),
            ("profile", "unknown"),
            ("profile", None),
        ):
            with self.subTest(field=field, value=value):
                arguments = self.arguments()
                arguments[field] = value
                with self.assertRaises(target.TargetError):
                    target.target_for(**arguments)

    def test_configuration_drift_refuses_at_resolution(self):
        cases = (
            lambda c: c["thread_start"].update(sandbox="read-only"),
            lambda c: c["thread_start"].update(approvalPolicy="on-request"),
            lambda c: c["thread_start"].update(permissions="some-named-profile"),
            lambda c: c.update(network_access=True),
            lambda c: c.update(network_access=0),
            lambda c: c.update(host="none"),
            lambda c: c.pop("worker_write_scope"),
        )
        for mutate in cases:
            arguments = self.arguments()
            mutate(arguments["configuration"])
            with self.subTest(configuration=arguments["configuration"]):
                with self.assertRaises(target.TargetError):
                    target.target_for(**arguments)

    def test_recorded_selection_drift_and_missing_classifications_refuse(self):
        good = load_policy("qualification-target")
        cases = (
            lambda d: d["selection"].update(profile="confidential"),
            lambda d: d["selection"].update(executable_sha256="1" * 64),
            lambda d: d["selection"]["package"].update(sha256="2" * 64),
            lambda d: d.update(execution_authorized=True),
            lambda d: d["properties"].pop("effective-configuration"),
            lambda d: d["properties"]["effective-configuration"].pop("classification"),
            lambda d: d["properties"]["effective-configuration"].update(classification="os-observed"),
            lambda d: d["properties"]["confidential-reads"].update(classification="unknown"),
            lambda d: d["properties"]["executable-identity"].update(classification="trusted"),
            lambda d: d["properties"].update(unlabelled={"finding": "unverified"}),
        )
        for index, mutate in enumerate(cases):
            with self.subTest(case=index):
                bad = copy.deepcopy(good)
                mutate(bad)
                self.assertTrue(policy_document_errors("qualification-target.yaml", bad))
                with mock.patch.object(target, "load_policy", return_value=bad):
                    with self.assertRaises(target.TargetError):
                        target.selected_target()

    def test_pin_drift_invalidates_selection(self):
        for field in ("sha256", "package_json_sha256", "target"):
            pin = pins.pin_for("0.163.0")
            pin["executable"][field] = "other"
            with self.subTest(field=field), mock.patch.object(target, "pin_for", return_value=pin):
                with self.assertRaises(target.TargetError):
                    target.selected_target()

    def test_missing_optional_package_pin_metadata_refuses(self):
        for field in ("package_json_sha256", "target"):
            pin = pins.pin_for("0.163.0")
            del pin["executable"][field]
            with self.subTest(field=field), mock.patch.object(target, "pin_for", return_value=pin):
                with self.assertRaises(target.TargetError):
                    target.selected_target()

    def test_recorded_observations_do_not_carry_over_to_changed_pin_metadata(self):
        for mutate in (
            lambda p: p["executable"].update(version_text="codex-cli other"),
            lambda p: p["bundles"]["stable"].update(digest="1" * 64),
            lambda p: p["bundles"]["experimental"].update(files=1),
        ):
            pin = pins.pin_for("0.163.0")
            mutate(pin)
            with self.subTest(pin=pin["bundles"]), mock.patch.object(target, "pin_for", return_value=pin):
                with self.assertRaises(target.TargetError):
                    target.selected_target()

    def test_every_property_has_a_classification_and_bounded_evidence(self):
        document = target.selected_target()
        labels = {row["classification"] for row in document["properties"].values()}
        self.assertEqual(labels, {"source-supported", "fake-tested", "os-observed", "unknown", "unsupported"})
        for name, row in document["properties"].items():
            with self.subTest(property=name):
                self.assertTrue(row["finding"].strip())
                self.assertTrue(row["evidence"])
                for evidence in row["evidence"]:
                    self.assertFalse(Path(evidence.split("#", 1)[0]).is_absolute())
                    self.assertTrue((ROOT / evidence.split("#", 1)[0]).is_file(), evidence)

    def test_portable_package_locator_and_recorded_observations(self):
        document = target.selected_target()
        package = document["selection"]["package"]
        self.assertEqual(package["entrypoint"], "bin/codex")
        self.assertEqual(package["manifest"], "codex-package.json")
        raw = json.dumps(document)
        self.assertNotIn("/home/", raw)
        self.assertNotIn("/Users/", raw)
        self.assertEqual(document["observations"]["version_text"], "codex-cli 0.163.0")
        self.assertIs(document["observations"]["model_calls"], False)
        self.assertIs(document["observations"]["containment_tested"], False)

    def test_repository_validation_uses_the_target_resolver(self):
        errors = []
        validate_repository.validate_qualification_target(errors)
        self.assertEqual(errors, [])
        with mock.patch.object(target, "selected_target", side_effect=target.TargetError("selection drift")):
            validate_repository.validate_qualification_target(errors)
        self.assertEqual(errors, ["qualification-target: selection drift"])

    def test_resolution_does_not_launch_processes_or_mutate_policy(self):
        arguments = self.arguments()
        with mock.patch("subprocess.Popen", side_effect=AssertionError("process launched")):
            selected = target.target_for(**arguments)
            selected["profile"] = "changed"
            self.assertEqual(target.target_for(**arguments)["profile"], "constrained-integrity")


if __name__ == "__main__":
    unittest.main()
