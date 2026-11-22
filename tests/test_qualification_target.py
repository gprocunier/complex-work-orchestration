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

from cwo_core import qualification_target as target
from cwo_core.policy import load_policy
from cwo_core.policy_schema import policy_document_errors
import validate_repository


class QualificationTargetTests(unittest.TestCase):
    def arguments(self):
        selected = load_policy("qualification-target")["selection"]
        return {
            "profile": selected["profile"],
            "configuration": copy.deepcopy(selected["configuration"]),
        }

    def test_selected_target_declares_support_floor_and_profile(self):
        document = target.selected_target()
        selected = document["selection"]
        self.assertEqual(selected["minimum_version"], "0.163.0")
        self.assertNotIn("pin_version", selected)
        self.assertNotIn("executable_sha256", selected)
        self.assertNotIn("package", selected)
        self.assertEqual(target.target_for(**self.arguments()), selected)
        self.assertEqual(document["profiles"]["constrained-integrity"]["status"], "selected-unqualified")
        self.assertEqual(document["profiles"]["confidential"]["status"], "unsupported")
        self.assertIs(document["execution_authorized"], False)

    def test_other_profiles_refuse_at_resolution(self):
        for value in ("confidential", "unknown", None):
            with self.subTest(profile=value):
                arguments = self.arguments()
                arguments["profile"] = value
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
            lambda d: d["selection"].update(minimum_version="latest"),
            lambda d: d["selection"].pop("minimum_version"),
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

    def test_current_offline_findings_preserve_holds_and_original_history(self):
        document = target.selected_target()
        current = document['offline_diagnostics']
        self.assertEqual(current['scope'], 'fixed-no-model-app-server-command-exec')
        self.assertIs(current['execution_authorized'], False)
        self.assertIs(current['accepted_output'], False)
        self.assertIs(current['model_calls'], False)
        self.assertIs(current['thread_or_turn_started'], False)
        self.assertEqual(current['named_candidate']['status'], 'runtime-refused-unselected')
        self.assertIn('native-model-tool-stdin', current['required_unperformed'])
        self.assertIs(document['observations']['containment_tested'], False)
        self.assertEqual(document['profiles']['constrained-integrity']['status'], 'selected-unqualified')

    def test_scoped_observations_cannot_be_relabelled_as_full_qualification(self):
        good = target.selected_target()
        for mutate in (
            lambda d: d['offline_diagnostics'].update(execution_authorized=True),
            lambda d: d['offline_diagnostics'].update(model_calls=True),
            lambda d: d['offline_diagnostics'].update(required_unperformed=[]),
            lambda d: d['offline_diagnostics']['named_candidate'].update(selected=True),
            lambda d: d['properties']['offline-owner-lifecycle'].update(classification='qualified'),
            lambda d: d['properties']['offline-command-patch']['evidence'].append('unrelated.txt'),
        ):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.subTest(document=bad):
                self.assertTrue(policy_document_errors('qualification-target.yaml', bad))
                with mock.patch.object(target, 'load_policy', return_value=bad):
                    with self.assertRaises(target.TargetError):
                        target.selected_target()

    def test_historical_fixture_lookup_is_independent_of_target_resolution(self):
        with mock.patch("cwo_core.codex_protocol_pin.load_pins", side_effect=AssertionError("fixture read")):
            self.assertEqual(target.selected_target()["selection"], target.target_for(**self.arguments()))

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

    def test_historical_package_observations_are_portable(self):
        document = target.selected_target()
        raw = json.dumps(document)
        self.assertNotIn("/home/", raw)
        self.assertNotIn("/Users/", raw)
        self.assertEqual(document["observations"]["version_text"], "codex-cli 0.163.0")
        self.assertEqual(document["offline_diagnostics"]["target_id"], "codex-0.163.0-constrained-integrity")
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
