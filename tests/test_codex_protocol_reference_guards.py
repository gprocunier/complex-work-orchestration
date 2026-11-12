"""Offline regression and sensitivity checks for the three reference guards."""

from __future__ import annotations

import inspect
import unittest
from copy import deepcopy
from unittest.mock import patch

from tests.test_codex_protocol_pin import ROOT, _failing_after, fixture_root, pins


VERSIONS = ("0.162.0", "0.163.0")
FORMS = ("direct", "outer", "inner")
TARGETS = {
    "standalone-kind": (
        "CommandExecutionRequestApprovalParams.json", "command-approval-kind"),
    "reachable-kind": (
        "ServerRequest.json", "command-approval-kind-reachable"),
    "decision": (
        "CommandExecutionRequestApprovalResponse.json", "command-approval-decision-union"),
}
MUTATIONS = {
    "direct": (
        'if set(node) - _ALLOWED_BESIDE_REF:',
        'if False:'),
    "outer": (
        'set(node) - {"allOf", "description", "title", "default"} or',
        'False or'),
    "inner": (
        'or set(all_of[0]) - _ALLOWED_BESIDE_REF:',
        'or False:'),
}


def _replace_reference(data: dict, target: str, form: str, extra: dict) -> None:
    """Rebuild only the reference site; keep the fixture's definitions and annotations."""
    if target == "reachable-kind":
        properties = data["definitions"]["CommandExecutionRequestApprovalParams"]["properties"]
    else:
        properties = data["properties"]
    field = "decision" if target == "decision" else "kind"
    original = properties[field]
    reference = original.get("$ref")
    if reference is None:
        reference = original["allOf"][0]["$ref"]
    item = {"$ref": reference}
    annotations = {key: deepcopy(original[key]) for key in ("description", "title", "default")
                   if key in original}
    if form == "direct":
        replacement = {**item, **annotations, **deepcopy(extra)}
    else:
        replacement = {"allOf": [item], **annotations}
        if form == "outer":
            replacement.update(deepcopy(extra))
        else:
            item.update(deepcopy(extra))
    properties[field] = replacement


class ReferenceGuardTests(unittest.TestCase):
    def _cases(self):
        for version in VERSIONS:
            for bundle in pins.BUNDLES:
                for target, (filename, fact) in TARGETS.items():
                    yield version, bundle, target, f"{bundle}/{filename}", f"{fact}-{bundle}"

    def _changed_facts(self, version, relative, target, form, extra):
        return _failing_after(
            version, relative,
            lambda data: _replace_reference(data, target, form, extra))

    def _assert_rejected(self, form: str) -> None:
        for version, bundle, target, relative, fact in self._cases():
            with self.subTest(version=version, bundle=bundle, target=target, form=form):
                self.assertEqual(
                    self._changed_facts(version, relative, target, form, {"type": "integer"}),
                    {fact})

    def test_unchanged_pinned_schemas_hold(self) -> None:
        for version in VERSIONS:
            with self.subTest(version=version):
                pin = pins.pin_for(version)
                self.assertEqual(
                    pins.check_facts(pin, fixture_root(pin), pins.load_manifest(pin, ROOT)), [])

    def test_unconstrained_reference_forms_hold(self) -> None:
        for version, bundle, target, relative, _ in self._cases():
            for form in FORMS:
                with self.subTest(version=version, bundle=bundle, target=target, form=form):
                    self.assertEqual(self._changed_facts(version, relative, target, form, {}), set())

    def test_allowlisted_annotations_hold(self) -> None:
        for version, bundle, target, relative, _ in self._cases():
            annotations = {
                "description": "Reference annotation.",
                "title": "Annotated reference",
                "default": "accept" if target == "decision" else "command",
            }
            for form in FORMS:
                for keyword, value in annotations.items():
                    with self.subTest(
                            version=version, bundle=bundle, target=target, form=form, keyword=keyword):
                        self.assertEqual(
                            self._changed_facts(version, relative, target, form, {keyword: value}), set())

    def test_constrained_reference_forms_are_rejected(self) -> None:
        variants = (
            ('test_constrained_direct_reference_is_rejected', 'direct'),
            ('test_constrained_singleton_outer_wrapper_is_rejected', 'outer'),
            ('test_constrained_singleton_inner_reference_is_rejected', 'inner'),
        )
        for original, reference_form in variants:
            with self.subTest(original=original):
                self._assert_rejected(reference_form)



    def test_each_guard_controls_the_corresponding_real_fact_verdict(self) -> None:
        """Compile one guard removal in memory; use the actual fixture producer and fact consumer."""
        original = pins._follow
        source = inspect.getsource(original)
        for form, (before, after) in MUTATIONS.items():
            with self.subTest(removed_guard=form):
                self.assertEqual(source.count(before), 1, "guard mutation anchor changed")
                namespace = dict(vars(pins))
                exec(compile(source.replace(before, after, 1), "<reference-guard-mutant>", "exec"), namespace)
                mutant = namespace["_follow"]
                with patch.object(pins, "_follow", mutant):
                    for version in VERSIONS:
                        pin = pins.pin_for(version)
                        self.assertEqual(
                            pins.check_facts(pin, fixture_root(pin), pins.load_manifest(pin, ROOT)), [])
                    for version, bundle, target, relative, fact in self._cases():
                        with self.subTest(version=version, bundle=bundle, target=target):
                            self.assertEqual(
                                self._changed_facts(version, relative, target, form, {"type": "integer"}),
                                set(), f"removing {form} must wrongly accept {fact}")
                self.assertIs(pins._follow, original)
                self._assert_rejected(form)


if __name__ == "__main__":
    unittest.main()
