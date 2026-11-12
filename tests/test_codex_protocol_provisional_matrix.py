"""Offline checks for actual, provisional 0.164.0 schema data; never a product pin."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cwo_core.codex_protocol_pin as pins  # noqa: E402

VERSION = "0.164.0"
FIXTURES = ROOT / "tests" / "fixtures" / "codex-protocol-provisional" / VERSION
EXECUTABLE_SHA256 = (
    "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306"
)
COUNTS = {"stable": 320, "experimental": 458}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class ProvisionalProtocolMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = read_json(FIXTURES / "MATRIX.json")
        cls.inventories = read_json(FIXTURES / "INVENTORIES.json")
        cls.facts = read_json(FIXTURES / "REFERENCE-FACTS.json")
        cls.expected = {bundle: cls.inventories[f"{bundle}-a"] for bundle in pins.BUNDLES}

    def manifest(self, root: Path) -> dict[str, dict[str, str]]:
        return {bundle: pins.bundle_manifest(root / bundle) for bundle in pins.BUNDLES}

    def problems(self, root: Path) -> dict[str, str]:
        manifest = self.manifest(root)
        return {
            problem.split(":", 1)[0]: problem
            for problem in pins.check_facts({"facts": self.facts}, root, manifest)
        }

    @contextmanager
    def copied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "schemas"
            shutil.copytree(FIXTURES, root, copy_function=shutil.copyfile)
            self.assertEqual(self.manifest(root), self.expected)
            yield root

    def edit_and_check(self, relative: str, change, expected: set[str]) -> None:
        with self.copied() as root:
            path = root / relative
            data = read_json(path)
            change(data)
            path.write_text(json.dumps(data), encoding="utf-8")
            bundle, filename = relative.split("/", 1)
            self.assertEqual(
                pins.verify_bundle(root / bundle, self.expected[bundle],
                                   pins.bundle_digest(self.expected[bundle])),
                [f"changed: {filename}", "bundle digest differs from the pin"],
            )
            # Rehash only the scratch data; capture metadata stays immutable.
            self.assertEqual(set(self.problems(root)), expected)

    def test_complete_inventory_and_repeat_capture(self) -> None:
        self.assertEqual(set(self.inventories), {f"{b}-{r}" for b in pins.BUNDLES for r in ("a", "b")})
        self.assertIs(self.matrix["repeat_inventories_exact"], True)
        self.assertEqual(self.matrix["counts"], {
            f"{bundle}-{repeat}": count
            for bundle, count in COUNTS.items() for repeat in ("a", "b")
        })
        actual = self.manifest(FIXTURES)
        for bundle, count in COUNTS.items():
            with self.subTest(bundle=bundle):
                self.assertEqual(len(actual[bundle]), count)
                self.assertEqual(self.inventories[f"{bundle}-a"], self.inventories[f"{bundle}-b"])
                self.assertEqual(actual[bundle], self.expected[bundle])
                self.assertEqual(
                    pins.verify_bundle(FIXTURES / bundle, self.expected[bundle],
                                       pins.bundle_digest(self.expected[bundle])), [],
                )
                for relative in actual[bundle]:
                    self.assertTrue(relative.endswith(".json"), relative)
                    with self.subTest(schema=f"{bundle}/{relative}"):
                        self.assertIsInstance(read_json(FIXTURES / bundle / relative), dict)

    def test_provenance_does_not_qualify_the_executable(self) -> None:
        self.assertEqual(self.matrix["actual_executable_version"], f"codex-cli {VERSION}")
        self.assertEqual(self.matrix["actual_executable_sha256"], EXECUTABLE_SHA256)
        self.assertIsNone(self.matrix["source_Git_revision"])
        self.assertEqual(self.matrix["OS_runtime_qualification"], "not performed")
        self.assertEqual(self.matrix["model_calls"], 0)
        self.assertIs(self.matrix["product_pins_policy_unchanged"], True)
        self.assertIn("generate-json-schema", self.matrix["generation"])
        self.assertIn("--experimental", self.matrix["generation"])
        self.assertIn("no app-server service/model/observer/network", self.matrix["generation"])
        loaded = pins.load_pins()
        qualified = VERSION in {pin["version"] for pin in loaded}
        self.assertIs(qualified, False)
        self.assertEqual({pin["version"]: pin["status"] for pin in loaded},
                         {"0.163.0": "current", "0.162.0": "historical"})
        with self.assertRaisesRegex(pins.PinError, "no Codex protocol pin"):
            pins.pin_for(VERSION)
        self.assertEqual(len(pins.executable_matches(
            pins.pin_for("0.163.0"), f"codex-cli {VERSION}", EXECUTABLE_SHA256)), 2)

    def test_all_reference_facts_reach_the_actual_schema_consumer(self) -> None:
        self.assertEqual(len(self.facts), 32)
        self.assertEqual(len({fact["id"] for fact in self.facts}), 32)
        self.assertEqual(self.facts, pins.pin_for("0.163.0")["facts"])
        manifest = self.manifest(FIXTURES)
        self.assertEqual(manifest, self.expected)
        rows = []
        for fact in self.facts:
            with self.subTest(fact=fact["id"]):
                problem = pins.evaluate_fact(fact, FIXTURES, manifest)
                self.assertIsNone(problem)
                rows.append({
                    "reference_fact_id": fact["id"],
                    "fact_kind": fact["kind"],
                    "diagnostic_status": "schema-supported" if problem is None else "unsupported",
                    "problem": problem,
                })
        self.assertEqual(self.matrix["rows"], rows)
        self.assertEqual(self.problems(FIXTURES), {})

    def test_missing_response_reaches_manifest_and_answerability_consumers(self) -> None:
        with self.copied() as root:
            filename = "CurrentTimeReadResponse.json"
            (root / "experimental" / filename).unlink()
            self.assertEqual(
                pins.verify_bundle(root / "experimental", self.expected["experimental"],
                                   pins.bundle_digest(self.expected["experimental"])),
                [f"missing: {filename}", "bundle digest differs from the pin"],
            )
            self.assertEqual(set(self.problems(root)), {"server-requests-answerable-experimental"})

    def test_tampered_schema_reaches_digest_and_json_consumers(self) -> None:
        with self.copied() as root:
            filename = "v2/ThreadStartParams.json"
            (root / "stable" / filename).write_text("{not json", encoding="utf-8")
            self.assertEqual(
                pins.verify_bundle(root / "stable", self.expected["stable"],
                                   pins.bundle_digest(self.expected["stable"])),
                [f"changed: {filename}", "bundle digest differs from the pin"],
            )
            problems = self.problems(root)
            self.assertEqual(set(problems), {
                "named-profile-selector-experimental-only", "approvals-reviewer-routing",
            })
            for problem in problems.values():
                self.assertIn("schema unreadable", problem)

    def test_named_profile_and_experimental_fields_are_not_interchangeable(self) -> None:
        changes = (
            ("stable/v2/ThreadStartParams.json",
             lambda data: data["properties"].update(permissions={"type": "string"}),
             {"named-profile-selector-experimental-only"}),
            ("experimental/v2/ThreadStartParams.json",
             lambda data: data["properties"].pop("permissions"),
             {"named-profile-selector-in-experimental"}),
            ("stable/CommandExecutionRequestApprovalParams.json",
             lambda data: data["properties"].update(additionalPermissions={"type": "object"}),
             {"additional-permissions-experimental-only"}),
            ("experimental/CommandExecutionRequestApprovalParams.json",
             lambda data: data["properties"].pop("availableDecisions"),
             {"additional-permissions-in-experimental"}),
        )
        for relative, change, expected in changes:
            with self.subTest(schema=relative):
                self.edit_and_check(relative, change, expected)

    def test_approval_correlation_and_absent_retry_fields_are_consumed(self) -> None:
        for bundle in pins.BUNDLES:
            relative = f"{bundle}/CommandExecutionRequestApprovalParams.json"
            changes = (
                ("required turn", lambda data: data["required"].remove("turnId"),
                 {f"command-approval-correlation-{bundle}"}),
                ("callback identity", lambda data: data["properties"]["approvalId"].update(description="Just an id."),
                 {f"command-approval-id-correlation-{bundle}"}),
                ("structured retry", lambda data: data["properties"].update(retryReason={"type": "string"}),
                 {f"no-structured-retry-class-CommandExecutionRequestApprovalParams-{bundle}"}),
            )
            for label, change, expected in changes:
                with self.subTest(bundle=bundle, change=label):
                    self.edit_and_check(relative, change, expected)

    def test_decisions_require_the_complete_closed_union(self) -> None:
        def add_grant(data: dict) -> None:
            data["definitions"]["CommandExecutionApprovalDecision"]["oneOf"].append(
                {"type": "string", "enum": ["grantAll"]})

        def drop_session(data: dict) -> None:
            union = data["definitions"]["CommandExecutionApprovalDecision"]
            union["oneOf"] = [branch for branch in union["oneOf"] if branch.get("enum") != ["acceptForSession"]]

        for bundle in pins.BUNDLES:
            union_fact = f"command-approval-decision-union-{bundle}"
            changes = (
                ("optional decision", lambda data: data["required"].remove("decision"), {union_fact}),
                ("unrecognized grant", add_grant, {union_fact}),
                ("session decision removed", drop_session,
                 {union_fact, "command-approval-decisions"} if bundle == "stable" else {union_fact}),
            )
            for label, change, expected in changes:
                with self.subTest(bundle=bundle, change=label):
                    self.edit_and_check(f"{bundle}/CommandExecutionRequestApprovalResponse.json", change, expected)


if __name__ == "__main__":
    unittest.main()
