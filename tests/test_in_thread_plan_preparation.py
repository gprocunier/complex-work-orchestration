"""Check inert proposals with real record validation and actual routing policy."""
from __future__ import annotations

import builtins
import contextlib
import copy
import hashlib
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import unittest
import urllib.request
from collections import Counter
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prepare_in_thread_plan as preview  # noqa: E402
from cwo_core import candidate_identity as ci  # noqa: E402
from cwo_core import requirement_baseline as rb  # noqa: E402
from cwo_core import beads, policy, policy_schema, routing, workspace_capture  # noqa: E402

READ_ONLY_POLICY_PATHS = frozenset(
    ROOT / "policy" / name for name in policy_schema.POLICY_VALIDATION_BOUNDARIES
)
READ_ONLY_SCHEMA_PATHS = frozenset(
    ROOT / "schemas" / name for name in policy_schema.POLICY_SCHEMAS.values()
)
READ_ONLY_SOURCE_PATHS = READ_ONLY_POLICY_PATHS | READ_ONLY_SCHEMA_PATHS


def independent_digest(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def example_criterion(criterion_id: str, evidence_kind: str) -> dict:
    return {
        "id": criterion_id, "requirement": "EXAMPLE preserve the requested copy.", "reference": "EXAMPLE requirement record.",
        "expected_outcome": "EXAMPLE requested copy is present and unrelated copy is preserved.",
        "applicability": "required", "evidence_kind": evidence_kind,
    }


def example_baseline() -> dict:
    criteria = [
        example_criterion("EXAMPLE-artifact", "artifact"),
        example_criterion("EXAMPLE-validator", "validator"),
        example_criterion("EXAMPLE-review", "review-gate"),
    ]
    excluded = example_criterion("EXAMPLE-na", "artifact")
    excluded.update(applicability="not-applicable", not_applicable_reason="EXAMPLE no platform change is requested.")
    return {
        "record_type": "cwo-requirement-baseline", "version": 1, "bead_id": "EXAMPLE-task",
        "baseline_version": 1, "criteria": [*criteria, excluded],
    }


def example_amendment(prior: dict) -> dict:
    new = copy.deepcopy(prior)
    new["baseline_version"] += 1
    new["criteria"].append(example_criterion("EXAMPLE-added", "artifact"))
    return {
        "record_type": "cwo-requirement-amendment",
        "version": 1, "bead_id": prior["bead_id"],
        "amendment_id": "EXAMPLE-add-copy",
        "prior_digest": independent_digest(prior),
        "prior_baseline_version": prior["baseline_version"],
        "added_criterion_ids": ["EXAMPLE-added"], "removed_criterion_ids": [], "changed_criterion_ids": [],
        "rationale": "EXAMPLE add an independent copy obligation.",
        "authority": {"role": "EXAMPLE operator", "reference": "EXAMPLE decision record."},
        "baseline": new,
    }


def example_candidate(chain: dict) -> dict:
    oid = hashlib.sha256(b"EXAMPLE structural identity only").hexdigest()[:40]
    return {
        "record_type": "cwo-candidate-identity",
        "version": 1, "bead_id": "EXAMPLE-task",
        "baseline": {"version": chain["version"], "digest": chain["digest"]},
        "repository": {"root_commits": [oid]},
        "base_commit": oid, "commit": oid, "tree": oid,
        "delivery_scope": {"paths": ["references/EXAMPLE-notes.md"], "live_resources": []},
        "excluded_paths": [], "worktree_manifest": [],
        "delivered_modes": "sha256:" + hashlib.sha256(b"EXAMPLE modes").hexdigest(),
    }


def example_request(amended: bool = True) -> dict:
    baseline = example_baseline()
    amendments = [example_amendment(baseline)] if amended else []
    chain = rb.resolve_chain(baseline, amendments)
    segment = "EXAMPLE Fix one typo in single-file docs notes."
    return {
        "record_type": "cwo-in-thread-plan-request", "version": 1,
        "baseline": baseline, "amendments": amendments,
        "candidate": example_candidate(chain),
        "task": {
            "text": segment, "text_segments": [segment],
            "file_paths": ["references/EXAMPLE-notes.md"], "requested_roles": [],
            "data_sensitivity": None, "delegation_requested": False,
            "dependencies": [], "required_reviews": [], "holds": [],
        },
    }


class PreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.effects = []
        self.controls = []
        for target, control in self._effect_controls():
            def deny(*args, _name=target, **kwargs):
                self.effects.append(_name)
                raise AssertionError("EXAMPLE forbidden effect: " + _name)
            self.stack.enter_context(patch(target, side_effect=deny))
            self.controls.append((target, control))
        self.reads = []
        real_builtin, real_io = builtins.open, io.open
        self.stack.enter_context(patch("builtins.open", side_effect=self._open_guard(real_builtin)))
        self.stack.enter_context(patch("io.open", side_effect=self._open_guard(real_io)))
        self.controls.extend([
            ("builtins.open", lambda: builtins.open("EXAMPLE-output", "w")),
            ("io.open", lambda: io.open("EXAMPLE-output", "w")),
            ("builtins.open read boundary", lambda: builtins.open(ROOT / "EXAMPLE-input.yaml", "r")),
            ("io.open read boundary", lambda: io.open(ROOT / "schemas" / "EXAMPLE-input.txt", "r")),
            ("builtins.open undeclared policy", lambda: builtins.open(ROOT / "policy" / "EXAMPLE-undeclared.yaml", "r")),
            ("builtins.open undeclared schema", lambda: builtins.open(ROOT / "schemas" / "EXAMPLE-undeclared.schema.json", "r")),
            ("io.open undeclared policy", lambda: io.open(ROOT / "policy" / "EXAMPLE-undeclared.yaml", "r")),
            ("io.open undeclared schema", lambda: io.open(ROOT / "schemas" / "EXAMPLE-undeclared.schema.json", "r")),
        ])
        self.request = example_request()

    def _open_guard(self, original):
        def guard(path, mode="r", *args, **kwargs):
            if any(flag in mode for flag in "wax+"):
                self.effects.append("file write")
                raise AssertionError("EXAMPLE file write refused.")
            source = Path(path)
            if source not in READ_ONLY_SOURCE_PATHS:
                self.effects.append("undeclared file read")
                raise AssertionError("EXAMPLE undeclared file read refused.")
            self.reads.append(str(source))
            return original(path, mode, *args, **kwargs)
        return guard

    @staticmethod
    def _effect_controls():
        return [
            ("cwo_core.candidate_identity.capture_candidate", lambda: ci.capture_candidate("EXAMPLE", chain={}, base_commit="EXAMPLE", scope_paths=[])),
            ("cwo_core.candidate_identity.verify_candidate", lambda: ci.verify_candidate({}, "EXAMPLE")),
            ("cwo_core.workspace_capture.capture", lambda: workspace_capture.capture("EXAMPLE")),
            ("cwo_core.beads.run_bd", lambda: beads.run_bd(["show", "EXAMPLE"])),
            ("cwo_core.beads.run_bd_structured", lambda: beads.run_bd_structured(["EXAMPLE"])),
            ("cwo_core.beads.create_bead", lambda: beads.create_bead("EXAMPLE")),
            ("cwo_core.beads.add_dependency", lambda: beads.add_dependency("EXAMPLE-a", "EXAMPLE-b")),
            ("subprocess.run", lambda: subprocess.run(["EXAMPLE-command"])),
            ("subprocess.Popen", lambda: subprocess.Popen(["EXAMPLE-command"])),
            ("os.system", lambda: os.system("EXAMPLE-command")),
            ("socket.create_connection", lambda: socket.create_connection(("EXAMPLE.invalid", 1))),
            ("urllib.request.urlopen", lambda: urllib.request.urlopen("https://EXAMPLE.invalid")),
            ("http.client.HTTPConnection.request", lambda: http.client.HTTPConnection.request(None, "GET", "/EXAMPLE")),
            ("os.open", lambda: os.open("EXAMPLE-output", os.O_WRONLY)),
            ("os.mkdir", lambda: os.mkdir("EXAMPLE-output")),
            ("os.unlink", lambda: os.unlink("EXAMPLE-output")),
            ("os.replace", lambda: os.replace("EXAMPLE-a", "EXAMPLE-b")),
            ("os.chmod", lambda: os.chmod("EXAMPLE-output", 0o600)),
            ("pathlib.Path.write_text", lambda: Path("EXAMPLE-output").write_text("EXAMPLE")),
            ("pathlib.Path.write_bytes", lambda: Path("EXAMPLE-output").write_bytes(b"EXAMPLE")),
        ]

    def tearDown(self) -> None:
        self.assertEqual(self.effects, [])
        for name, control in self.controls:
            with self.subTest(spy=name):
                before = len(self.effects)
                with self.assertRaises(AssertionError):
                    control()
                self.assertEqual(len(self.effects), before + 1)

    def assert_held(self, result: dict) -> None:
        for field in (
            "operative", "qualified", "effect_authority", "production_ready",
            "minimal_tier_available", "successful_closure_available",
            "candidate_current_authenticated", "baseline_custody_authenticated",
        ):
            self.assertIs(result[field], False)
        self.assertIn("structural consistency input", result["candidate_scope"])
        self.assertIn("not an observed current checkout", result["candidate_scope"])
        self.assertIn("Full production closure qualification remains open.", result["open_requirements"])
        self.assertIn("In-thread plan activation remains open.", result["open_requirements"])

    def prepare(self, request=None) -> dict:
        result = preview.prepare_proposal(self.request if request is None else request)
        self.assert_held(result)
        return result

    def test_actual_validators_and_classifier_prepare_the_complete_low_risk_case(self) -> None:
        with patch.object(rb, "baseline_errors", wraps=rb.baseline_errors) as baseline, \
                patch.object(rb, "resolve_chain", wraps=rb.resolve_chain) as resolve, \
                patch.object(ci, "candidate_errors", wraps=ci.candidate_errors) as identity, \
                patch.object(ci, "baseline_binding_errors", wraps=ci.baseline_binding_errors) as binding, \
                patch.object(routing, "classify_work", wraps=routing.classify_work) as classifier:
            result = self.prepare()
            for validator in (baseline, resolve, identity, binding):
                validator.assert_called()
            self.assertEqual(result["status"], "proposed-in-thread")
            classifier.assert_called_once_with(
                self.request["task"]["text"],
                text_segments=self.request["task"]["text_segments"],
                file_paths=self.request["task"]["file_paths"],
                requested_roles=[],
                data_sensitivity=None, share_boundary="no-outside-sharing",
                external_ok=False, local_ok=False, prefer_local=False,
                allow_disclosure_escalation=False, current_authority=None,
                operative_evaluated_at="2000-01-01T00:00:00Z",
            )
        self.assertEqual(result["baseline_chain"]["baseline"], self.request["amendments"][0]["baseline"])
        self.assertEqual(result["candidate"], self.request["candidate"])
        self.assertEqual(result["task_context"], self.request["task"])
        self.assertEqual(self.prepare(), result)

    def test_registered_documentation_aliases_and_case_preserve_context(self) -> None:
        profile = policy.load_policy("expert-registry")["experts"]["documentation"]
        aliases = [
            "documentation", profile["discipline"], profile["job_description_label"],
            *profile.get("aliases", []),
        ]
        for alias in dict.fromkeys(aliases):
            for role in (alias, alias.upper()):
                with self.subTest(role=role):
                    changed = copy.deepcopy(self.request)
                    changed["task"]["requested_roles"] = [role]
                    expected = preview._classify(changed["task"])
                    result = self.prepare(changed)
                    self.assertEqual(result["status"], "proposed-in-thread")
                    self.assertIn("documentation", {expert["name"] for expert in expected["ranked_experts"]})
                    self.assertEqual(result["routing_recommendation"], expected)
                    self.assertEqual(result["task_context"], changed["task"])

    def test_unknown_and_mixed_roles_require_a_consequential_plan(self) -> None:
        cases = (
            (["EXAMPLE_UNREGISTERED_ROLE"], [0]),
            (["documentation", "EXAMPLE_UNREGISTERED_ROLE"], [1]),
            (["EXAMPLE_UNREGISTERED_ROLE", "DOCUMENTATION"], [0]),
            (["EXAMPLE_UNREGISTERED_ROLE", "EXAMPLE_OTHER_UNREGISTERED_ROLE"], [0, 1]),
            (["documentation-EXAMPLE"], [0]),
            ([" documentation"], [0]),
            (["documentation "], [0]),
        )
        for roles, unknown_indices in cases:
            with self.subTest(roles=roles):
                changed = copy.deepcopy(self.request)
                changed["task"]["requested_roles"] = roles
                expected = preview._classify(changed["task"])
                result = self.prepare(changed)
                self.assertEqual(result["status"], "consequential-plan-needed")
                self.assertIsNone(result["shape"])
                self.assertEqual(result["nodes"], [])
                self.assertEqual(result["routing_recommendation"], expected)
                self.assertEqual(result["task_context"], changed["task"])
                for index in unknown_indices:
                    self.assertIn(
                        f"Requested role at index {index} is not registered in the real expert registry.",
                        result["errors"],
                    )

    def test_registered_role_accounting_requires_its_ranked_expert(self) -> None:
        task = copy.deepcopy(self.request["task"])
        task["requested_roles"] = ["DOCUMENTATION"]
        route = preview._classify(task)
        self.assertEqual(preview._requested_role_reasons(task, route), [])
        route["ranked_experts"] = [
            expert for expert in route["ranked_experts"] if expert["name"] != "documentation"
        ]
        self.assertEqual(
            preview._requested_role_reasons(task, route),
            ["Requested role at index 0 has unaccounted experts: documentation."],
        )

    def test_generic_internal_worker_acceptance_does_not_require_delegation(self) -> None:
        expected = preview._classify(self.request["task"])
        self.assertEqual((expected["route"], expected["risk_level"]), ("internal-worker", "low"))
        self.assertEqual(expected["hard_stops"], [])
        self.assertEqual(expected["risk_assessment"]["required_experts"], [])
        self.assertEqual(expected["acceptance_required_experts"], [])
        self.assertEqual(
            {expert["name"] for expert in expected["ranked_experts"]},
            {"documentation", "general_reasoning"},
        )
        for expert in expected["ranked_experts"]:
            self.assertIs(expert["validation_gate_required"], False)
            self.assertEqual(expert["executor_policy_violations"], [])
            selected = expert["selected_executor"]
            self.assertEqual(selected["key"], "internal_worker")
            self.assertEqual(selected["dispatch_mode"], "codex_worker")
            self.assertIs(selected["external"], False)
            self.assertEqual(selected["codex_pickup"], "allowed")
            self.assertIs(selected["acceptance_required"], True)
        self.assertFalse(any(
            value is not False
            for key, value in expected.items()
            if key.endswith("_required") and key != "beads_required_for_full_handoff"
        ))
        result = self.prepare()
        self.assertEqual(result["status"], "proposed-in-thread")
        self.assertEqual(result["routing_recommendation"], expected)
        self.assertIs(result["routing_recommendation"]["selected_executor"]["acceptance_required"], True)
        self.assertFalse(self.request["task"]["delegation_requested"])
        self.assertEqual(self.request["task"]["required_reviews"], [])

    def test_conditional_worker_acceptance_preserves_named_reviews_and_dependencies(self) -> None:
        expected = preview._classify(self.request["task"])
        self.assertIs(expected["selected_executor"]["acceptance_required"], True)
        cases = (
            ("required_reviews", {"id": "EXAMPLE-review", "reason": "EXAMPLE independent review is required."}),
            ("dependencies", {
                "id": "EXAMPLE-dependency", "reason": "EXAMPLE independent preparation remains required.",
                "kind": "external",
            }),
        )
        for field, obligation in cases:
            with self.subTest(obligation=field):
                changed = copy.deepcopy(self.request)
                changed["task"][field] = [obligation]
                result = self.prepare(changed)
                self.assertEqual(result["status"], "consequential-plan-needed")
                self.assertIsNone(result["shape"])
                self.assertEqual(result["nodes"], [])
                self.assertEqual(result["routing_recommendation"], expected)
                self.assertEqual(result["task_context"][field], [obligation])
                self.assertTrue(result["errors"])


    def test_exact_membership_closed_references_and_content_order(self) -> None:
        result = self.prepare()
        nodes = result["nodes"]
        baseline = result["baseline_chain"]["baseline"]
        required = [item["id"] for item in baseline["criteria"] if item["applicability"] == "required"]
        membership = Counter(criterion_id for node in nodes for criterion_id in node["criterion_ids"])
        self.assertEqual(membership, Counter(required))
        self.assertEqual({item["criterion_id"] for item in result["applicability"]}, {item["id"] for item in baseline["criteria"]})
        self.assertEqual(result["applicability"][-2]["criterion_id"], "EXAMPLE-na")
        self.assertEqual(result["applicability"][-2]["reason"], "EXAMPLE no platform change is requested.")
        seen = set()
        ancestors = {}
        for node in nodes:
            self.assertEqual(set(node), {"id", "kind", "depends_on", "criterion_ids", "obligation"})
            self.assertNotIn(node["id"], seen)
            self.assertTrue(set(node["depends_on"]) <= seen)
            ancestors[node["id"]] = set(node["depends_on"])
            for dependency in node["depends_on"]:
                ancestors[node["id"]].update(ancestors[dependency])
            if node["kind"] in {"obligation", "review", "disclosure", "report"}:
                self.assertIn("content", ancestors[node["id"]])
            seen.add(node["id"])
        self.assertIn("adjudication", seen)
        self.assertFalse(any(node["kind"] in {"worker", "dispatch", "admission", "paid-review"} for node in nodes))
        self.assertIn("independently check baseline custody", result["future_invalidation_requirement"])
        self.assertFalse(any("status" in node for node in nodes))

    def test_content_candidate_and_baseline_changes_alter_the_binding(self) -> None:
        original = self.prepare()["proposal_binding"]
        changed = copy.deepcopy(self.request)
        changed["task"]["text_segments"][0] += " EXAMPLE clearer copy."
        changed["task"]["text"] = "\n".join(changed["task"]["text_segments"])
        self.assertNotEqual(self.prepare(changed)["proposal_binding"], original)
        changed = copy.deepcopy(self.request)
        changed["candidate"]["tree"] = hashlib.sha256(b"EXAMPLE different tree").hexdigest()[:40]
        self.assertNotEqual(self.prepare(changed)["proposal_binding"], original)
        changed = example_request(amended=False)
        self.assertNotEqual(self.prepare(changed)["proposal_binding"], original)
        changed = copy.deepcopy(self.request)
        changed["candidate"]["worktree_manifest"] = [
            {"path": "references/EXAMPLE-notes.md", "change": "modified", "type": "file",
             "mode": "100644", "size": len(b"EXAMPLE changed copy"),
             "sha256": hashlib.sha256(b"EXAMPLE changed copy").hexdigest()}]
        self.assertNotEqual(self.prepare(changed)["proposal_binding"], original)


    def test_appended_original_segments_preserve_actual_risk_features(self) -> None:
        changed = copy.deepcopy(self.request)
        segments = ["EXAMPLE Fix one typo in docs notes. Inspect sign ", "in", "g"]
        changed["task"].update(text="\n".join(segments), text_segments=segments)
        result = self.prepare(changed)
        self.assertEqual(result["status"], "consequential-plan-needed")
        assessment = result["routing_recommendation"]["risk_assessment"]
        self.assertTrue(assessment["features"])
        self.assertEqual(result["task_context"]["text_segments"], segments)
        original = routing.classify_work("".join(segments[:2]), current_authority=None)
        self.assertTrue({item["feature"] for item in original["risk_assessment"]["features"]} <= {item["feature"] for item in assessment["features"]})
        self.assertTrue(set(original["risk_assessment"]["required_experts"]) <= set(assessment["required_experts"]))

    def test_declared_dependencies_reviews_delegation_and_holds_prevent_the_small_shape(self) -> None:
        for field in ("delegation_requested", "dependencies", "required_reviews", "holds"):
            changed = copy.deepcopy(self.request)
            value = True if field == "delegation_requested" else [{"id": "EXAMPLE-obligation", "reason": "EXAMPLE unfinished obligation."}]
            if field == "dependencies":
                value[0]["kind"] = "internal"
            changed["task"][field] = value
            result = self.prepare(changed)
            self.assertEqual(result["status"], "consequential-plan-needed")
            self.assertEqual(result["task_context"][field], value)


    def test_stdin_stdout_cli_and_unsupported_arguments(self) -> None:
        stdout = io.StringIO()
        code = preview.main([], stdin=io.BytesIO(json.dumps(self.request).encode("utf-8")), stdout=stdout)
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assert_held(result)
        self.assertEqual(result["status"], "proposed-in-thread")
        for args in (["--help"], ["--file", "EXAMPLE-input"]):
            stdout = io.StringIO()
            code = preview.main(args, stdin=io.BytesIO(b""), stdout=stdout)
            self.assertEqual(code, 1)
            self.assert_held(json.loads(stdout.getvalue()))

    def test_parse_failures_limits_and_integer_type_distinctions_are_structured(self) -> None:
        inputs = [
            b"{", b"[]", b'{"version":1,"version":1}', b'{"x":NaN}',
            b'{"x":1.5}', b'{"x":9223372036854775808}', b'{"x":true}', b"\xff",
            b'{"x":"\\ud800"}', b"[" * (preview.MAX_DEPTH + 1) + b"]" * (preview.MAX_DEPTH + 1),
            b"[" + b"null," * preview.MAX_NODES + b"null]",
            b'{"x":' + b"9" * 4400 + b"}",
        ]
        before = sys.get_int_max_str_digits()
        for raw in inputs:
            with self.subTest(size=len(raw)):
                result = preview.prepare_json(raw)
                self.assert_held(result)
                self.assertEqual(result["status"], "refused")
                self.assertIsInstance(result["errors"], list)
                self.assertTrue(result["errors"])
        self.assertEqual(sys.get_int_max_str_digits(), before)
        for value in (True, 1.0, "1"):
            changed = copy.deepcopy(self.request)
            changed["version"] = value
            self.assertEqual(self.prepare(changed)["status"], "refused")
        for field in ("baseline", "candidate"):
            changed = copy.deepcopy(self.request)
            changed[field]["version"] = True
            self.assertEqual(self.prepare(changed)["status"], "refused")

    def test_byte_and_depth_limits_precede_parsing_and_stdin_reads_are_bounded(self) -> None:
        for raw in (b" " * (preview.MAX_BYTES + 1), b"[" * (preview.MAX_DEPTH + 1)):
            with patch.object(preview.json, "loads", side_effect=AssertionError("EXAMPLE parsing ran")) as decoder:
                result = preview.prepare_json(raw)
                decoder.assert_not_called()
            self.assert_held(result)
            self.assertEqual(result["status"], "refused")

        class BoundedInput(io.BytesIO):
            def read(stream, size=-1):
                self.assertEqual(size, preview.MAX_BYTES + 1)
                return super().read(size)
        stdout = io.StringIO()
        self.assertEqual(preview.main([], stdin=BoundedInput(b" " * (preview.MAX_BYTES + 2)), stdout=stdout), 1)
        self.assert_held(json.loads(stdout.getvalue()))

    def test_actual_policy_reads_are_allowed_without_project_observation(self) -> None:
        policy.clear_policy_cache()
        policy_schema._load_schema_cached.cache_clear()
        result = self.prepare()
        self.assertEqual(result["status"], "proposed-in-thread")
        sources = {Path(path) for path in self.reads}
        self.assertIn(ROOT / "policy" / "native-worker-execution.yaml", sources)
        self.assertIn(ROOT / "policy" / "expert-registry.yaml", sources)
        self.assertIn(ROOT / "policy" / "routing-policy.yaml", sources)
        policy_sources = sources & READ_ONLY_POLICY_PATHS
        schema_sources = sources & READ_ONLY_SCHEMA_PATHS
        self.assertTrue(schema_sources)
        self.assertEqual(sources, policy_sources | schema_sources)
        self.assertEqual(
            schema_sources,
            {
                ROOT / "schemas" / policy_schema.POLICY_SCHEMAS[path.name]
                for path in policy_sources
                if path.name in policy_schema.POLICY_SCHEMAS
            },
        )


    def test_unknown_selection_risk_authority_and_review_records_refuse(self) -> None:
        cases = [
            ("minimal", True), ("routing", {"risk_level": "low"}), ("reviews", [{"status": "approved"}]),
            ("operative_authority", {}), ("risk_scope", {}),
        ]
        for key, value in cases:
            changed = copy.deepcopy(self.request)
            changed[key] = value
            self.assertEqual(self.prepare(changed)["status"], "refused")
        for status in ("passed", "approved", "completed"):
            changed = copy.deepcopy(self.request)
            changed["task"]["required_reviews"] = [{"id": "EXAMPLE-review", "reason": "EXAMPLE future review.", "status": status}]
            self.assertEqual(self.prepare(changed)["status"], "refused")
        changed = copy.deepcopy(self.request)
        changed["task"]["text_segments"].append("EXAMPLE omitted original segment.")
        self.assertEqual(self.prepare(changed)["status"], "refused")


    def test_actual_mandatory_review_gates_prevent_the_small_shape(self) -> None:
        cases = (
            (
                "EXAMPLE Fix a docs typo and request ChatGPT Pro Extended Reasoning master plan review.",
                "blocking_review_required",
            ),
            ("EXAMPLE Revise public docs wording.", "editor_gate_required"),
        )
        for text, flag in cases:
            with self.subTest(required_gate=flag):
                changed = copy.deepcopy(self.request)
                changed["task"].update(text=text, text_segments=[text])
                result = self.prepare(changed)
                self.assertEqual(result["status"], "consequential-plan-needed")
                self.assertEqual(result["nodes"], [])
                self.assertIs(result["routing_recommendation"][flag], True)
                self.assertIn(f"Policy obligation {flag} remains required or unresolved.", result["errors"])
                self.assertEqual(result["task_context"]["required_reviews"], [])
                self.assertEqual(result["task_context"]["dependencies"], [])
                if flag == "editor_gate_required":
                    self.assertTrue(any(
                        expert["validation_gate_required"] is True
                        for expert in result["routing_recommendation"]["ranked_experts"]
                    ))

    def test_missing_replaced_and_unsupported_criteria_refuse(self) -> None:
        for field in ("expected_outcome", "reference", "id"):
            changed = copy.deepcopy(self.request)
            del changed["baseline"]["criteria"][0][field]
            self.assertEqual(self.prepare(changed)["status"], "refused")
        changed = copy.deepcopy(self.request)
        changed["baseline"]["criteria"].pop(0)
        self.assertEqual(self.prepare(changed)["status"], "refused")
        for field in ("requirement", "id"):
            changed = copy.deepcopy(self.request)
            changed["amendments"][0]["baseline"]["criteria"][0][field] += "EXAMPLE"
            self.assertEqual(self.prepare(changed)["status"], "refused")
        changed = copy.deepcopy(self.request)
        changed["amendments"][0]["added_criterion_ids"] = []
        self.assertEqual(self.prepare(changed)["status"], "refused")

    def test_candidate_validation_and_baseline_binding_refuse_invalid_records(self) -> None:
        for key, value in (("version", True), ("commit", "EXAMPLE-invalid"), ("approved_by", "EXAMPLE-reviewer")):
            changed = copy.deepcopy(self.request)
            changed["candidate"][key] = value
            self.assertEqual(self.prepare(changed)["status"], "refused")
        changed = copy.deepcopy(self.request)
        changed["candidate"]["baseline"]["digest"] = independent_digest(example_baseline())
        changed["candidate"]["baseline"]["version"] = 1
        self.assertEqual(self.prepare(changed)["status"], "refused")
        changed = copy.deepcopy(self.request)
        changed["candidate"]["bead_id"] = "EXAMPLE-other"
        self.assertEqual(self.prepare(changed)["status"], "refused")

    def test_consequential_work_retains_actual_risk_and_named_obligations(self) -> None:
        for text in (
            "EXAMPLE Fix one-file docs typo for OIDC sign in and production rollout.",
            "EXAMPLE Fix a docs typo and request ChatGPT Pro Extended Reasoning master plan review.",
        ):
            changed = copy.deepcopy(self.request)
            changed["task"].update(text=text, text_segments=[text])
            changed["task"]["dependencies"] = [{"id": "EXAMPLE-W09", "reason": "EXAMPLE external dependency.", "kind": "external"}]
            changed["task"]["required_reviews"] = [{"id": "EXAMPLE-security", "reason": "EXAMPLE independent review remains required."}]
            changed["task"]["holds"] = [{"id": "EXAMPLE-activation", "reason": "EXAMPLE activation remains held."}]
            result = self.prepare(changed)
            self.assertEqual(result["status"], "consequential-plan-needed")
            self.assertEqual(result["nodes"], [])
            self.assertEqual(result["task_context"], changed["task"])
            task = changed["task"]
            expected = routing.classify_work(
                text, text_segments=task["text_segments"], file_paths=task["file_paths"],
                requested_roles=task["requested_roles"], data_sensitivity=None,
                share_boundary="no-outside-sharing", external_ok=False, local_ok=False, prefer_local=False,
                allow_disclosure_escalation=False, current_authority=None,
                operative_evaluated_at="2000-01-01T00:00:00Z",
            )
            self.assertEqual(result["routing_recommendation"], expected)
            self.assertTrue(expected["risk_assessment"]["features"] or expected["blocking_review_required"])


class ReadObserverTests(unittest.TestCase):
    def test_declared_reads_and_undeclared_matching_suffixes(self) -> None:
        observer = PreparationTests("test_actual_policy_reads_are_allowed_without_project_observation")
        observer.effects = []
        observer.reads = []
        opened = []

        def underlying(path, mode="r", *args, **kwargs):
            opened.append((path, mode))
            return "EXAMPLE underlying read"

        guard = observer._open_guard(underlying)
        declared = sorted(READ_ONLY_SOURCE_PATHS)
        for source in declared:
            with self.subTest(declared_source=source.name):
                self.assertEqual(guard(source, "r"), "EXAMPLE underlying read")
        self.assertEqual(opened, [(source, "r") for source in declared])
        self.assertEqual(observer.reads, [str(source) for source in declared])
        self.assertEqual(observer.effects, [])
        before = opened.copy()
        for relative in ("policy/EXAMPLE-undeclared.yaml", "schemas/EXAMPLE-undeclared.schema.json"):
            with self.subTest(undeclared_source=relative):
                source = ROOT / relative
                self.assertNotIn(source, READ_ONLY_SOURCE_PATHS)
                with self.assertRaisesRegex(AssertionError, "undeclared file read refused"):
                    guard(source, "r")
                self.assertEqual(opened, before)
        self.assertEqual(observer.effects, ["undeclared file read", "undeclared file read"])
        self.assertEqual(observer.reads, [str(source) for source in declared])


if __name__ == "__main__":
    unittest.main()
