from __future__ import annotations

import ast
import contextlib
import io
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, NamedTuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.coach import coach_orchestration_prompt, prompt_coach_rationale, workerbee_parallelism_options  # noqa: E402
from cwo_core.policy import RISK_ORDER  # noqa: E402
from cwo_core.routing import classify_work  # noqa: E402

# Imports stay local so compatibility runs fail at the exercised boundary.

CORPUS = json.loads((ROOT / "tests" / "fixtures" / "routing" / "risk-corpus.json").read_text(encoding="utf-8"))
DENIAL_FRAGMENTS = ("no qualified operative route", "until current authority", "no available codex", "registry/tool mismatch is resolved")
REFUSAL = "risk narrowing is not supported in this version"

# Structured narrowing inputs are refused without being read.
DOCS_SCOPE = {"action": "documentation-edit", "paths": ["README.md"], "environment": "none",
              "evidence": {"path": "tests/fixtures/routing/risk-evidence/docs-typo-production.json", "sha256": "1" * 64}}
NARROWING_INPUTS = (
    ("verified-shape scope", {"risk_scope": DOCS_SCOPE}),
    ("bare evidence string", {"risk_scope": {**DOCS_SCOPE, "evidence": "bead-docs-typo-1"}}),
    ("empty evidence", {"risk_scope": {**DOCS_SCOPE, "evidence": ""}}),
    ("empty scope", {"risk_scope": {}}),
    ("malformed scope", {"risk_scope": ["documentation-edit"]}),
    ("approval-shaped scope", {"risk_scope": {**DOCS_SCOPE, "approved": True}}),
    ("evidence directory alone", {"risk_evidence_dir": "tests/fixtures/routing"}),
    ("empty evidence directory", {"risk_evidence_dir": ""}),
    ("scope and evidence directory", {"risk_scope": DOCS_SCOPE, "risk_evidence_dir": "tests/fixtures/routing"}),
)
RUNBOOK_TYPO = "Fix the typo in the production runbook README"
OIDC_FOURTH = "Add OIDC login to the OpenShift platform cluster networking and storage layer"


def rank(level: str | None) -> int:
    return -1 if level is None else RISK_ORDER.index(level)


def case_segments(case: dict, *suffixes: str) -> list[str]:
    return [case["task"], *case.get("segments", []), *(suffix for suffix in suffixes if suffix)]


def route_for(case: dict, *suffixes: str, **overrides: object) -> dict:
    """Route a corpus case; appended text goes in as separate segments, as every production caller passes it."""
    segments = case_segments(case, *suffixes)
    arguments: dict[str, object] = {"file_paths": case.get("file_paths"), "stage": case.get("stage")}
    if len(segments) > 1:
        arguments["text_segments"] = segments
    arguments.update(overrides)
    return classify_work("".join(segments), **arguments)  # type: ignore[arg-type]


def generated_suffixes() -> list[str]:
    spec = CORPUS["suffixes"]["generated"]
    return ["".join(parts) for width in range(1, spec["max_fragments"] + 1)
            for parts in itertools.product(spec["fragments"], repeat=width)]


def feature_names(route: dict) -> set[str]:
    return {item["feature"] for item in route["risk_assessment"]["features"]}


def resolved_names(route: dict) -> list[str]:
    return [item["feature"] for item in route["risk_assessment"]["features"] if item["resolved"]]


@contextlib.contextmanager
def native_dispatch_denied():
    from cwo_core.native_containment import native_operative_containment

    denied = {**native_operative_containment(), "dispatch_authorized": False}
    with mock.patch("cwo_core.routing.native_operative_containment", return_value=denied):
        yield


class CorpusOracleRow(NamedTuple):
    original_id: str
    oracle: Callable[[dict, dict], None]
    benign_only: bool = False


class RiskCorpusTests(unittest.TestCase):
    """The labelled corpus: features, floors, risk bounds and experts from task meaning and declared policy."""

    def test_the_corpus_matches_the_policy_version(self) -> None:
        policy = json.loads((ROOT / "policy" / "risk-features.yaml").read_text(encoding="utf-8"))
        self.assertEqual(CORPUS["policy"]["version"], policy["version"])

    def assert_corpus_labels(self, case: dict, route: dict) -> None:
        if "minimum_risk" in case:
            self.assertGreaterEqual(rank(route["risk_level"]), rank(case["minimum_risk"]), route["risk_level"])
        if "maximum_risk" in case:
            self.assertLessEqual(rank(route["risk_level"]), rank(case["maximum_risk"]), route["risk_level"])
        experts = {expert["name"] for expert in route["ranked_experts"]}
        self.assertLessEqual(set(case["required_experts"]), experts)
        self.assertFalse(set(case.get("forbidden_experts", [])) & experts)
        assessment = route["risk_assessment"]
        self.assertEqual(sorted(feature_names(route)), sorted(case["features"]))
        self.assertEqual(sorted(resolved_names(route)), sorted(case.get("resolved", [])))
        self.assertEqual(assessment["floor"], case["floor"])
        self.assertEqual(assessment["risk_level"], route["risk_level"], "risk contributions stay visible")
        self.assertLessEqual(set(assessment["required_experts"]), experts, "required experts are never dropped")
        self.assertEqual(assessment["unmet_required_experts"], [])
        self.assertNotIn("scope_resolution", assessment)

    def test_every_corpus_narrowing_input_is_refused(self) -> None:
        from cwo_core.errors import CWOValidationError

        cases = [case for case in CORPUS["cases"] if "narrowing_input" in case]
        self.assertGreaterEqual(len(cases), 13)
        for case in cases:
            with self.subTest(case=case["id"]):
                with self.assertRaises(CWOValidationError) as raised:
                    route_for(case, **case["narrowing_input"])
                self.assertIn(REFUSAL, str(raised.exception))

    def test_corpus_route_oracle_family(self) -> None:
        benign = [case for case in CORPUS["cases"] if not case["features"]]
        self.assertGreaterEqual(len(benign), 12)

        def benign_oracle(case: dict, route: dict) -> None:
            assessment = route["risk_assessment"]
            self.assertEqual(assessment["features"], [])
            self.assertIsNone(assessment["floor"])
            self.assertEqual(assessment["required_experts"], [])
            self.assertEqual(route["risk_level"], assessment["expert_risk"], "no risk floor is added")

        rows = (
            CorpusOracleRow("tests.test_routing_risk_features.RiskCorpusTests.test_every_case_meets_its_labels", self.assert_corpus_labels),
            CorpusOracleRow("tests.test_routing_risk_features.RiskCorpusTests.test_benign_corpus_tasks_route_proportionately_without_features",
                            benign_oracle, True),
        )
        routes = {}
        for case in CORPUS["cases"]:
            with self.subTest(case=case["id"]):
                route = route_for(case)
                routes[case["id"]] = route
                for row in rows:
                    if not row.benign_only or not case["features"]:
                        with self.subTest(original_id=row.original_id):
                            row.oracle(case, route)
        for case_id in ("readme-typo", "benign-docs-guide-typo", "benign-changelog-spelling"):
            with self.subTest(original_id=rows[1].original_id, case=case_id):
                case = next(item for item in CORPUS["cases"] if item["id"] == case_id)
                self.assertEqual(routes[case["id"]]["risk_level"], "low")


class AppendRuleTests(unittest.TestCase):
    """Appended segments cannot remove a retained feature or lower its floor under unchanged structured scope."""

    def test_combined_suffixes_keep_the_floor(self) -> None:
        from cwo_core.risk_features import assess_risk_features

        benign = CORPUS["suffixes"]["benign"]
        for case in (case for case in CORPUS["cases"] if case["retained"]):
            base = assess_risk_features("".join(case_segments(case)), segments=case_segments(case))
            for first, second in itertools.permutations(benign, 2):
                segments = case_segments(case, first, second)
                with self.subTest(case=case["id"], suffix=first + second):
                    after = assess_risk_features("".join(segments), segments=segments)
                    self.assertGreaterEqual(rank(after.floor), rank(base.floor))
                    self.assertLessEqual(set(base.features), set(after.features))

    def test_bounded_generated_suffixes_keep_features_floor_and_experts(self) -> None:
        from cwo_core.risk_features import assess_risk_features

        suffixes = generated_suffixes()
        self.assertEqual(len(suffixes), 16 + 16 * 16)
        for case in (case for case in CORPUS["cases"] if case["retained"]):
            base = assess_risk_features("".join(case_segments(case)), segments=case_segments(case))
            for suffix in suffixes:
                segments = case_segments(case, suffix)
                after = assess_risk_features("".join(segments), segments=segments)
                if not (set(base.features) <= set(after.features) and rank(after.floor) >= rank(base.floor)
                        and set(base.required_experts) <= set(after.required_experts)):
                    self.fail(f"{case['id']} lost a feature, floor or expert with suffix {suffix!r}")

    def test_token_extension_and_combining_segments_keep_oidc(self) -> None:
        for suffix in ("s and publish the runbook", "́ and publish the runbook"):
            with self.subTest(suffix=suffix):
                route = classify_work("Inspect OIDC" + suffix, text_segments=["Inspect OIDC", suffix])
                self.assertIn("asset:authentication", feature_names(route))
                self.assertEqual(route["risk_assessment"]["floor"], "high")
                self.assertIn("security", route["risk_assessment"]["required_experts"])
                self.assertIn("security", {expert["name"] for expert in route["ranked_experts"]})
                self.assertEqual(route["risk_assessment"]["assessed_segments"], 3)

    def test_the_guarantee_is_stated_for_segments_not_for_text_joined_before_routing(self) -> None:
        """One joined string is assessed as written: the whole token OIDCs is not OIDC. Callers pass segments."""
        from cwo_core.risk_features import assess_risk_features

        self.assertNotIn("asset:authentication", assess_risk_features("Inspect OIDCs and publish the runbook").features)
        self.assertIn("asset:authentication", assess_risk_features(
            "Inspect OIDCs and publish the runbook", segments=["Inspect OIDC", "s and publish the runbook"]).features)

    def test_every_production_call_site_that_joins_text_passes_segments(self) -> None:
        entry_points = {"classify_work", "coach_orchestration_prompt"}
        found = []
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) in entry_points:
                    found.append(path.relative_to(ROOT).as_posix())
                    with self.subTest(path=found[-1], line=node.lineno):
                        self.assertIn("text_segments", {keyword.arg for keyword in node.keywords})
        self.assertGreaterEqual(len(found), 7, found)

    def test_the_cli_reads_text_and_file_as_separate_segments(self) -> None:
        import tempfile

        from cwo_core.util import read_text_arg, read_text_segments

        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as handle:
            handle.write("s and publish the runbook")
        try:
            self.assertEqual(read_text_segments("Inspect OIDC", handle.name), ["Inspect OIDC", "s and publish the runbook"])
            self.assertEqual(read_text_arg("Inspect OIDC", handle.name), "Inspect OIDC\n\ns and publish the runbook")
        finally:
            Path(handle.name).unlink()


    def test_benign_and_risky_suffixes_never_lower_risk_or_drop_experts(self) -> None:
        suffixes = CORPUS["suffixes"]["benign"] + CORPUS["suffixes"]["risky"] + CORPUS["suffixes"]["token_extension"]
        for case in (case for case in CORPUS["cases"] if case["retained"]):
            base = route_for(case)
            base_experts = {expert["name"] for expert in base["ranked_experts"]} & set(case["required_experts"])
            for suffix in suffixes:
                with self.subTest(case=case["id"], suffix=suffix):
                    route = route_for(case, suffix)
                    self.assertGreaterEqual(rank(route["risk_level"]), rank(base["risk_level"]), route["risk_level"])
                    self.assertLessEqual(base_experts, {expert["name"] for expert in route["ranked_experts"]})
                    self.assertLessEqual(feature_names(base), feature_names(route))
                    self.assertGreaterEqual(rank(route["risk_assessment"]["floor"]), rank(base["risk_assessment"]["floor"]))

    def test_a_docs_path_or_stage_flag_cannot_erase_conflicting_risky_text(self) -> None:
        for case in (case for case in CORPUS["cases"] if case["retained"]):
            base = route_for(case)
            for flags in ({"file_paths": ["README.md"]}, {"stage": "docs"}, {"file_paths": ["docs/guide.md"], "stage": "docs"}):
                with self.subTest(case=case["id"], flags=flags):
                    route = route_for(case, **flags)
                    self.assertGreaterEqual(rank(route["risk_level"]), rank(case["minimum_risk"]), route["risk_level"])
                    self.assertEqual(feature_names(route), feature_names(base))
                    self.assertEqual(route["risk_assessment"]["floor"], base["risk_assessment"]["floor"])
                    self.assertEqual(resolved_names(route), [])
                    self.assertNotIn("scope_resolution", route["risk_assessment"])

# Each history: segments in order. The append at index ``forms`` creates the feature; a later append would erase it
# if only the joined text were assessed. Boundary cases form the feature at a segment boundary, mid-token cases inside
# a token.
FEATURE_HISTORIES = (
    (("Inspect sign ", "in", "g"), "asset:authentication", "boundary"),
    (("Inspect sign", " in", "dicator"), "asset:authentication", "boundary"),
    (("Back up the ", "db", "x export"), "asset:database", "boundary"),
    (("Inspect OI", "DC", "s and publish the runbook"), "asset:authentication", "mid-token"),
    (("Fix au", "th", "orship notes"), "asset:authentication", "mid-token"),
    (("Rotate the to", "ken", "izer"), "asset:credentials", "mid-token"),
    (("Check the pro", "d", "ucts page"), "environment:production", "mid-token"),
    (("Delet", "e", "r class cleanup"), "action:destructive", "mid-token"),
)


def assess_history(segments: list[str] | tuple[str, ...]):
    from cwo_core.risk_features import assess_risk_features

    return assess_risk_features("".join(segments), segments=list(segments))


class SegmentHistoryTests(unittest.TestCase):
    """A feature formed at any point in the append history stays, with its floor and experts."""

    def assert_kept(self, before, after, label: str) -> None:
        self.assertLessEqual(set(before.features), set(after.features), label)
        self.assertGreaterEqual(rank(after.floor), rank(before.floor), label)
        self.assertLessEqual(set(before.required_experts), set(after.required_experts), label)

    def test_the_reviewer_history_keeps_authentication_its_floor_and_the_security_expert(self) -> None:
        route = classify_work("Inspect sign ing", text_segments=["Inspect sign ", "in", "g"])
        self.assertIn("asset:authentication", feature_names(route))
        self.assertEqual(route["risk_assessment"]["floor"], "high")
        self.assertIn("security", route["risk_assessment"]["required_experts"])
        self.assertIn("security", {expert["name"] for expert in route["ranked_experts"]})
        self.assertEqual(route["risk_assessment"]["assessed_segments"], 4)
        self.assertEqual(route["risk_assessment"]["assessed_prefixes"], 3)

    def test_a_feature_one_append_forms_survives_a_later_append_that_would_erase_it(self) -> None:
        from cwo_core.risk_features import assess_risk_features

        for history, feature, kind in FEATURE_HISTORIES:
            with self.subTest(history=history, kind=kind):
                self.assertNotIn(feature, assess_history(history[:1]).features, "precondition: the first segment lacks it")
                self.assertIn(feature, assess_history(history[:2]).features, "precondition: the append forms it")
                self.assertNotIn(feature, assess_risk_features("".join(history)).features,
                                 "precondition: the final joined text alone lacks it")
                for step in range(2, len(history) + 1):
                    self.assert_kept(assess_history(history[:step - 1]), assess_history(history[:step]), f"step {step}")
                self.assertIn(feature, assess_history(history).features)

    def test_the_route_keeps_the_floor_and_experts_across_the_history(self) -> None:
        for history, feature, kind in FEATURE_HISTORIES:
            with self.subTest(history=history, kind=kind):
                formed = classify_work("".join(history[:2]), text_segments=list(history[:2]))
                final = classify_work("".join(history), text_segments=list(history))
                self.assertIn(feature, feature_names(final))
                self.assertGreaterEqual(rank(final["risk_level"]), rank(formed["risk_level"]))
                self.assertGreaterEqual(rank(final["risk_assessment"]["floor"]), rank(formed["risk_assessment"]["floor"]))
                self.assertLessEqual(set(formed["risk_assessment"]["required_experts"]),
                                     {expert["name"] for expert in final["ranked_experts"]})

    def test_generated_multi_segment_histories_keep_features_floor_and_experts(self) -> None:
        """Each generated fragment is appended as its own segment, after every feature history and retained case."""
        spec = CORPUS["suffixes"]["generated"]
        bases = [list(history[:2]) for history, _feature, _kind in FEATURE_HISTORIES]
        bases += [case_segments(case) for case in CORPUS["cases"] if case["retained"]]
        cache: dict[tuple[str, ...], object] = {}

        def assessed(history: list[str]):
            key = tuple(history)
            if key not in cache:
                cache[key] = assess_history(key)
            return cache[key]

        runs = 0
        for base in bases:
            for width in range(1, spec["max_fragments"] + 1):
                for parts in itertools.product(spec["fragments"], repeat=width):
                    before = assessed(base)
                    history = list(base)
                    for part in parts:
                        history.append(part)
                        after = assessed(history)
                        runs += 1
                        if not (set(before.features) <= set(after.features) and rank(after.floor) >= rank(before.floor)
                                and set(before.required_experts) <= set(after.required_experts)):
                            self.fail(f"{base!r} lost a feature, floor or expert after appending {history[len(base):]!r}")
                        before = after
        self.assertGreater(runs, 0)



def run_script(script: str, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *arguments],
        cwd=ROOT, capture_output=True, text=True, check=False, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


# Each CLI with arguments that would otherwise route and print. Narrowing flags are added per case.
CLI_INVOCATIONS = (
    ("route_work.py", ["--json", "--file-path", "README.md", RUNBOOK_TYPO]),
    ("coach_prompt.py", ["--json", "--file-path", "README.md", RUNBOOK_TYPO]),
    ("dispatch_work.py", ["--json", RUNBOOK_TYPO]),
    ("generate_manual_dispatch_prompt.py", ["--json", RUNBOOK_TYPO]),
    ("spawn_expert_reviews.py", ["--dry-run", RUNBOOK_TYPO]),
    ("scaffold_workgraph.py", ["--dry-run", "--title", RUNBOOK_TYPO]),
)


class NarrowingRefusalTests(unittest.TestCase):
    """Every narrowing input is refused before any routing output."""

    def test_classify_work_refuses_every_narrowing_input_before_routing(self) -> None:
        from cwo_core.errors import CWOValidationError

        untouched = mock.Mock(side_effect=AssertionError("routing ran after a narrowing input"))
        with mock.patch("cwo_core.routing.native_operative_containment", untouched), \
                mock.patch("cwo_core.routing.score_experts_v2", untouched), \
                mock.patch("cwo_core.routing.assess_risk_features", untouched):
            for label, narrowing in NARROWING_INPUTS:
                with self.subTest(input=label):
                    with self.assertRaises(CWOValidationError) as raised:
                        classify_work(RUNBOOK_TYPO, file_paths=["README.md"], **narrowing)  # type: ignore[arg-type]
                    self.assertIn(REFUSAL, str(raised.exception))
        untouched.assert_not_called()

    def test_the_coach_refuses_every_narrowing_input_before_routing(self) -> None:
        from cwo_core.errors import CWOValidationError

        untouched = mock.Mock(side_effect=AssertionError("the coach routed after a narrowing input"))
        with mock.patch("cwo_core.coach.classify_work", untouched):
            for label, narrowing in NARROWING_INPUTS:
                with self.subTest(input=label):
                    with self.assertRaises(CWOValidationError) as raised:
                        coach_orchestration_prompt(RUNBOOK_TYPO, file_paths=["README.md"], **narrowing)  # type: ignore[arg-type]
                    self.assertIn(REFUSAL, str(raised.exception))
        untouched.assert_not_called()

    def test_every_cli_refuses_each_narrowing_flag_with_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scope_file = Path(directory) / "scope.json"
            scope_file.write_text(json.dumps(DOCS_SCOPE), encoding="utf-8")
            flag_sets = (
                ["--risk-scope", str(scope_file)],
                ["--risk-scope", str(Path(directory) / "absent.json")],
                ["--risk-scope", ""],
                ["--risk-evidence-dir", directory],
                ["--risk-scope", str(scope_file), "--risk-evidence-dir", directory],
            )
            for script, arguments in CLI_INVOCATIONS:
                for flags in flag_sets:
                    with self.subTest(script=script, flags=flags[::2]):
                        result = run_script(script, *flags, *arguments)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertEqual(result.stdout, "", "no routing output")
                        self.assertIn(REFUSAL, result.stderr)
                        self.assertNotIn("Traceback", result.stderr)

    def test_the_parameters_and_flags_remain_only_as_refusals(self) -> None:
        import inspect

        from cwo_core import risk_features

        for function in (classify_work, coach_orchestration_prompt):
            with self.subTest(function=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertIn("risk_scope", parameters)
                self.assertIn("risk_evidence_dir", parameters)
        for name in ("resolve_with_validated_scope", "validate_risk_scope", "verify_scope_evidence", "EVIDENCE_MAX_BYTES"):
            with self.subTest(removed=name):
                self.assertFalse(hasattr(risk_features, name))
        policy = json.loads((ROOT / "policy" / "risk-features.yaml").read_text(encoding="utf-8"))
        self.assertNotIn("validated_scope", policy)
        self.assertFalse((ROOT / "tests" / "fixtures" / "routing" / "risk-evidence").exists())
        for script, _arguments in CLI_INVOCATIONS:
            with self.subTest(script=script):
                result = run_script(script, "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--risk-scope", result.stdout)
                self.assertIn("risk narrowing is unavailable", " ".join(result.stdout.split()))

    def test_an_older_record_with_a_scope_resolution_still_validates(self) -> None:
        from tests.test_prompt_coach import validate_schema_instance

        schema = json.loads((ROOT / "schemas" / "route-result.schema.json").read_text(encoding="utf-8"))
        older = {
            "version": 1, "features": [{"feature": "environment:production", "terms": ["production"],
                                        "resolved": "validated documentation-edit scope"}],
            "floor": None, "floor_reasons": [], "required_experts": [], "expert_risk": "low", "risk_level": "low",
            "assessed_segments": 1, "assessed_prefixes": 0,
            "scope_resolution": {"action": "documentation-edit", "paths": ["README.md"], "environment": "none",
                                 "evidence": "docs.json", "evidence_sha256": "1" * 64, "evidence_root": "repository",
                                 "evidence_status": "verified", "evidence_lists": ["environment:production"],
                                 "applied": True, "resolved": [{"feature": "environment:production", "evidence": "docs.json"}],
                                 "retained": [], "reasons": [], "floor_before": "medium"},
        }
        validate_schema_instance(older, schema["properties"]["risk_assessment"], root=schema)

    def test_a_docs_path_and_stage_still_route_without_narrowing(self) -> None:
        route = classify_work(RUNBOOK_TYPO, file_paths=["README.md"], stage="docs")
        self.assertEqual(feature_names(route), {"environment:production"})
        self.assertEqual(resolved_names(route), [])
        self.assertEqual(route["risk_assessment"]["floor"], "medium")
        self.assertFalse(route["operative_route"]["dispatch_authorized"], "routing risk is not dispatch authority")


    def test_routes_never_claim_a_resolution_and_validate_against_the_schema(self) -> None:
        from tests.test_prompt_coach import validate_schema_instance

        schema = json.loads((ROOT / "schemas" / "route-result.schema.json").read_text(encoding="utf-8"))
        assessment_schema = schema["properties"]["risk_assessment"]
        for case in CORPUS["cases"]:
            with self.subTest(case=case["id"]):
                assessment = route_for(case)["risk_assessment"]
                self.assertTrue(all(item["resolved"] is None for item in assessment["features"]))
                self.assertNotIn("scope_resolution", assessment)
                validate_schema_instance(assessment, assessment_schema, root=schema)


def drop_expert_from_registry(name: str):
    """Patch routing so the expert registry lacks ``name``: the expert is unavailable to every route."""
    from cwo_core import routing

    real = routing.load_policy

    def load(policy_name: str):
        data = real(policy_name)
        if policy_name == "expert-registry":
            data = {**data, "experts": {key: value for key, value in data["experts"].items() if key != name}}
        return data

    return mock.patch("cwo_core.routing.load_policy", side_effect=load)


class RequiredExpertTests(unittest.TestCase):
    """Every risk-required expert survives ranking, limits, tight scaffolding and fallback, or is reported unmet."""

    def oidc_route(self) -> dict:
        route = classify_work(OIDC_FOURTH)
        names = [expert["name"] for expert in route["ranked_experts"]]
        self.assertIn("security", route["risk_assessment"]["required_experts"])
        self.assertGreaterEqual(names.index("security"), 3, f"precondition: three experts rank ahead of security: {names}")
        return route

    def test_default_review_spawning_keeps_security_ranked_fourth(self) -> None:
        from spawn_expert_reviews import planned_expert_reviews

        route = self.oidc_route()
        for top_n in (3, 1, 0):
            with self.subTest(top_n=top_n):
                reviews, unmet = planned_expert_reviews("Expert review", route, top_n)
                self.assertIn("Expert review: Security Distinguished Engineer", [review["title"] for review in reviews])
                self.assertEqual(unmet, [])
        reviews, _unmet = planned_expert_reviews("Expert review", route, 3)
        self.assertEqual(len([review for review in reviews if review["title"].startswith("Expert review:")]), 4,
                         "the top three stay and security is added, not swapped in")

    def test_the_review_cli_dry_run_plans_security(self) -> None:
        result = run_script("spawn_expert_reviews.py", "--dry-run", OIDC_FOURTH)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertIn("Expert review: Security Distinguished Engineer", [review["title"] for review in output["planned_reviews"]])
        self.assertEqual(output["required_experts"], ["security"])
        self.assertEqual(output["unmet_required_experts"], [])
        self.assertTrue(output["review_plan_complete"])

    def test_tight_scaffolding_keeps_security_ranked_fourth(self) -> None:
        from scaffold_workgraph import planned_graph

        route = self.oidc_route()
        for size in ("tight", "full"):
            with self.subTest(size=size):
                graph = planned_graph("OIDC login", route, scaffold_size=size)
                lanes = {item.get("lane"): item for item in graph}
                self.assertIn("expert-review-security", lanes)
                self.assertIn("Risk-required experts: security", graph[0]["notes"])
        tight = planned_graph("OIDC login", route, scaffold_size="tight")
        expert_lanes = [item["lane"] for item in tight if item.get("metadata", {}).get("expert")]
        self.assertNotIn("expert-review-storage", expert_lanes, "optional fan-out is still limited")

    def test_the_scaffold_cli_dry_run_keeps_security(self) -> None:
        result = run_script("scaffold_workgraph.py", "--dry-run", "--tight-chain", "--title", OIDC_FOURTH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("expert-review-security", {item.get("lane") for item in json.loads(result.stdout)})

    def test_displayed_expert_lists_keep_security(self) -> None:
        import generate_manual_dispatch_prompt
        import route_work

        route = self.oidc_route()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            route_work.print_human(route, 1)
        self.assertIn("- security score=", output.getvalue())
        self.assertIn("Security Distinguished Engineer", generate_manual_dispatch_prompt.render_prompt(OIDC_FOURTH, route))

    def test_a_required_expert_ranked_last_survives_every_limit(self) -> None:
        from cwo_core.routing import experts_with_required
        from scaffold_workgraph import planned_graph
        from spawn_expert_reviews import planned_expert_reviews

        route = self.oidc_route()
        experts = route["ranked_experts"]
        reordered = {**route, "ranked_experts": [*[e for e in experts if e["name"] != "security"],
                                                 *[e for e in experts if e["name"] == "security"]]}
        for limit in (0, 1, 2, -1):
            with self.subTest(limit=limit):
                self.assertIn("security", [expert["name"] for expert in experts_with_required(reordered, limit)])
                self.assertEqual(planned_expert_reviews("Expert review", reordered, limit)[1], [])
        self.assertIn("expert-review-security", {item.get("lane") for item in planned_graph("x", reordered, "tight")})

    def test_an_unavailable_required_expert_is_reported_as_unmet(self) -> None:
        from scaffold_workgraph import planned_graph
        from spawn_expert_reviews import planned_expert_reviews

        with drop_expert_from_registry("security"):
            route = classify_work(OIDC_FOURTH)
        unmet = [{"expert": "security", "reason": "not defined in the expert registry"}]
        self.assertEqual(route["risk_assessment"]["required_experts"], ["security"])
        self.assertEqual(route["risk_assessment"]["unmet_required_experts"], unmet)
        self.assertNotIn("security", {expert["name"] for expert in route["ranked_experts"]})
        self.assertEqual(route["risk_level"], "high", "the floor stays even when the expert is unmet")
        reviews, reported = planned_expert_reviews("Expert review", route, 3)
        self.assertEqual(reported, unmet)
        for size in ("tight", "full"):
            with self.subTest(size=size):
                with self.assertRaises(ValueError) as raised:
                    planned_graph("OIDC login", route, scaffold_size=size)
                self.assertIn("required experts unmet: security (not defined in the expert registry)", str(raised.exception))

    def test_a_route_missing_a_required_expert_is_refused_by_the_review_and_scaffold_commands(self) -> None:
        import scaffold_workgraph
        import spawn_expert_reviews

        route = self.oidc_route()
        missing = {**route, "ranked_experts": [e for e in route["ranked_experts"] if e["name"] != "security"]}
        creator = mock.Mock(side_effect=AssertionError("a Bead was created without a required expert"))
        for module, argv in ((spawn_expert_reviews, ["spawn_expert_reviews.py", OIDC_FOURTH]),
                             (spawn_expert_reviews, ["spawn_expert_reviews.py", "--dry-run", OIDC_FOURTH]),
                             (scaffold_workgraph, ["scaffold_workgraph.py", "--title", OIDC_FOURTH]),
                             (scaffold_workgraph, ["scaffold_workgraph.py", "--dry-run", "--tight-chain", "--title", OIDC_FOURTH])):
            with self.subTest(argv=argv):
                output = io.StringIO()
                with mock.patch.object(module, "classify_work", return_value=missing), \
                        mock.patch.object(module, "create_bead", creator), mock.patch.object(sys, "argv", argv), \
                        contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as raised:
                        module.main()
                self.assertIn("required experts unmet: security (not among the routed experts)", str(raised.exception.code))
                if "--dry-run" in argv and module is spawn_expert_reviews:
                    planned = json.loads(output.getvalue())
                    self.assertEqual(planned["unmet_required_experts"], [{"expert": "security", "reason": "not among the routed experts"}])
                    self.assertFalse(planned["review_plan_complete"])
                else:
                    self.assertEqual(output.getvalue(), "")
        creator.assert_not_called()


    def test_routing_keeps_required_experts_after_its_own_filters(self) -> None:
        tasks = (
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract migration of the OIDC login.",
            "Inspect OIDC",
            "Fix the typo in the README about rotating the production database credentials",
        )
        for task in tasks:
            with self.subTest(task=task):
                route = classify_work(task, external_ok=True, share_boundary="redacted-packet")
                required = set(route["risk_assessment"]["required_experts"])
                self.assertTrue(required)
                self.assertLessEqual(required, {expert["name"] for expert in route["ranked_experts"]})
                self.assertEqual(route["risk_assessment"]["unmet_required_experts"], [])

    def test_a_named_architecture_critic_stands_in_for_required_architecture(self) -> None:
        from scaffold_workgraph import planned_graph

        route = classify_work(
            "Use Claude Opus 4.6 and Gemini 3.1 Pro Preview as independent second opinion critics "
            "of the Codex architect design for a cross-cutting public contract architecture migration.",
            external_ok=True, share_boundary="redacted-packet", requested_roles=["architecture"],
        )
        self.assertIn("architecture", route["risk_assessment"]["required_experts"])
        for size in ("tight", "full"):
            with self.subTest(size=size):
                lanes = {item.get("lane") for item in planned_graph("Critic review", route, scaffold_size=size)}
                self.assertIn("expert-review-architecture-critic-claude-architecture-critic", lanes)

class NormalizationTests(unittest.TestCase):
    def test_tokens_are_whole_words_after_compatibility_folding(self) -> None:
        from cwo_core.risk_features import assess_risk_features, normalized_tokens

        self.assertEqual(normalized_tokens("Ｐｒｏｄ-DB_creds, re-key!"), ("prod", "db", "creds", "re", "key"))
        self.assertEqual(sorted(assess_risk_features("prod-db").features), ["asset:database", "environment:production"])

    def test_short_terms_match_only_as_whole_tokens(self) -> None:
        from cwo_core.risk_features import assess_risk_features

        for text, features in (
            ("Update the products notes", []), ("Update the prod notes", ["environment:production"]),
            ("Update the authorship notes", []), ("List the authors in the changelog", []),
            ("Fix auth for the CLI", ["asset:authentication"]),
            ("Update the tokenizer notes", []), ("Tokenize the input string", []), ("Revoke the token", ["action:rotation", "asset:credentials"]),
            ("Export the report with dbx", []), ("Back up the db", ["asset:database"]),
            ("Refactor the deleter class", []), ("Delete the cache", ["action:destructive"]),
            ("Update the rotatable notes", []), ("Migrate the notes", ["action:migration"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(sorted(assess_risk_features(text).features), features)

    def test_multi_word_terms_match_only_consecutive_whole_tokens(self) -> None:
        from cwo_core.risk_features import assess_risk_features

        self.assertEqual(assess_risk_features("Design the sign indicator").features, {})
        self.assertEqual(assess_risk_features("Design the sign-in page").features, {"asset:authentication": ["sign in"]})
        self.assertEqual(assess_risk_features("Sign the release, in order").features, {})
        self.assertEqual(sorted(assess_risk_features("Rotate the API_KEYS").features), ["action:rotation", "asset:credentials"])
        self.assertEqual(assess_risk_features("Update the apis keys page").features, {})

    def test_segments_must_be_strings(self) -> None:
        from cwo_core.errors import CWOValidationError
        from cwo_core.risk_features import assess_risk_features

        for segments in ("Inspect OIDC", ["Inspect OIDC", 3]):
            with self.subTest(segments=segments):
                with self.assertRaises(CWOValidationError):
                    assess_risk_features("Inspect OIDC", segments=segments)  # type: ignore[arg-type]


class CoachPlanningTests(unittest.TestCase):
    """Planning output: complete sentences, no denial fragments in optional choices, execution availability apart."""

    def all_text(self, coach: dict) -> list[str]:
        texts = list(coach.get("rationale", [])) + list(coach.get("warnings", []))
        for question in coach.get("interactive_questions", []):
            texts += [question.get("question", ""), question.get("why", "")]
            for option in question.get("options", []):
                texts += [option.get("label", ""), option.get("description", "")]
        return texts

    def test_simple_tasks_show_no_garbled_choices_or_parent_wide_hard_stop(self) -> None:
        for task in ("Plan a small internal feature", "Fix the typo in README"):
            with self.subTest(task=task):
                coach = coach_orchestration_prompt(task)
                for text in self.all_text(coach):
                    self.assertNotIn("hard stop", text.lower())
                    for fragment in DENIAL_FRAGMENTS:
                        self.assertNotIn(fragment, text.lower())

    def test_a_planning_task_explains_execution_availability_separately(self) -> None:
        coach = coach_orchestration_prompt("Plan architecture and documentation review")
        self.assertFalse(any(text.startswith("Policy hard stop") for text in coach["warnings"]))
        availability = coach["execution_availability"]
        self.assertFalse(availability["dispatch_authorized"])
        self.assertIn("current-authority-missing", availability["stops"])
        self.assertIn("dispatch stays refused", availability["summary"])
        self.assertFalse(coach["route"]["operative_route"]["dispatch_authorized"], "denied native dispatch remains denied")
        for option in (option for question in coach.get("interactive_questions", []) for option in question.get("options", [])):
            for fragment in DENIAL_FRAGMENTS:
                self.assertNotIn(fragment, option.get("description", "").lower())
        self.assertFalse(any("recommended as blocked" in text for text in coach["rationale"]))

    def test_an_unavailable_route_never_leaks_into_choice_text(self) -> None:
        from cwo_core.coach import workerbee_prompt_line, workerbee_use_phrase

        unavailable = {"recommended_mode": "review-only", "hard_stop": False, "spark_dispatch": {"status": "unqualified"},
                       "recommended_model": "gpt-other", "suggested_lanes": ["docs review"]}
        self.assertEqual(workerbee_use_phrase(unavailable), "Use subagents")
        first = {"label": "Review subagents (Recommended)", "value": "review-subagents", "description": "x"}
        for option in workerbee_parallelism_options("implementation-capable", first, workerbee_use_phrase(unavailable)):
            self.assertTrue(option["description"].startswith(("Use subagents", "Keep all work", "x")), option)
        line = workerbee_prompt_line(unavailable)
        self.assertTrue(line.startswith("Use subagents for review-only parallelism"))
        self.assertIn("No qualified operative route is available until current authority and admission gates pass.", line)

    def test_the_rationale_uses_complete_sentences_for_blocked_parallelism(self) -> None:
        blocked = {"recommended_mode": "blocked", "hard_stop": True}
        rationale = prompt_coach_rationale("full-harness", {"route": "architect-review", "risk_level": "high",
                                                            "recommended_executor": "frontier_architect",
                                                            "execution_environment": "connected-codex"},
                                           [], blocked)
        sentence = next(text for text in rationale if text.startswith("Subagent"))
        self.assertEqual(sentence, "Subagent lanes would suit bounded sidecar workstreams, but none can run now. "
                                   "No qualified operative route is available until current authority and admission gates pass.")


class ExecutionAuthorityTests(unittest.TestCase):
    """Route classification and risk features never become dispatch authority."""

    def test_risk_features_do_not_change_dispatch_authority(self) -> None:
        for task in ("Fix the typo in README", "Migrate the production database and rotate credentials"):
            with self.subTest(task=task):
                route = classify_work(task)
                self.assertFalse(route["operative_route"]["dispatch_authorized"])
                self.assertNotIn("dispatch_authorized", route["risk_assessment"])

    def test_production_database_work_without_action_keyword_keeps_floor_despite_docs_paths(self) -> None:
        route = classify_work("Restart the production PostgreSQL service", file_paths=["README.md"])
        assessment = route["risk_assessment"]
        self.assertLessEqual({"environment:production", "asset:database"}, feature_names(route))
        self.assertEqual(assessment["floor"], "high")
        self.assertIn("storage", assessment["required_experts"])
        self.assertEqual(resolved_names(route), [])

    def test_native_containment_denial_always_yields_unavailable(self) -> None:
        from cwo_core.coach import execution_availability

        availability = execution_availability({
            "operative_route": {"dispatch_authorized": True},
            "hard_stops": [],
            "native_operative_dispatch": {"dispatch_authorized": False, "stop_reason": "native precommit containment"},
        })
        self.assertFalse(availability["dispatch_authorized"])
        self.assertIn("native containment", availability["summary"].lower())
        self.assertTrue(any("native containment" in stop for stop in availability["stops"]))


PARALLEL_DOCS_TASK = "Do a deep second pass on docs, GitHub Pages flow, routing policy, and tests."


class CoachContainmentPrecedenceTests(unittest.TestCase):
    """Native containment takes precedence throughout the coach, and complete results satisfy the coach schema."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((ROOT / "schemas" / "prompt-coach-result.schema.json").read_text(encoding="utf-8"))

    def assert_schema_valid(self, result: dict) -> None:
        from tests.test_prompt_coach import validate_schema_instance

        validate_schema_instance(result, self.schema)
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            return
        errors = sorted(error.message for error in Draft202012Validator(self.schema).iter_errors(result))
        self.assertEqual(errors, [])

    def test_a_route_hard_stop_result_is_schema_valid(self) -> None:
        result = coach_orchestration_prompt("Plan architecture and documentation review")
        self.assertIn("current-authority-missing", result["route"]["hard_stops"])
        self.assertFalse(result["execution_availability"]["dispatch_authorized"])
        self.assert_schema_valid(result)

    def test_brief_output_shows_availability_when_dispatch_is_available(self) -> None:
        import coach_prompt
        from tests.test_prompt_coach import qualified_current_coach

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            coach_prompt.print_brief(qualified_current_coach(PARALLEL_DOCS_TASK))
        self.assertIn("Model dispatch available: yes", output.getvalue())
        self.assertNotIn("Dispatch denied by", output.getvalue())

    def test_brief_and_human_output_show_the_containment_denial(self) -> None:
        import coach_prompt

        result = self.denied_but_route_authorized()
        for render in (coach_prompt.print_brief, coach_prompt.print_human):
            with self.subTest(render=render.__name__):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    render(result)
                text = output.getvalue()
                self.assertNotIn("dispatch authorized: True", text)
                self.assertNotIn("Dispatch authorized: True", text)
                self.assertIn("Model dispatch available: no", text)
                self.assertIn("Dispatch denied by: native containment", text)

    def test_native_denial_with_an_authorized_operative_route_is_a_schema_valid_hard_stop(self) -> None:
        result = self.denied_but_route_authorized()
        workerbees = result["workerbee_parallelism"]
        self.assertTrue(workerbees["hard_stop"])
        self.assertEqual(workerbees["hard_stop_reason"], "native_precommit_containment")
        self.assertEqual(workerbees["recommended_mode"], "blocked")
        self.assertIsNone(workerbees["recommended_model"])
        self.assertEqual(workerbees["spark_dispatch"]["status"], "hard-stop")
        self.assertIsNone(result["workerbee_planned_delegation"]["model"])
        self.assertTrue(any(text.startswith("Native operative dispatch remains contained") for text in result["warnings"]))
        self.assertNotIn("workerbee-dispatch-route=task-selected-v3", result["enabled_levers"])
        availability = result["execution_availability"]
        self.assertFalse(availability["dispatch_authorized"])
        self.assertTrue(any(stop.startswith("native containment") for stop in availability["stops"]), availability)
        self.assertTrue(result["operative_route"]["dispatch_authorized"], "operative_route authority is unchanged")
        self.assert_schema_valid(result)

    def denied_but_route_authorized(self) -> dict:
        from tests.test_prompt_coach import qualified_current_coach

        with native_dispatch_denied():
            result = qualified_current_coach(PARALLEL_DOCS_TASK)
        self.assertTrue(result["route"]["operative_route"]["dispatch_authorized"], "precondition: route selection succeeded")
        self.assertFalse(result["route"]["native_operative_dispatch"]["dispatch_authorized"], "precondition: contained")
        return result


    def test_a_fully_available_result_is_schema_valid(self) -> None:
        from tests.test_prompt_coach import qualified_current_coach

        result = qualified_current_coach(PARALLEL_DOCS_TASK)
        self.assertTrue(result["route"]["native_operative_dispatch"]["dispatch_authorized"])
        self.assertTrue(result["execution_availability"]["dispatch_authorized"], result["execution_availability"])
        self.assertFalse(result["workerbee_parallelism"]["hard_stop"])
        self.assert_schema_valid(result)

if __name__ == "__main__":
    unittest.main()
