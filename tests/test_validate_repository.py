from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_repository as validate_repository_module  # noqa: E402
from validate_repository import (  # noqa: E402
    CI_REQUIRED_COMMANDS,
    validate_closure_pressure_contract,
    validate_ci_workflow,
    validate_local_inference_peer_review_guidance,
    validate_native_pool_capacity_invariants,
    validate_native_supervision_tech_preview_copy,
    validate_public_docs_do_not_expose_hardware_categories,
    validate_repository,
    validate_retired_beads_context_aliases,
    validate_waiver_conventions,
)
from cwo_core.waivers import require_waiver_reason  # noqa: E402


class ValidateRepositoryTests(unittest.TestCase):
    # Independent golden fixture: the positive test is not allowed to read the
    # page that the production validator checks.
    NATIVE_SUPERVISION_TECH_PREVIEW_COPY = """
      <nav>
        <a href="#default-path">Default</a>
        <a href="#concurrency-preview">Concurrency</a>
      </nav>
      <section id="default-path">
        <p>Native supervision is the normal connected-Codex control when CWO delegates reading, editing, or validation.</p>
        <p><code>gpt-5.3-codex-spark</code>. Candidate E owns architecture.</p>
        <p>A worker statement cannot widen the task.</p>
      </section>
      <section id="control-turn">
        <p>The host persists supervision state and registers the observer before it sends the task.</p>
        <p>All actions share one control-turn identity.</p>
      </section>
      <section id="workspace-authority"><p>The packet's declared working directory is authoritative.</p></section>
      <section id="failure-recovery"><p>Control loss, unsafe tool use, or unattributed mutation stops the attempt.</p></section>
      <section id="concurrency-preview">
        <p>Concurrency is experimental and disabled by default.</p>
        <table><tr><th scope="row">Two workers</th><td>Opt-in Tech Preview</td></tr>
        <tr><th scope="row">Three workers</th><td>Opt-in Tech Preview</td></tr>
        <tr><th scope="row">Four or more</th><td>Blocked</td></tr></table>
        <p>Fresh same-host capability and a safe fixed cohort use isolated mutable worktrees or shared read-only topology.</p>
        <p>Precommit, packet construction, critics, integration, retry, replay, and publication remain single-flight.</p>
      </section>
      <p>Ordinary supervised workers require exact server-side tool allowlisting.</p>
      <p><code>n1-read-only</code>, <code>n2-read-only</code>, and <code>n1-mutable</code></p>
      <a href="https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision.md">Single worker</a>
      <a href="https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision-pools.md">Pools</a>
    """

    def test_repository_control_plane_is_consistent(self) -> None:
        self.assertEqual(validate_repository(), [])

    def test_native_pool_capacity_validator_rejects_divergent_literal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "policy").mkdir()
            shutil.copy2(
                ROOT / "policy/native-worker-execution.yaml",
                root / "policy/native-worker-execution.yaml",
            )
            shutil.copytree(ROOT / "schemas", root / "schemas")
            source = root / "scripts/cwo_core/native_pool.py"
            source.parent.mkdir(parents=True)
            source.write_text("MAX_ACTIVE_WORKERS = 99\n", encoding="utf-8")
            errors: list[str] = []
            validate_native_pool_capacity_invariants(errors, repo_root=root)
        self.assertIn(
            "active native-pool source uses deprecated MAX_ACTIVE_WORKERS: "
            "scripts/cwo_core/native_pool.py",
            errors,
        )

    def test_native_pool_capacity_validator_rejects_duplicate_schedulability_math(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "policy").mkdir()
            shutil.copy2(
                ROOT / "policy/native-worker-execution.yaml",
                root / "policy/native-worker-execution.yaml",
            )
            shutil.copytree(ROOT / "schemas", root / "schemas")
            source = root / "scripts/cwo_core/native_pool.py"
            source.parent.mkdir(parents=True)
            source.write_text(
                "demand = lifecycle_max + workers * check_max + overhead\n",
                encoding="utf-8",
            )
            errors: list[str] = []
            validate_native_pool_capacity_invariants(errors, repo_root=root)
        self.assertIn(
            "active native-pool source duplicates schedulability arithmetic: "
            "scripts/cwo_core/native_pool.py",
            errors,
        )

    def test_native_pool_capacity_validator_rejects_unschedulable_hard_cap(
        self,
    ) -> None:
        policy = json.loads(
            (ROOT / "policy/native-worker-execution.yaml").read_text(
                encoding="utf-8"
            )
        )
        policy["native_supervision_pool"]["capacity"][
            "hard_max_active_workers"
        ] = 4
        errors: list[str] = []
        validate_native_pool_capacity_invariants(
            errors,
            repo_root=ROOT,
            policy_document=policy,
        )
        self.assertIn(
            "pool-hard-cap-unschedulable:demand=1150:slack=-150",
            errors,
        )

    def test_native_supervision_tech_preview_copy_is_complete(self) -> None:
        errors: list[str] = []
        validate_native_supervision_tech_preview_copy(
            errors,
            content=self.NATIVE_SUPERVISION_TECH_PREVIEW_COPY,
        )
        self.assertEqual(errors, [])

    def test_native_supervision_tech_preview_copy_rejects_contract_gaps(self) -> None:
        cases = {
            "default section anchor": ('id="default-path"', 'id="default"'),
            "default navigation link": ('href="#default-path"', 'href="#default"'),
            "control-turn section anchor": ('id="control-turn"', 'id="control"'),
            "workspace section anchor": ('id="workspace-authority"', 'id="workspace"'),
            "failure section anchor": ('id="failure-recovery"', 'id="failures"'),
            "concurrency section anchor": ('id="concurrency-preview"', 'id="concurrency"'),
            "concurrency navigation link": ('href="#concurrency-preview"', 'href="#concurrency"'),
            "standard single-worker wording": (
                "normal connected-Codex control",
                "optional connected-Codex control",
            ),
            "exact native model wording": (
                "<code>gpt-5.3-codex-spark</code>",
                "<code>any-model</code>",
            ),
            "concurrency stability wording": (
                "Concurrency is experimental and disabled by default",
                "Concurrency is the default",
            ),
            "higher-capacity gate wording": (
                "Four or more</th><td>Blocked",
                "Four or more</th><td>Available",
            ),
            "exact tool boundary wording": (
                "exact server-side tool",
                "optional tool",
            ),
            "single-worker operator link": (
                "https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision.md",
                "./reference.html#single-worker",
            ),
            "pool operator link": (
                "https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision-pools.md",
                "./reference.html",
            ),
            "fixed activation profiles": (
                "<code>n1-read-only</code>",
                "<code>arbitrary-profile</code>",
            ),
        }
        for expected_label, (required, replacement) in cases.items():
            with self.subTest(contract=expected_label):
                errors: list[str] = []
                validate_native_supervision_tech_preview_copy(
                    errors,
                    content=self.NATIVE_SUPERVISION_TECH_PREVIEW_COPY.replace(required, replacement),
                )
                self.assertTrue(any(expected_label in error for error in errors), errors)

    def test_missing_ci_workflow_is_allowed_for_installed_skill_layout(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            validate_ci_workflow(errors, Path(tmpdir) / "missing.yml")
        self.assertEqual(errors, [])

    def test_present_ci_workflow_still_enforces_required_commands(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            ci_path = Path(tmpdir) / "ci.yml"
            ci_path.write_text(CI_REQUIRED_COMMANDS[0], encoding="utf-8")
            validate_ci_workflow(errors, ci_path)
        self.assertIn(f"CI workflow is missing required command: {CI_REQUIRED_COMMANDS[1]}", errors)
        self.assertIn(f"CI workflow is missing required command: {CI_REQUIRED_COMMANDS[2]}", errors)

    def test_local_inference_evaluator_peer_review_guidance_is_route_derived(self) -> None:
        errors: list[str] = []
        validate_local_inference_peer_review_guidance(
            errors,
            content=(
                "python3 scripts/evaluate_return.py --file local-return.md\n"
                "--executor openshift_ai_vllm_worker\n"
                "provider_trust_tier\n"
                "provenance_class\n"
                "Add `--peer-review-required` only when route_work.py or evaluator policy requires it.\n"
            ),
        )
        self.assertEqual(errors, [])

    def test_local_inference_rejects_unconditional_peer_review_flag(self) -> None:
        errors: list[str] = []
        validate_local_inference_peer_review_guidance(
            errors,
            content="python3 scripts/evaluate_return.py --file local-return.md --peer-review-required\n",
        )
        self.assertTrue(any("unconditional --peer-review-required" in error for error in errors))

    def test_public_docs_reject_hardware_specific_category_terms(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            public_doc = Path(tmpdir) / "page.html"
            public_doc.write_text("Use H200/CerIO Enterprise Candidates.", encoding="utf-8")
            validate_public_docs_do_not_expose_hardware_categories(errors, [public_doc])
        self.assertTrue(any("hardware-specific public category terms" in error for error in errors))

    def test_public_docs_allow_generic_enterprise_targets(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            public_doc = Path(tmpdir) / "page.html"
            public_doc.write_text("Use Enterprise evaluation targets after a benchmark gate.", encoding="utf-8")
            validate_public_docs_do_not_expose_hardware_categories(errors, [public_doc])
        self.assertEqual(errors, [])

    def test_retired_beads_context_alias_is_rejected(self) -> None:
        errors: list[str] = []
        retired_field = "beads_" + "briefing_depth"
        retired_flag = "--beads-" + "briefing-depth"
        with tempfile.TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "scripts" / "tool.py"
            script.parent.mkdir()
            script.write_text(f"print({retired_field!r})\n", encoding="utf-8")
            doc = Path(tmpdir) / "README.md"
            doc.write_text(retired_flag + "\n", encoding="utf-8")
            validate_retired_beads_context_aliases(errors, repo_root=Path(tmpdir))
        self.assertTrue(any(retired_field in error for error in errors))
        self.assertTrue(any(retired_flag.lstrip("-") in error for error in errors))

    def test_retired_beads_context_alias_is_ignored_in_gitignored_artifacts(self) -> None:
        errors: list[str] = []
        retired_field = "beads_" + "briefing_depth"
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            if subprocess.call(["git", "-C", str(repo), "init", "-q"]) != 0:
                self.skipTest("git unavailable for validate_retired_beads_context_aliases gitignore path")

            (repo / ".gitignore").write_text("work-packets/\n", encoding="utf-8")
            ignored = repo / "work-packets"
            ignored.mkdir()
            (ignored / "artifact.py").write_text(f"print('{retired_field}')\n", encoding="utf-8")

            tracked = repo / "tracked.py"
            tracked.write_text(f"print('{retired_field}')\n", encoding="utf-8")

            validate_retired_beads_context_aliases(errors, repo_root=repo)

        self.assertTrue(any("tracked.py" in error for error in errors))
        self.assertFalse(any("work-packets/artifact.py" in error for error in errors))

    def test_waiver_convention_rejects_missing_reason_and_audit_fields(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "scripts" / "tool.py"
            script.parent.mkdir()
            script.write_text(
                "import argparse\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--no-audit', action='store_true')\n",
                encoding="utf-8",
            )
            validate_waiver_conventions(
                errors,
                scripts={"scripts/tool.py": {"flags": ["--no-audit"], "audit_fields": True}},
                repo_root=Path(tmpdir),
            )
        self.assertTrue(any("add_waiver_reason_argument" in error for error in errors))
        self.assertTrue(any("must require --waiver-reason for: audit" in error for error in errors))
        self.assertTrue(any("must add waiver audit fields for: audit" in error for error in errors))

    def test_waiver_reason_rejects_unknown_flag_destination(self) -> None:
        with self.assertRaises(SystemExit) as context:
            require_waiver_reason(type("Args", (), {"waiver_reason": "test"})(), ["audit"])

        self.assertIn("waiver-controlled flag destination 'audit' is not defined", str(context.exception))

    def test_waiver_convention_rejects_uncovered_bypass_shaped_flag(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "scripts" / "tool.py"
            script.parent.mkdir()
            script.write_text(
                "import argparse\n"
                "from cwo_core.waivers import add_waiver_reason_argument\n"
                "parser = argparse.ArgumentParser()\n"
                "add_waiver_reason_argument(parser)\n"
                "parser.add_argument('--allow-danger', action='store_true')\n",
                encoding="utf-8",
            )
            validate_waiver_conventions(
                errors,
                scripts={"scripts/tool.py": {"flags": []}},
                repo_root=Path(tmpdir),
            )

        self.assertTrue(any("not covered by WAIVER_CONVENTION_SCRIPTS: --allow-danger" in error for error in errors))

    def test_closure_pressure_contract_passes(self) -> None:
        errors: list[str] = []
        validate_closure_pressure_contract(errors)
        self.assertEqual(errors, [])

    def test_validate_repository_reports_evaluator_regression(self) -> None:
        original_evaluator = (
            validate_repository_module.epic_convergence.evaluate_closure_pressure
        )

        def broken_evaluator(active: bool, action: str, disposition: str | None) -> dict[str, object]:
            if active and disposition is None:
                return {
                    "active": True,
                    "action": action,
                    "disposition": None,
                    "allowed": True,
                    "reason": "legacy-allow",
                    "allowed_dispositions": ["retain", "correct", "quarantine", "defer", "close"],
                }
            return original_evaluator(active, action, disposition)

        with mock.patch.object(
            validate_repository_module.epic_convergence,
            "evaluate_closure_pressure",
            side_effect=broken_evaluator,
        ):
            errors: list[str] = []
            validate_closure_pressure_contract(errors)

        self.assertTrue(
            any("closure-pressure contract regression (evaluator)" in error for error in errors)
        )
        self.assertTrue(
            any("decision mismatch for active=True: {" in error for error in errors)
        )

    def test_validate_repository_reports_graph_contract_regression(self) -> None:
        original_planned_graph = validate_repository_module.scaffold_workgraph.planned_graph

        def broken_planned_graph(*args: object, **kwargs: object) -> list[dict[str, object]]:
            graph = copy.deepcopy(original_planned_graph(*args, **kwargs))
            for item in graph:
                metadata = item.setdefault("metadata", {})
                metadata.pop("closure_pressure_active", None)
                metadata.pop("routine_repair_child_forbidden", None)
                closure_pressure = metadata.get("closure_pressure", {})
                if isinstance(closure_pressure, dict):
                    closure_pressure["disposition"] = "wrong"
            return graph

        with mock.patch.object(
            validate_repository_module.scaffold_workgraph, "planned_graph", side_effect=broken_planned_graph
        ):
            errors: list[str] = []
            validate_closure_pressure_contract(errors)

        self.assertTrue(
            any("closure-pressure contract regression (graph)" in error for error in errors)
        )
        self.assertTrue(any("closure_pressure.disposition='wrong'" in error for error in errors))

    def test_validate_repository_reports_unexpected_routine_child_allowance(self) -> None:
        original_planned_graph = validate_repository_module.scaffold_workgraph.planned_graph

        def allow_routine_child(*args: object, **kwargs: object) -> list[dict[str, object]]:
            route = args[1] if len(args) > 1 else kwargs.get("route", {})
            closure = route.get("closure_pressure", {}) if isinstance(route, dict) else {}
            if isinstance(closure, dict) and closure.get("action") == "create-routine-repair-child":
                return []
            return original_planned_graph(*args, **kwargs)

        with mock.patch.object(
            validate_repository_module.scaffold_workgraph,
            "planned_graph",
            side_effect=allow_routine_child,
        ):
            errors: list[str] = []
            validate_closure_pressure_contract(errors)

        self.assertTrue(any("was unexpectedly allowed" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
