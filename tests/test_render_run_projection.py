from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_run_projection import build_projection, render_markdown  # noqa: E402


def sample_plan() -> dict[str, object]:
    return json.loads((ROOT / "examples" / "sample-run-readiness-plan.json").read_text(encoding="utf-8"))


class RenderRunProjectionTests(unittest.TestCase):
    def test_run_sheet_projection_is_beads_derived_and_non_authoritative(self) -> None:
        projection = build_projection(sample_plan(), "run-sheet", Path("sample.json"))

        self.assertEqual(projection["result_type"], "cwo-run-projection")
        self.assertEqual(projection["projection_type"], "run-sheet")
        self.assertEqual(projection["authority"], "projection")
        self.assertEqual(projection["canonical_source"], "beads")
        self.assertEqual(projection["projection_source"], "run-readiness-plan")
        self.assertEqual(projection["beads_derivation"], "declared-by-validated-readiness-plan")
        self.assertEqual(projection["projection_contract"]["type"], "run-sheet")
        self.assertEqual(projection["epic_id"], "complex-work-orchestration-example")
        self.assertEqual(projection["rubric"]["version"], "rubric-v1")
        self.assertGreaterEqual(len(projection["workstreams"]), 2)

    def test_run_sheet_markdown_includes_workstreams_rubric_and_handoff(self) -> None:
        projection = build_projection(sample_plan(), "run-sheet", Path("sample.json"))
        rendered = render_markdown(projection)

        self.assertIn("# CWO Run Sheet Projection", rendered)
        self.assertIn("## Workstreams", rendered)
        self.assertIn("rubric schema", rendered)
        self.assertIn("Immutable per run: `True`", rendered)
        self.assertIn("## Handoff Evidence Requirements", rendered)

    def test_wrap_up_projection_includes_adjudication_and_provider_provenance(self) -> None:
        projection = build_projection(sample_plan(), "wrap-up-status", Path("sample.json"))
        rendered = render_markdown(projection)

        self.assertEqual(projection["projection_type"], "wrap-up-status")
        self.assertIn("CWO Wrap-Up/Status Projection", rendered)
        self.assertIn("run sheet and wrap-up/status views are useful as projections", rendered)
        self.assertIn("Gemini mutation claim", rendered)
        self.assertIn("gemini_architecture_critic", rendered)
        self.assertIn("## Adjudication Evidence Refs", rendered)
        self.assertIn("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", rendered)

    def test_next_version_projection_keeps_patrol_research_only(self) -> None:
        projection = build_projection(sample_plan(), "next-version", Path("sample.json"))
        rendered = render_markdown(projection)

        self.assertEqual(projection["projection_type"], "next-version")
        self.assertIn("recurring patrol execution", rendered)
        self.assertIn("needs-research", rendered)
        self.assertIn("Research only until accepted: `True`", rendered)
        self.assertIn("provider_neutral_execution", rendered)

    def test_cli_json_projection_validates_sample_plan(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_run_projection.py"),
                str(ROOT / "examples" / "sample-run-readiness-plan.json"),
                "--projection",
                "wrap-up-status",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["projection_type"], "wrap-up-status")
        self.assertEqual(payload["authority"], "projection")

    def test_cli_keeps_legacy_wrap_up_alias(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_run_projection.py"),
                str(ROOT / "examples" / "sample-run-readiness-plan.json"),
                "--projection",
                "wrap-up",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["projection_type"], "wrap-up-status")

    def test_cli_json_next_version_projection_validates_sample_plan(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "render_run_projection.py"),
                str(ROOT / "examples" / "sample-run-readiness-plan.json"),
                "--projection",
                "next-version",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["projection_type"], "next-version")
        self.assertEqual(payload["next_version_rail"][0]["reason_type"], "needs-research")
        self.assertIn("provider_neutral_execution", payload["patrol_stopping_rule"]["required_acceptance_evidence"])

    def test_cli_fails_closed_on_invalid_plan(self) -> None:
        plan = copy.deepcopy(sample_plan())
        plan["beads_scope"]["canonical_source"] = "flat-file"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid-plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "render_run_projection.py"),
                    str(path),
                    "--projection",
                    "run-sheet",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("beads_scope.canonical_source must be beads", result.stderr)

    def test_markdown_table_escapes_pipes_backticks_and_newlines(self) -> None:
        plan = sample_plan()
        plan["workstreams"][0]["name"] = "name | injected"
        plan["workstreams"][0]["exit_condition"] = "done\n| bad |"
        plan["workstreams"][0]["owner"] = "`owner`"
        projection = build_projection(plan, "run-sheet", Path("sample.json"))
        rendered = render_markdown(projection)

        self.assertIn("name \\| injected", rendered)
        self.assertIn("done<br>\\| bad \\|", rendered)
        self.assertIn("\\`owner\\`", rendered)


if __name__ == "__main__":
    unittest.main()
