from __future__ import annotations

import json
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from continue_sprint import (  # noqa: E402
    MODELING_NOTE,
    build_continuation_brief,
    load_markdown_items,
)
from cwo_core.beads_ready_set import (  # noqa: E402
    build_ready_set_evidence,
    canonical_json_sha256,
)
from tests.test_beads_ready_set import (  # noqa: E402
    ready_item,
    released_three_policy,
)
from tests.real_beads_fixture import (  # noqa: E402
    REAL_BEADS_FIXTURE_TIMEOUT_SECONDS,
    initialize_real_beads,
    run_fixture_subprocess,
)

BD_PATH = shutil.which("bd")
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
V2_READY_SET_FIELDS = {
    "ranked_ready_issues",
    "recommended_ready_set",
    "compatible_ready_sets",
    "excluded_ready_issues",
    "beads_readiness_snapshot",
    "beads_readiness_snapshot_sha256",
    "fanout_decision",
    "fanout_reasons",
    "candidate_capacity_evidence",
    "ready_set_authority",
    "dispatch_authorized",
}


class ContinueSprintTests(unittest.TestCase):
    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_v2_output_and_historical_v1_shape_validate(self) -> None:
        from jsonschema import Draft202012Validator, ValidationError

        result = build_continuation_brief(
            [
                {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
                {"id": "task", "title": "Do Work", "type": "task", "status": "open"},
            ],
            epic_id="epic",
        )
        schema = json.loads(
            (ROOT / "schemas" / "sprint-continuation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)

        validator.validate(result)
        historical = {
            key: value for key, value in result.items() if key not in V2_READY_SET_FIELDS
        }
        historical["version"] = 1
        validator.validate(historical)
        historical_with_explicit_safe_default = {
            **historical,
            "dispatch_authorized": False,
        }
        validator.validate(historical_with_explicit_safe_default)
        with self.assertRaises(ValidationError):
            validator.validate({**historical, "dispatch_authorized": True})

    def test_ranks_ready_issues_by_priority_then_unblocking_value(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "docs", "title": "Docs", "status": "open", "priority": 2, "labels": ["docs"]},
            {"id": "engine", "title": "Engine", "status": "open", "priority": 1, "labels": ["feature"]},
            {
                "id": "validate",
                "title": "Validate",
                "status": "open",
                "priority": 3,
                "labels": ["validation"],
                "dependencies": ["engine"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")

        self.assertEqual(result["recommended_next_issue"]["id"], "engine")
        self.assertIn("priority 1", result["why_next"])
        self.assertIn("unblocks 1 downstream", result["why_next"])
        self.assertEqual([item["id"] for item in result["ready_issues"]], ["engine", "docs"])

    def test_beads_dependency_objects_ignore_parent_child_and_extract_blockers(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "issue_type": "epic", "status": "open"},
            {
                "id": "architect",
                "title": "Frame",
                "issue_type": "task",
                "status": "open",
                "labels": ["architect"],
                "dependencies": [
                    {"issue_id": "architect", "depends_on_id": "epic", "type": "parent-child"},
                ],
                "parent": "epic",
            },
            {
                "id": "implementation",
                "title": "Implement",
                "issue_type": "task",
                "status": "open",
                "labels": ["workerbee"],
                "dependencies": [
                    {"issue_id": "implementation", "depends_on_id": "epic", "type": "parent-child"},
                    {"issue_id": "implementation", "depends_on_id": "architect", "type": "blocks"},
                ],
                "parent": "epic",
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(result["recommended_next_issue"]["id"], "architect")
        self.assertEqual(blockers["implementation"], ["depends on architect (open)"])

    def test_nonblocking_relationship_types_do_not_suppress_ready_work(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "issue_type": "epic", "status": "open"},
            {"id": "publication", "title": "Publication parent", "issue_type": "feature", "status": "open"},
            {
                "id": "implementation",
                "title": "Implement",
                "issue_type": "task",
                "status": "open",
                "priority": 1,
                "dependencies": [
                    {"depends_on_id": "publication", "type": "tracks"},
                    {"depends_on_id": "publication", "type": "validates"},
                    {"depends_on_id": "publication", "type": "related"},
                ],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")

        self.assertEqual(result["recommended_next_issue"]["id"], "implementation")
        self.assertEqual(result["recommended_next_issue"]["dependencies"], [])

    def test_epic_typed_items_are_not_recommended_as_next_work(self) -> None:
        items = [
            {"id": "requested-epic", "title": "Requested Epic", "type": "epic", "status": "open"},
            {"id": "fallback-epic", "title": "Fallback Epic", "type": "epic", "status": "open", "priority": 0},
            {"id": "task", "title": "Do Work", "type": "task", "status": "open", "priority": 2},
        ]

        result = build_continuation_brief(items, epic_id="requested-epic")

        self.assertEqual(result["recommended_next_issue"]["id"], "task")
        self.assertEqual([item["id"] for item in result["ready_issues"]], ["task"])

    def test_lane_dependency_blocks_on_any_open_item_in_that_lane(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "design-closed", "title": "Closed Design", "status": "closed", "metadata": {"lane": "design"}},
            {"id": "design-open", "title": "Open Design", "status": "open", "metadata": {"lane": "design"}},
            {
                "id": "implementation",
                "title": "Implement",
                "status": "open",
                "dependencies": ["design"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(blockers["implementation"], ["depends on design-open (open)"])

    def test_reports_blockers_and_guard_labels(self) -> None:
        items = [
            {"id": "epic", "title": "Continuation", "type": "epic", "status": "open"},
            {"id": "architect", "title": "Frame", "status": "open", "labels": ["architect"]},
            {
                "id": "implementation",
                "title": "Implement",
                "status": "open",
                "labels": ["workerbee"],
                "dependencies": ["architect"],
            },
            {
                "id": "contract",
                "title": "External lane",
                "status": "open",
                "labels": ["contractor-only", "no-codex-exec"],
            },
        ]

        result = build_continuation_brief(items, epic_id="epic")
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertIn("depends on architect (open)", blockers["implementation"])
        self.assertIn("guard label contractor-only prevents normal Codex pickup", blockers["contract"])
        self.assertIn("guard label no-codex-exec prevents normal Codex pickup", blockers["contract"])

    def test_markdown_fallback_is_reduced_durability_and_preserves_modeling_note(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### architect: Architect Frame

- Type: `task`
- Lane: `architect`
- Labels: `architect`, `framing`
- Depends on lanes: none

### implementation: Implement Example

- Type: `task`
- Lane: `implementation`
- Labels: `workerbee`, `implementation`
- Depends on lanes: `architect`
""",
                encoding="utf-8",
            )

            items = load_markdown_items(path, "epic")

        result = build_continuation_brief(items, epic_id="epic", source="markdown-workgraph")

        self.assertEqual(result["durability"], "reduced")
        self.assertEqual(result["source"], "markdown-workgraph")
        self.assertEqual(result["modeling_note"], MODELING_NOTE)
        self.assertIn(MODELING_NOTE, result["warnings"])
        self.assertEqual(result["recommended_next_issue"]["id"], "architect")
        self.assertEqual(result["blocked_issues"][0]["id"], "implementation")
        self.assertEqual(
            result["operator_handoff_packet"]["next_executable_bead"],
            "architect Architect Frame",
        )
        self.assertEqual(
            result["operator_handoff_packet"]["exact_command_resume"],
            "python3 scripts/cwo.py continue --epic epic --markdown-workgraph <path>",
        )
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["fanout_decision"], "single")
        self.assertEqual(result["recommended_ready_set"], [])
        self.assertIsNone(result["beads_readiness_snapshot_sha256"])
        self.assertFalse(result["dispatch_authorized"])

    def test_cli_json_uses_markdown_workgraph_without_bd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### pm: PM Coordinate

- Type: `task`
- Lane: `pm`
- Labels: `pm`, `coordination`
- Depends on lanes: none
""",
                encoding="utf-8",
            )
            env = {**os.environ, "PATH": temp_dir}
            output = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "continue_sprint.py"),
                    "--epic",
                    "epic",
                    "--markdown-workgraph",
                    str(path),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=env,
                text=True,
            )

        result = json.loads(output)
        self.assertEqual(result["continuation_result_type"], "complex-work-orchestration-sprint-continuation")
        self.assertEqual(result["recommended_next_issue"]["id"], "pm")
        self.assertEqual(result["durability"], "reduced")
        self.assertIn("operator_handoff_packet", result)
        self.assertEqual(
            result["operator_handoff_packet"]["exact_command_resume"],
            f"python3 scripts/cwo.py continue --epic epic --markdown-workgraph {path}",
        )

    def test_cwo_entrypoint_runs_continue_text_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "workgraph.md"
            path.write_text(
                """# Example

> Reduced durability fallback: Beads is unavailable or not in use.

## Work Items

### epic: Example

- Type: `epic`
- Lane: `epic`
- Labels: `orchestration`
- Depends on lanes: none

### validation: Validate Example

- Type: `task`
- Lane: `validation`
- Labels: `validation`
- Depends on lanes: none
""",
                encoding="utf-8",
            )
            output = subprocess.check_output(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "continue",
                    "--epic",
                    "epic",
                    "--markdown-workgraph",
                    str(path),
                ],
                cwd=ROOT,
                text=True,
            )

        self.assertIn("Sprint Continuation Brief", output)
        self.assertIn("validation Validate Example", output)
        self.assertIn("Operator Handoff Packet", output)
        self.assertIn(f"Exact command/resume: python3 scripts/cwo.py continue --epic epic --markdown-workgraph {path}", output)
        self.assertIn(MODELING_NOTE, output)

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    def test_cwo_continue_reads_real_bd_dependency_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_fixture_subprocess(["git", "init", "-q"], cwd=temp_dir, check=True)
            initialize_real_beads(
                [
                    BD_PATH,
                    "init",
                    "--non-interactive",
                    "--skip-agents",
                    "--skip-hooks",
                    "-p",
                    "cwo",
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            def bd_output(*args: str) -> str:
                return run_fixture_subprocess(
                    [BD_PATH, *args],
                    cwd=temp_dir,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()

            epic = bd_output(
                "create",
                "Sprint continuation smoke",
                "--type",
                "epic",
                "--priority",
                "1",
                "--labels",
                "orchestration",
                "--silent",
            )
            package = bd_output(
                "create",
                "Open package parent",
                "--type",
                "feature",
                "--parent",
                epic,
                "--priority",
                "1",
                "--labels",
                "publication-parent",
                "--silent",
            )
            architect = bd_output(
                "create",
                "Architect frame",
                "--type",
                "task",
                "--parent",
                package,
                "--priority",
                "1",
                "--labels",
                "architect",
                "--silent",
            )
            implementation = bd_output(
                "create",
                "Implement next",
                "--type",
                "task",
                "--parent",
                package,
                "--priority",
                "2",
                "--labels",
                "workerbee",
                "--deps",
                architect,
                "--silent",
            )
            env = {
                **os.environ,
                "BEADS_DIR": str(Path(temp_dir) / ".beads"),
                "CWO_BEADS_TIMEOUT_SECONDS": str(REAL_BEADS_FIXTURE_TIMEOUT_SECONDS),
            }
            output = run_fixture_subprocess(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "continue",
                    "--epic",
                    epic,
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=env,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout

        result = json.loads(output)
        blockers = {item["id"]: item["blockers"] for item in result["blocked_issues"]}

        self.assertEqual(result["source"], "beads")
        self.assertEqual(result["durability"], "durable")
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["recommended_next_issue"]["id"], architect)
        self.assertEqual(blockers[implementation], [f"depends on {architect} (open)"])
        self.assertIn(package, blockers)
        self.assertIn("grouping container", " ".join(blockers[package]))
        self.assertEqual(
            [item["id"] for item in result["ranked_ready_issues"]],
            [architect],
        )
        self.assertEqual(
            result["beads_readiness_snapshot"]["snapshot_type"],
            "cwo-beads-ready-set-snapshot:v2",
        )
        self.assertEqual(
            result["beads_readiness_snapshot_sha256"],
            result["beads_readiness_snapshot"]["snapshot_sha256"],
        )
        self.assertFalse(result["dispatch_authorized"])
        self.assertIn("operator_handoff_packet", result)

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    @unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is not installed")
    def test_real_beads_metadata_yields_released_n3_and_structured_exclusions(self) -> None:
        from jsonschema import Draft202012Validator

        with tempfile.TemporaryDirectory() as temp_dir:
            run_fixture_subprocess(["git", "init", "-q"], cwd=temp_dir, check=True)
            initialize_real_beads(
                [
                    BD_PATH,
                    "init",
                    "--non-interactive",
                    "--skip-agents",
                    "--skip-hooks",
                    "-p",
                    "cwo",
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            def bd_output(*args: str) -> str:
                return run_fixture_subprocess(
                    [BD_PATH, *args],
                    cwd=temp_dir,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()

            def create_leaf(
                title: str,
                parent: str,
                *,
                priority: int,
                labels: str = "implementation",
            ) -> str:
                return bd_output(
                    "create",
                    title,
                    "--type",
                    "task",
                    "--parent",
                    parent,
                    "--priority",
                    str(priority),
                    "--labels",
                    labels,
                    "--silent",
                )

            epic = bd_output(
                "create",
                "Ready-set metadata smoke",
                "--type",
                "epic",
                "--priority",
                "1",
                "--labels",
                "orchestration",
                "--silent",
            )
            package = bd_output(
                "create",
                "Open package parent",
                "--type",
                "feature",
                "--parent",
                epic,
                "--priority",
                "1",
                "--labels",
                "publication-parent",
                "--silent",
            )
            valid_ids = [
                create_leaf("Ready A", package, priority=1),
                create_leaf("Ready B", package, priority=2),
                create_leaf("Ready C", package, priority=3),
                create_leaf("Ready D", package, priority=4),
            ]
            for index, bead_id in enumerate(valid_ids):
                write_index = 0 if index == 1 else index
                metadata = ready_item(
                    bead_id,
                    write_paths=[f"scripts/e2e-{write_index}.py"],
                )["raw"]["metadata"]
                run_fixture_subprocess(
                    [BD_PATH, "update", bead_id, "--metadata", json.dumps(metadata)],
                    cwd=temp_dir,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )

            claimed = create_leaf("Claimed", package, priority=2)
            claimed_metadata = ready_item(
                claimed, write_paths=["scripts/claimed.py"]
            )["raw"]["metadata"]
            run_fixture_subprocess(
                [
                    BD_PATH,
                    "update",
                    claimed,
                    "--metadata",
                    json.dumps(claimed_metadata),
                    "--assignee",
                    "existing-owner",
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            restricted = create_leaf(
                "Restricted",
                package,
                priority=2,
                labels="implementation,no-codex-exec",
            )
            restricted_metadata = ready_item(
                restricted,
                write_paths=["scripts/restricted.py"],
                labels=["implementation", "no-codex-exec"],
            )["raw"]["metadata"]
            run_fixture_subprocess(
                [
                    BD_PATH,
                    "update",
                    restricted,
                    "--metadata",
                    json.dumps(restricted_metadata),
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            invalid = create_leaf("Invalid metadata", package, priority=2)
            run_fixture_subprocess(
                [
                    BD_PATH,
                    "update",
                    invalid,
                    "--metadata",
                    json.dumps({"cwo_ready_set_admission": {"version": 2}}),
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            env = {
                **os.environ,
                "BEADS_DIR": str(Path(temp_dir) / ".beads"),
                "CWO_BEADS_TIMEOUT_SECONDS": str(REAL_BEADS_FIXTURE_TIMEOUT_SECONDS),
            }
            output = run_fixture_subprocess(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "cwo.py"),
                    "continue",
                    "--epic",
                    epic,
                    "--requested-workers",
                    "3",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=env,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout
            assignees = {
                item["id"]: item.get("assignee")
                for item in json.loads(
                    bd_output("show", *valid_ids, claimed, "--json")
                )
            }

        result = json.loads(output)
        schema = json.loads(
            (ROOT / "schemas" / "sprint-continuation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(schema).validate(result)
        self.assertEqual(
            [item["id"] for item in result["recommended_ready_set"]],
            [valid_ids[0], valid_ids[2], valid_ids[3]],
            json.dumps(result["excluded_ready_issues"], indent=2),
        )
        compatible_sets = {
            tuple(item["issue_ids"]) for item in result["compatible_ready_sets"]
        }
        self.assertNotIn((valid_ids[0], valid_ids[1]), compatible_sets)
        self.assertIn((valid_ids[0], valid_ids[2], valid_ids[3]), compatible_sets)
        self.assertIn((valid_ids[1], valid_ids[2], valid_ids[3]), compatible_sets)
        self.assertEqual(
            result["candidate_capacity_evidence"]["released_max_active_workers"],
            3,
        )
        self.assertFalse(
            result["candidate_capacity_evidence"][
                "selected_exceeds_released_capacity"
            ]
        )
        self.assertTrue(
            result["candidate_capacity_evidence"][
                "selected_within_released_capacity"
            ]
        )
        self.assertFalse(result["dispatch_authorized"])
        self.assertEqual(assignees[valid_ids[0]], None)
        self.assertEqual(assignees[valid_ids[1]], None)
        self.assertEqual(assignees[valid_ids[2]], None)
        self.assertEqual(assignees[claimed], "existing-owner")

        excluded = {
            item["id"]: {reason["code"] for reason in item["reasons"]}
            for item in result["excluded_ready_issues"]
        }
        self.assertIn("grouping-container", excluded[package])
        self.assertIn("non-leaf", excluded[package])
        self.assertIn("already-claimed", excluded[claimed])
        self.assertIn("not-canonical-ready", excluded[claimed])
        self.assertIn("restricted-label", excluded[restricted])
        self.assertIn("invalid-admission-metadata", excluded[invalid])

    @unittest.skipUnless(BD_PATH, "bd CLI not available")
    def test_real_beads_issue_and_admission_drift_changes_snapshot_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            run_fixture_subprocess(["git", "init", "-q"], cwd=temp_dir, check=True)
            initialize_real_beads(
                [
                    BD_PATH,
                    "init",
                    "--non-interactive",
                    "--skip-agents",
                    "--skip-hooks",
                    "-p",
                    "cwo",
                ],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )

            def bd_output(*args: str) -> str:
                return run_fixture_subprocess(
                    [BD_PATH, *args],
                    cwd=temp_dir,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()

            def update(*args: str) -> None:
                run_fixture_subprocess(
                    [BD_PATH, "update", *args],
                    cwd=temp_dir,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )

            def continuation() -> dict:
                env = {
                    **os.environ,
                    "BEADS_DIR": str(Path(temp_dir) / ".beads"),
                    "CWO_BEADS_TIMEOUT_SECONDS": str(
                        REAL_BEADS_FIXTURE_TIMEOUT_SECONDS
                    ),
                }
                output = run_fixture_subprocess(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "cwo.py"),
                        "continue",
                        "--epic",
                        epic,
                        "--requested-workers",
                        "3",
                        "--format",
                        "json",
                    ],
                    cwd=ROOT,
                    env=env,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout
                return json.loads(output)

            def show(issue_id: str) -> dict:
                return json.loads(bd_output("show", issue_id, "--json"))[0]

            epic = bd_output(
                "create",
                "Drift test epic",
                "--type",
                "epic",
                "--priority",
                "1",
                "--labels",
                "orchestration",
                "--silent",
            )
            package = bd_output(
                "create",
                "Drift package",
                "--type",
                "feature",
                "--parent",
                epic,
                "--priority",
                "1",
                "--labels",
                "publication-parent",
                "--silent",
            )
            leaf = bd_output(
                "create",
                "Original title",
                "--description",
                "Original description",
                "--type",
                "task",
                "--parent",
                package,
                "--priority",
                "1",
                "--labels",
                "implementation",
                "--silent",
            )
            blocker = bd_output(
                "create",
                "Open blocker",
                "--type",
                "task",
                "--parent",
                package,
                "--priority",
                "4",
                "--silent",
            )
            admission_metadata = ready_item(
                leaf, write_paths=["scripts/real-drift.py"]
            )["raw"]["metadata"]
            update(leaf, "--metadata", json.dumps(admission_metadata))

            baseline = continuation()
            prior_sha256 = baseline["beads_readiness_snapshot_sha256"]
            self.assertEqual(
                [item["id"] for item in baseline["recommended_ready_set"]],
                [leaf],
            )

            same_second_pair: tuple[dict, dict] | None = None
            for attempt in range(8):
                before = show(leaf)
                update(
                    leaf,
                    "--title",
                    f"Same-second title drift {attempt}",
                    "--description",
                    f"Same-second description drift {attempt}",
                )
                after = show(leaf)
                if before["updated_at"] == after["updated_at"]:
                    same_second_pair = (before, after)
                    break
            self.assertIsNotNone(
                same_second_pair,
                "could not reproduce Beads' second-resolution update timestamp",
            )
            assert same_second_pair is not None
            before, after = same_second_pair
            self.assertNotEqual(before["title"], after["title"])
            self.assertNotEqual(before["description"], after["description"])
            before_seal = build_ready_set_evidence(
                [before],
                epic_id=epic,
                policy_document=released_three_policy(),
            )
            after_seal = build_ready_set_evidence(
                [after],
                epic_id=epic,
                policy_document=released_three_policy(),
            )
            self.assertNotEqual(
                before_seal["beads_readiness_snapshot_sha256"],
                after_seal["beads_readiness_snapshot_sha256"],
            )
            projection = after_seal["beads_readiness_snapshot"][
                "issue_projections"
            ][0]
            self.assertEqual(projection["title"], after["title"])
            self.assertEqual(projection["description"], after["description"])
            self.assertEqual(
                projection["exact_show_raw_sha256"],
                canonical_json_sha256(after),
            )

            issue_drift = continuation()
            self.assertNotEqual(
                prior_sha256, issue_drift["beads_readiness_snapshot_sha256"]
            )
            prior_sha256 = issue_drift["beads_readiness_snapshot_sha256"]

            run_fixture_subprocess(
                [BD_PATH, "dep", "add", leaf, blocker],
                cwd=temp_dir,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            dependency_drift = continuation()
            self.assertNotEqual(
                prior_sha256,
                dependency_drift["beads_readiness_snapshot_sha256"],
            )
            self.assertNotIn(
                leaf,
                [item["id"] for item in dependency_drift["recommended_ready_set"]],
            )
            prior_sha256 = dependency_drift["beads_readiness_snapshot_sha256"]

            update(leaf, "--add-label", "no-codex-exec")
            label_drift = continuation()
            self.assertNotEqual(
                prior_sha256, label_drift["beads_readiness_snapshot_sha256"]
            )
            label_exclusions = {
                item["id"]: {reason["code"] for reason in item["reasons"]}
                for item in label_drift["excluded_ready_issues"]
            }
            self.assertIn("restricted-label", label_exclusions[leaf])
            prior_sha256 = label_drift["beads_readiness_snapshot_sha256"]

            admission = admission_metadata["cwo_ready_set_admission"]
            admission["work_plan"]["primary_outcome"] = "drifted estimate"
            update(leaf, "--metadata", json.dumps(admission_metadata))
            estimate_drift = continuation()
            self.assertNotEqual(
                prior_sha256, estimate_drift["beads_readiness_snapshot_sha256"]
            )
            estimate_exclusions = {
                item["id"]: {reason["code"] for reason in item["reasons"]}
                for item in estimate_drift["excluded_ready_issues"]
            }
            self.assertIn("invalid-worker-commitment", estimate_exclusions[leaf])
            prior_sha256 = estimate_drift["beads_readiness_snapshot_sha256"]

            admission["architecture_authority"] = "different-architect"
            update(leaf, "--metadata", json.dumps(admission_metadata))
            ownership_drift = continuation()
            self.assertNotEqual(
                prior_sha256, ownership_drift["beads_readiness_snapshot_sha256"]
            )
            ownership_exclusions = {
                item["id"]: {reason["code"] for reason in item["reasons"]}
                for item in ownership_drift["excluded_ready_issues"]
            }
            self.assertIn(
                "unapproved-architecture-authority",
                ownership_exclusions[leaf],
            )
            prior_sha256 = ownership_drift["beads_readiness_snapshot_sha256"]

            admission["declared_read_paths"] = ["new/real/read/scope"]
            update(leaf, "--metadata", json.dumps(admission_metadata))
            scope_drift = continuation()
            self.assertNotEqual(
                prior_sha256, scope_drift["beads_readiness_snapshot_sha256"]
            )


if __name__ == "__main__":
    unittest.main()
