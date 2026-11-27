from __future__ import annotations

import copy
from contextlib import redirect_stderr
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_activation_preview import (  # noqa: E402
    MUTABLE_PATCH_INPUT,
    NativeActivationPreviewError,
    acquire_activation_claim,
    activation_dry_run,
    approve_activation_plan,
    canonical_activation_sha256,
    fixed_activation_tool_trace,
    generate_activation_key,
    load_activation_plan,
    prepare_activation_plan,
    read_activation_key,
    validate_activation_plan,
)
from cwo_core.native_activation_ledger import (  # noqa: E402
    NativeActivationLedgerStore,
)
from cwo_core.native_pool_leases import capture_owner_identity  # noqa: E402
from cwo_core.native_tool_activation import (  # noqa: E402
    verify_tool_enforcement_activation,
)
from run_native_pool_activation_preview import parser  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture


BD_PATH = shutil.which("bd")
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None
RISK = "unlisted-built-ins-may-act-before-detection"


def initialize_source(root: Path) -> Path:
    source = root / "source"
    source.mkdir(mode=0o700)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    configure_git_fixture(source)
    subprocess.run(
        ["git", "config", "user.name", "Activation Preview Test"],
        cwd=source,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "config",
            "user.email",
            "activation-preview@example.invalid",
        ],
        cwd=source,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "baseline"],
        cwd=source,
        check=True,
    )
    return source


def claim_worker(
    plan: dict,
    approval: dict,
    start: multiprocessing.Event,
    queue: multiprocessing.Queue,
) -> None:
    start.wait()
    try:
        claim = acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        queue.put(("accepted", claim["claim_sha256"]))
    except BaseException as exc:
        queue.put(("rejected", str(exc)))


class ActivationWorkspaceInspectionTests(unittest.TestCase):
    def test_source_identity_uses_real_clean_capture_and_refuses_dirty_or_incomplete(self) -> None:
        from cwo_core import native_activation_preview as preview
        from cwo_core import workspace

        with tempfile.TemporaryDirectory() as temporary:
            source = initialize_source(Path(temporary))
            tracked = source / "source.txt"
            tracked.write_text("trusted source\n", encoding="utf-8")
            subprocess.run(["git", "add", "source.txt"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-qm", "source input"], cwd=source, check=True)
            root, commit, tree = preview._source_identity(source)
            self.assertEqual(root, source)
            self.assertEqual(commit, preview._git(source, "rev-parse", "HEAD^{commit}"))
            self.assertEqual(tree, preview._git(source, "rev-parse", "HEAD^{tree}"))
            tracked.write_text("changed source\n", encoding="utf-8")
            with self.assertRaisesRegex(NativeActivationPreviewError, "activation-source-repository-dirty"):
                preview._source_identity(source)
            tracked.write_text("trusted source\n", encoding="utf-8")
            with patch.dict(workspace.STATE_CAPS, {"max_files": 0}):
                evidence = workspace.capture_tracked_workspace_state(source)
                self.assertTrue(evidence["incomplete"])
                with self.assertRaisesRegex(NativeActivationPreviewError, "activation-source-repository-dirty"):
                    preview._source_identity(source)

    def test_shared_monitor_uses_real_capture_for_clean_metadata_and_incomplete_controls(self) -> None:
        from cwo_core import native_pool_workspace as pool_workspace
        from tests.test_native_pool_workspace import WorkspaceFixture

        with tempfile.TemporaryDirectory() as temporary:
            fixture = WorkspaceFixture(Path(temporary))
            hook = fixture.integration / ".git" / "hooks" / "activation-control"
            hook.write_text("# inert hook 0\n", encoding="utf-8")
            contract, worktrees = fixture.contract(read_only=True)
            monitor = pool_workspace.PoolWorkspaceMonitor(contract,
                integration_root=fixture.integration, child_worktrees=worktrees)
            clean = monitor.compare(contract=contract, phase="unchanged")
            self.assertTrue(clean["integration_root_clean"])
            self.assertTrue(clean["child_worktrees_clean"])
            hook.write_text("# inert hook 1\n", encoding="utf-8")
            changed = monitor.compare(contract=contract, phase="same-size-hook")
            self.assertFalse(changed["integration_root_clean"])
            self.assertFalse(changed["child_worktrees_clean"])
            report = monitor.observations()[-1]["children"]["child-0"]
            self.assertIn(".git:common:hooks/activation-control",
                          {item["path"] for item in report["git_metadata_changes"]})
            hook.write_text("# inert hook 0\n", encoding="utf-8")
            original = pool_workspace.capture_workspace_baseline

            def capped(*args, **kwargs):
                return original(*args, **{**kwargs, "max_files": 0})

            with patch.object(pool_workspace, "capture_workspace_baseline", side_effect=capped):
                incomplete = monitor.compare(contract=contract, phase="capture-cap")
            self.assertFalse(incomplete["integration_root_clean"])
            self.assertFalse(incomplete["child_worktrees_clean"])
            self.assertTrue(monitor.observations()[-1]["children"]["child-0"]["incomplete"])


@unittest.skipUnless(BD_PATH, "bd CLI not available")
class NativeActivationPreviewTests(unittest.TestCase):
    def test_prepare_root_refuses_before_graph_and_private_graph_uses_only_fake_bd(self) -> None:
        from cwo_core import native_activation_preview as preview

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir(mode=0o700)
            with patch.object(preview, "_source_identity", return_value=(source, "a" * 40, "b" * 40)), \
                    patch.object(preview, "_create_git_layout", return_value={"integration": root / "integration"}), \
                    patch.object(preview, "_create_beads_graph", side_effect=NativeActivationPreviewError("EXAMPLE graph reached")) as graph, \
                    patch.object(preview.subprocess, "run", side_effect=AssertionError("real process")):
                for selected in (source, source / "nested"):
                    with self.subTest(control_root=selected):
                        failure = None
                        try:
                            prepare_activation_plan(selected, profile="n1-read-only", source_repository=source)
                        except NativeActivationPreviewError as exc:
                            failure = exc
                        graph.assert_not_called()
                        self.assertIn("activation-control-root-inside-source-forbidden", str(failure))
                graph.reset_mock()
                with self.assertRaisesRegex(NativeActivationPreviewError, "EXAMPLE graph reached"):
                    prepare_activation_plan(root / "control", profile="n1-read-only", source_repository=source)
                graph.assert_called_once()
                self.assertEqual(graph.call_args.kwargs["profile"], "n1-read-only")
                self.assertEqual(graph.call_args.args[0].parent, root / "control" / "runs")

            # Exercise actual _create_beads_graph -> _bd -> _run for all finite
            # profiles. Only the bd process and private Git are replaced.
            for profile in preview.PROFILE:
                with self.subTest(profile=profile):
                    run_root = root / profile
                    run_root.mkdir(mode=0o700)
                    private = run_root / "private-beads"
                    children = [f"EXAMPLE-{i}" for i in range(preview.PROFILE[profile]["workers"])]
                    creates = iter(["EXAMPLE-epic", *children])
                    history = []

                    def fake_bd(command, **kwargs):
                        self.assertEqual(command[0], "bd")
                        self.assertEqual(kwargs["cwd"], private)
                        self.assertEqual(kwargs["env"]["BEADS_DIR"], str(private / ".beads"))
                        self.assertEqual(kwargs["env"]["BEADS_ACTOR"], "native-activation-preview-controller")
                        self.assertEqual(kwargs["timeout"], 60)
                        self.assertFalse(kwargs["check"])
                        self.assertTrue(kwargs["capture_output"])
                        history.append(command)
                        action = command[1]
                        if action == "init":
                            (private / ".beads" / "embeddeddolt").mkdir(parents=True)
                            output = ""
                        elif action == "create":
                            if "--parent" in command:
                                self.assertEqual(command[command.index("--parent") + 1], "EXAMPLE-epic")
                            output = next(creates)
                        elif action == "ready":
                            self.assertEqual(command, ["bd", "ready", "--json", "--parent",
                                "EXAMPLE-epic", "--unassigned", "--limit", "0"])
                            output = json.dumps([{"id": child} for child in children])
                        elif action == "show":
                            self.assertEqual(command, ["bd", "show", "--json", "--", "EXAMPLE-epic", *children])
                            output = json.dumps([{"id": child} for child in ["EXAMPLE-epic", *children]])
                        else:
                            self.assertEqual(action, "update")
                            updated = sum(row[1] == "update" for row in history) - 1
                            self.assertEqual(command, ["bd", "update", "--metadata",
                                '{"cwo_ready_set_admission":{}}', "--json", "--", children[updated]])
                            output = "{}"
                        return subprocess.CompletedProcess(command, 0, output, "")

                    with patch.object(preview.shutil, "which", return_value="/EXAMPLE/bd"), \
                            patch.object(preview, "_private_git"), \
                            patch.object(preview, "_admission_metadata", return_value=({}, {})), \
                            patch.object(preview, "_normalize_issue", side_effect=lambda raw, **_kw: raw), \
                            patch.object(preview.subprocess, "run", side_effect=fake_bd):
                        result = preview._create_beads_graph(run_root, profile=profile,
                            integration=root / "integration", override={}, now=None)
                    self.assertEqual(result[:4], (private, private / ".beads" / "embeddeddolt", "EXAMPLE-epic", children))
                    self.assertEqual([command[1] for command in history],
                                     ["init", "create", *[action for _ in children for action in ("create", "update")], "ready", "show"])

    def fixture(
        self,
        *,
        profile: str = "n1-read-only",
    ) -> tuple[tempfile.TemporaryDirectory, Path, Path, Path, dict, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        root.chmod(0o700)
        source = initialize_source(root)
        control = root / "control"
        generate_activation_key(control)
        plan_path, plan = prepare_activation_plan(
            control,
            profile=profile,
            source_repository=source,
        )
        approval_path, approval = approve_activation_plan(
            plan_path,
            control_root=control,
            actor_id="operator-1",
            identity_source="trusted-control-session",
            ttl_seconds=600,
            risk_acknowledgement=RISK,
        )
        return (
            temporary,
            control,
            plan_path,
            approval_path,
            plan,
            approval,
        )

    def test_a_plan_must_use_the_private_beads_database_of_its_run(self) -> None:
        temporary, control, _plan_path, _approval_path, plan, _approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(validate_activation_plan(plan, check_live_source=False), [])
        project = Path(temporary.name) / "project"
        for directory, database in (
            (project, project / ".beads" / "embeddeddolt"),
            (
                Path(plan["paths"]["beads_directory"]),
                Path(temporary.name) / "other-database",
            ),
        ):
            with self.subTest(directory=directory, database=database):
                tampered = copy.deepcopy(plan)
                tampered["paths"]["beads_directory"] = str(directory)
                tampered["paths"]["beads_database"] = str(database)
                tampered.pop("plan_sha256")
                tampered["plan_sha256"] = canonical_activation_sha256(tampered)
                self.assertEqual(
                    validate_activation_plan(tampered, check_live_source=False),
                    ["activation-plan-beads-not-private"],
                )

    def test_prospective_task_uses_real_snapshot_and_refuses_dirty_or_incomplete(self) -> None:
        from cwo_core import native_activation_preview as preview
        from cwo_core import native_pool_workspace as pool_workspace

        temporary, _control, _plan_path, _approval_path, plan, _approval = self.fixture()
        self.addCleanup(temporary.cleanup)
        selected = plan["tasks"][0]
        root = Path(selected["worktree"])
        arguments = dict(profile=plan["profile"], ordinal=0, bead_id=selected["bead_id"],
            estimate=plan["work_estimates"][selected["bead_id"]], worktree=root, override=plan["override"])
        expected = pool_workspace.capture_workspace_snapshot(root, allowed_paths=[])
        task = preview._prospective_task(**arguments)
        self.assertEqual(task["worktree_identity_sha256"], canonical_activation_sha256(expected["identity"]))
        self.assertEqual(task["declared_write_paths"], [])
        dirt = root / "unexpected.txt"
        dirt.write_text("unapproved task input\n", encoding="utf-8")
        with self.assertRaisesRegex(pool_workspace.PoolWorkspaceError, "workspace-baseline-not-clean"):
            preview._prospective_task(**arguments)
        dirt.unlink()
        original = pool_workspace.capture_workspace_baseline

        def capped(*args, **kwargs):
            return original(*args, **{**kwargs, "max_files": 0})

        with patch.object(pool_workspace, "capture_workspace_baseline", side_effect=capped), \
                self.assertRaisesRegex(pool_workspace.PoolWorkspaceError, "workspace-baseline-incomplete"):
            preview._prospective_task(**arguments)

    def test_keygen_prepare_approve_and_dry_run_are_non_live(self) -> None:
        temporary, control, plan_path, approval_path, plan, _approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        key_path = control / "activation-preview.key"
        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key_path.stat().st_nlink, 1)
        self.assertEqual(plan_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(approval_path.stat().st_mode & 0o777, 0o600)

        result = activation_dry_run(
            plan_path,
            approval_path,
            control_root=control,
            actor_id="operator-1",
            identity_source="trusted-control-session",
        )
        self.assertEqual(result["status"], "dry-run-accepted")
        self.assertFalse(result["live"])
        self.assertFalse(result["consumed"])
        for forbidden in (
            Path(plan["paths"]["ledger"]),
            Path(plan["paths"]["leases"]),
            Path(plan["paths"]["result"]),
            Path(plan["paths"]["approval_replay"]),
        ):
            self.assertFalse(forbidden.exists(), forbidden)
        self.assertEqual(list(Path(plan["paths"]["claims"]).glob("*.json")), [])

        if HAS_JSONSCHEMA:
            from jsonschema import Draft202012Validator

            schema = json.loads(
                (
                    ROOT
                    / "schemas"
                    / "native-tool-activation-plan.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(plan)

    def test_all_profiles_compile_only_fixed_tasks(self) -> None:
        for profile, expected_roles in (
            ("n1-read-only", ["read-only-0"]),
            ("n2-read-only", ["read-only-0", "read-only-1"]),
            ("n1-mutable", ["mutable-0"]),
        ):
            with self.subTest(profile=profile):
                temporary, _control, _path, _approval_path, plan, _approval = (
                    self.fixture(profile=profile)
                )
                self.addCleanup(temporary.cleanup)
                self.assertEqual(
                    [task["role"] for task in plan["tasks"]],
                    expected_roles,
                )
                self.assertTrue(
                    all(
                        task["prompt"].startswith("Use ")
                        for task in plan["tasks"]
                    )
                )
                traces = [
                    fixed_activation_tool_trace(
                        profile,
                        int(task["ordinal"]),
                        worktree=task["worktree"],
                    )
                    for task in plan["tasks"]
                ]
                self.assertTrue(
                    all(len(trace) == 2 for trace in traces)
                )
                self.assertTrue(
                    all(
                        len(step["canonical_argument_hashes"])
                        in {1, 3}
                        for trace in traces
                        for step in trace
                    )
                )
                if profile == "n1-mutable":
                    self.assertEqual(
                        plan["tasks"][0]["integration_target_paths"],
                        ["targets/activation.txt"],
                    )
                    self.assertIn(
                        MUTABLE_PATCH_INPUT,
                        plan["tasks"][0]["prompt"],
                    )
                else:
                    self.assertTrue(
                        all(
                            not task["integration_target_paths"]
                            for task in plan["tasks"]
                        )
                    )
                    self.assertNotEqual(
                        plan["tasks"][0]["worktree"],
                        plan["paths"]["integration"],
                    )
                    self.assertEqual(
                        len(
                            {
                                task["worktree"]
                                for task in plan["tasks"]
                            }
                        ),
                        1,
                    )
                if profile == "n2-read-only":
                    self.assertEqual(
                        plan["proportionality_assessment"][
                            "selected_cohort"
                        ]["worker_count"],
                        2,
                    )
                    self.assertIn(
                        2,
                        {
                            item["worker_count"]
                            for item in plan["readiness_evidence"][
                                "compatible_ready_sets"
                            ]
                        },
                    )

    def test_cli_has_no_arbitrary_work_or_continuation_options(self) -> None:
        command = parser()
        help_text = command.format_help()
        self.assertEqual(
            set(command._subparsers._group_actions[0].choices),
            {"keygen", "prepare", "approve", "run"},
        )
        run_parser = command._subparsers._group_actions[0].choices["run"]
        all_options = {
            option
            for action in run_parser._actions
            for option in action.option_strings
        }
        for forbidden in (
            "--prompt",
            "--model",
            "--tool",
            "--task",
            "--mutation-path",
            "--retry",
            "--resume",
            "--refill",
            "--replacement",
        ):
            self.assertNotIn(forbidden, all_options)
            self.assertNotIn(forbidden, help_text)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            command.parse_args(
                [
                    "run",
                    "--control-root",
                    "/tmp/control",
                    "--prepared",
                    "/tmp/plan",
                    "--approval",
                    "/tmp/approval",
                    "--operator-id",
                    "operator",
                    "--identity-source",
                    "trusted",
                ]
            )

    def test_bad_approval_is_burned_before_verification(self) -> None:
        temporary, control, plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        bad = copy.deepcopy(approval)
        bad["signature"] = "0" * 64
        claim = acquire_activation_claim(
            plan,
            bad,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        self.assertEqual(claim["approval_sha256"], canonical_json_hash(bad))
        self.validate_schema("native-tool-activation-claim", claim)
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-claim-activation-reused",
        ):
            acquire_activation_claim(
                load_activation_plan(plan_path),
                approval,
                controller_identity=capture_owner_identity(os.getpid()),
            )

    def test_two_processes_racing_same_claim_have_one_winner(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        context = multiprocessing.get_context("fork")
        start = context.Event()
        queue = context.Queue()
        workers = [
            context.Process(
                target=claim_worker,
                args=(plan, approval, start, queue),
            )
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        start.set()
        results = [queue.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(timeout=20)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(
            sorted(result[0] for result in results),
            ["accepted", "rejected"],
        )

    def test_approval_replay_rejects_from_fresh_verifier(self) -> None:
        temporary, control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        key = read_activation_key(control)
        from cwo_core.native_activation_preview import operator_approval_verifier

        first = verify_tool_enforcement_activation(
            plan["activation_request"],
            approval_receipt=approval,
            operator_approval_verifier=operator_approval_verifier(
                plan,
                key=key,
                actor_id="operator-1",
                identity_source="trusted-control-session",
            ),
        )
        self.assertEqual(first.state, "available")
        with self.assertRaisesRegex(Exception, "operator-approval-replayed"):
            verify_tool_enforcement_activation(
                plan["activation_request"],
                approval_receipt=approval,
                operator_approval_verifier=operator_approval_verifier(
                    plan,
                    key=key,
                    actor_id="operator-1",
                    identity_source="trusted-control-session",
                ),
            )

    def validate_schema(self, name: str, artifact: dict) -> None:
        if not HAS_JSONSCHEMA:
            return
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (ROOT / "schemas" / f"{name}.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact)

    def test_primary_claim_reconstructs_missing_markers(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        claims = Path(plan["paths"]["claims"])
        for marker in claims.glob("marker-*.json"):
            marker.unlink()
        self.assertEqual(list(claims.glob("marker-*.json")), [])
        with self.assertRaisesRegex(
            NativeActivationPreviewError,
            "activation-claim-activation-reused",
        ):
            acquire_activation_claim(
                plan,
                approval,
                controller_identity=capture_owner_identity(os.getpid()),
            )
        self.assertEqual(len(list(claims.glob("marker-*.json"))), 2)

    def test_current_schemas_validate_emitted_artifacts(self) -> None:
        temporary, _control, _plan_path, _approval_path, plan, approval = (
            self.fixture()
        )
        self.addCleanup(temporary.cleanup)
        claim = acquire_activation_claim(
            plan,
            approval,
            controller_identity=capture_owner_identity(os.getpid()),
        )
        ledger = NativeActivationLedgerStore.create(
            Path(plan["paths"]["ledger"]),
            profile=plan["profile"],
            plan_sha256=plan["plan_sha256"],
            claim_sha256=claim["claim_sha256"],
            action_sha256=plan["activation_artifacts"][
                "action_sha256"
            ],
            campaign_nonce=plan["campaign_nonce"],
        ).load()
        for name, artifact in (
            ("native-tool-activation-plan", plan),
            ("native-tool-activation-claim", claim),
            ("native-tool-activation-ledger", ledger),
        ):
            with self.subTest(schema=name):
                self.validate_schema(name, artifact)


def canonical_json_hash(value: object) -> str:
    import hashlib

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
