from __future__ import annotations

import copy
import json
import os
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
from check_installed_skill import load_projection  # noqa: E402
from validate_repository import (  # noqa: E402
    CI_REQUIRED_COMMANDS,
    validate_closure_pressure_contract,
    validate_ci_workflow,
    validate_local_inference_peer_review_guidance,
    validate_native_pool_capacity_invariants,
    validate_native_supervision_tech_preview_copy,
    validate_public_docs_do_not_expose_hardware_categories,
    validate_release_version,
    validate_repository,
    validate_retired_beads_context_aliases,
    validate_waiver_conventions,
)
from cwo_core import release_effect_routes
from cwo_core.waivers import require_waiver_reason  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture


class ValidateRepositoryTests(unittest.TestCase):
    WEEKLY_CODEX_WORKFLOW = (
        "name: Weekly stable Codex\non:\n  schedule:\n    - cron: '41 4 * * 2'\n"
        "permissions:\n  contents: read\njobs:\n  codex-protocol-contract:\n"
        "    runs-on: ubuntu-latest\n    timeout-minutes: 8\n    steps:\n"
        "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n"
        "        with:\n          persist-credentials: false\n"
        "      - run: npm install --global --ignore-scripts @openai/codex@latest\n"
        "      - name: Check schema\n        run: python scripts/check_codex_protocol_capabilities.py\n"
    )

    # Independent golden fixture: the positive test is not allowed to read the
    # page that the production validator checks.
    NATIVE_SUPERVISION_TECH_PREVIEW_COPY = """
<p>id="default-path"</p>
<p>href="#single-worker"</p>
<p>id="control-turn"</p>
<p>id="workspace-authority"</p>
<p>id="failure-recovery"</p>
<p>id="concurrency-preview"</p>
<p>no unsupervised opt-out</p>
<p>configured Luna model</p>
<p>Sol handles recorded coding escalation</p>
<p>Terra handles explicitly classified interface, visual and computer-use work</p>
<p>Do not silently substitute an available model</p>
<p>Save the control state and register monitoring before sending the assignment</p>
<p>enforced filesystem/network boundaries</p>
<p>finite time/usage allowance</p>
<p>which files actually changed</p>
<p>Confirm owned processes and resources are closed</p>
<p>two or three independent approved assignments</p>
<p>measures its callbacks on the same host</p>
<p>Registered contained pools</p>
<p>Beads updates, integration and publication in their normal order</p>
<p>A stopped attempt cannot be resumed; another attempt needs its own fresh allowance</p>
<p>https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision.md</p>
<p>https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision-pools.md</p>
    """

    def test_repository_control_plane_is_consistent(self) -> None:
        self.assertEqual(validate_repository(), [])

    def test_repository_rejects_versions_outside_major_one(self) -> None:
        version_path = ROOT / "VERSION"
        changelog_path = ROOT / "CHANGELOG.md"
        headings = (
            "## 2.0 - 2026-11-21",
            "## 2.0.0 - 2026-11-21",
            "## 0.9.0 - 2026-11-21",
            "## [v3.1.0-rc.1] - 2026-11-21",
            "## 0.8.0 - 2026-11-21",
            "## 0.8.0 - 2026-11-15",
        )
        read_text = Path.read_text

        def read_release_metadata(path: Path, *args: object, **kwargs: object) -> str:
            if path == version_path:
                return "2.0.0\n"
            contents = read_text(path, *args, **kwargs)
            if path == changelog_path:
                new_entries = (
                    "## Unreleased",
                    "- Preserve upgrades from 0.8.0.",
                    "## 1.2 - 2026-11-21",
                    "## 1.2.0 - 2026-11-21",
                    "## [v1.2.0-rc.1] - 2026-11-21",
                    *headings,
                )
                return contents.replace("## Unreleased", "\n\n".join(new_entries), 1)
            return contents

        with (
            mock.patch.object(Path, "read_text", read_release_metadata),
            mock.patch.object(validate_repository_module, "validate_release_effect_inventory"),
        ):
            errors = validate_repository()

        version_errors = [error for error in errors if error.startswith("VERSION ")]
        heading_errors = [error for error in errors if error.startswith("CHANGELOG.md:")]
        with self.subTest(source="VERSION"):
            self.assertEqual(len(version_errors), 1, errors)
            self.assertIn("2.0.0", version_errors[0])
        with self.subTest(source="CHANGELOG.md"):
            self.assertEqual(len(heading_errors), len(headings), errors)
        for heading in headings:
            with self.subTest(heading=heading):
                self.assertTrue(any(heading in error for error in heading_errors), errors)

    def test_release_version_file_accepts_major_one(self) -> None:
        cases = (("1.2.0", True), ("1.20.3-rc.1+build.2", True), ("0.8.0", False), ("1.2", False))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copyfile(ROOT / "CHANGELOG.md", root / "CHANGELOG.md")
            for version, accepted in cases:
                with self.subTest(version=version):
                    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
                    errors: list[str] = []
                    validate_release_version(errors, root)
                    if accepted:
                        self.assertEqual(errors, [])
                    else:
                        self.assertEqual(len(errors), 1, errors)
                        self.assertIn(f"VERSION must contain a 1.x version, found {version!r}", errors)

    def test_real_validator_rejects_stale_release_inventory_source(self) -> None:
        """Real copied validator refuses drift; healthy and restored copies pass."""
        projection = load_projection(ROOT)
        source_entries = {
            entry["path"].split("/", 1)[0]
            for section in ("entries", "excluded")
            for entry in projection[section]
        }
        ignore_local = shutil.ignore_patterns(
            ".git", "__pycache__", ".ruff_cache", ".beads", ".orchestration-audit",
        )

        def ignore(directory: str, names: list[str]) -> set[str]:
            ignored = set(ignore_local(directory, names))
            if Path(directory) == ROOT:
                # Other tests can create and retire temporary roots during the copy.
                ignored.update(set(names) - source_entries)
            return ignored

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            shutil.copytree(ROOT, root, ignore=ignore)
            # A validator fault must reach the behavioural assertion below.
            # Rebind only its copied bytes, preserving every other source and
            # primitive disposition, so stale self-metadata cannot kill it first.
            inventory_path = root / release_effect_routes.INVENTORY
            inventory = json.loads(inventory_path.read_bytes())
            validator = "scripts/validate_repository.py"
            _data, identity = release_effect_routes.read_file(root, validator)
            inventory["source_bindings"][validator] = identity
            inventory_path.write_bytes(release_effect_routes.inventory_bytes(inventory))
            environment = {
                key: value for key, value in os.environ.items()
                if not key.startswith("PYTHON")
            }

            def run_validator() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-B", "scripts/validate_repository.py"],
                    cwd=root, env=environment, capture_output=True, text=True,
                    timeout=900, check=False,
                )

            healthy = run_validator()
            self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)
            self.assertIn("Repository validation passed.", healthy.stdout)
            source = root / "scripts/cwo_core/util.py"
            original = source.read_bytes()
            source.write_bytes(original + b"\n# Disposable release inventory drift probe.\n")
            stale = run_validator()
            self.assertEqual(
                stale.returncode, 1,
                "actual validator accepted stale release source: " + stale.stdout + stale.stderr,
            )
            self.assertIn("release effect inventory refused: stale route source binding", stale.stderr)
            self.assertNotIn("Repository validation passed.", stale.stdout)
            source.write_bytes(original)
            restored = run_validator()
            self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
            self.assertIn("Repository validation passed.", restored.stdout)

    def test_native_pool_capacity_source_contract_refusals(self) -> None:
        variants = (
            ('test_native_pool_capacity_validator_rejects_divergent_literal',
             'MAX_ACTIVE_WORKERS = 99\n',
             'active native-pool source uses deprecated MAX_ACTIVE_WORKERS: scripts/cwo_core/native_pool.py'),
            ('test_native_pool_capacity_validator_rejects_duplicate_schedulability_math',
             'demand = lifecycle_max + workers * check_max + overhead\n',
             'active native-pool source duplicates schedulability arithmetic: scripts/cwo_core/native_pool.py'),
        )
        for original, source_text, diagnostic in variants:
            with self.subTest(original=original):
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
                    source.write_text(source_text, encoding="utf-8")
                    errors: list[str] = []
                    validate_native_pool_capacity_invariants(errors, repo_root=root)
                self.assertIn(
                    diagnostic,
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
            "pool-hard-cap-unschedulable:demand=1175:slack=-175",
            errors,
        )

    def test_native_supervision_tech_preview_copy_is_complete(self) -> None:
        errors: list[str] = []
        validate_native_supervision_tech_preview_copy(
            errors,
            content=self.NATIVE_SUPERVISION_TECH_PREVIEW_COPY,
        )
        self.assertEqual(errors, [])

    def test_native_supervision_copy_rejects_permission_to_resume_stopped_attempt(self) -> None:
        errors: list[str] = []
        content = self.NATIVE_SUPERVISION_TECH_PREVIEW_COPY.replace(
            'A stopped attempt cannot be resumed', 'A stopped attempt may be resumed'
        )
        validate_native_supervision_tech_preview_copy(errors, content=content)
        self.assertTrue(any('terminal attempts' in error for error in errors), errors)

    def test_native_supervision_tech_preview_copy_rejects_contract_gaps(self) -> None:
        cases = {
            'default section anchor': ('id="default-path"', 'REMOVED_CONTRACT'),
            'single-worker navigation': ('href="#single-worker"', 'REMOVED_CONTRACT'),
            'control-turn section anchor': ('id="control-turn"', 'REMOVED_CONTRACT'),
            'workspace section anchor': ('id="workspace-authority"', 'REMOVED_CONTRACT'),
            'failure section anchor': ('id="failure-recovery"', 'REMOVED_CONTRACT'),
            'concurrency section anchor': ('id="concurrency-preview"', 'REMOVED_CONTRACT'),
            'mandatory supervision': ('no unsupervised opt-out', 'REMOVED_CONTRACT'),
            'configured Luna role': ('configured Luna model', 'REMOVED_CONTRACT'),
            'Sol escalation role': ('Sol handles recorded coding escalation', 'REMOVED_CONTRACT'),
            'Terra assignment': ('Terra handles explicitly classified interface, visual and computer-use work', 'REMOVED_CONTRACT'),
            'no model substitution': ('Do not silently substitute an available model', 'REMOVED_CONTRACT'),
            'persistence before triggering': ('Save the control state and register monitoring before sending the assignment', 'REMOVED_CONTRACT'),
            'enforced effect boundary': ('enforced filesystem/network boundaries', 'REMOVED_CONTRACT'),
            'finite operation reservation': ('finite time/usage allowance', 'REMOVED_CONTRACT'),
            'final attribution': ('which files actually changed', 'REMOVED_CONTRACT'),
            'owned cleanup': ('Confirm owned processes and resources are closed', 'REMOVED_CONTRACT'),
            'fixed cohort ceiling': ('two or three independent approved assignments', 'four independent approved assignments'),
            'same-host callback measurement': ('measures its callbacks on the same host', 'measures its callbacks on another host'),
            'registered contained route': ('Registered contained pools', 'Unrestricted pools'),
            'stateful operation ordering': ('Beads updates, integration and publication in their normal order', 'Concurrent Beads updates, integration and publication'),
            'terminal attempts': ('A stopped attempt cannot be resumed; another attempt needs its own fresh allowance', 'REMOVED_CONTRACT'),
            'single-worker operator link': ('https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision.md', 'REMOVED_CONTRACT'),
            'pool operator link': ('https://github.com/gprocunier/complex-work-orchestration/blob/main/references/native-supervision-pools.md', 'REMOVED_CONTRACT'),
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

    def test_ci_contract_requires_runner_sized_worker_validation(self) -> None:
        # Hosted runners have four cores; timing-bounded tests need one worker per core.
        self.assertTrue(
            any(command.startswith("python -m compileall -j 8 -x ") for command in CI_REQUIRED_COMMANDS)
        )
        self.assertIn(
            'python scripts/run_parallel_unittest.py --workers 4 --verbose '
            '--shard-index "${CWO_TEST_SHARD_INDEX:-0}" --shard-count "${CWO_TEST_SHARD_COUNT:-1}"',
            CI_REQUIRED_COMMANDS,
        )

    @staticmethod
    def _ci_fixture() -> str:
        unit_command = ('python scripts/run_parallel_unittest.py --workers 4 --verbose '
                        '--shard-index "${CWO_TEST_SHARD_INDEX:-0}" '
                        '--shard-count "${CWO_TEST_SHARD_COUNT:-1}"')
        codex_command = 'python scripts/check_codex_protocol_capabilities.py'
        commands = "".join(f"      - run: {command}\n" for command in CI_REQUIRED_COMMANDS
                           if command not in (unit_command, codex_command))
        return ("on:\n  pull_request:\npermissions:\n  contents: read\nconcurrency:\n  cancel-in-progress: true\n"
                "jobs:\n  test:\n    name: unit-tests (${{ matrix.shard }}/4)\n"
                "    runs-on: ubuntu-latest\n    timeout-minutes: 90\n"
                "    strategy:\n      fail-fast: false\n      matrix:\n        shard: [0, 1, 2, 3]\n"
                "    env:\n      CWO_TEST_SHARD_INDEX: ${{ matrix.shard }}\n"
                "      CWO_TEST_SHARD_COUNT: 4\n    steps:\n"
                "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n"
                "        with:\n          persist-credentials: false\n" + commands +
                "      - name: Unit tests\n        run: " + unit_command + "\n"
                "  codex-protocol-contract:\n    runs-on: ubuntu-latest\n    timeout-minutes: 8\n"
                "    strategy:\n      fail-fast: false\n      matrix:\n"
                "        codex-version: ['0.163.0', '0.171.0']\n"
                "    env:\n      CODEX_VERSION: ${{ matrix.codex-version }}\n    steps:\n"
                '      - run: npm install --global --ignore-scripts "@openai/codex@$CODEX_VERSION"\n'
                "      - name: Check schema\n        run: " + codex_command + "\n"
                "  test-result:\n    name: test\n    runs-on: ubuntu-latest\n"
                "    timeout-minutes: 5\n    needs: [test, codex-protocol-contract]\n    if: ${{ always() }}\n"
                "    env:\n      UNIT_TEST_RESULT: ${{ needs.test.result }}\n"
                "      CODEX_PROTOCOL_RESULT: ${{ needs.codex-protocol-contract.result }}\n    steps:\n"
                "      - name: Require all unit test shards and Codex protocol contracts\n"
                '        run: test "$UNIT_TEST_RESULT" = success && test "$CODEX_PROTOCOL_RESULT" = success\n'
                "  codeql:\n    timeout-minutes: 15\n  shellcheck:\n    timeout-minutes: 10\n")

    @staticmethod
    def _ci_errors(content: str, weekly: str | None = WEEKLY_CODEX_WORKFLOW) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".github/workflows/ci.yml"
            path.parent.mkdir(parents=True)
            path.write_text(content, encoding="utf-8")
            if weekly is not None:
                path.with_name("codex-protocol-latest.yml").write_text(weekly, encoding="utf-8")
            errors: list[str] = []
            with mock.patch.object(validate_repository_module, "REPO_ROOT", root):
                validate_ci_workflow(errors, path)
            return errors

    def test_ci_sharding_contract_rejects_missing_work_and_gate_context_changes(self) -> None:
        fixture = self._ci_fixture()
        self.assertEqual(self._ci_errors(fixture), [])
        changes = (
            ("shard: [0, 1, 2, 3]", "shard: [0, 1, 2]"),
            ("shard: [0, 1, 2, 3]", "shard: [0, 1, 2, 2]"),
            ("fail-fast: false", "fail-fast: true"),
            ("CWO_TEST_SHARD_COUNT: 4", "CWO_TEST_SHARD_COUNT: 3"),
            ("CWO_TEST_SHARD_INDEX: ${{ matrix.shard }}", "CWO_TEST_SHARD_INDEX: 0"),
            ("      - name: Unit tests\n", "      - name: Unit tests\n        if: false\n"),
            ("      - name: Unit tests\n", "      - name: Unit tests\n        env: {}\n"),
            ("      - name: Unit tests\n", "      - name: Unit tests\n        shell: bash\n"),
            ("      - name: Unit tests\n", "      - name: Unit tests\n        working-directory: tests\n"),
            ("    strategy:\n", "    if: false\n    strategy:\n"),
            ("    strategy:\n", "    continue-on-error: true\n    strategy:\n"),
            ('--shard-index "${CWO_TEST_SHARD_INDEX:-0}"', '--shard-index "${{ matrix.shard }}"'),
        )
        for old, new in changes:
            with self.subTest(change=new):
                self.assertIn(old, fixture)
                self.assertTrue(any("unit shard" in error for error in self._ci_errors(fixture.replace(old, new))))

    def test_ci_sharding_contract_requires_exact_checked_in_matrix(self) -> None:
        fixture = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        matrix = "      matrix:\n        shard: [0, 1, 2, 3]\n"
        self.assertEqual(fixture.count(matrix), 1)
        with self.subTest(matrix="unchanged"):
            self.assertEqual(self._ci_errors(fixture), [])
        additions = {
            "exclude": "        exclude:\n          - shard: 3\n",
            "include": "        include:\n          - shard: 4\n",
            "extra axis": "        python-version: ['3.12', '3.13']\n",
        }
        for label, addition in additions.items():
            with self.subTest(matrix=label):
                errors = self._ci_errors(fixture.replace(matrix, matrix + addition, 1))
                self.assertTrue(any("unit shard" in error for error in errors), errors)

    def test_ci_aggregate_requires_all_results_and_always_runs(self) -> None:
        fixture = self._ci_fixture()
        changes = (
            ("    name: test\n", "    name: summary\n"),
            ("    needs: [test, codex-protocol-contract]\n", "    needs: [test]\n"),
            ("    if: ${{ always() }}\n", ""),
            ("${{ needs.test.result }}", "success"),
            ("${{ needs.codex-protocol-contract.result }}", "success"),
            (' && test "$CODEX_PROTOCOL_RESULT" = success', ""),
            ("      - name: Require all unit test shards and Codex protocol contracts\n",
             "      - name: Require all unit test shards and Codex protocol contracts\n        if: false\n"),
            ("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    continue-on-error: true\n"),
        )
        for old, new in changes:
            with self.subTest(change=new):
                self.assertTrue(any("aggregate" in error for error in self._ci_errors(fixture.replace(old, new))))

    def test_checked_in_aggregate_shell_refuses_unsuccessful_results(self) -> None:
        content = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("  test-result:\n", content)
        aggregate = content.split("  test-result:\n", 1)[1].split("\n  debian-filesystem:", 1)[0]
        command = next(line.removeprefix("        run: ") for line in aggregate.splitlines()
                       if line.startswith("        run: "))
        for name in ("UNIT_TEST_RESULT", "CODEX_PROTOCOL_RESULT"):
            for result in ("success", "failure", "cancelled", "skipped", "", "unknown"):
                with self.subTest(name=name, result=result):
                    env = dict(os.environ, UNIT_TEST_RESULT="success", CODEX_PROTOCOL_RESULT="success")
                    env[name] = result
                    process = subprocess.run(["/bin/sh", "-c", command], env=env, check=False)
                    self.assertEqual(process.returncode, int(result != "success"))

    def test_pr_codex_contract_requires_both_release_witnesses_and_a_mandatory_check(self) -> None:
        fixture = self._ci_fixture()
        changes = (
            ("  pull_request:\n", "  push:\n"),
            ("['0.163.0', '0.171.0']", "['0.171.0']"),
            ("${{ matrix.codex-version }}", "0.171.0"),
            ("        run: python scripts/check_codex_protocol_capabilities.py", "        run: true"),
            ("      - name: Check schema\n", "      - name: Check schema\n        if: false\n"),
            ("  codex-protocol-contract:\n", "  codex-protocol-contract:\n    continue-on-error: true\n"),
        )
        for old, new in changes:
            with self.subTest(change=new):
                errors = self._ci_errors(fixture.replace(old, new))
                self.assertTrue(any(error.startswith("CI Codex protocol contract") for error in errors), errors)

    def test_weekly_codex_contract_requires_schedule_latest_and_mandatory_check(self) -> None:
        workflow = self.WEEKLY_CODEX_WORKFLOW
        changes = (
            ("  schedule:\n    - cron: '41 4 * * 2'", "  workflow_dispatch:"),
            ("41 4 * * 2", "41 4 * * *"),
            ("41 4 * * 2", "41 4 2 * 2"),
            ("contents: read", "contents: write"),
            ("@openai/codex@latest", "@openai/codex@0.171.0"),
            ("        run: python scripts/check_codex_protocol_capabilities.py", "        run: true"),
            ("      - name: Check schema\n", "      - name: Check schema\n        if: false\n"),
            ("  codex-protocol-contract:\n", "  codex-protocol-contract:\n    continue-on-error: true\n"),
        )
        for old, new in changes:
            with self.subTest(change=new):
                errors = self._ci_errors(self._ci_fixture(), workflow.replace(old, new))
                self.assertTrue(any(error.startswith("Weekly Codex protocol contract") for error in errors), errors)
        self.assertIn("Weekly Codex protocol contract workflow is missing", self._ci_errors(self._ci_fixture(), None))

    def test_pages_deploy_waits_for_the_artifact_upload_job(self) -> None:
        workflow = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
        build = validate_repository_module._ci_job_block(workflow, "build")
        deploy = validate_repository_module._ci_job_block(workflow, "deploy")
        upload_action = "uses: actions/upload-pages-artifact@"
        deploy_action = "uses: actions/deploy-pages@"

        self.assertIn(upload_action, build)
        self.assertIn(deploy_action, deploy)
        self.assertIn("    needs: build", deploy.splitlines())
        self.assertNotRegex(deploy, r"(?m)^    if:")
        self.assertEqual(workflow.count(upload_action), 1)
        self.assertEqual(workflow.count(deploy_action), 1)

    def test_workflow_controls_accept_independent_positive_fixture(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            fixture = root / "ci.yml"
            fixture.write_text(self._ci_fixture(), encoding="utf-8")
            original = validate_repository_module.REPO_ROOT
            validate_repository_module.REPO_ROOT = root
            try:
                (workflow_dir / "ci.yml").write_text("uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n" + fixture.read_text(), encoding="utf-8")
                (workflow_dir / "codex-protocol-latest.yml").write_text(self.WEEKLY_CODEX_WORKFLOW, encoding="utf-8")
                validate_ci_workflow(errors, fixture)
            finally:
                validate_repository_module.REPO_ROOT = original
        self.assertEqual(errors, [])

    def test_workflow_controls_reject_mutable_or_commentless_pins(self) -> None:
        errors: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            fixture = root / "ci.yml"
            fixture.write_text(self._ci_fixture(), encoding="utf-8")
            original = validate_repository_module.REPO_ROOT
            validate_repository_module.REPO_ROOT = root
            try:
                (workflow_dir / "ci.yml").write_text("uses: actions/checkout@v6\n" + fixture.read_text(), encoding="utf-8")
                validate_ci_workflow(errors, fixture)
            finally:
                validate_repository_module.REPO_ROOT = original
        self.assertTrue(any("invalid" in error for error in errors))

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
            configure_git_fixture(repo)

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
