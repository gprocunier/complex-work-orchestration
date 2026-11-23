"""Offline qualification preparation and original host ingress refusals."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from cwo_core import native_live_availability  # noqa: E402
from cwo_core.invocation_ledger import MAX_UNITS  # noqa: E402
from cwo_core.model_identities import resolve_model  # noqa: E402
from cwo_core.native_pool_qualification_fixtures import (  # noqa: E402
    POOL_QUALIFICATION_SEED,
    fixed_pool_qualification_cohorts,
)
from cwo_core.qualification_target import selected_target  # noqa: E402
from offline_n1_host import _metadata, _output_paths  # noqa: E402
import prepare_native_pool_qualification as preparation  # noqa: E402
from registered_native_pool_client import submit  # noqa: E402
from registered_native_pool_host import RegisteredNativePoolHost  # noqa: E402


ARGS = ("--runs-per-cohort", "2", "--max-sessions", "5", "--max-tool-calls", "10",
        "--max-runtime-seconds", "60")


class OfflinePoolQualificationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def cli(self, *args, umask=-1):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPTS / "prepare_native_pool_qualification.py"), *args],
            cwd=self.scratch, env={**os.environ, "PATH": str(self.scratch)},
            capture_output=True, text=True, timeout=15, check=False, umask=umask,
        )

    def plan(self):
        completed = self.cli(*ARGS)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_dry_preparation_prints_budgets_and_initial_short_record(self):
        before = datetime.now(timezone.utc).date().isoformat()
        plan = self.plan()
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertEqual(plan["mode"], "prepare-only")
        self.assertIs(plan["dispatch_authorized"], False)
        self.assertEqual(plan["model_calls"], 0)
        self.assertEqual((plan["worker_role"], plan["worker_model"]), ("luna", resolve_model("luna")))
        selection = selected_target()["selection"]
        self.assertEqual(plan["target_profile"], selection["profile"])
        self.assertEqual(plan["runs_per_cohort"], 2)
        limits = {"sessions": 5, "tool_calls": 10, "runtime_seconds": 60}
        self.assertEqual(plan["per_run_limits"], limits)
        self.assertEqual(plan["stage_ceiling"], {key: value * 4 for key, value in limits.items()})
        record = plan["qualification_record"]
        self.assertEqual(set(record), {"cwo_version", "minimum_codex_version", "date", "outcome", "limitations"})
        self.assertEqual(record["cwo_version"], (ROOT / "VERSION").read_text().strip())
        self.assertEqual(record["minimum_codex_version"], selection["minimum_version"])
        self.assertIn(record["date"], (before, datetime.now(timezone.utc).date().isoformat()))
        self.assertEqual(record["outcome"], "not-run")
        self.assertTrue(record["limitations"])

    def test_cli_refuses_absent_invalid_and_authority_inputs(self):
        cases = (
            (ARGS[:6], "--max-runtime-seconds"),
            ((ARGS[0], "0", *ARGS[2:]), "use an integer"),
            ((ARGS[0], "inf", *ARGS[2:]), "invalid"),
            ((ARGS[0], str(MAX_UNITS), *ARGS[2:]), "stage ceilings exceed"),
            ((*ARGS[:3], "2", *ARGS[4:]), "at least three sessions"),
            ((*ARGS, "--execute", "--adapter", "/untrusted"), "unrecognized arguments"),
            ((*ARGS, "--max-tokens", "5000"), "unrecognized arguments: --max-tokens"),
            ((*ARGS, "--max-cost-microunits", "100000"), "unrecognized arguments: --max-cost-microunits"),
        )
        for argv, diagnostic in cases:
            with self.subTest(argv=argv):
                completed = self.cli(*argv)
                self.assertEqual(completed.returncode, 2)
                self.assertIn(diagnostic, completed.stderr)
                self.assertEqual(completed.stdout, "")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def git(self, *args, cwd):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=" + os.devnull, *args], cwd=cwd,
            env={"PATH": os.environ.get("PATH", os.defpath), "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": os.devnull},
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout.strip()

    def test_fixture_git_disables_automatic_maintenance_for_each_seed_command(self):
        config = ["-c", "maintenance.auto=false", "-c", "gc.auto=0"]
        result = subprocess.CompletedProcess([], 0)
        for args in (("init", "--quiet"), ("add", "--", "README.txt"),
                     ("-c", "user.name=Fixture", "commit", "-m", "Seed")):
            with (self.subTest(args=args),
                  patch.object(preparation, "trusted_git_private", return_value=result) as git):
                preparation._fixture_git(self.scratch, *args)
                git.assert_called_once_with(self.scratch, [*config, *args])

    def test_seed_supports_independent_worker_and_integration_clones(self):
        root = self.scratch / "fixture"
        with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "invalid", "GIT_DIR": str(self.scratch / "bypass")}):
            completed = self.cli(*ARGS, "--fixture-root", root.name)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["mode"], "prepare-only")
        self.assertIs(plan["dispatch_authorized"], False)
        self.assertEqual(plan["model_calls"], 0)
        self.assertEqual(plan["seed_files"], POOL_QUALIFICATION_SEED)
        self.assertEqual(plan["cohorts"], fixed_pool_qualification_cohorts())
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual({item.name for item in root.iterdir()}, {"seed", "n2", "n3"})
        seed = root / "seed"
        self.assertEqual(self.git("remote", cwd=seed), "")
        seed_head = self.git("rev-parse", "HEAD", cwd=seed)
        self.assertEqual([cohort["size"] for cohort in plan["cohorts"]], [2, 3])
        metadata = _metadata(seed)
        for cohort in plan["cohorts"]:
            tasks = cohort["tasks"]
            self.assertEqual(len(tasks), cohort["size"])
            paths = [task["write_path"] for task in tasks]
            self.assertEqual(_output_paths(paths), sorted(paths))
            self.assertEqual(len({item["completion_marker"] for item in tasks}), cohort["size"])
            runs = root / f"n{cohort['size']}"
            self.assertEqual({item.name for item in runs.iterdir()}, {"run-1", "run-2"})
            for run in runs.iterdir():
                self.assertEqual({item.name for item in run.iterdir()},
                                 {"integration", *(task["worker_slot"] for task in tasks)})
                for clone in run.iterdir():
                    self.assertEqual(self.git("remote", cwd=clone), "")
                    self.assertEqual(self.git("status", "--porcelain", cwd=clone), "")
                    self.assertEqual(self.git("rev-parse", "HEAD", cwd=clone), seed_head)
                    for name, data in plan["seed_files"].items():
                        self.assertEqual((clone / name).read_bytes(), data.encode("utf-8"))
                    clone_metadata = _metadata(clone)
                    self.assertTrue(metadata.isdisjoint(clone_metadata))
                    metadata.update(clone_metadata)

    def test_fixture_directories_are_protected_under_group_writable_umask(self):
        root = self.scratch / "fixture"
        completed = self.cli(*ARGS, "--fixture-root", root.name, umask=0o002)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        shared = sorted(
            Path(directory).relative_to(root).as_posix()
            for directory, _, _ in os.walk(root)
            if Path(directory).stat().st_mode & 0o022
        )
        self.assertEqual(shared, [])

    def test_fixture_root_refuses_existing_links_and_shared_parent(self):
        existing = self.scratch / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("preserve", encoding="utf-8")
        link = self.scratch / "link"
        link.symlink_to(existing, target_is_directory=True)
        shared = self.scratch / "shared"
        shared.mkdir()
        shared.chmod(0o770)
        for root in (existing, link, link / "fixture", shared / "fixture"):
            with self.subTest(root=root):
                completed = self.cli(*ARGS, "--fixture-root", str(root))
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(completed.stdout, "")
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")
        self.assertTrue(link.is_symlink())
        self.assertEqual(list(existing.iterdir()), [sentinel])
        self.assertEqual(list(shared.iterdir()), [])
        self.assertEqual({item.name for item in self.scratch.iterdir()}, {"existing", "link", "shared"})

    def test_partial_fixture_copy_is_removed_and_emits_no_plan(self):
        root = self.scratch / "fixture"
        original = preparation.copytree

        def fail_after_copy(source, destination, **options):
            original(source, destination, **options)
            raise OSError("fixture disk failure")

        stdout, stderr = StringIO(), StringIO()
        with (patch.object(preparation, "copytree", side_effect=fail_after_copy),
              redirect_stdout(stdout), redirect_stderr(stderr)):
            code = preparation.main([*ARGS, "--fixture-root", str(root)])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("fixture disk failure", stderr.getvalue())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_prepared_cohorts_cannot_authorize_existing_execution(self):
        for cohort in self.plan()["cohorts"]:
            request = {"version": 1, "mode": "execute", "pool_id": f"qualification-n{cohort['size']}",
                       "workers": [task["worker_slot"] for task in cohort["tasks"]]}
            dry = submit(dict(request, mode="validate-only"))
            self.assertTrue(dry["structurally_valid"])
            self.assertFalse(dry["dispatch_authorized"])
            with self.assertRaisesRegex(ValueError, "registered-pool-host-required"):
                submit(request)
            host = object.__new__(RegisteredNativePoolHost)
            with patch.object(native_live_availability, "POOL_LIVE_AVAILABLE", False):
                with self.assertRaisesRegex(native_live_availability.NativeLiveUnavailable, "native-pool-live-unavailable"):
                    submit(request, host=host)
        self.assertEqual(list(self.scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
