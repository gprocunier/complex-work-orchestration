from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAKE_BD = r"""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
assert not any(name.startswith("GIT_") for name in os.environ)
cwd = Path.cwd()
project = cwd
selector = None
explicit_directory = False
while args and args[0] in ("-C", "--db"):
    flag, value, *args = args
    if flag == "-C":
        project = Path(value)
        explicit_directory = True
    else:
        selector = Path(value)
location = selector
if location is None:
    for directory in (project, *project.parents):
        if (directory / ".beads").is_dir():
            location = directory / ".beads"
            break
        if not explicit_directory and (directory / ".git").exists():
            break
with Path(os.environ["CWO_TEST_BD_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps([str(cwd), str(location), selector is not None, args[0]]) + "\n")
if location is None:
    sys.exit("no beads database found")
storage = location / "database"
marker = storage.read_text()
command = args[0]
epic = {"id": "fixture-1", "title": marker + " epic", "issue_type": "epic", "status": "open"}
task = {"id": "fixture-2", "title": marker + " task", "issue_type": "task", "status": "open",
        "parent": "fixture-1", "priority": 1}
if command == "where":
    if selector and os.environ.get("CWO_TEST_ALTERNATE_STORAGE"):
        storage = storage.with_suffix(".alternate")
    result = {"path": str(location), "database_path": str(storage)}
elif command == "ready":
    result = [task]
elif command == "list":
    result = [] if "--parent" in args and args[args.index("--parent") + 1] == task["id"] else [task]
elif command == "show":
    issues = {item["id"]: item for item in (epic, task)}
    result = [issues[item_id] for item_id in args[args.index("--") + 1:]]
elif command == "create":
    assert args[-2] == "--"
    print("Created issue: fixture-" + str(Path(os.environ["CWO_TEST_BD_LOG"]).read_text().count("\n") + 10))
    sys.exit(0)
elif command in ("dep", "comment", "close"):
    if command == "comment" and os.environ.get("CWO_TEST_REPLACE_BD"):
        storage.rename(storage.with_suffix(".old"))
        storage.write_text(marker)
    sys.exit(0)
else:
    sys.exit("unexpected Beads command: " + command)
print(json.dumps(result))
"""


class BeadsProjectBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.area = Path(temporary.name).resolve()
        self.package = self.area / "installed-package"
        self.project = self.area / "calling-project"
        self.nested = self.project / "nested"
        self.nested.mkdir(parents=True)
        self.bin = self.area / "bin"
        self.bin.mkdir()
        self.log = self.area / "bd.jsonl"
        for name in ("scripts", "policy", "schemas", "experts", "prompts"):
            shutil.copytree(ROOT / name, self.package / name, ignore=shutil.ignore_patterns("__pycache__"))
        self.env = {
            name: value for name, value in os.environ.items()
            if not name.startswith(("BEADS_", "BD_", "DOLT_", "GIT_"))
        }
        self.env.update(
            PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            CWO_TEST_BD_LOG=str(self.log),
            CWO_TEMP_ROOT=str(self.area / "tmp"),
        )
        for directory, marker in ((self.package, "package decoy"), (self.project, "calling project")):
            (directory / ".beads").mkdir()
            (directory / ".beads" / "database").write_text(marker, encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=directory, env=self.env, check=True)
        fake_bd = self.bin / "bd"
        fake_bd.write_text(f"#!{sys.executable}\n" + FAKE_BD, encoding="utf-8")
        fake_bd.chmod(0o755)

    def invoke(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        self.log.unlink(missing_ok=True)
        return subprocess.run(
            [sys.executable, str(self.package / "scripts" / args[0]), *args[1:]],
            cwd=cwd or self.nested, env=self.env, capture_output=True, text=True, timeout=30, check=False,
        )

    def calls(self) -> list[tuple[str, str, bool, str]]:
        if not self.log.exists():
            return []
        return [tuple(json.loads(line)) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_installed_helpers_only_use_the_calling_projects_database(self) -> None:
        commands = (
            (("cwo.py", "beads-brief", "--bead", "fixture-2", "--json"), {"show"}, "calling project task"),
            (("cwo.py", "continue", "--epic", "fixture-1", "--format", "json"),
             {"ready", "list", "show"}, "calling project epic"),
            (("summarize_resume_state.py",), {"ready", "list"}, "calling project task"),
            (("cwo.py", "scaffold", "--title", "Implement invoice totals", "--tight-chain"), {"create", "dep"}, None),
            (("spawn_expert_reviews.py", "Prepare public documentation and GitHub Pages.", "--top-n", "8"),
             {"create"}, None),
            (("cwo.py", "close-bead", "--bead", "fixture-2", "--disposition", "abandoned",
              "--why", "The requested work has been superseded", "--close"), {"comment", "close"}, None),
        )
        for args, operations, expected in commands:
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = self.calls()
                self.assertEqual({command for _, _, _, command in calls if command != "where"}, operations)
                self.assertEqual({directory for directory, _, _, _ in calls}, {str(self.project)})
                self.assertEqual({location for _, location, _, _ in calls}, {str(self.project / ".beads")})
                self.assertTrue(all(pinned for _, _, pinned, command in calls if command != "where"))
                self.assertEqual(sum(command == "where" for _, _, _, command in calls), 2)
                self.assertNotIn("Unable to read:", result.stdout)
                if expected:
                    self.assertIn(expected, result.stdout)

    def test_no_project_database_refuses_before_issue_access(self) -> None:
        shutil.rmtree(self.project / ".beads")
        result = self.invoke("cwo.py", "beads-brief", "--bead", "fixture-2", "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no beads database found", result.stderr.casefold())
        self.assertFalse([call for call in self.calls() if call[3] != "where"])

    def test_nested_checkout_cannot_fall_through_to_ancestor_database(self) -> None:
        directory = self.package / "unrelated"
        directory.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=directory, env=self.env, check=True)
        result = self.invoke("cwo.py", "beads-brief", "--bead", "fixture-2", "--json", cwd=directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [(str(directory), "None", False, "where")])

    def test_explicit_beads_directory_is_pinned_without_git_overrides(self) -> None:
        self.env.update(BEADS_DIR="../installed-package/.beads", GIT_DIR=str(self.package / ".git"))
        result = self.invoke("cwo.py", "beads-brief", "--bead", "fixture-2", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("package decoy task", result.stdout)
        self.assertEqual(self.calls(), [
            (str(self.project), str(self.package / ".beads"), True, command)
            for command in ("where", "where", "show")
        ])

    def test_database_replacement_refuses_second_mutation(self) -> None:
        self.env["CWO_TEST_REPLACE_BD"] = "yes"
        result = self.invoke("cwo.py", "close-bead", "--bead", "fixture-2", "--disposition", "abandoned",
                             "--why", "The requested work has been superseded", "--close", "--json")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("project Beads database changed", result.stderr)
        self.assertTrue(json.loads(result.stdout)["partial_persistence"])
        self.assertEqual([command for _, _, _, command in self.calls()], ["where", "where", "comment"])

    def test_database_pin_must_select_the_discovered_storage(self) -> None:
        self.env["CWO_TEST_ALTERNATE_STORAGE"] = "yes"
        (self.project / ".beads" / "database.alternate").touch()
        result = self.invoke("cwo.py", "beads-brief", "--bead", "fixture-2", "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit Beads command selected another database", result.stderr)
        self.assertEqual([command for _, _, _, command in self.calls()], ["where", "where"])

    def test_candidate_projection_and_packet_assignment_read_the_calling_project(self) -> None:
        (self.package / "scripts" / "read_assignment_probe.py").write_text(
            "from argparse import Namespace\n"
            "from candidate_identity import _bead_projection\n"
            "from build_contractor_packet import _packet_assignment\n"
            "bead = 'fixture-2'\n"
            "print(_bead_projection(Namespace(bead_json=None), bead)['title'])\n"
            "print(_packet_assignment(Namespace(bead=bead, bead_json_file=None, rehearsal=False))[0][0]['title'])\n",
            encoding="utf-8",
        )
        result = self.invoke("read_assignment_probe.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["calling project task"] * 2)
        self.assertEqual([(location, command) for _, location, _, command in self.calls()],
                         [(str(self.project / ".beads"), command) for command in ("where", "where", "show") * 2])
