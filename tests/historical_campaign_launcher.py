"""Public Git sources for offline campaign witnesses."""

from __future__ import annotations

import ast
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PRE_RETIREMENT = "d0e2d682659fd724ddb9f50cd50beb6877fb1eda"
RETIRED_CAMPAIGN = "a559a0bb2b9fc4e83b8acbef7b13b48172a47983"  # v1.37.0
HELD_QUALIFICATION_PRODUCERS = "7b2f3db802d7b1d1c4c555960d65d2502220f93b"  # v1.48.0
REVIEWED_CAMPAIGN_SOURCE = "bd458b84e9ab1ef7161fe43f555c11f6ebac8c41"
RUNNER_PATH = "scripts/run_native_pool_live_canaries.py"


def pinned_git(revision: str, *args: str) -> bytes:
    """Read a named commit offline; only absent history in limited checkouts skips."""
    from cwo_core.workspace_capture import trusted_git_completed

    git_entry = ROOT / ".git"
    if not git_entry.exists() and not git_entry.is_symlink():
        raise unittest.SkipTest("exact campaign witness requires a Git checkout")
    commit = trusted_git_completed(ROOT, ["cat-file", "-t", revision])
    if commit.returncode:
        shallow = trusted_git_completed(ROOT, ["rev-parse", "--is-shallow-repository"])
        if shallow.returncode == 0 and shallow.stdout == b"true\n":
            raise unittest.SkipTest(f"shallow checkout lacks campaign witness {revision}")
        raise AssertionError(f"required campaign witness commit unavailable: {revision}")
    if commit.stdout != b"commit\n":
        raise AssertionError(f"campaign witness is not a commit: {revision}")
    result = trusted_git_completed(ROOT, list(args))
    if result.returncode:
        raise AssertionError(f"campaign witness Git read failed for {revision}: {result.stderr.decode(errors='replace')}")
    return result.stdout


def pinned_blob(revision: str, path: str) -> bytes:
    return pinned_git(revision, "cat-file", "blob", f"{revision}:{path}")


def launcher_before_retirement() -> str:
    source = pinned_blob(PRE_RETIREMENT, RUNNER_PATH).decode("utf-8")
    entries = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    if len(entries) != 1:
        raise AssertionError("pre-retirement campaign launcher requires exactly one main definition")
    (entry,) = entries
    historical = "".join(source.splitlines(keepends=True)[entry.lineno - 1:entry.end_lineno])
    if hashlib.sha256(historical.encode("utf-8")).hexdigest() != (
        "98e29491d4950b0073e12d53e80b268aff8851f672283e512e1bc1b876d17f06"
    ):
        raise AssertionError("pre-retirement-campaign-launcher-sha256-drift")
    return historical


def _install_archived_head(
    case: unittest.TestCase, root: Path, revision: str, environment: dict[str, str]
) -> None:
    from cwo_core.workspace_capture import INERT_GIT_CONFIG, trusted_git

    git = trusted_git()
    if git is None:
        raise AssertionError("trusted Git unavailable for archived campaign HEAD")
    commands = (
        ("clone", "--local", "--no-hardlinks", "--no-checkout", "--no-tags", "--template=",
         "--", str(ROOT), "."),
        ("remote", "remove", "origin"),
        ("update-ref", "--no-deref", "HEAD", revision),
    )
    for command in commands:
        git_environment = {**environment, "GIT_ALLOW_PROTOCOL": "file"} if command[0] == "clone" else environment
        result = subprocess.run(
            [git.path, *INERT_GIT_CONFIG, *command], cwd=root,
            env=git_environment, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=60,
        )
        case.assertEqual(result.returncode, 0, result.stderr)
    case.assertEqual((root / ".git" / "HEAD").read_text(encoding="ascii"), revision + "\n")


def run_archived_cases(
    case: unittest.TestCase, revision: str, *tests: str,
    all_paths: bool = False, with_git_head: bool = False, dependency_path: Path | None = None,
) -> None:
    """Use the fixed revision's matching helpers and supply HEAD when requested."""
    paths = () if all_paths else ("scripts", "schemas", "policy", "tests", "references")
    raw = pinned_git(revision, "archive", "--format=tar", revision, *paths)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("GIT_", "PYTHON"))}
    environment.update(GIT_ALLOW_PROTOCOL="", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
                       GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    with tempfile.TemporaryDirectory(prefix="cwo-historical-campaign-") as directory:
        root = Path(directory)
        if with_git_head:
            _install_archived_head(case, root, revision, environment)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            archive.extractall(directory, filter="data")
        # The archived generation suite imports some sibling fixtures by bare name.
        environment["PYTHONPATH"] = str(root / "tests")
        command = [sys.executable, "-B", "-m", "unittest"]
        if dependency_path is not None:
            # Add this witness's dependency after interpreter startup so its
            # directory is absent from startup customization and other children.
            command = [sys.executable, "-B", "-c",
                       "import runpy, sys; sys.path.append(sys.argv.pop(1)); "
                       "runpy.run_module('unittest', run_name='__main__', alter_sys=True)",
                       str(dependency_path)]
        child = subprocess.run([*command, "-v", *tests],
                               cwd=directory, env=environment, capture_output=True, text=True, timeout=90)
    case.assertEqual(child.returncode, 0, child.stdout + child.stderr)
    case.assertNotIn("skipped", child.stderr)
