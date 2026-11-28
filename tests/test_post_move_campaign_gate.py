"""Replay the historical tree gate and check the current launcher refusal."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_live_canaries as LIVE  # noqa: E402
from tests import historical_campaign_launcher
from tests.historical_campaign_launcher import (  # noqa: E402
    PRE_RETIREMENT,
    REVIEWED_CAMPAIGN_SOURCE,
    RUNNER_PATH,
    launcher_before_retirement,
    pinned_blob,
    run_archived_cases,
)
from tests.historical_policy_fixtures import portable_repository  # noqa: E402


READ_ONLY_GIT = {"ls-tree", "show", "rev-parse", "cat-file", "--version"}


def read_only_git_command(argv):
    """Recognize the exact hardened prefix, not '-C' as a Git subcommand.

    This is a test effect spy, not a general Git authorization predicate.
    Unknown prefixes/commands are stopped before subprocess execution.
    """
    from cwo_core.workspace_capture import INERT_GIT_CONFIG

    args = list(map(str, argv[1:]))
    if args[:1] == ["-C"]:
        if len(args) < 2:
            return None
        args = args[2:]
        prefix = list(INERT_GIT_CONFIG)
        if args[:len(prefix)] != prefix:
            return None
        args = args[len(prefix):]
    return args[0] if args and args[0] in READ_ONLY_GIT else None


class GitEffectSpyTests(unittest.TestCase):
    def test_hardened_read_and_version_are_recognized(self):
        from cwo_core.workspace_capture import INERT_GIT_CONFIG
        self.assertEqual(read_only_git_command(["git", "--version"]), "--version")
        self.assertEqual(read_only_git_command(["git", "-C", "/tmp/repo", *INERT_GIT_CONFIG,
                                               "rev-parse", "HEAD"]), "rev-parse")

    def test_mutation_and_unknown_prefix_are_not_reads(self):
        from cwo_core.workspace_capture import INERT_GIT_CONFIG
        for args in (["commit"], ["-C", "/tmp/repo", *INERT_GIT_CONFIG, "update-ref", "refs/a", "HEAD"],
                     ["-C"], ["-c", "core.fsmonitor=attack", "show", "HEAD"]):
            with self.subTest(args=args):
                self.assertIsNone(read_only_git_command(["git", *args]))

    def test_exact_witness_refuses_incomplete_or_wrong_objects_in_full_history(self):
        from cwo_core.workspace_capture import trusted_git_private

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(historical_campaign_launcher, "ROOT", Path(directory)):
            with self.assertRaisesRegex(unittest.SkipTest, "requires a Git checkout"):
                pinned_blob(PRE_RETIREMENT, RUNNER_PATH)
            result = trusted_git_private(Path(directory), ["init", "-q"])
            self.assertEqual(result.returncode, 0, result.stderr)
            with self.assertRaisesRegex(AssertionError, "required campaign witness commit unavailable"):
                pinned_blob(PRE_RETIREMENT, RUNNER_PATH)
        fixture = portable_repository()
        with mock.patch.object(historical_campaign_launcher, "ROOT", fixture.root):
            with self.assertRaisesRegex(AssertionError, "campaign witness is not a commit"):
                pinned_blob(fixture.trees["baseline"], RUNNER_PATH)
            with self.assertRaisesRegex(AssertionError, "campaign witness Git read failed"):
                pinned_blob(fixture.commits["baseline"], "EXAMPLE-absent.py")


class ValidatorContractV6TreeTests(unittest.TestCase):
    def test_archived_v6_tree_gate(self) -> None:
        run_archived_cases(
            self, REVIEWED_CAMPAIGN_SOURCE,
            "tests.test_post_move_campaign_gate.ValidatorContractV6TreeTests",
            with_git_head=True,
        )


class _EffectReached(Exception):
    """Raised by an effect spy; main() reports it as its failure."""


_OUTPUTS = {
    "evidence_basename": "evidence.json",
    "authorization_state_basename": "authorization-state.json",
    "steering_registry_basename": "steering-registry.json",
    "allocation_ledger_basename": "allocation-ledger",
}
_CURRENT_EFFECTS = (
    "load_private_bytes",
    "load_private_json",
    "load_private_json_snapshot",
    "build_pool_inputs",
    "validate_and_acquire_global_campaign_claim",
    "acquire_global_campaign_claim",
    "write_private_artifact",
    "_start_campaign_server",
    "contain_started_threads",
)


def _tree_state(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): (
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "<dir>"
        )
        for path in sorted(root.rglob("*"))
    }


def drive_current_launcher(directory: Path, tree: str) -> dict:
    """Run the current launcher offline with the formerly accepted fixture tree."""

    inputs = directory / "inputs"
    outputs = directory / "outputs"
    for path in (directory, inputs, outputs):
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    output = outputs / _OUTPUTS["evidence_basename"]
    nonce = str(uuid.UUID(int=1))
    contents = {
        "authorization": {
            "version": 12,
            "authorization_id": str(uuid.UUID(int=2)),
            "bindings": {"checkpoint_tree": tree, "campaign_nonce": nonce},
        },
        "campaign_manifest": {"version": 8, "outputs": dict(_OUTPUTS), "candidate": {"tree": tree}},
    }
    argv = [LIVE.__file__, "--output", str(output), "--campaign-nonce", nonce]
    for name, record in contents.items():
        path = inputs / (name + ".json")
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)
        argv.extend(["--" + name.replace("_", "-"), str(path)])
    before = _tree_state(directory)

    stdout = io.StringIO()
    stderr = io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(mock.patch.multiple(LIVE.live_availability,
            N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True))
        stack.enter_context(mock.patch.object(sys, "argv", argv))
        spawn = stack.enter_context(mock.patch("subprocess.Popen", side_effect=_EffectReached))
        request = stack.enter_context(mock.patch.object(LIVE.AppServer, "request", side_effect=_EffectReached))
        server = stack.enter_context(mock.patch.object(LIVE, "AppServer", side_effect=_EffectReached))
        effects = {name: stack.enter_context(mock.patch.object(LIVE, name, side_effect=_EffectReached))
                   for name in _CURRENT_EFFECTS}
        stack.enter_context(redirect_stderr(stderr))
        stack.enter_context(redirect_stdout(stdout))
        return_code = LIVE.main()
    report = json.loads(stderr.getvalue())
    after = _tree_state(directory)
    return {
        "return_code": return_code,
        "failure_code": report.get("failure_code"),
        "failure_evidence_persisted": report.get("failure_evidence_persisted"),
        "stdout": stdout.getvalue(),
        "process_launches": spawn.call_count,
        "server_constructions": server.call_count,
        "thread_start_requests": request.call_count,
        "effect_calls": {name: spy.call_count for name, spy in effects.items()},
        "files_created_or_changed": sorted(
            path for path in set(before) | set(after) if before.get(path) != after.get(path)),
    }


class PostMoveCampaignGateLauncherTests(unittest.TestCase):
    """Historical preclaim checks and the current launcher refusal."""

    maxDiff = None

    def test_pre_retirement_launcher_tree_gate_and_refusals(self) -> None:
        launcher_before_retirement()
        run_archived_cases(self, PRE_RETIREMENT,
                           "tests.test_post_move_campaign_gate.PostMoveCampaignGateLauncherTests")

    def test_current_launcher_refuses_before_the_historical_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = drive_current_launcher(Path(directory) / "case", portable_repository().trees["baseline"])
        self.assertEqual(record, {
            "return_code": 1,
            "failure_code": "legacy-pool-execution-retired",
            "failure_evidence_persisted": False,
            "stdout": "",
            "process_launches": 0,
            "server_constructions": 0,
            "thread_start_requests": 0,
            "effect_calls": {name: 0 for name in _CURRENT_EFFECTS},
            "files_created_or_changed": [],
        })


if __name__ == "__main__":
    unittest.main()
