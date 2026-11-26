"""The launcher refuses a post-move campaign under validator contract V6.

The operative compatibility tuple still selects validator contract V6, which
binds the runner but none of the files the transport moved into. V7 binds them,
but no campaign version selects it yet. Until one does, the launcher's preclaim
checks refuse every campaign whose authorization checkpoint tree or manifest
candidate tree is not a pre-move tree, before the global campaign claim or any
other effect. "Pre-move" is known identity, not source shape: the runner and
tool-surface blobs must be a reviewed pair derived from the history V6 binds,
and no moved source may exist. The production identity table is pinned by a
public digest projection; neutral disposable Git objects exercise the gate.

The tree cases run the verified pre-retirement launcher offline. Every input
is a private placeholder file and the operative authorization validator is
stubbed to accept. The fixture spies on process launch, thread start, the
global claim and every durable write. It allows read-only Git commands and
checks before/after hashes of the case files. The current launcher refuses
even the previously accepted tree before reading inputs or reaching any effect.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_native_pool_live_canaries as LIVE  # noqa: E402
from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from tests import historical_campaign_launcher
from tests.historical_campaign_launcher import PRE_RETIREMENT, launcher_before_retirement, pinned_blob, run_archived_cases
from tests.real_beads_fixture import configure_git_fixture


from tests.historical_policy_fixtures import contract_evidence, portable_repository

FIXTURE = portable_repository()
BASE_COMMIT_B8F6251 = FIXTURE.commits["baseline"]
BASE_TREE_B8F6251 = FIXTURE.trees["baseline"]
V6_INTRODUCED_COMMIT = FIXTURE.commits["v6"]
V6_INTRODUCED_TREE = FIXTURE.trees["v6"]
PRE_V6_TREES = {name: FIXTURE.trees[name] for name in ("v5", "v2")}
RUNNER = "scripts/run_native_pool_live_canaries.py"
TOOL_SURFACE = "scripts/codex_tool_surface.py"
MOVED = (
    "scripts/cwo_core/codex_tool_surface.py",
    "scripts/cwo_core/supervision/__init__.py",
    "scripts/cwo_core/supervision/transport/__init__.py",
    "scripts/cwo_core/supervision/transport/app_server.py",
    "scripts/cwo_core/supervision/transport/errors.py",
    "scripts/cwo_core/supervision/transport/private_io.py",
)
APP_SERVER = "scripts/cwo_core/supervision/transport/app_server.py"
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
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(historical_campaign_launcher, "ROOT", Path(directory)):
            with self.assertRaisesRegex(unittest.SkipTest, "requires a Git checkout"):
                pinned_blob(PRE_RETIREMENT, RUNNER)
            git(Path(directory), "init", "-q")
            with self.assertRaisesRegex(AssertionError, "required campaign witness commit unavailable"):
                pinned_blob(PRE_RETIREMENT, RUNNER)
        with mock.patch.object(historical_campaign_launcher, "ROOT", FIXTURE.root):
            with self.assertRaisesRegex(AssertionError, "campaign witness is not a commit"):
                pinned_blob(BASE_TREE_B8F6251, RUNNER)
            with self.assertRaisesRegex(AssertionError, "campaign witness Git read failed"):
                pinned_blob(BASE_COMMIT_B8F6251, "EXAMPLE-absent.py")


# The round-3 source-shape test, kept only to show each bypass tree would pass it.
SOURCE_SHAPE_MARKER = re.compile(rb"^class AppServer\b", re.MULTILINE)
IDENTITY_UNKNOWN = "validator-contract-v6-pre-move-identity-unknown"
POST_MOVE = "validator-contract-v6-post-move-tree"
ALL_MISSING = tuple(f"validator-contract-v6-moved-source-missing:{path}" for path in MOVED)
# Trees that pass the round-3 source-shape test with no moved source.
SOURCE_SHAPE_BYPASSES = (
    "marker-string-runner", "delegating-subclass-relocated", "one-byte-changed-runner",
    "tool-surface-shim-relocated", "tool-surface-symlink",
)


def git(root: Path, *args: str, data: bool = False):
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    completed = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=not data, env=environment
    )
    return completed.stdout if data else completed.stdout.strip()


def blob(revision: str, path: str) -> bytes:
    return (ROOT / path).read_bytes() if revision == "HEAD" else FIXTURE.blob(revision, path)


def marker_string_runner() -> bytes:
    """The post-move runner with a ``class AppServer`` line inside a string."""

    return blob("HEAD", RUNNER) + b'\n_NOTE = """\nclass AppServer:\n    pass\n"""\n'


def delegating_runner() -> bytes:
    """A post-move runner whose AppServer subclasses a relocated transport."""

    text = blob("HEAD", RUNNER).decode()
    text = text.replace("from cwo_core.supervision.transport.", "from relocated_transport.")
    text = text.replace("\n    AppServer,\n", "\n    AppServer as _RelocatedAppServer,\n", 1)
    head, separator, tail = text.partition("\ndef ")
    return (head + "\n\nclass AppServer(_RelocatedAppServer):\n    pass\n\n" + separator + tail).encode()


def one_byte_changed_runner() -> bytes:
    """The allowlisted pre-move runner with one docstring byte changed."""

    data = bytearray(blob(BASE_COMMIT_B8F6251, RUNNER))
    index = data.index(b"Run disposable") + len(b"Run disposabl")
    data[index] ^= 0x20  # "e" to "E"
    return bytes(data)


TOOL_SURFACE_SHIM = b"from relocated_tool_surface import *  # noqa: F403\n"
RELOCATED_TRANSPORT = {
    f"scripts/relocated_transport/{name}": ("HEAD", f"scripts/cwo_core/supervision/transport/{name}")
    for name in ("__init__.py", "app_server.py", "errors.py", "private_io.py")
}


class TreeRepository:
    """A throwaway repository holding pre-move, post-move and broken trees.

    Each tree carries every V6 path, so V6 itself computes on all of them; they
    differ only in where the transport is. Blobs come from neutral fixture
    objects (pre-move), current source files (post-move), or the bypass runners
    above.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        git(root, "init", "-q")
        configure_git_fixture(root)
        v6 = CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6
        pre = (*v6, TOOL_SURFACE)
        self.trees = {
            "pre-move": self.tree(BASE_COMMIT_B8F6251, pre),
            "post-move": self.tree("HEAD", CONTRACTS.VALIDATOR_CONTRACT_PATHS_V7),
            "post-move-app-server-missing": self.tree(
                "HEAD", tuple(p for p in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V7 if p != APP_SERVER)),
            "post-move-all-moved-sources-missing": self.tree(
                "HEAD", tuple(p for p in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V7 if p not in MOVED)),
            "pre-move-runner-without-transport": self.tree(
                BASE_COMMIT_B8F6251, pre, replace={RUNNER: ("HEAD", RUNNER)}),
            "pre-move-runner-plus-moved-copies": self.tree(
                BASE_COMMIT_B8F6251, pre, extra={path: ("HEAD", path) for path in MOVED}),
            "runner-absent": self.tree(BASE_COMMIT_B8F6251, tuple(p for p in pre if p != RUNNER)),
            # The round-3 bypasses: each passes the source-shape test with no moved source.
            "marker-string-runner": self.tree("HEAD", v6, content={RUNNER: marker_string_runner()}),
            "delegating-subclass-relocated": self.tree(
                "HEAD", (*v6, TOOL_SURFACE), extra=RELOCATED_TRANSPORT,
                content={RUNNER: delegating_runner()}),
            "one-byte-changed-runner": self.tree(
                BASE_COMMIT_B8F6251, pre, content={RUNNER: one_byte_changed_runner()}),
            "tool-surface-shim-relocated": self.tree(
                BASE_COMMIT_B8F6251, pre,
                extra={"scripts/relocated_tool_surface.py": (BASE_COMMIT_B8F6251, TOOL_SURFACE)},
                content={TOOL_SURFACE: TOOL_SURFACE_SHIM}),
            "pre-move-runner-tool-surface-absent": self.tree(BASE_COMMIT_B8F6251, v6),
            "v6-introduced-runner-with-tool-surface": self.tree(
                BASE_COMMIT_B8F6251, pre, replace={RUNNER: (V6_INTRODUCED_COMMIT, RUNNER)}),
            "v6-introduced": self.tree(V6_INTRODUCED_COMMIT, v6),
            # Allowlisted bytes, but behind a symbolic link instead of a regular blob.
            "tool-surface-symlink": self.tree(
                BASE_COMMIT_B8F6251, v6,
                extra={"scripts/relocated_tool_surface.py": (BASE_COMMIT_B8F6251, TOOL_SURFACE)},
                symlinks={TOOL_SURFACE: "relocated_tool_surface.py"}),
            "runner-symlink": self.tree(
                BASE_COMMIT_B8F6251, tuple(p for p in pre if p != RUNNER),
                extra={"scripts/relocated_runner.py": (BASE_COMMIT_B8F6251, RUNNER)},
                symlinks={RUNNER: "relocated_runner.py"}),
        }

    def tree(self, revision: str, paths, *, replace=None, extra=None, content=None,
             symlinks=None) -> str:
        git(self.root, "read-tree", "--empty")
        sources = {path: (revision, path) for path in paths}
        sources.update(replace or {})
        sources.update(extra or {})
        data = {path: blob(*source) for path, source in sources.items()}
        data.update(content or {})
        for path, value in sorted(data.items()):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.unlink(missing_ok=True)  # never write through a link left by another tree
            target.write_bytes(value)
            git(self.root, "add", "-f", "--", path)
        for path, link in sorted((symlinks or {}).items()):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.unlink(missing_ok=True)
            target.symlink_to(link)
            git(self.root, "add", "-f", "--", path)
        tree = git(self.root, "write-tree")
        git(self.root, "read-tree", "--empty")
        return tree


class ValidatorContractV6TreeTests(unittest.TestCase):
    """The tree classification the launcher gate uses."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.repository = TreeRepository(Path(cls._temporary.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def errors(self, tree, root: Path | None = None) -> list[str]:
        selected = root or self.repository.root
        if selected == ROOT:
            return CONTRACTS.validator_contract_v6_tree_errors(selected, tree)
        with mock.patch.object(CONTRACTS, "_V6_PRE_MOVE_IDENTITY_PAIRS", FIXTURE.pairs):
            return CONTRACTS.validator_contract_v6_tree_errors(selected, tree)

    def test_moved_source_paths_are_the_v7_additions_except_the_shim(self) -> None:
        v6 = CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6
        v7 = CONTRACTS.VALIDATOR_CONTRACT_PATHS_V7
        self.assertEqual(CONTRACTS.TRANSPORT_MOVED_SOURCE_PATHS, MOVED)
        self.assertEqual(v7[len(v6):], ("scripts/codex_tool_surface.py", *MOVED))

    def test_the_allowlist_is_the_history_v6_binds(self) -> None:
        """Pin production pairs; independently derive the neutral Git fixture pairs."""
        listed = CONTRACTS.VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES
        self.assertEqual([list(row[:2]) for row in listed],
                         contract_evidence()["production_pre_move_identities"])
        self.assertEqual(CONTRACTS._V6_PRE_MOVE_IDENTITY_PAIRS,
                         frozenset(tuple(row) for row in contract_evidence()["production_pre_move_identities"]))
        self.assertEqual(hashlib.sha256(json.dumps(listed, sort_keys=True, separators=(",", ":"),
                                                 allow_nan=False).encode()).hexdigest(),
                         contract_evidence()["production_pre_move_metadata_sha256"])
        self.assertEqual(len(listed), 32)
        chain, _introducing, _accepted = FIXTURE.history()
        self.assertEqual(len(chain), 182)
        derived = set()
        for commit in chain:
            names = set(FIXTURE.git("ls-tree", "-r", "--name-only", commit).splitlines())
            self.assertLessEqual(set(CONTRACTS.VALIDATOR_CONTRACT_PATHS_V6), names)
            self.assertFalse(set(MOVED) & names)
            runner = FIXTURE.blob(commit, RUNNER)
            self.assertRegex(runner, SOURCE_SHAPE_MARKER)
            surface = FIXTURE.blob(commit, TOOL_SURFACE) if TOOL_SURFACE in names else None
            derived.add((hashlib.sha256(runner).hexdigest(),
                         hashlib.sha256(surface).hexdigest() if surface is not None else None))
        self.assertEqual(len(derived), 31)
        self.assertEqual(derived, set(FIXTURE.pairs) - {
            (hashlib.sha256(FIXTURE.runner(31)).hexdigest(),
             hashlib.sha256(FIXTURE.sources["surface"].encode()).hexdigest())})
        for runner, surface, provenance in listed[:31]:
            with self.subTest(provenance=provenance):
                match = re.fullmatch(r"runner blob ([0-9a-f]{12}) from ([0-9a-f]{7})"
                                     r"(?:, tool surface blob ([0-9a-f]{12}))?", provenance)
                self.assertIsNotNone(match)
                self.assertEqual(match[3] is None, surface is None)
                self.assertRegex(runner, r"^[0-9a-f]{64}$")

    def test_accepted_continuation_pair_is_derived_not_source_shaped(self) -> None:
        chain, introducing, accepted = FIXTURE.history()
        pair = lambda commit: (hashlib.sha256(FIXTURE.blob(commit, RUNNER)).hexdigest(),
                               hashlib.sha256(FIXTURE.blob(commit, TOOL_SURFACE)).hexdigest())
        continuation = FIXTURE.git("rev-list", "--first-parent", "--reverse",
                                   chain[-1] + ".." + accepted).split()
        self.assertEqual(continuation, [introducing, accepted])
        self.assertNotEqual(pair(chain[-1]), pair(introducing))
        self.assertEqual(pair(accepted), pair(introducing))
        self.assertIn(pair(accepted), FIXTURE.pairs)
        self.assertEqual(self.errors(FIXTURE.git("rev-parse", accepted + "^{tree}"), FIXTURE.root), [])
        self.assertEqual(list(CONTRACTS.VALIDATOR_CONTRACT_V6_PRE_MOVE_IDENTITIES[-1][:2]),
                         contract_evidence()["production_pre_move_identities"][-1])

    def test_allowlisted_pre_move_trees_are_accepted(self) -> None:
        self.assertEqual(self.errors(BASE_TREE_B8F6251, FIXTURE.root), [])
        self.assertEqual(self.errors(V6_INTRODUCED_TREE, FIXTURE.root), [])
        for label in ("pre-move", "v6-introduced"):
            with self.subTest(tree=label):
                self.assertEqual(self.errors(self.repository.trees[label]), [])

    def test_pre_v6_trees_are_refused(self) -> None:
        for label, tree in PRE_V6_TREES.items():
            with self.subTest(tree=label):
                self.assertEqual(self.errors(tree, FIXTURE.root), [IDENTITY_UNKNOWN, *ALL_MISSING])

    def test_the_candidate_tree_is_refused(self) -> None:
        tree = self.repository.trees["post-move"]
        self.assertEqual(self.errors(tree), [IDENTITY_UNKNOWN, POST_MOVE])
        # V6 itself still computes on that tree: the gate, not V6, refuses it.
        self.assertRegex(CONTRACTS.validator_contract_sha256_v6(self.repository.root, tree), r"^[0-9a-f]{64}$")
        if (ROOT / ".git").exists():
            tree = git(ROOT, "rev-parse", "HEAD^{tree}")
            self.assertEqual(self.errors(tree, ROOT), [IDENTITY_UNKNOWN, POST_MOVE])
            self.assertRegex(CONTRACTS.validator_contract_sha256_v6(ROOT, tree), r"^[0-9a-f]{64}$")

    def test_missing_moved_sources_are_refused_and_named(self) -> None:
        trees = self.repository.trees
        self.assertEqual(self.errors(trees["post-move-app-server-missing"]), [
            IDENTITY_UNKNOWN, POST_MOVE, f"validator-contract-v6-moved-source-missing:{APP_SERVER}",
        ])
        # No moved source at all, and the runner no longer defines the transport.
        for label in ("post-move-all-moved-sources-missing", "pre-move-runner-without-transport"):
            with self.subTest(tree=label):
                self.assertEqual(self.errors(trees[label]), [IDENTITY_UNKNOWN, *ALL_MISSING])
        for label in ("post-move-app-server-missing", "post-move-all-moved-sources-missing",
                      "pre-move-runner-without-transport"):
            with self.subTest(tree=label):
                self.assertRegex(
                    CONTRACTS.validator_contract_sha256_v6(self.repository.root, trees[label]),
                    r"^[0-9a-f]{64}$")

    def test_moved_copies_next_to_a_pre_move_runner_are_refused(self) -> None:
        self.assertEqual(self.errors(self.repository.trees["pre-move-runner-plus-moved-copies"]),
                         [POST_MOVE])

    def test_source_shape_bypasses_are_refused(self) -> None:
        """Each tree passes the round-3 source-shape test; none is a known identity."""

        trees = self.repository.trees
        for label in SOURCE_SHAPE_BYPASSES:
            with self.subTest(tree=label):
                tree = trees[label]
                listing = git(self.repository.root, "ls-tree", "-r", "--name-only", tree)
                self.assertNotIn("scripts/cwo_core/supervision", listing)
                self.assertNotIn("scripts/cwo_core/codex_tool_surface.py", listing)
                self.assertRegex(git(self.repository.root, "show", f"{tree}:{RUNNER}", data=True),
                                 SOURCE_SHAPE_MARKER)
                self.assertEqual(self.errors(tree), [IDENTITY_UNKNOWN, *ALL_MISSING])
                self.assertRegex(CONTRACTS.validator_contract_sha256_v6(self.repository.root, tree),
                                 r"^[0-9a-f]{64}$")
        changed = one_byte_changed_runner()
        original = blob(BASE_COMMIT_B8F6251, RUNNER)
        self.assertEqual(len(changed), len(original))
        self.assertEqual(sum(a != b for a, b in zip(changed, original)), 1)

    def test_only_the_recorded_runner_and_tool_surface_pairs_are_accepted(self) -> None:
        trees = self.repository.trees
        # The base runner without its tool surface, and an older runner with one.
        for label in ("pre-move-runner-tool-surface-absent", "v6-introduced-runner-with-tool-surface"):
            with self.subTest(tree=label):
                self.assertEqual(self.errors(trees[label]), [IDENTITY_UNKNOWN, *ALL_MISSING])

    def test_unreadable_inputs_are_refused(self) -> None:
        self.assertEqual(self.errors(self.repository.trees["runner-absent"]),
                         ["validator-contract-runner-unreadable"])
        # A link to the allowlisted runner bytes is not a regular runner blob.
        tree = self.repository.trees["runner-symlink"]
        self.assertTrue(git(self.repository.root, "ls-tree", tree, "--", RUNNER).startswith("120000 "))
        self.assertEqual(self.errors(tree), ["validator-contract-runner-unreadable"])
        self.assertEqual(self.errors("0" * 40), ["validator-contract-tree-unreadable"])
        for value in (None, "not-a-tree", "A" * 40, 7, {"tree": BASE_TREE_B8F6251}):
            with self.subTest(value=value):
                self.assertEqual(self.errors(value), ["validator-contract-tree-invalid"])


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
    real_parse_args = argparse.ArgumentParser.parse_args
    before: dict[str, str] = {}

    def parse_args(self, args=None, namespace=None):
        argv = ["--output", str(output), "--campaign-nonce", nonce]
        for action in self._actions:
            if not action.required or action.dest in {"output", "campaign_nonce"}:
                continue
            path = inputs / f"{action.dest}.json"
            path.write_text(json.dumps(contents.get(action.dest, {"placeholder": action.dest})), encoding="utf-8")
            path.chmod(0o600)
            argv.extend([action.option_strings[0], str(path)])
        before.update(_tree_state(directory))
        return real_parse_args(self, argv, namespace)

    stdout = io.StringIO()
    stderr = io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(mock.patch.multiple(LIVE.live_availability,
            N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True))
        stack.enter_context(mock.patch.object(argparse.ArgumentParser, "parse_args", parse_args))
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

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.repository = TreeRepository(Path(cls._temporary.name) / "trees")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_pre_retirement_launcher_tree_gate_and_refusals(self) -> None:
        launcher_before_retirement()
        run_archived_cases(self, PRE_RETIREMENT,
                           "tests.test_post_move_campaign_gate.PostMoveCampaignGateLauncherTests")

    def test_current_launcher_refuses_before_the_historical_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = drive_current_launcher(Path(directory) / "case", self.repository.trees["pre-move"])
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
