"""Explicit inactive-v3 fixtures for historical Spark/v2 compatibility tests.

Only policy input is replaced. Real route, receipt, packet, release and
supervision validators remain in place. Never apply this context to a test
claiming current Luna-first dispatch authority.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import policy  # noqa: E402


@contextmanager
def historical_v2_policy():
    """Read historical records under an explicitly nonactivated v3 policy."""
    original = policy._load_policy_cached
    native = copy.deepcopy(original("native-worker-execution.yaml"))
    selected = native["task_selected_routing"]
    selected["status"] = "inactive-prospective"
    selected["activation"].update(active=False, dispatch_authority=False)

    def load(filename):
        if filename == "native-worker-execution.yaml":
            return copy.deepcopy(native)
        return original(filename)

    with patch.object(policy, "_load_policy_cached", side_effect=load):
        yield native


def historical_cli_args(script: str | Path, *args: str) -> list[str]:
    """Run the real CLI in a subprocess with only the historical policy input."""
    return [sys.executable, str(Path(__file__).resolve()), str(script), *args]



# Public compatibility inputs are deliberately distinct from archived source.
CONTRACT_EVIDENCE_PATH = "tests/fixtures/w20_affected_contract_w13/source-pins-2026-10-23.json"
CONTRACT_EVIDENCE_SHA256 = "8828c94c7041e4750f6f895e87828ce95e824e938d9cc54bc4c8404c26c13d28"

def contract_evidence():
    """Read pinned neutral inputs; never resolve private source revisions."""
    import hashlib
    import json

    document = json.loads((ROOT / CONTRACT_EVIDENCE_PATH).read_bytes())["portable_contract_evidence"]
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_EVIDENCE_SHA256:
        raise AssertionError("portable-contract-evidence-drift")
    if (document["schema"] != "cwo-portable-contract-inputs-v1"
            or type(document["version"]) is not int or document["version"] != 1
            or document["effect_authority"] is not False):
        raise AssertionError("portable-contract-evidence-header-invalid")
    return document


class ContractRepository:
    """Construct actual Git objects from neutral contract inputs in a temporary root.

    Fixture IDs and SHA-256 values never stand in for production source IDs.
    The 182-commit fixture has 31 distinct runner pairs, plus a continuation.
    Only the identity *input* is substituted; real tree/digest validators run.
    """

    def __init__(self):
        import hashlib
        import tempfile

        self.temporary = tempfile.TemporaryDirectory(prefix="cwo-contract-")
        self.root = Path(self.temporary.name)
        self.evidence = contract_evidence()
        self.sources = self.evidence["sources"]
        self.git("init", "-q")
        from tests.real_beads_fixture import configure_git_fixture
        from cwo_core import native_live_campaign_contracts as contracts

        configure_git_fixture(self.root)
        self.commits = {}
        self.trees = {}
        for label, version in (("v2", "V2"), ("v5", "V5"), ("v6", "V6"), ("baseline", "V6")):
            paths = getattr(contracts, "VALIDATOR_CONTRACT_PATHS_" + version)
            files = {name: ("# neutral contract input: " + name + "\n").encode() for name in paths}
            variant = 30 if label == "baseline" else 0 if label == "v6" else -1
            files["scripts/run_native_pool_live_canaries.py"] = self.runner(variant)
            if label == "v5":
                # V6 must reach its missing v11 schema after reading this regular blob.
                files["scripts/cwo_core/native_pool_config.py"] = (
                    b"# neutral contract input: scripts/cwo_core/native_pool_config.py\n")
            if label == "baseline":
                files["scripts/codex_tool_surface.py"] = self.sources["surface"].encode()
            self.trees[label] = self.tree(files)
            self.commits[label] = self.commit(self.trees[label], label)
        generation = {"scripts/run_native_pool_live_canaries.py": self.sources["generation11_runner"].encode(),
                      "scripts/cwo_core/native_session_boundary.py": self.sources["generation11_boundary"].encode()}
        self.trees["generation11"] = self.tree(generation)
        self.commits["generation11"] = self.commit(self.trees["generation11"], "generation11")
        self.pairs = frozenset((hashlib.sha256(self.runner(n)).hexdigest(),
                               hashlib.sha256(self.sources["surface"].encode()).hexdigest() if n >= 30 else None)
                              for n in range(32))

    def git(self, *args, data=False, input=None):
        import os
        import subprocess

        environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                       "GIT_AUTHOR_NAME": "Contract Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                       "GIT_COMMITTER_NAME": "Contract Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                       "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
                       "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00"}
        result = subprocess.run(["git", *args], cwd=self.root, env=environment,
                                input=input, capture_output=True, check=True, timeout=20)
        return result.stdout if data else result.stdout.decode().strip()

    def runner(self, variant):
        return self.sources["runner_template"].format(variant=variant).encode()

    def tree(self, files):
        self.git("read-tree", "--empty")
        for name, raw in sorted(files.items()):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git("add", "-f", "--", *sorted(files))
        return self.git("write-tree")

    def commit(self, tree, label, parent=None):
        return self.git("commit-tree", tree, *(["-p", parent] if parent else []), input=(label + "\n").encode())

    def blob(self, revision, name):
        return self.git("show", revision + ":" + name, data=True)

    def history(self):
        """Build a bounded first-parent chain without archived commits or prose."""
        from cwo_core import native_live_campaign_contracts as contracts

        parent = self.commit(self.trees["v5"], "before contract")
        chain = []
        last_variant = None
        for index in range(182):
            variant = index * 31 // 182
            if variant != last_variant:
                files = {name: ("# neutral contract input: " + name + "\n").encode()
                         for name in contracts.VALIDATOR_CONTRACT_PATHS_V6}
                files["scripts/run_native_pool_live_canaries.py"] = self.runner(variant)
                if variant == 30:
                    files["scripts/codex_tool_surface.py"] = self.sources["surface"].encode()
                tree = self.tree(files)
                last_variant = variant
            parent = self.commit(tree, "contract fixture " + str(index), parent)
            chain.append(parent)
        files["scripts/run_native_pool_live_canaries.py"] = self.runner(31)
        tree = self.tree(files)
        introducing = self.commit(tree, "continuation input", parent)
        accepted = self.commit(tree, "continuation unchanged", introducing)
        return chain, introducing, accepted


from functools import lru_cache


@lru_cache(maxsize=1)
def portable_repository():
    import atexit

    repository = ContractRepository()
    atexit.register(repository.temporary.cleanup)
    return repository


@contextmanager
def contract_repository():
    repository = ContractRepository()
    try:
        yield repository
    finally:
        repository.temporary.cleanup()

if __name__ == "__main__":
    script = Path(sys.argv[1]).resolve()
    # This helper cannot launch arbitrary commands: historical fixtures only
    # cover repository scripts, and nothing changes the installed/live policy.
    if script.parent != ROOT / "scripts" or script.suffix != ".py":
        raise SystemExit("historical CLI fixture requires a repository Python script")
    sys.argv = sys.argv[1:]
    with historical_v2_policy():
        runpy.run_path(str(script), run_name="__main__")
