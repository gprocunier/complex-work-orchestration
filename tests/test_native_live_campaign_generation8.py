"""Current V1/V2 contract digest witness.

The full offline Generation 8 proof chain is documented in native-supervision-pools.md.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from tests.real_beads_fixture import configure_git_fixture  # noqa: E402


class Generation8FiniteDagContractTests(unittest.TestCase):
    def test_v1_digest_is_frozen_and_v2_requires_the_new_schema_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            subprocess.run(
                ["git", "add", *CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install v1 contract"],
                cwd=root,
                check=True,
            )
            v1_tree = CONTRACTS._run_git(root, "rev-parse", "HEAD^{tree}")
            v1_digest = CONTRACTS.validator_contract_sha256(root, v1_tree)
            with self.assertRaisesRegex(ValueError, "validator-contract-path-invalid"):
                CONTRACTS.validator_contract_sha256_v2(root, v1_tree)

            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            subprocess.run(
                ["git", "add", *CONTRACTS.VALIDATOR_CONTRACT_PATHS_V2],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "install v2 contract"],
                cwd=root,
                check=True,
            )
            v2_tree = CONTRACTS._run_git(root, "rev-parse", "HEAD^{tree}")
            self.assertEqual(
                CONTRACTS.validator_contract_sha256(root, v1_tree), v1_digest
            )
            self.assertNotEqual(
                CONTRACTS.validator_contract_sha256_v2(root, v2_tree),
                v1_digest,
            )
