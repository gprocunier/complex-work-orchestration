"""Current Git digest compatibility for the frozen campaign contract."""

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


class Generation11PreallocationContractTests(unittest.TestCase):
    def test_validator_contract_v5_adds_v10_v7_without_changing_v4(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V5:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CWO Test",
                    "-c",
                    "user.email=cwo@example.invalid",
                    "commit",
                    "-qm",
                    "validator-v5",
                ],
                cwd=root,
                check=True,
            )
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            self.assertNotEqual(
                CONTRACTS.validator_contract_sha256_v4(root, tree),
                CONTRACTS.validator_contract_sha256_v5(root, tree),
            )
            subprocess.run(
                [
                    "git",
                    "rm",
                    "-q",
                    "schemas/full-auto-run-authorization-v10.schema.json",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CWO Test",
                    "-c",
                    "user.email=cwo@example.invalid",
                    "commit",
                    "-qm",
                    "remove-v10",
                ],
                cwd=root,
                check=True,
            )
            changed_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            with self.assertRaisesRegex(
                ValueError, "validator-contract-path-invalid"
            ):
                CONTRACTS.validator_contract_sha256_v5(root, changed_tree)


if __name__ == "__main__":
    unittest.main()
