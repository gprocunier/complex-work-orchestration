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


class Generation9QuarantineContractTests(unittest.TestCase):
    def test_validator_contract_v3_adds_schema_blobs_without_changing_v1_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            configure_git_fixture(root)
            for relative in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V3:
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
                    "validator-v3",
                ],
                cwd=root,
                check=True,
            )
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            v1 = CONTRACTS.validator_contract_sha256(root, tree)
            v2 = CONTRACTS.validator_contract_sha256_v2(root, tree)
            v3 = CONTRACTS.validator_contract_sha256_v3(root, tree)
            self.assertEqual(len({v1, v2, v3}), 3)
            subprocess.run(
                ["git", "rm", "-q", "schemas/full-auto-run-authorization-v8.schema.json"],
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
                    "remove-v8",
                ],
                cwd=root,
                check=True,
            )
            old_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()
            with self.assertRaisesRegex(ValueError, "validator-contract-path-invalid"):
                CONTRACTS.validator_contract_sha256_v3(root, old_tree)


if __name__ == "__main__":
    unittest.main()
