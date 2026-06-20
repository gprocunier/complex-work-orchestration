from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


ALLOWED_IMPORTS = {
    "paths": set(),
    "util": set(),
    "policy": {"paths", "util"},
    "routing": {"policy", "synthesis", "util"},
    "synthesis": {"policy", "util"},
    "coach": {"routing", "synthesis", "util"},
    "packets": {"paths", "policy", "util"},
    "returns": {"policy", "util"},
    "workspace": {"paths", "util"},
    "audit": {"paths", "policy", "util"},
    "beads": {"paths", "util"},
    "harness": {"policy", "util"},
}


class CwoCoreImportContractTests(unittest.TestCase):
    def test_package_does_not_reexport_monolith_symbols(self) -> None:
        import cwo_core  # noqa: E402

        public = {name for name in dir(cwo_core) if not name.startswith("_")}
        self.assertLessEqual(public, set(cwo_core.__all__))
        self.assertNotIn("classify_work", public)
        self.assertNotIn("run_bd", public)

    def test_old_monolith_import_path_is_dead(self) -> None:
        old_module = "orchestration" + "_lib"
        sys.modules.pop(old_module, None)
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module(old_module)

    def test_core_paths_resolve_from_package_layout(self) -> None:
        from cwo_core import paths  # noqa: E402

        self.assertEqual(paths.REPO_ROOT, ROOT)
        self.assertEqual(paths.POLICY_DIR, ROOT / "policy")
        self.assertEqual(paths.AUDIT_DIR, ROOT / ".orchestration-audit")
        self.assertEqual(paths.AUDIT_LOG, ROOT / ".orchestration-audit" / "audit.jsonl")

    def test_no_legacy_import_or_patch_target_references_remain(self) -> None:
        legacy_name = "orchestration" + "_lib"
        offenders: list[str] = []
        for directory in [ROOT / "scripts", ROOT / "tests"]:
            for path in sorted(directory.rglob("*.py")):
                if path == Path(__file__).resolve():
                    continue
                text = path.read_text(encoding="utf-8")
                if legacy_name in text:
                    offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(offenders, [])

    def test_cwo_core_dependency_direction(self) -> None:
        errors: list[str] = []
        for path in sorted((ROOT / "scripts" / "cwo_core").glob("*.py")):
            if path.name == "__init__.py":
                continue
            module = path.stem
            tree = ast.parse(path.read_text(encoding="utf-8"))
            allowed = ALLOWED_IMPORTS[module]
            for node in ast.walk(tree):
                imported: str | None = None
                if isinstance(node, ast.ImportFrom):
                    if node.level == 1 and node.module:
                        imported = node.module.split(".", 1)[0]
                    elif node.module and node.module.startswith("cwo_core."):
                        imported = node.module.split(".", 1)[1].split(".", 1)[0]
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("cwo_core."):
                            imported = alias.name.split(".", 1)[1].split(".", 1)[0]
                if imported and imported != module and imported not in allowed:
                    errors.append(f"{module} imports {imported}")
        self.assertEqual(errors, [])

    def test_all_cwo_core_modules_import(self) -> None:
        for module in ALLOWED_IMPORTS:
            with self.subTest(module=module):
                importlib.import_module(f"cwo_core.{module}")


if __name__ == "__main__":
    unittest.main()
