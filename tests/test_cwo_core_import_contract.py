from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


ALLOWED_IMPORTS = {
    "access_profiles": {"policy"},
    "checked_command": set(),
    "checked_command_sequence": {"checked_command"},
    "paths": set(),
    "util": set(),
    "chatgpt_urls": set(),
    "policy": {"paths", "util"},
    "routing": {"access_profiles", "errors", "native_containment", "policy", "routing_signals", "synthesis", "types", "util"},
    "routing_signals": {"util"},
    "synthesis": {"policy", "util"},
    "coach": {"routing", "synthesis", "types", "util"},
    "epic_convergence": set(),
    "packets": {"errors", "paths", "policy", "return_language", "util"},
    "return_common": {"policy"},
    "return_language": {"errors", "policy", "return_common", "types"},
    "return_sections": {"errors", "policy"},
    "return_boundary": {"return_common", "return_sections"},
    "return_evidence": {"return_common", "return_sections", "types"},
    "return_risk": {"policy", "return_common", "return_evidence", "return_language", "return_sections", "types"},
    "return_language_calibration": {"return_language", "returns"},
    "returns": {"policy", "return_boundary", "return_common", "return_evidence", "return_language", "return_risk", "return_sections", "types", "util"},
    "workspace": {"paths", "util"},
    "workgraph_markdown": set(),
    "telemetry": {"epic_convergence", "util"},
    "audit": {"paths", "policy", "telemetry", "util"},
    "waivers": set(),
    "beads": {"paths", "util"},
    "beads_ready_set": {
        "native_authority",
        "native_capability",
        "native_pool_capacity",
        "native_pool_schedulability",
        "native_tool_isolation",
        "policy",
        "work_sizing",
    },
    "harness": {"access_profiles", "policy", "util"},
    "native_authority": set(),
    "native_capability": {"native_authority"},
    "native_canary_contracts": {"native_stop_scope", "util"},
    "native_live_campaign_contracts": {
        "native_authority",
        "native_canary_contracts",
        "native_live_allocation_ledger",
    },
    "proportional_execution": {"native_capability", "native_containment"},
    "native_containment": {"native_release", "policy"},
    "native_precommit": {"audit", "native_session", "native_session_boundary", "paths", "policy", "util", "workspace"},
    "native_tool_isolation": set(),
    "native_stop_scope": {"native_authority"},
    "native_pool_capacity": {"paths", "policy"},
    "native_pool_capacity_compat": set(),
    "native_pool_schedulability": set(),
    "native_pool_contracts": {
        "native_authority",
        "native_pool_capacity",
        "native_pool_capacity_compat",
        "native_pool_schedulability",
        "native_stop_scope",
        "native_tool_isolation",
    },
    "native_live_allocation_ledger": {
        "audit",
        "native_canary_contracts",
        "native_turn_dispatch",
    },
    "native_turn_dispatch": set(),
    "native_pool_scheduler": {"native_pool_contracts"},
    "native_pool_leases": {"native_pool_contracts"},
    "native_pool_workspace": {"native_pool_contracts", "workspace"},
    "native_pool": {
        "native_authority",
        "native_control",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_leases",
        "native_pool_scheduler",
        "native_pool_schedulability",
        "native_stop_scope",
    },
    "native_pool_config": {
        "native_control",
        "native_live_campaign_contracts",
        "native_pool_capacity",
        "native_pool_capacity_compat",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_pool_leases",
        "native_pool_workspace",
        "native_tool_isolation",
        "policy",
    },
    "native_pool_preflight": {
        "native_authority",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_tool_isolation",
    },
    "native_pool_proportionality": {
        "native_authority",
        "native_pool_capacity",
        "native_pool_schedulability",
        "policy",
        "work_sizing",
    },
    "native_pool_reporting": {"audit", "native_pool_contracts"},
    "native_release": {"native_precommit", "paths", "policy", "util"},
    "native_control": set(),
    "native_disposition": set(),
    "native_progress": {"native_authority", "native_stop_scope", "policy"},
    "native_recovery": set(),
    "native_recovery_authority": {
        "native_live_allocation_ledger",
        "native_recovery_policy",
        "native_retry",
    },
    "native_recovery_policy": set(),
    "native_retry": {"native_authority"},
    "native_replanning": {"native_authority", "policy"},
    "native_session": {"native_disposition"},
    "native_session_boundary": {"native_session"},
    "native_worker_contracts": {"native_disposition"},
    "execution_enhancement_metrics": set(),
    "execution_status_report": {"audit", "epic_convergence", "execution_enhancement_metrics", "paths"},
    "work_sizing": {"checked_command", "native_authority", "native_containment", "native_precommit", "policy"},
    "public_copy": set(),
    "errors": set(),
    "types": set(),
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

    def test_routing_and_coach_contract_types_import(self) -> None:
        from cwo_core.types import CoachResult, RouteResult  # noqa: E402

        self.assertEqual(CoachResult.__name__, "CoachResult")
        self.assertEqual(RouteResult.__name__, "RouteResult")


if __name__ == "__main__":
    unittest.main()
