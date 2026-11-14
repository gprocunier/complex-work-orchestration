from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


ALLOWED_IMPORTS = {
    "release_effect_routes": set(),
    "ownership_producer": {"process_identity"},
    "server_request_preparation": set(),
    "access_profiles": {"codex_hook_enforcement", "policy"},
    "checked_command": {"path_contract"},
    "checked_command_sequence": {"checked_command"},
    "codex_hook_enforcement": {"codex_protocol_pin", "errors"},
    "codex_protocol_pin": {"policy"},
    "codex_tool_surface": {"native_tool_isolation"},
    "supervision": set(),
    "supervision.turn_observations": set(),
    "supervision.transport": set(),
    "supervision.transport.errors": {"native_turn_dispatch"},
    "supervision.transport.private_io": {"native_live_campaign_contracts", "supervision.transport.errors"},
    "supervision.transport.app_server": {
        "native_live_availability",
        "codex_tool_surface",
        "native_canary_contracts",
        "native_live_allocation_ledger",
        "native_pool_contracts",
        "native_turn_dispatch",
        "supervision.transport.errors",
        "supervision.transport.private_io",
    },
    "paths": set(),
    "util": set(),
    "chatgpt_urls": set(),
    "path_contract": set(),
    "private_artifact": set(),
    "process_identity": set(),
    "invocation_ledger": {"paths", "process_identity"},
    "local_invocation": {"invocation_ledger", "policy", "prepared_outbound"},
    "policy": {"errors", "paths", "policy_schema", "util"},
    "policy_schema": {"paths"},
    "model_identity_scope": {"policy", "policy_schema"},
    "routing": {"access_profiles", "errors", "native_containment", "operative_routing", "policy", "risk_features", "routing_signals", "synthesis", "types", "util"},
    "routing_signals": {"util"},
    "adjudication": {"policy", "synthesis_inputs"},
    "adjudication_binding": {"adjudication", "errors", "path_contract", "policy", "returns", "synthesis_inputs"},
    "adjudication_source": {"adjudication", "adjudication_binding", "errors", "synthesis_inputs"},
    "synthesis": {"adjudication", "policy", "synthesis_inputs", "util"},
    "synthesis_inputs": {"policy"},
    "coach": {"model_identities", "routing", "synthesis", "types", "util"},
    "frozen_protocol": set(),
    "comparative_evaluation": {"frozen_protocol"},
    "epic_convergence": set(),
    "packets": {"errors", "paths", "policy", "return_language", "util"},
    "packet_provenance": {"audit", "packets"},
    "model_identities": set(),
    "outbound_screen": {"policy"},
    "prepared_outbound": {"outbound_screen"},
    "return_common": {"errors", "policy"},
    "return_language": {"errors", "policy", "return_common", "types"},
    "return_sections": {"errors", "policy"},
    "return_boundary": {"return_common", "return_sections"},
    "return_evidence": {"return_common", "return_sections", "types"},
    "return_risk": {"errors", "peer_review", "policy", "return_common", "return_evidence", "return_language", "return_sections", "types"},
    "peer_review": {"errors", "peer_review_identity"},
    "peer_review_identity": {"adjudication", "errors", "host_records", "peer_review", "policy"},
    "host_records": {"audit", "audit_segments", "errors", "host_record_inventory", "host_record_quarantine", "paths"},
    "host_record_inventory": {"host_records"},
    "host_record_quarantine": {"audit", "audit_segments", "host_record_inventory", "host_records"},
    "host_acceptance": {"errors", "host_records", "peer_review", "peer_review_identity", "policy", "policy_schema", "returns"},
    "audit_segments": {"audit", "host_records"},
    "host_return_intake": {"errors", "peer_review", "policy_schema"},
    "return_tripwires": {"policy", "return_language"},
    "risk_features": {"errors", "policy"},
    "return_language_calibration": {"return_language", "returns"},
    "returns": {"peer_review", "policy", "return_boundary", "return_common", "return_evidence", "return_language", "return_risk", "return_sections", "return_tripwires", "types", "util"},
    "workspace": {"path_contract", "paths", "util", "workspace_capture"},
    "workspace_capture": {"git_store", "path_contract"},
    "git_store": set(),
    "workgraph_markdown": set(),
    "telemetry": {"epic_convergence", "peer_review", "peer_review_identity", "util"},
    "audit": {"audit_segments", "host_record_quarantine", "host_records", "paths", "policy", "telemetry", "util"},
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
    "harness": {"access_profiles", "operative_routing", "policy", "util"},
    "native_authority": set(),
    "native_activation_ledger": set(),
    "native_activation_preview": {
        "beads_ready_set",
        "model_identities",
        "native_activation_ledger",
        "native_authority",
        "native_capability",
        "native_pool_admission",
        "native_pool_contracts",
        "native_pool_preflight",
        "native_pool_proportionality",
        "native_pool_workspace",
        "native_tool_activation",
        "native_tool_isolation",
        "policy",
        "work_sizing",
        "workspace",
        "workspace_capture",
    },
    "native_capability": {"native_authority"},
    "native_canary_contracts": {"native_stop_scope", "util"},
    "native_live_campaign_contracts": {
        "native_authority",
        "native_canary_contracts",
        "native_live_allocation_ledger",
        "workspace",
        "workspace_capture",
    },
    "proportional_execution": {"native_capability", "native_containment"},
    "native_containment": {"native_release", "policy"},
    "native_precommit": {"maintenance_authority", "audit", "model_identities", "native_session", "native_session_boundary", "operative_routing", "paths", "policy", "util", "workspace"},
    "native_tool_activation": {
        "native_authority",
        "native_pool_admission",
        "native_recovery_authority",
        "native_tool_isolation",
    },
    "native_tool_isolation": set(),
    "native_stop_scope": {"native_authority"},
    "native_pool_admission": {
        "beads",
        "beads_ready_set",
        "native_pool_capacity",
        "native_pool_proportionality",
        "native_recovery_authority",
        "policy",
        "work_sizing",
    },
    "native_pool_capacity": {"paths", "policy"},
    "native_pool_capacity_compat": set(),
    "native_pool_schedulability": set(),
    "native_pool_contracts": {
        "native_authority",
        "native_control",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_capacity_compat",
        "native_recovery_authority",
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
    "maintenance_native_runtime": {'native_live_availability', 'maintenance_qualification', 'maintenance_image', 'native_precommit', 'native_pool_config', 'native_pool_contracts', 'native_pool_preflight', 'workspace', 'native_control', 'native_tool_isolation', 'native_pool_transaction', 'maintenance_runtime_support', 'native_pool_leases', 'paths', 'policy', 'native_pool_workspace', 'native_pool_admission', 'native_stop_scope', 'supervision.transport.app_server', 'supervision.transport.errors', 'supervision.turn_observations'},
    "maintenance_runtime_support": {'maintenance_authority', 'native_pool_admission', 'native_pool_contracts'},
    "maintenance_authority": {"native_authority", "native_pool_contracts"},
    "maintenance_image": {"native_pool_contracts", "paths"},
    "maintenance_readiness": {"model_identities", "maintenance_authority", "native_pool_contracts", "native_pool_transaction", "native_precommit", "work_sizing"},
    'maintenance_qualification': {'native_live_availability', 'maintenance_image', 'native_tool_isolation', 'native_pool_contracts', 'maintenance_runtime_support', 'maintenance_authority', 'native_authority', 'native_canary_contracts', 'checked_command', 'native_turn_dispatch', 'codex_tool_surface', 'supervision.transport.app_server', 'supervision.transport.errors'},
    'maintenance_release': {'native_precommit', 'native_pool_contracts', 'maintenance_authority', 'maintenance_qualification', 'operative_routing', 'work_sizing'},
    'private_authority_input': {'native_precommit', 'operative_routing'},

    "requirement_baseline": set(),
    "typed_artifact_requirement": {"requirement_baseline"},
    "candidate_identity": {"git_store", "requirement_baseline", "workspace_capture"},
    "stage_evidence": set(),
    "stage_completion": {"stage_evidence", "checked_command", "native_pool_transaction"},
    "native_pool_transaction": {
        "maintenance_authority",
        "native_pool_admitted",
        "native_pool_contracts",
        "util",
    },
    "native_pool_leases": {"native_pool_contracts"},
    "native_pool_workspace": {"native_pool_contracts", "workspace", "workspace_capture"},
    "native_pool": {
        "native_authority",
        "native_control",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_leases",
        "native_recovery_authority",
        "native_pool_scheduler",
        "native_pool_schedulability",
        "native_stop_scope",
    },
    "native_pool_admitted": {
        "native_pool",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_leases",
        "native_pool_preflight",
        "native_tool_activation",
    },
    "native_pool_config": {
        "native_control",
        "native_live_campaign_contracts",
        "native_pool_capacity",
        "native_pool_capacity_compat",
        "native_pool_admission",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_pool_leases",
        "native_pool_workspace",
        "native_tool_isolation",
        "policy",
    },
    "native_pool_preflight": {
        "native_authority",
        "native_pool_admission",
        "native_pool_capacity",
        "native_pool_contracts",
        "native_pool_schedulability",
        "native_tool_activation",
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
    "native_release": {
        "maintenance_release", "work_sizing","native_precommit", "operative_routing", "paths", "policy", "util"},
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
    "native_live_availability": set(),
    "native_worker_contracts": {"native_disposition"},
    "operative_routing": {"model_identities", "policy", "work_sizing"},
    "execution_enhancement_metrics": set(),
    "execution_status_report": {"audit", "epic_convergence", "execution_enhancement_metrics", "model_identities", "paths"},
    "work_sizing": {"model_identities", "checked_command", "model_identities", "native_authority", "native_containment", "native_precommit", "policy"},
    "public_copy": set(),
    "errors": set(),
    "types": set(),
}


def core_import_targets(node: ast.AST, module: str, is_package: bool) -> set[str]:
    """cwo_core modules one import depends on, named by longest known dotted prefix."""

    candidates: list[list[str]] = []
    if isinstance(node, ast.Import):
        candidates = [alias.name.split(".")[1:] for alias in node.names if alias.name.startswith("cwo_core.")]
    elif isinstance(node, ast.ImportFrom):
        named = node.module.split(".") if node.module else []
        if node.level == 0:
            if named[:1] != ["cwo_core"]:
                return set()
            base = named[1:]
        else:
            package = module.split(".") if is_package else module.split(".")[:-1]
            if node.level - 1 > len(package):
                return {"<outside cwo_core>"}
            base = package[: len(package) - (node.level - 1)] + named
        candidates = ([base] if base else []) + [base + [alias.name] for alias in node.names if alias.name != "*"]
    targets: set[str] = set()
    for parts in candidates:
        known = [".".join(parts[:end]) for end in range(len(parts), 0, -1) if ".".join(parts[:end]) in ALLOWED_IMPORTS]
        targets.add(known[0] if known else parts[0])
    return targets


class CwoCoreImportContractTests(unittest.TestCase):
    def test_r6_package_does_not_reexport_monolith_symbols(self) -> None:
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
        self.assertEqual(paths.AUDIT_DIR, paths.HOST_STATE_ROOT)
        self.assertFalse(paths.HOST_STATE_ROOT.is_relative_to(ROOT))
        self.assertEqual(paths.AUDIT_LOG, paths.HOST_STATE_ROOT / "audit.jsonl")

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

    def test_r6_runtime_and_independent_dependency_declarations_match(self) -> None:
        source = (ROOT / "scripts" / "validate_repository.py").read_text(encoding="utf-8")
        declarations = [
            node for node in ast.parse(source).body
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "CWO_CORE_ALLOWED_IMPORTS"
                for target in node.targets
            )
        ]
        self.assertEqual(len(declarations), 1)
        # Keep two independent declarations; never replace this test's table
        # with the runtime table and thereby make the direction check circular.
        runtime_declaration = ast.literal_eval(declarations[0].value)
        self.assertEqual(ALLOWED_IMPORTS, runtime_declaration)

    def test_r6_cwo_core_dependency_direction(self) -> None:
        core = ROOT / "scripts" / "cwo_core"
        errors: list[str] = []
        for path in sorted(core.rglob("*.py")):
            if path == core / "__init__.py":
                continue
            parts = path.relative_to(core).with_suffix("").parts
            is_package = parts[-1] == "__init__"
            module = ".".join(parts[:-1] if is_package else parts)
            self.assertIn(module, ALLOWED_IMPORTS, path.relative_to(ROOT).as_posix())
            tree = ast.parse(path.read_text(encoding="utf-8"))
            allowed = ALLOWED_IMPORTS[module]
            for node in ast.walk(tree):
                for imported in core_import_targets(node, module, is_package):
                    if imported != module and imported not in allowed:
                        errors.append(f"{module} imports {imported}")
        self.assertEqual(errors, [])

    def test_dependency_direction_names_subpackage_targets(self) -> None:
        cases = {
            ("from cwo_core.routing import classify_work", "coach", False): {"routing"},
            ("import cwo_core.routing.signals", "coach", False): {"routing"},
            ("from . import checked_command", "maintenance_qualification", False): {"checked_command"},
            (
                "from .supervision.transport.app_server import AppServer",
                "maintenance_qualification",
                False,
            ): {"supervision.transport.app_server"},
            (
                "from cwo_core.supervision.transport.errors import AppServerError",
                "supervision.transport.app_server",
                False,
            ): {"supervision.transport.errors"},
            ("from .errors import AppServerError", "supervision.transport.app_server", False): {
                "supervision.transport.errors"
            },
            ("from ...routing import classify_work", "supervision.transport.app_server", False): {"routing"},
            ("from . import errors", "supervision.transport", True): {
                "supervision.transport",
                "supervision.transport.errors",
            },
            ("from cwo_core.unknown_module import thing", "supervision.transport.app_server", False): {
                "unknown_module"
            },
            ("from .... import paths", "supervision.transport.app_server", False): {"<outside cwo_core>"},
            ("import json", "supervision.transport.app_server", False): set(),
            ("from run_native_pool_live_canaries import AppServer", "maintenance_qualification", False): set(),
        }
        for (source, module, is_package), expected in cases.items():
            with self.subTest(source=source, module=module):
                node = ast.parse(source).body[0]
                self.assertEqual(core_import_targets(node, module, is_package), expected)

    def test_preparation_has_exact_isolated_module_contract(self) -> None:
        module_name = "server_request_preparation"
        self.assertEqual(ALLOWED_IMPORTS[module_name], set())
        self.assertFalse(any(module_name in targets for targets in ALLOWED_IMPORTS.values()))
        module = importlib.import_module(f"cwo_core.{module_name}")
        self.assertEqual(set(module.__all__), {
            "CAPTURED_VERSION", "EVIDENCE_QUALIFIER", "CONTEXT_PROVENANCE",
            "COMMAND", "FILE", "PERMISSIONS", "PreparationError",
            "Response", "Notification", "ServerRequest", "Correlation",
            "FakeItemContext", "DecisionWork", "PreparedReply",
            "classify_message", "FakeRequestPreparer",
        })

    def test_preparation_stays_outside_operative_supervision_import_graph(self) -> None:
        core = ROOT / "scripts" / "cwo_core"
        module_name = "server_request_preparation"
        module = importlib.import_module(f"cwo_core.{module_name}")
        source = Path(module.__file__).resolve()
        self.assertEqual(source, (core / f"{module_name}.py").resolve())
        self.assertFalse(source.is_relative_to((core / "supervision").resolve()))
        self.assertFalse((core / "supervision" / "transport" / f"{module_name}.py").exists())
        graph: dict[str, set[str]] = {}
        for path in sorted(core.rglob("*.py")):
            parts = path.relative_to(core).with_suffix("").parts
            is_package = parts[-1] == "__init__"
            name = ".".join(parts[:-1] if is_package else parts)
            tree = ast.parse(path.read_text(encoding="utf-8"))
            graph[name] = set()
            for node in ast.walk(tree):
                graph[name].update(core_import_targets(
                    node, name or "__init__", is_package and bool(name),
                ))
        reachable: set[str] = set()
        pending = ["supervision.transport.app_server"]
        while pending:
            name = pending.pop()
            if name in reachable:
                continue
            reachable.add(name)
            self.assertIn(name, graph)
            pending.extend(graph[name])
            # Importing a module also executes its ancestor package initializers.
            parts = name.split(".")
            pending.extend(".".join(parts[:end]) for end in range(len(parts)))
        self.assertNotIn(module_name, reachable)

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
