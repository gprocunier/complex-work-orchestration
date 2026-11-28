"""Offline transport compatibility under public, self-contained contract inputs.

Real validators, legacy import paths, entry-point holds and tamper refusals are
exercised with neutral disposable Git objects. The fixture digest projection is
distinct from archived provenance. No model/provider or network calls are made;
Git and disposable fixture processes are used.
Retained neutral-input verdicts remain checked against the original golden.
The pinned pre-repair transport supplies historical source lineage separately
from the repaired current transport. Neither projection establishes archived
semantic acceptance or equality between historical and current behavior.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import codex_tool_surface as SURFACE  # noqa: E402
import run_native_pool_live_canaries as LIVE  # noqa: E402
from cwo_core import maintenance_qualification as MQ  # noqa: E402
from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from cwo_core import native_pool_contracts as POOL  # noqa: E402
from cwo_core.supervision import callback_timing as TIMING  # noqa: E402
from cwo_core.supervision import session_evidence as EVIDENCE  # noqa: E402
from cwo_core.supervision.transport import app_server as TRANSPORT  # noqa: E402
from tests import test_codex_tool_surface as SURFACE_TESTS  # noqa: E402
from tests import test_native_pool_contracts as POOL_TESTS  # noqa: E402
from tests.historical_campaign_launcher import (  # noqa: E402
    PRE_RETIREMENT, RETIRED_CAMPAIGN, launcher_before_retirement, pinned_blob, pinned_git, run_archived_cases,
)


def setUpModule() -> None:
    # Deliberate current-source holds are patched only for historical
    # mechanics comparisons; archived source pins and golden bytes stay fixed.
    global _F5_HELD_ROUTE_PATCH
    _F5_HELD_ROUTE_PATCH = mock.patch.multiple(LIVE.live_availability,
        N1_LIVE_AVAILABLE=True, POOL_LIVE_AVAILABLE=True, CAMPAIGN_LIVE_AVAILABLE=True)
    _F5_HELD_ROUTE_PATCH.start()


def tearDownModule() -> None:
    _F5_HELD_ROUTE_PATCH.stop()


GOLDEN = ROOT / "tests" / "fixtures" / "w20_affected_contract_w13" / "golden-b8f6251.json"
LEGACY_TRANSPORT_SOURCE = ROOT / "tests/fixtures/affected_contract_compatibility/legacy-transport-before-bounds.txt"
LEGACY_TRANSPORT_MODULE_SHA256 = "264522cef555c0682227edf927ec1ab57dbee8776d8e360722c3d2e8fd874566"
LEGACY_TRANSPORT_CLASS_SHA256 = "543715d9bee197b8674ea832c9f2b38bd74b19a6b07b7eafdaa453bf195f1591"
from tests.historical_policy_fixtures import contract_evidence, portable_repository

FIXTURE = portable_repository()
BASELINE_COMMIT = FIXTURE.commits["baseline"]
MODEL = "gpt-5.3-codex-spark"
HISTORICAL_MODEL = "gpt-5.2-codex"
OPERATIVE_TOOLS = sorted(SURFACE.EXACT_OPERATIVE_TOOLS)

# Neutral trees cover the V6, V5 and V2 path rosters and unavailable inputs.
# Stable case labels are not the identities of the supplied Git objects.
CONTRACT_TREES = {
    "b8f6251-baseline": FIXTURE.trees["baseline"],
    "0aafd2f-v6-introduced": FIXTURE.trees["v6"],
    "e7f5406-v5-introduced-generation11": FIXTURE.trees["v5"],
    "5564ba2-v2-introduced": FIXTURE.trees["v2"],
    "unknown-tree": "0" * 40,
    "malformed-tree": "not-a-tree",
}
CONTRACT_FUNCTIONS = {
    "v1": "validator_contract_sha256",
    "v2": "validator_contract_sha256_v2",
    "v3": "validator_contract_sha256_v3",
    "v4": "validator_contract_sha256_v4",
    "v5": "validator_contract_sha256_v5",
    "v6": "validator_contract_sha256_v6",
}
RUNNER_PATH = "scripts/run_native_pool_live_canaries.py"
BOUNDARY_PATH = "scripts/cwo_core/native_session_boundary.py"
RETIRED_CALIBRATION_PATHS = {RUNNER_PATH, "scripts/cwo_core/supervision/calibration.py"}
RETIRED_PREVIEW_IMPORTS = {"CONTROL_TURN_ID", "calibration", "capture_server_tool_surface",
                           "contain_started_threads", "pool_sleep"}
CURRENT_CALIBRATION_PATH = "scripts/registered_pool_qualification_calibration.py"

# Retained imports of the moved objects, by the baseline's module path.
BASELINE_IMPORTS = {
    "check_codex_worker_surface": {
        "codex_tool_surface": [
            "EXACT_READ_ONLY_TOOLS",
            "EXACT_CORE_RESOURCE_OPERATIVE_TOOLS", "EXACT_CORE_RESOURCE_READ_ONLY_TOOLS",
            "tools_are_mutable", "normalized_tools",
        ],
    },
    "run_native_pool_activation_preview": {
        "run_native_pool_live_canaries": [
            "CONTROL_TURN_ID", "AppServer", "AppServerError", "LiveThreadAdapter",
            "calibration", "capture_server_tool_surface", "contain_started_threads",
            "pool_sleep",
        ],
    },
    "cwo_core.maintenance_native_runtime": {
        "run_native_pool_live_canaries": [
            "AppServer", "AppServerError", "LiveThreadAdapter",
            "THREAD_PHASE_PRECOMMIT_FIT", "capture_server_tool_surface",
            "contain_started_threads", "pool_sleep", "turn_items",
        ],
    },
}
# maintenance_qualification imports these lazily inside functions.
BASELINE_LAZY_IMPORTS = {
    "cwo_core.maintenance_qualification": {
        "run_native_pool_live_canaries": [
            "AppServer", "AppServerRpcError", "THREAD_PHASE_PRECOMMIT_FIT",
            "contain_started_threads",
        ],
        "codex_tool_surface": [
            "PROOF_VERSION", "require_zero_endpoint_inventory", "canonical_sha256",
            "TOOL_PROFILES", "require_surface_proof", "ALLOWLIST_PARAMETER",
            "tool_profile_is_mutable",
        ],
    },
}
MOVED_DEFINITIONS = (
    "AppServerError", "AppServerRpcError", "AmbiguousTurnStartError",
    "_load_owned_regular_bytes", "load_private_bytes", "load_private_json_snapshot",
    "load_private_json", "_private_control_directory", "_open_private_control_lock",
    "_fsync_private_control_directory", "_fsync_owned_control_directory",
    "sha256_bytes", "sha256_text", "_seal_same_process_proof",
    "_validated_same_process_proof", "AppServer", "_canonical_controller_workdir",
)
MOVED_CONSTANTS = (
    "EXACT_MODEL", "THREAD_PHASE_LIVE_CANARY", "THREAD_PHASE_PRECOMMIT_FIT",
    "CONTROL_TURN_ID", "THREAD_READ_TIMEOUT_SECONDS",
    "AMBIGUOUS_TURN_DISCOVERY_TIMEOUT_SECONDS", "AMBIGUOUS_TURN_DISCOVERY_POLL_SECONDS",
)


class _EffectReached(Exception):
    """Raised by a spy when control reaches an effect; nothing is executed."""


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical(value) -> str:
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def _source_sha256(value) -> str:
    return _sha256(inspect.getsource(value))


def _git_blob(commit: str, path: str) -> bytes:
    return FIXTURE.blob(commit, path)


def _relative(path: str | Path) -> str:
    return Path(path).resolve().relative_to(ROOT.resolve()).as_posix()


def _defining_file(value) -> str:
    return _relative(inspect.getsourcefile(value))


def _outcome(function, *args, **kwargs) -> dict:
    try:
        return {"outcome": "returned", "value": function(*args, **kwargs)}
    except Exception as exc:  # normalized verdict, not a crash
        return {"outcome": "refused", "error_type": type(exc).__name__, "message": str(exc)}


# --- Frozen validator-contract digests (V1 to V6) -------------------------------------


def validator_contract_section() -> dict:
    paths = {
        name: list(getattr(CONTRACTS, "VALIDATOR_CONTRACT_PATHS_" + name.upper()))
        for name in CONTRACT_FUNCTIONS
    }
    verdicts = {}
    for name, function_name in CONTRACT_FUNCTIONS.items():
        function = getattr(CONTRACTS, function_name)
        for label, tree in CONTRACT_TREES.items():
            result = _outcome(function, FIXTURE.root, tree)
            verdicts[f"{name}@{label}"] = {
                "input": {"contract": name, "checkpoint_tree": tree},
                **result,
            }
    return {
        "path_lists": paths,
        "legacy_alias_is_v1": CONTRACTS.VALIDATOR_CONTRACT_PATHS is CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1,
        "verdicts": verdicts,
    }


# --- Codex tool-surface proofs: historical verifier versus current authority -----------


def _reseal(value: dict, field: str) -> dict:
    body = {key: item for key, item in value.items() if key != field}
    sealed = dict(body)
    sealed[field] = SURFACE.canonical_sha256(body)
    return sealed


_PATH_DERIVED_SEALS = {"proof_sha256", "binding_sha256", "capture_binding_sha256", "lockdown_config_sha256"}


def _normalized(value, home: str):
    """Replace the temporary home and the seals that hash it, for a stable input hash."""

    if isinstance(value, dict):
        return {
            key: ("<derived>" if key in _PATH_DERIVED_SEALS else _normalized(item, home))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalized(item, home) for item in value]
    if isinstance(value, str):
        return value.replace(home, "<HOME>")
    return value


class _SurfaceWorld:
    """A fake Codex home and binary file; the binary is never executed."""

    def __init__(self, directory: Path) -> None:
        self.home = directory.resolve()
        (self.home / "config.toml").write_text("[mcp_servers.alpha]\ncommand = 'false'\n", encoding="utf-8")
        (self.home / "models_cache.json").write_text(json.dumps({"models": [{
            "slug": MODEL, "shell_type": "unified_exec",
            "apply_patch_tool_type": "freeform", "experimental_supported_tools": [],
        }]}), encoding="utf-8")
        self.binary = self.home / "codex"
        self.binary.write_bytes(b"codex-test-binary")
        self.empty_path = self.home / "empty-path"
        self.empty_path.mkdir()

    def patches(self, stack: ExitStack, *, binary: Path | None = None) -> None:
        stack.enter_context(mock.patch.object(SURFACE, "_codex_binary", return_value=binary or self.binary))
        stack.enter_context(mock.patch.object(SURFACE, "_codex_version", return_value="test-version"))
        stack.enter_context(mock.patch.object(TRANSPORT, "check_codex_capabilities"))
        stack.enter_context(mock.patch.dict(os.environ, {"PATH": str(self.empty_path)}))

    def proofs(self) -> dict[str, dict]:
        captured = {"model": MODEL, "tools": [{"name": name} for name in OPERATIVE_TOOLS]}
        with ExitStack() as stack:
            self.patches(stack)
            v5 = SURFACE_TESTS.bound_fixture_proof(captured, codex_home=self.home, requested_model=MODEL)
        binding = deepcopy(v5["capture_binding"])
        binding.pop("tool_profile")
        binding.pop("effect_policy")
        binding = _reseal(binding, "binding_sha256")
        process = deepcopy(v5["process_binding"])
        process.pop("endpoint_inventory")
        process["capture_binding_sha256"] = binding["binding_sha256"]
        v4 = deepcopy(v5)
        v4.pop("effect_policy")
        v4.update({"version": 4, "capture_binding": binding, "process_binding": process})
        v4 = _reseal(v4, "proof_sha256")
        v3 = deepcopy(v5)
        v3["version"] = 3
        for key in SURFACE.CAPTURE_PROOF_FIELDS | SURFACE.CURRENT_EFFECT_FIELDS:
            v3.pop(key)
        v3 = _reseal(v3, "proof_sha256")
        v2 = deepcopy(v3)
        v2["version"] = 2
        for key in SURFACE.PROFILE_PROOF_FIELDS:
            v2.pop(key)
        v2 = _reseal(v2, "proof_sha256")

        model_unsealed = deepcopy(v3)
        model_unsealed.update({"requested_model": HISTORICAL_MODEL, "observed_model": HISTORICAL_MODEL})
        model_resealed = _reseal(model_unsealed, "proof_sha256")
        v3_as_v5 = _reseal({**v3, "version": 5}, "proof_sha256")
        v4_as_v5 = _reseal({**v4, "version": 5, "effect_policy": deepcopy(v5["effect_policy"])}, "proof_sha256")
        lockdown_tampered = deepcopy(v5)
        lockdown_tampered["lockdown_config"]["web_search"] = "enabled"
        unknown_version = _reseal({**v2, "version": 1}, "proof_sha256")
        return {
            "v5-current": v5,
            "v4-historical": v4,
            "v3-historical": v3,
            "v2-historical": v2,
            "v3-historical-model-relabel-unsealed": model_unsealed,
            "v3-historical-model-relabel-resealed": model_resealed,
            "v3-relabelled-as-v5": v3_as_v5,
            "v4-converted-to-v5": v4_as_v5,
            "v5-lockdown-tampered": lockdown_tampered,
            "v1-unknown-version": unknown_version,
        }


def _bare_app_server(proof: dict, request_spy) -> object:
    """An unconnected instance: only the fields start_thread reads before any request."""

    server = object.__new__(LIVE.AppServer)
    server.allocation_ledger = None
    server.requested_model = MODEL
    server._tool_surface_proof = deepcopy(proof)
    server.request = request_spy
    return server


def tool_surface_section() -> dict:
    with tempfile.TemporaryDirectory() as directory:
        world = _SurfaceWorld(Path(directory))
        home = str(world.home)
        proofs = world.proofs()
        verify_cases = {label: (label, OPERATIVE_TOOLS, None) for label in proofs}
        verify_cases.update({
            "v2-historical-read-only-tools": ("v2-historical", sorted(SURFACE.EXACT_READ_ONLY_TOOLS), None),
            "v4-historical-core-resource-tools": (
                "v4-historical", sorted(SURFACE.EXACT_CORE_RESOURCE_OPERATIVE_TOOLS), None),
            "v5-current-binary-drift": ("v5-current", OPERATIVE_TOOLS, "drifted"),
        })
        drifted = world.home / "codex-drifted"
        drifted.write_bytes(b"other-binary")

        verifier = {}
        for label, (proof_label, tools, binary) in verify_cases.items():
            proof = proofs[proof_label]
            with ExitStack() as stack:
                world.patches(stack, binary=drifted if binary else None)
                historical = SURFACE.validate_surface_proof(proof, requested_model=MODEL, permitted_tools=tools)
                current = _outcome(SURFACE.require_surface_proof, proof, requested_model=MODEL, permitted_tools=tools)
                enforcement = _outcome(SURFACE.thread_start_enforcement_params, proof,
                                       requested_model=MODEL, permitted_tools=tools)
            if current["outcome"] == "returned":
                current["value"] = "proof-accepted"
            if enforcement["outcome"] == "returned":
                value = enforcement["value"]
                enforcement["value"] = {
                    "keys": sorted(value),
                    "config_is_proof_lockdown": value.get(SURFACE.ALLOWLIST_PARAMETER) == proof["lockdown_config"],
                    "dynamicTools": value.get("dynamicTools"),
                }
            verifier[label] = _normalized({
                "input": {
                    "proof": proof_label,
                    "normalized_proof_sha256": _canonical(_normalized(proof, home)),
                    "permitted_tools": tools,
                    "binary": "drifted" if binary else "fixture",
                },
                "historical_verifier_errors": historical,
                "current_dispatch_authority": current,
                "thread_start_enforcement": enforcement,
            }, home)

        entry = {}
        for label in proofs:
            proof = proofs[label]
            # Entry 1: AppServer construction, the only path that spawns the app server.
            with ExitStack() as stack:
                world.patches(stack)
                popen = stack.enter_context(mock.patch("subprocess.Popen", side_effect=_EffectReached))
                # Direct helper calls do not run setUpModule. Patch the
                # hold only after the fake launch boundary is installed.
                stack.enter_context(mock.patch.object(LIVE.live_availability, "N1_LIVE_AVAILABLE", True))
                try:
                    LIVE.AppServer(tool_surface_proof=deepcopy(proof))
                    construction = {"outcome": "constructed"}
                except _EffectReached:
                    construction = {"outcome": "effect-reached"}
                except Exception as exc:
                    construction = {
                        "outcome": "refused", "error_type": type(exc).__name__, "message": str(exc),
                        "cleanup": getattr(exc, "app_server_cleanup", None),
                    }
                construction["popen_calls"] = popen.call_count
                if popen.call_count:
                    args, kwargs = popen.call_args
                    construction["argv"] = list(args[0])
                    construction["codex_home_env"] = kwargs["env"]["CODEX_HOME"]
            # Entry 2: thread/start on an unconnected instance holding the proof.
            calls = []

            def request_spy(method, params, timeout=None, **_kwargs):
                calls.append({"method": method, "params": deepcopy(params)})
                raise _EffectReached(method)

            server = _bare_app_server(proof, request_spy)
            with ExitStack() as stack:
                world.patches(stack)
                popen = stack.enter_context(mock.patch("subprocess.Popen", side_effect=_EffectReached))
                try:
                    server.start_thread(world.home, mutable=True, permitted_tools=list(OPERATIVE_TOOLS),
                                        allowlist_parameter=SURFACE.ALLOWLIST_PARAMETER)
                    start = {"outcome": "returned"}
                except _EffectReached:
                    start = {"outcome": "effect-reached"}
                except Exception as exc:
                    start = {"outcome": "refused", "error_type": type(exc).__name__, "message": str(exc)}
                adapter_version = _outcome(server.capability_adapter_version)
            start["request_calls"] = len(calls)
            start["popen_calls"] = popen.call_count
            if calls:
                params = calls[0]["params"]
                start["request"] = {
                    "method": calls[0]["method"],
                    "param_keys": sorted(params),
                    "config_is_proof_lockdown": params.get("config") == proof["lockdown_config"],
                    "dynamicTools": params.get("dynamicTools"),
                    "approvalPolicy": params.get("approvalPolicy"),
                    "sandbox": params.get("sandbox"),
                    "model": params.get("model"),
                }
            entry[label] = _normalized({
                "app_server_construction": construction,
                "thread_start": start,
                "capability_adapter_version": adapter_version,
            }, home)

    return {
        "validator_source_sha256": {
            "validate_surface_proof": _source_sha256(SURFACE.validate_surface_proof),
            "require_surface_proof": _source_sha256(SURFACE.require_surface_proof),
            "require_capture_binding": _source_sha256(SURFACE.require_capture_binding),
            "AppServer": _source_sha256(LIVE.AppServer),
        },
        "verifier": verifier,
        "entry_points": entry,
    }


# --- Capability receipts and the adapter implementation digest ------------------------


def capability_receipt_section() -> dict:
    baseline_runner_sha256 = _sha256(_git_blob(BASELINE_COMMIT, RUNNER_PATH))
    now = POOL_TESTS.dt.datetime(2026, 7, 16, 0, 10, tzinfo=POOL_TESTS.dt.timezone.utc)
    later = POOL_TESTS.dt.datetime(2026, 7, 17, 0, 0, tzinfo=POOL_TESTS.dt.timezone.utc)

    def receipt(adapter_digest, *, legacy=False):
        payload = POOL_TESTS.capability_payload()
        certification = payload["certification"]
        if legacy:
            certification["version"] = POOL_TESTS.LEGACY_CERTIFICATION_VERSION
            certification["scheduler_model"] = POOL_TESTS.LEGACY_SCHEDULER_MODEL
            certification["response_time_equation"] = POOL_TESTS.LEGACY_RESPONSE_TIME_EQUATION
            certification.pop("slack_warning_fraction")
            policy = {key: value for key, value in certification.items()
                      if key not in {"policy_sha256", "adapter_implementation_sha256"}}
            certification["policy_sha256"] = POOL.callback_certification_policy_sha256(policy)
        certification["adapter_implementation_sha256"] = adapter_digest
        return POOL.seal_artifact(payload, "receipt_sha256")

    def contract_for(value):
        contract, _ = POOL_TESTS.pool_contract()
        contract = deepcopy(contract)
        contract["capability_receipt_sha256"] = value["receipt_sha256"]
        return POOL.seal_artifact(contract, "contract_sha256")

    current = receipt(baseline_runner_sha256)
    legacy = receipt(baseline_runner_sha256, legacy=True)
    malformed = receipt("not-a-digest")
    unrelated = receipt(POOL_TESTS.sha("unrelated-implementation"))
    cases = {
        "current-shape-baseline-adapter-digest": (current, None, now),
        "current-shape-baseline-adapter-digest-under-contract": (current, contract_for(current), now),
        "current-shape-expired": (current, contract_for(current), later),
        "legacy-certification-historical-read": (legacy, None, now),
        "legacy-certification-as-current-authority": (legacy, contract_for(legacy), now),
        "adapter-digest-malformed": (malformed, None, now),
        # KNOWN DEFECT, labelled, not canonized as safe: the validator checks only
        # the digest's shape, so a digest of no known implementation is accepted.
        "known-defect-adapter-digest-unbound-to-implementation": (unrelated, contract_for(unrelated), now),
    }
    return {
        "validator_source_sha256": _source_sha256(POOL.validate_capability_receipt),
        "baseline_runner_sha256": baseline_runner_sha256,
        "verdicts": {
            label: {
                "input": {"receipt_sha256": value["receipt_sha256"], "under_contract": contract is not None},
                "errors": POOL.validate_capability_receipt(value, expected_contract=contract, now=moment),
            }
            for label, (value, contract, moment) in cases.items()
        },
    }


def adapter_digest_coverage_section() -> dict:
    """Which source files the produced adapter digest covers (copies under a patched root)."""

    covered = {
        "runner": RUNNER_PATH,
        "registered-calibration": CURRENT_CALIBRATION_PATH,
        "AppServer": _defining_file(LIVE.AppServer),
        "AppServerError": _defining_file(LIVE.AppServerError),
        "load_private_bytes": _defining_file(LIVE.load_private_bytes),
        # KNOWN GAP, labelled: AppServer depends on the tool-surface module, but
        # the adapter digest has never covered it.
        "known-gap-codex_tool_surface": _defining_file(SURFACE.require_surface_proof),
    }
    result = {}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        shutil.copytree(ROOT / "policy", root / "policy")
        for relative in set(covered.values()) | set(LIVE.ADAPTER_IMPLEMENTATION_PATHS):
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, root / relative)
        with mock.patch.object(TIMING, "ROOT", root):
            baseline = LIVE.capability_certification()["adapter_implementation_sha256"]
            for label, relative in covered.items():
                original = (root / relative).read_bytes()
                (root / relative).write_bytes(original + b"\n# current dependency coverage probe\n")
                changed = LIVE.capability_certification()["adapter_implementation_sha256"]
                (root / relative).write_bytes(original)
                result[label] = changed != baseline
            stable = LIVE.capability_certification()["adapter_implementation_sha256"] == baseline
    return {"digest_changes_when_file_changes": result, "digest_stable_when_restored": stable}


# --- Maintenance qualification code pins ----------------------------------------------


def code_pins_section() -> dict:
    pins = MQ._code_pins()
    executable = str(Path(sys.executable).resolve())
    relative = sorted(_relative(path) for path in pins if path != executable)
    defining = {
        "runner": RUNNER_PATH,
        "codex_tool_surface-old-path": "scripts/codex_tool_surface.py",
        "AppServer": _defining_file(LIVE.AppServer),
        "AppServerError": _defining_file(LIVE.AppServerError),
        "load_private_bytes": _defining_file(LIVE.load_private_bytes),
        "codex_tool_surface-implementation": _defining_file(SURFACE.require_surface_proof),
    }
    return {
        "pin_paths": relative,
        "interpreter_pinned": executable in pins,
        "covers": {label: path in relative for label, path in defining.items()},
    }


# --- Lazy (function-level) imports of the moved code ----------------------------------

# Modules whose lazy imports reach the moved code, by absolute name.
_TRANSPORT_MODULES = ("run_native_pool_live_canaries", "codex_tool_surface", "cwo_core.codex_tool_surface")


def _module_name(path: Path) -> tuple[str, str]:
    """Module and package name of a file under ``scripts`` (which is on sys.path)."""

    parts = list(path.relative_to(ROOT / "scripts").with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
        return ".".join(parts), ".".join(parts)
    return ".".join(parts), ".".join(parts[:-1])


def _absolute_target(node: ast.ImportFrom, package: str) -> str:
    if not node.level:
        return node.module or ""
    base = package.split(".") if package else []
    base = base[: len(base) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


def _lazy_import_statements(path: Path) -> list[tuple[str, ast.stmt]]:
    """Every import statement inside a function body, with its function path."""

    found: list[tuple[str, ast.stmt]] = []

    def visit(node: ast.AST, scope: str, in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = f"{scope}.{child.name}" if scope else child.name
                visit(child, inner, in_function or not isinstance(child, ast.ClassDef))
                continue
            if in_function and isinstance(child, (ast.Import, ast.ImportFrom)):
                found.append((scope, child))
            visit(child, scope, in_function)

    visit(ast.parse(path.read_text(encoding="utf-8")), "", False)
    return found


def _is_transport_target(name: str) -> bool:
    return name in _TRANSPORT_MODULES or name == "cwo_core.supervision" or name.startswith("cwo_core.supervision.")


def _lazy_consumers() -> dict[str, Path]:
    """Repository modules with a lazy import of the moved code (static scan, nothing imported)."""

    consumers = {}
    for path in sorted((ROOT / "scripts").rglob("*.py")):
        module, package = _module_name(path)
        for _scope, node in _lazy_import_statements(path):
            targets = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                       else [_absolute_target(node, package)])
            if any(_is_transport_target(target) for target in targets):
                consumers[module] = path
    return consumers


# Runner names the baseline lazy imports took from the runner itself.
_RUNNER_LAZY_NAMES = frozenset(
    name for sources in BASELINE_LAZY_IMPORTS.values()
    for name in sources.get("run_native_pool_live_canaries", ()))


def _old_path_label(value, name: str) -> str:
    """The baseline import path a resolved object is identical to.

    Tool-surface names are matched on ``codex_tool_surface``, the transport names
    on the runner; anything else is labelled by its unchanged definition site.
    Unmoved code retains its original module identity.
    """

    if name in vars(SURFACE) and vars(SURFACE)[name] is value:
        return f"codex_tool_surface.{name}"
    if name in _RUNNER_LAZY_NAMES and name in vars(LIVE) and vars(LIVE)[name] is value:
        return f"run_native_pool_live_canaries.{name}"
    if name in _RUNNER_LAZY_NAMES:
        return f"MISMATCH:{name}-is-not-run_native_pool_live_canaries.{name}"
    owner = getattr(value, "__module__", None) or type(value).__module__
    return f"other:{owner}.{getattr(value, '__qualname__', type(value).__qualname__)}"


def resolve_lazy_imports(path: Path, module_name: str, package: str) -> list[dict]:
    """Resolve each lazy import statement's targets the way the interpreter would."""

    resolved = []
    for scope, node in _lazy_import_statements(path):
        if isinstance(node, ast.Import):
            bindings = [(alias.name, alias.asname or alias.name.split(".")[0], alias.name, None)
                        for alias in node.names]
        else:
            target = _absolute_target(node, package)
            bindings = [(target, alias.asname or alias.name, target, alias.name) for alias in node.names]
        for statement_target, bound, module_target, attribute in bindings:
            entry = {"consumer": module_name, "function": scope, "bound_name": bound,
                     "imported_name": attribute or module_target}
            try:
                target_module = importlib.import_module(module_target)
                if attribute is None:
                    value = target_module
                elif hasattr(target_module, attribute):
                    value = getattr(target_module, attribute)
                else:  # ``from package import submodule``
                    value = importlib.import_module(f"{target_module.__name__}.{attribute}")
            except Exception as exc:  # a missing target is the failure this probe exists for
                entry["resolved"] = f"UNRESOLVED:{type(exc).__name__}:{statement_target}:{attribute}"
            else:
                entry["resolved"] = _old_path_label(value, attribute or module_target)
            resolved.append(entry)
    return resolved


def lazy_import_section() -> dict:
    consumers = _lazy_consumers()
    statements = []
    for module_name, path in consumers.items():
        _module, package = _module_name(path)
        statements.extend(resolve_lazy_imports(path, module_name, package))
    # Module-agnostic view: the names each function binds and the old-path object
    # each resolves to. The statement's source module may change; the binding may not.
    bindings = sorted(
        f"{entry['consumer']}:{entry['function']}:{entry['bound_name']}={entry['resolved']}"
        for entry in statements
    )
    return {"consumers": sorted(consumers), "bindings": bindings}


# --- Identities, constants and model identities --------------------------------------


def identity_section() -> dict:
    signature = inspect.signature(LIVE.AppServer.__init__)
    return {
        "model_identities": {
            "EXACT_MODEL": LIVE.EXACT_MODEL,
            "AppServer.requested_model.default": signature.parameters["requested_model"].default,
        },
        "constants": {name: getattr(LIVE, name) for name in MOVED_CONSTANTS},
        "thread_start_phases": sorted(LIVE.THREAD_START_PHASES),
        "surface": {
            "PROOF_TYPE": SURFACE.PROOF_TYPE,
            "PROOF_VERSION": SURFACE.PROOF_VERSION,
            "ALLOWLIST_PARAMETER": SURFACE.ALLOWLIST_PARAMETER,
            "TOOL_PROFILES": {",".join(key): value for key, value in sorted(SURFACE.TOOL_PROFILES.items())},
        },
        "source_sha256": {
            **{name: _source_sha256(getattr(LIVE, name)) for name in MOVED_DEFINITIONS},
            "codex_tool_surface-module": _source_sha256(SURFACE),
        },
    }


SECTIONS = {
    "validator_contracts": validator_contract_section,
    "tool_surface": tool_surface_section,
    "capability_receipts": capability_receipt_section,
    "adapter_digest_coverage": adapter_digest_coverage_section,
    "code_pins": code_pins_section,
    "lazy_imports": lazy_import_section,
    "identities": identity_section,
}


def compute(names=None) -> dict:
    return json.loads(json.dumps(
        {name: SECTIONS[name]() for name in (names or SECTIONS)}, sort_keys=True, default=str))


def _r5_surface_source_identity(expected: str, current_pin: str) -> str:
    """The full archived module is preserved after reversing exact probe edits."""
    source = Path(SURFACE.__file__).read_text()
    edits = (
        ('def _codex_version(binary: Path, *, codex_home: Path | None = None) -> str:\n',
         'def _codex_version(binary: Path) -> str:\n'),
        ('        env=None if codex_home is None else dict(os.environ, CODEX_HOME=str(codex_home),\n'
         '                                                PATH=str(binary.parent) + os.pathsep + os.defpath),\n', ''),
        ('    expected_binary: Path | str | None = None,\n', ''),
        ('    """Freeze causal host inputs; reject an unselected binary before probe reads."""',
         '    """Freeze causal host inputs BEFORE the process and capture exist."""'),
        ('    if expected_binary is not None and (not isinstance(expected_binary, (str, Path))\n'
         '            or not Path(expected_binary).is_absolute() or binary != Path(expected_binary).resolve()):\n'
         '        raise CodexToolSurfaceError("codex-capture-binding-drift:codex_binary")\n', ''),
        ('"codex_version": _codex_version(binary, codex_home=home), "codex_home": str(home),',
         '"codex_version": _codex_version(binary), "codex_home": str(home),'),
        ('            permitted_tools=value["requested_tools"], catalog_projection=startup.get("model_catalog_json"),\n'
         '            expected_binary=value["codex_binary"])',
         '            permitted_tools=value["requested_tools"], catalog_projection=startup.get("model_catalog_json"))'),
    )
    historical = source
    for current, previous in edits:
        if historical.count(current) != 1:
            raise AssertionError('r5-probe-source-lineage-drift')
        historical = historical.replace(current, previous)
    if _sha256(historical) != expected or _sha256(source) != current_pin:
        raise AssertionError('r5-probe-source-binding-drift')
    return _sha256(source)


def _historical_transport_fixture():
    """Pinned pre-repair bytes; never execute or select this historical source."""
    raw = LEGACY_TRANSPORT_SOURCE.read_bytes()
    if _sha256(raw) != LEGACY_TRANSPORT_MODULE_SHA256:
        raise AssertionError("pre-repair-transport-module-binding-drift")
    lines = raw.decode("utf-8").splitlines(keepends=True)
    node = next(node for node in ast.parse(raw).body if isinstance(node, ast.ClassDef) and node.name == "AppServer")
    source = "".join(lines[node.lineno - 1:node.end_lineno])
    if _sha256(source) != LEGACY_TRANSPORT_CLASS_SHA256:
        raise AssertionError("pre-repair-transport-class-binding-drift")
    methods = {child.name: "".join(lines[child.lineno - 1:child.end_lineno])
               for child in node.body if isinstance(child, ast.FunctionDef)}
    return source, methods


def _current_transport_source(manifest):
    source = inspect.getsource(LIVE.AppServer)
    transport = Path(inspect.getfile(LIVE.AppServer)).read_bytes()
    if _sha256(transport) != manifest["files"]["scripts/cwo_core/supervision/transport/app_server.py"]:
        raise AssertionError("current-transport-source-binding-drift")
    lines = transport.decode("utf-8").splitlines(keepends=True)
    node = next(node for node in ast.parse(transport).body if isinstance(node, ast.ClassDef) and node.name == "AppServer")
    if source != "".join(lines[node.lineno - 1:node.end_lineno]):
        raise AssertionError("current-transport-class-binding-drift")
    return source


def load_golden() -> dict:
    """Bind public fixture digests, retained semantic outcomes and current sources."""
    historical = GOLDEN.read_bytes()
    document = json.loads(historical)
    path = GOLDEN.with_name("source-pins-2026-10-23.json")
    pins = json.loads(path.read_bytes())
    if pins["public_golden_sha256"] != _sha256(historical):
        raise AssertionError("public-golden-changed")
    allowed = {"validator_contracts", "generation11_runner_source"}
    if set(pins["source_pins"]) != allowed:
        raise AssertionError("source-pin-scope-invalid")
    for section, pin in pins["source_pins"].items():
        if document["sections"][section]["validator_source_sha256"] != pin["fixture"]:
            raise AssertionError("public-fixture-source-pin-mismatch")
        document["sections"][section]["validator_source_sha256"] = pin["current"]
    # Current module/class bindings cover the repaired transport. Historical
    # lineage is independently reconstructed only from the pinned pre-repair
    # fixture. No stripping of current limits or historical semantic claim.
    manifest = ROOT / "tests/fixtures/affected_contract_compatibility/EXAMPLE-manifest.json"
    manifest_value = json.loads(manifest.read_bytes())
    current_app_server = manifest_value["current_app_server_source_sha256"]
    identities = document["sections"]["identities"]["source_sha256"]
    rpc_error = _source_sha256(LIVE.AppServerRpcError)
    if rpc_error != manifest_value["current_app_server_rpc_error_source_sha256"]:
        raise AssertionError("current-rpc-error-class-binding-drift")
    identities["AppServerRpcError"] = rpc_error
    identities["codex_tool_surface-module"] = _r5_surface_source_identity(
        identities["codex_tool_surface-module"], manifest_value["files"]["scripts/cwo_core/codex_tool_surface.py"])
    # The full-module reversal above verifies the former validator bytes too.
    document["sections"]["tool_surface"]["validator_source_sha256"]["require_capture_binding"] = (
        _source_sha256(SURFACE.require_capture_binding))
    source = _current_transport_source(manifest_value)
    # Apply the retained exact hold/launch reversals to historical fixture
    # methods only; the repaired current implementation is checked separately.
    historical_source, historical_methods = _historical_transport_fixture()
    for name, count in (("notify", 1), ("request", 2), ("request_once_with_guard", 2)):
        current = historical_methods[name]
        gate = "_require_native_rpc(method)\n"
        if current.count(gate) != count:
            raise AssertionError("native RPC gate occurrence count changed: " + name)
        previous = "".join(line for line in current.splitlines(keepends=True) if line.strip() != gate.strip())
        historical_source = historical_source.replace(current, previous)
    current = historical_methods["start_turn"]
    entry = "        live_availability.require_n1_live()\n"
    wire = "            live_availability.require_n1_live()\n"
    if current.count("live_availability.require_n1_live()") != 2:
        raise AssertionError("turn entry/wire guard occurrence count changed")
    previous = current.replace(wire, "").replace(entry, "")
    historical_source = historical_source.replace(current, previous)
    # Explicit raw launch selection changes are reversed one exact edit at a time
    # before the held-route lineage check; historical golden bytes stay pinned.
    launch_edits = (
        ('        executable: Path | str | None = None,\n'
         '        codex_home: Path | str | None = None,\n', ''),
        ('            home = None\n',
         '            home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).resolve()\n'),
        ('                binding = _explicit_probe_binding(executable, codex_home,\n'
         '                    self.requested_model, tool_surface_probe_catalog)\n',
         '                binding = prepare_capture_binding(home, requested_model=self.requested_model,\n'
         '                    permitted_tools=["exec_command", "write_stdin"], catalog_projection=tool_surface_probe_catalog)\n'),
        ('            else:\n                home = _explicit_launch_home(executable, codex_home)\n', ''),
        ('            self.launched_executable = binding["codex_binary"] if binding else str(executable)\n',
         '            self.launched_executable = binding["codex_binary"] if binding else str(_codex_binary())\n'),
        ('            environment = dict(os.environ, CODEX_HOME=str(home),\n'
         '                               PATH=str(Path(self.launched_executable).parent))\n',
         '            environment = dict(os.environ, CODEX_HOME=str(home))\n'),
    )
    for current, previous in launch_edits:
        if historical_source.count(current) != 1:
            raise AssertionError("r5-explicit-launch-lineage-drift")
        historical_source = historical_source.replace(current, previous)
    gate = "            live_availability.require_n1_live()\n"
    if historical_source.count(gate) != 2 or _sha256(historical_source.replace(gate, "")) != current_app_server:
        raise AssertionError("f5-held-route-transport-lineage-drift")
    current_app_server = _sha256(source)
    document["sections"]["identities"]["source_sha256"]["AppServer"] = current_app_server
    document["sections"]["tool_surface"]["validator_source_sha256"]["AppServer"] = current_app_server
    return document


class GoldenVerdictTests(unittest.TestCase):
    """Each section preserves its contract outcomes under neutral fixture identities."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = load_golden()["sections"]

    def check(self, name: str) -> dict:
        observed = compute([name])[name]
        expected = self.golden[name]
        if name == "validator_contracts":
            expected = {key: value for key, value in expected.items() if key != "validator_source_sha256"}
        if name == "identities":
            identities = dict(expected["model_identities"])
            del identities["CONTRACTS.EXACT_OPERATIVE_MODEL"]
            expected = {**expected, "model_identities": identities}
        self.assertEqual(observed, expected)
        return observed

    def test_frozen_validator_contract_digests_are_unchanged(self) -> None:
        observed = self.check("validator_contracts")
        verdicts = observed["verdicts"]
        # The baseline tree binds every contract; unavailable history fails clearly.
        for name in CONTRACT_FUNCTIONS:
            self.assertEqual(verdicts[f"{name}@b8f6251-baseline"]["outcome"], "returned")
            self.assertEqual(verdicts[f"{name}@malformed-tree"]["message"], "validator-contract-tree-invalid")
            self.assertTrue(verdicts[f"{name}@unknown-tree"]["message"].startswith("validator-contract-path-invalid:"))
        # Independent semantic witness: a neutral V5 config must let V6 reach
        # the absent authorization-v11 schema, just as the original input did.
        witness = verdicts["v6@e7f5406-v5-introduced-generation11"]
        self.assertEqual(witness["outcome"], "refused")
        self.assertEqual(witness["error_type"], "ValueError")
        self.assertEqual(witness["message"],
                         "validator-contract-path-invalid:schemas/full-auto-run-authorization-v11.schema.json")
        config = "scripts/cwo_core/native_pool_config.py"
        v5_tree = FIXTURE.trees["v5"]
        self.assertEqual(FIXTURE.git("ls-tree", v5_tree, "--", config).split()[0], "100644")
        # Retain the earlier missing-config refusal separately, outside the
        # unchanged 36-case matrix, using only neutral V5-roster bytes.
        missing_config = FIXTURE.tree({
            name: FIXTURE.blob(FIXTURE.commits["v5"], name)
            for name in CONTRACTS.VALIDATOR_CONTRACT_PATHS_V5})
        self.assertEqual(_outcome(CONTRACTS.validator_contract_sha256_v6, FIXTURE.root, missing_config),
                         {"outcome": "refused", "error_type": "ValueError",
                          "message": "validator-contract-path-invalid:scripts/cwo_core/native_pool_config.py"})

    def test_moved_paths_are_in_no_frozen_contract_list(self) -> None:
        moved = {
            _defining_file(LIVE.AppServer), _defining_file(LIVE.AppServerError),
            _defining_file(LIVE.load_private_bytes), _defining_file(SURFACE.require_surface_proof),
        } - {RUNNER_PATH, "scripts/codex_tool_surface.py"}
        for name in CONTRACT_FUNCTIONS:
            paths = set(getattr(CONTRACTS, "VALIDATOR_CONTRACT_PATHS_" + name.upper()))
            self.assertIn(RUNNER_PATH, paths)
            self.assertFalse(moved & paths, name)

    def test_archived_launcher_refuses_historical_authorization_with_zero_effects(self) -> None:
        launcher_before_retirement()
        run_archived_cases(
            self, PRE_RETIREMENT,
            "tests.test_w20_affected_contract_w13.GoldenVerdictTests."
            "test_launcher_refuses_historical_authorization_with_zero_effects",
        )

    def test_archived_validator_and_record_source_pins(self) -> None:
        suite = "tests.test_w20_affected_contract_w13.GoldenVerdictTests."
        run_archived_cases(
            self, RETIRED_CAMPAIGN,
            suite + "test_frozen_validator_contract_digests_are_unchanged",
            suite + "test_moved_paths_are_in_no_frozen_contract_list",
            suite + "test_generation11_runner_source_binding_is_unchanged",
            suite + "test_template_records_are_recorded_as_observed",
            suite + "test_f5_held_route_identities_keep_historical_lineage_with_explicit_gates",
        )

    def test_neutral_generation11_git_sources_match_golden(self) -> None:
        revision = FIXTURE.commits["generation11"]
        self.assertEqual(FIXTURE.git("rev-parse", revision + "^{tree}"), FIXTURE.trees["generation11"])
        expected = self.golden["generation11_runner_source"]
        for name, path in (("runner", RUNNER_PATH), ("session_boundary", BOUNDARY_PATH)):
            with self.subTest(path=path):
                self.assertEqual(_sha256(_git_blob(revision, path)), expected[f"history_{name}_blob_sha256"])

    def test_public_generation11_git_sources_match_recorded_digests(self) -> None:
        revision = "e7f540654e0ed605e4720bd4d3b670a11cb8f701"
        self.assertEqual(pinned_git(revision, "rev-parse", revision + "^{tree}"),
                         b"ccd2663b0ca4127ce562159e53f4de1a43e0cc69\n")
        observed = {name: _sha256(pinned_blob(revision, path))
                    for name, path in (("runner", RUNNER_PATH), ("boundary", BOUNDARY_PATH))}
        self.assertEqual(observed, contract_evidence()["production_generation11_sources"])

    def test_tool_surface_historical_proofs_verify_but_grant_no_dispatch(self) -> None:
        observed = self.check("tool_surface")
        verifier, entry = observed["verifier"], observed["entry_points"]
        for label in ("v4-historical", "v3-historical", "v2-historical"):
            self.assertEqual(verifier[label]["historical_verifier_errors"], [], label)
            self.assertEqual(verifier[label]["current_dispatch_authority"]["message"],
                             "codex-tool-surface-historical-proof-not-dispatch-authority")
        self.assertEqual(verifier["v5-current"]["current_dispatch_authority"]["outcome"], "returned")
        for label, record in entry.items():
            if label == "v5-current":
                # Control: the spies are wired, so a current proof reaches the effect.
                self.assertEqual(record["app_server_construction"]["popen_calls"], 1)
                self.assertEqual(record["thread_start"]["request_calls"], 1)
                continue
            with self.subTest(label=label):
                self.assertEqual(record["app_server_construction"]["outcome"], "refused")
                self.assertEqual(record["app_server_construction"]["popen_calls"], 0)
                self.assertEqual(record["thread_start"]["outcome"], "refused")
                self.assertEqual(record["thread_start"]["request_calls"], 0)
                self.assertEqual(record["thread_start"]["popen_calls"], 0)

    def test_capability_receipt_verdicts_are_unchanged(self) -> None:
        observed = self.check("capability_receipts")
        verdicts = observed["verdicts"]
        self.assertEqual(verdicts["legacy-certification-historical-read"]["errors"], [])
        self.assertTrue(verdicts["legacy-certification-as-current-authority"]["errors"])
        self.assertEqual(verdicts["known-defect-adapter-digest-unbound-to-implementation"]["errors"], [])

    def test_f5_held_route_adapter_digest_covers_transport_and_availability(self) -> None:
        observed = compute(["adapter_digest_coverage"])["adapter_digest_coverage"]
        changes = observed["digest_changes_when_file_changes"]
        golden = self.golden["adapter_digest_coverage"]["digest_changes_when_file_changes"]
        self.assertEqual(changes, {**golden, "runner": False, "registered-calibration": True})
        self.assertTrue(observed["digest_stable_when_restored"])

    def test_code_pins_still_cover_the_moved_code(self) -> None:
        observed = compute(["code_pins"])["code_pins"]
        golden = self.golden["code_pins"]
        self.assertLessEqual(set(golden["pin_paths"]) - RETIRED_CALIBRATION_PATHS, set(observed["pin_paths"]))
        self.assertFalse(RETIRED_CALIBRATION_PATHS & set(observed["pin_paths"]))
        self.assertEqual(observed["covers"], {**golden["covers"], "runner": False})
        self.assertEqual(observed["interpreter_pinned"], golden["interpreter_pinned"])
        self.assertTrue(all(covered for label, covered in observed["covers"].items() if label != "runner"))

    def test_f5_held_route_identities_keep_historical_lineage_with_explicit_gates(self) -> None:
        self.check("identities")


class TransportLineageBindingTests(unittest.TestCase):
    """Historical source lineage and current fixture outcomes are distinct."""

    def test_pinned_historical_fixture_is_distinct_from_current_transport(self) -> None:
        historical, methods = _historical_transport_fixture()
        self.assertEqual(_sha256(historical), LEGACY_TRANSPORT_CLASS_SHA256)
        self.assertIn("for raw in self.process.stdout:", methods["_read_stdout"])
        self.assertNotEqual(_sha256(inspect.getsource(LIVE.AppServer)), LEGACY_TRANSPORT_CLASS_SHA256)
        observed = load_golden()["sections"]["identities"]["source_sha256"]["AppServer"]
        self.assertEqual(observed, _source_sha256(LIVE.AppServer))

    def test_historical_module_and_class_tampering_are_refused(self) -> None:
        module = sys.modules[__name__]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "historical.txt"
            path.write_bytes(LEGACY_TRANSPORT_SOURCE.read_bytes() + b"\n# changed\n")
            with mock.patch.object(module, "LEGACY_TRANSPORT_SOURCE", path):
                with self.assertRaisesRegex(AssertionError, "^pre-repair-transport-module-binding-drift$"):
                    _historical_transport_fixture()
        with mock.patch.object(module, "LEGACY_TRANSPORT_CLASS_SHA256", "0" * 64):
            with self.assertRaisesRegex(AssertionError, "^pre-repair-transport-class-binding-drift$"):
                _historical_transport_fixture()

    def test_current_module_and_loaded_class_tampering_are_refused(self) -> None:
        read = Path.read_bytes
        transport = Path(inspect.getfile(LIVE.AppServer))
        def changed(path):
            raw = read(path)
            return raw + b"\n# changed\n" if path == transport else raw
        with mock.patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(AssertionError, "^current-transport-source-binding-drift$"):
                load_golden()
        source = inspect.getsource
        def changed_class(value):
            text = source(value)
            return text + "\n# changed\n" if value is LIVE.AppServer else text
        with mock.patch.object(inspect, "getsource", changed_class):
            with self.assertRaisesRegex(AssertionError, "^current-transport-class-binding-drift$"):
                load_golden()

        def changed_rpc_error(value):
            text = source(value)
            return text + "\n# changed\n" if value is LIVE.AppServerRpcError else text
        with mock.patch.object(inspect, "getsource", changed_rpc_error):
            with self.assertRaisesRegex(AssertionError, "^current-rpc-error-class-binding-drift$"):
                load_golden()


class ConsumerCompatibilityTests(unittest.TestCase):
    """Preserve baseline observations and check explicitly moved current owners."""

    def test_baseline_imports_resolve_to_the_same_objects(self) -> None:
        for consumer_name, sources in BASELINE_IMPORTS.items():
            consumer = importlib.import_module(consumer_name)
            for source_name, names in sources.items():
                source = importlib.import_module(source_name)
                for name in names:
                    with self.subTest(consumer=consumer_name, source=source_name, name=name):
                        if consumer_name == "run_native_pool_activation_preview" and name in RETIRED_PREVIEW_IMPORTS:
                            self.assertFalse(hasattr(consumer, name))
                            continue
                        # The baseline inventory stays historical. The pure helper
                        # retains its owning module without rewriting the facade.
                        current = source
                        if (consumer_name, source_name, name) == (
                            "cwo_core.maintenance_native_runtime",
                            "run_native_pool_live_canaries", "turn_items",
                        ):
                            current = importlib.import_module("cwo_core.supervision.turn_observations")
                        self.assertIs(getattr(consumer, name), getattr(current, name))

    def test_current_turn_owner_preserves_frozen_helper_implementations(self) -> None:
        owner = importlib.import_module("cwo_core.supervision.turn_observations")
        runtime = importlib.import_module("cwo_core.maintenance_native_runtime")
        self.assertIs(runtime.turn_items, owner.turn_items)
        self.assertIsNot(runtime.turn_items, LIVE.turn_items)
        for name in ("turn_from_thread", "turn_items"):
            with self.subTest(helper=name):
                old = getattr(LIVE, name)
                current = getattr(owner, name)
                self.assertIs(old, getattr(EVIDENCE, name))
                self.assertEqual(old.__module__, "cwo_core.supervision.session_evidence")
                self.assertEqual(current.__module__, "cwo_core.supervision.turn_observations")
                self.assertEqual(
                    ast.dump(ast.parse(inspect.getsource(old))),
                    ast.dump(ast.parse(inspect.getsource(current))),
                )

    def test_lazy_imports_resolve_to_the_same_objects(self) -> None:
        # Each function-level import statement in every lazy consumer of the moved
        # code is resolved as the interpreter would, so a missing module or name
        # inside a function body fails here instead of at run time.
        observed = compute(["lazy_imports"])["lazy_imports"]
        unresolved = [binding for binding in observed["bindings"] if "=UNRESOLVED:" in binding]
        self.assertEqual(unresolved, [])
        historical = load_golden()["sections"]["lazy_imports"]
        retired = "cwo_core.maintenance_qualification:observe_qualification:"
        retained = [binding for binding in historical["bindings"] if not binding.startswith(retired)]
        self.assertEqual(observed, {"consumers": historical["consumers"], "bindings": retained})
        self.assertIn("cwo_core.maintenance_qualification", observed["consumers"])

    def test_retired_observer_refuses_non_capability_before_effects(self) -> None:
        with mock.patch("subprocess.Popen", side_effect=_EffectReached) as popen, \
                mock.patch.object(LIVE.AppServer, "request", side_effect=_EffectReached) as request:
            with self.assertRaisesRegex(Exception, "opaque-operation-required"):
                MQ.observe_qualification(
                    operation=None, verifier=None, plan=None, workspace=Path("/nonexistent"),
                    output=Path("/nonexistent/output"), session_ledger=None, tool_surface_proof={},
                    control_image_sha256="0" * 64, fit_prompt="")
        self.assertEqual(popen.call_count, 0)
        self.assertEqual(request.call_count, 0)

    def test_patch_on_the_tool_surface_module_reaches_the_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            world = _SurfaceWorld(Path(directory))
            proof = world.proofs()["v5-current"]
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, {"PATH": str(world.empty_path)}))
                popen = stack.enter_context(mock.patch("subprocess.Popen", side_effect=_EffectReached))
                # Without the patch no codex can be found, so construction is refused.
                with self.assertRaisesRegex(LIVE.AppServerError, "codex-binary-unavailable"):
                    LIVE.AppServer(tool_surface_proof=deepcopy(proof))
                self.assertEqual(popen.call_count, 0)
                world.patches(stack)
                with self.assertRaises(_EffectReached):
                    LIVE.AppServer(tool_surface_proof=deepcopy(proof))
                self.assertEqual(popen.call_count, 1)


INSTALLED_PROBE = r"""
import hashlib, inspect, json, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "scripts"))
import run_native_pool_live_canaries as LIVE
import codex_tool_surface as SURFACE
import check_codex_worker_surface as CHECK
import run_native_pool_activation_preview as PREVIEW
from cwo_core import maintenance_native_runtime as RUNTIME
from cwo_core import maintenance_qualification as MQ
prefixes = tuple(str(Path(p).resolve()) for p in {sys.prefix, sys.base_prefix, sys.exec_prefix})
loaded = sorted({str(Path(m.__file__).resolve()) for m in list(sys.modules.values())
                 if isinstance(getattr(m, "__file__", None), str)})
outside = [p for p in loaded if not p.startswith(str(root) + "/") and not p.startswith(prefixes)]
executable = str(Path(sys.executable).resolve())
pins = MQ._code_pins()
def source(value):
    return hashlib.sha256(inspect.getsource(value).encode()).hexdigest()
print(json.dumps({
    "outside": outside,
    "pins_outside": sorted(p for p in pins if p != executable and not p.startswith(str(root) + "/")),
    "app_server_file_inside": inspect.getsourcefile(LIVE.AppServer).startswith(str(root) + "/"),
    "one_app_server": LIVE.AppServer is PREVIEW.AppServer is RUNTIME.AppServer,
    "probe_validates_shared_tools": CHECK.normalized_tools is SURFACE.normalized_tools,
    "test_only_host_absent": not (root / "scripts/qualified_n1_host.py").exists(),
    "app_server_source_sha256": source(LIVE.AppServer),
    "surface_source_sha256": source(SURFACE),
}, sort_keys=True))
"""


class InstalledProjectionTests(unittest.TestCase):
    """The installed skill carries the whole transport closure and nothing leaks to the repo."""

    def test_f5_held_route_installed_skill_imports_current_transport_from_its_own_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            skills = work / "skills"
            installed = subprocess.run(
                [str(ROOT / "scripts" / "install.sh"), "--skills-dir", str(skills), "--yes"],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr or installed.stdout)
            target = skills / "complex-work-orchestration"
            empty = work / "empty-path"
            empty.mkdir()
            probe = subprocess.run(
                [sys.executable, "-I", "-c", INSTALLED_PROBE, str(target)],
                cwd=work, capture_output=True, text=True, check=False,
                env={"PATH": str(empty), "HOME": str(work), "LC_ALL": "C.UTF-8",
                     "TMPDIR": tempfile.gettempdir()},
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            observed = json.loads(probe.stdout)
        identities = load_golden()["sections"]["identities"]["source_sha256"]
        self.assertEqual(observed["outside"], [])
        self.assertEqual(observed["pins_outside"], [])
        self.assertTrue(observed["app_server_file_inside"])
        self.assertTrue(observed["one_app_server"])
        self.assertTrue(observed["probe_validates_shared_tools"])
        self.assertTrue(observed["test_only_host_absent"])
        self.assertEqual(observed["app_server_source_sha256"], identities["AppServer"])
        self.assertEqual(observed["surface_source_sha256"], identities["codex_tool_surface-module"])


def _assert_current_caller_bindings(case, checkpoint, manifest):
    """Original lifecycle fakes and direct callers are compatibility inputs."""
    # The selected four-component source retains the original transport and request caller.
    name = "tests/test_registered_n1_factory.py"
    reference = "references/registered-effect-contract.md"
    case.assertIn(name, manifest["registered_current_consumers"])
    request_caller = "tests/test_registered_server_requests.py"
    case.assertIn(request_caller, manifest["registered_current_consumers"])
    for binding in (name, reference, request_caller):
        case.assertEqual(manifest["registered_source_callers"][binding],
                         _sha256((ROOT / binding).read_bytes()))
        case.assertEqual(manifest["files"][binding], _sha256((ROOT / binding).read_bytes()))
    native_methods = {node.name for node in ast.walk(ast.parse((ROOT / name).read_bytes()))
                      if isinstance(node, ast.FunctionDef)}
    case.assertIn("test_original_registered_useful_then_forbidden_effect_matrix", native_methods)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'"""Neutral obsolete caller fixture; never executed."""\n')
        with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency drift: " + name):
            checkpoint.verify_files(root, {name: manifest["files"][name]})
        for name in manifest["registered_current_consumers"]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = (ROOT / name).read_bytes()
            expected = {name: manifest["files"][name]}
            modes = {name: manifest["current_file_modes"][name]}
            path.write_bytes(raw)
            path.chmod(modes[name])
            checkpoint.verify_files(root, expected)
            checkpoint.verify_modes(root, modes)
            path.chmod(modes[name] ^ 0o100)
            with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "mode drift"):
                checkpoint.verify_modes(root, modes)
            path.chmod(modes[name])
            path.write_bytes(raw + b"\n# EXAMPLE original caller drift\n")
            with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency drift"):
                checkpoint.verify_files(root, expected)
            path.unlink()
            with case.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                checkpoint.verify_files(root, expected)


class RunIdentityReport(unittest.TestCase):
    """Bind finite registered consumers and report the loaded source identity."""

    def test_f5_f6_report_current_run_identity(self) -> None:
        import verify_affected_historical_contract as checkpoint

        registered = checkpoint.registered_consumer_observations()
        manifest = json.loads((ROOT / checkpoint.MANIFEST).read_bytes())
        self.assertEqual(registered["current_roots"], manifest["registered_current_roots"])
        self.assertIn("scripts/verify_affected_historical_contract.py",
                      manifest["local_import_edges"]["tests/test_w20_affected_contract_w13.py"])
        _assert_current_caller_bindings(self, checkpoint, manifest)
        self.assertFalse(registered["current_authority"])
        self.assertEqual(registered["hostless_execution_refusal"], "registered-pool-host-required")
        # The checkpoint binds every registered producer/pool path.
        # paths. Exercise actual missing/changed files without new test methods.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in [*registered["current_roots"], "scripts/verify_affected_historical_contract.py",
                         *manifest["registered_current_resources"]]:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = (ROOT / name).read_bytes()
                expected = {name: manifest["files"][name]}
                target.write_bytes(raw)
                checkpoint.verify_files(root, expected)
                target.write_bytes(raw + b"\n# EXAMPLE current dependency drift\n")
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency drift"):
                    checkpoint.verify_files(root, expected)
                target.unlink()
                with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                    checkpoint.verify_files(root, expected)
            # Mandatory review snapshots the full policy roster beyond Python imports.
            # the full policy roster, beyond Python import edges. Missing/extra
            # policy files must invalidate the checkpoint before history/imports.
            manifest_path = root / checkpoint.MANIFEST
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_bytes((ROOT / checkpoint.MANIFEST).read_bytes())
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "policy roster drift"):
                checkpoint.verify_fixture_checkpoint(root=root)
            # Isolate an addition to a complete genuine roster. The missing
            # dependency refusal shows that the exact roster gate passed first.
            self.assertIn("policy/qualification-target.yaml", manifest["registered_current_resources"])
            policies = {checkpoint.MODEL_ROLE_POLICY, *(name for name in manifest["registered_current_resources"]
                                                        if name.startswith("policy/"))}
            expected = {name for name in policies if name.endswith(".yaml")}
            self.assertEqual({str(path.relative_to(ROOT)) for path in (ROOT / "policy").glob("*.yaml")}, expected)
            for name in sorted(policies):
                source = ROOT / name
                (root / name).write_bytes(source.read_bytes())
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                checkpoint.verify_fixture_checkpoint(root=root)
            self.assertEqual({str(path.relative_to(root)) for path in (root / "policy").glob("*.yaml")}, expected)
            (root / "policy/EXAMPLE-extra-policy.yaml").write_text("{}\n")
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "policy roster drift"):
                checkpoint.verify_fixture_checkpoint(root=root)
        scripts = (ROOT / "scripts").resolve()
        closure = {}
        for module in list(sys.modules.values()):
            path = getattr(module, "__file__", None)
            if isinstance(path, str) and Path(path).resolve().is_relative_to(scripts):
                closure[_relative(path)] = _sha256(Path(path).read_bytes())
        print("\nOffline transport run identity " + json.dumps({
            "interpreter": sys.version.split()[0],
            "golden_sha256": _sha256(GOLDEN.read_bytes()),
            "loaded_scripts_closure": dict(sorted(closure.items())),
        }, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-golden"]:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "consumer": "transport",
            "checkpoint": "offline-transport-compatibility",
            "baseline_commit": BASELINE_COMMIT,
            "interpreter": sys.version.split()[0],
            "note": "Observed verdicts at the baseline. Not proof of equivalence beyond these inputs; grants no current authority.",
            "sections": compute(),
        }
        GOLDEN.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {GOLDEN}")
    else:
        unittest.main()
