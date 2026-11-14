"""Offline transport compatibility under public, self-contained contract inputs.

Real validators, legacy import paths, entry-point holds and tamper refusals are
exercised with neutral disposable Git objects. The fixture digest projection is
distinct from archived provenance. No model/provider or network calls are made;
Git and disposable fixture processes are used.
Golden semantic outcomes must remain unchanged when fixture identities change.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib
import inspect
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import codex_tool_surface as SURFACE  # noqa: E402
import run_native_pool_live_canaries as LIVE  # noqa: E402
from cwo_core import maintenance_qualification as MQ  # noqa: E402
from cwo_core import native_live_campaign_contracts as CONTRACTS  # noqa: E402
from cwo_core import native_pool_contracts as POOL  # noqa: E402
from tests import test_codex_tool_surface as SURFACE_TESTS  # noqa: E402
from tests import test_native_live_campaign_generation12 as G12  # noqa: E402
from tests import test_native_pool_contracts as POOL_TESTS  # noqa: E402


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
GENERATION11_COMMIT = FIXTURE.commits["generation11"]
GENERATION11_TREE = FIXTURE.trees["generation11"]
BASELINE_TREE = FIXTURE.trees["baseline"]
RUNNER_PATH = "scripts/run_native_pool_live_canaries.py"
BOUNDARY_PATH = "scripts/cwo_core/native_session_boundary.py"

# Names each runtime consumer imported at the baseline, by old module path.
BASELINE_IMPORTS = {
    "check_codex_worker_surface": {
        "codex_tool_surface": [
            "CodexToolSurfaceError", "EXACT_READ_ONLY_TOOLS",
            "EXACT_CORE_RESOURCE_OPERATIVE_TOOLS", "EXACT_CORE_RESOURCE_READ_ONLY_TOOLS",
            "tools_are_mutable", "normalized_tools", "prepare_capture_binding",
            "require_capture_binding", "bind_capture_process", "canonical_sha256",
            "prepare_read_only_catalog", "build_surface_proof", "probe_thread_config",
            "validate_surface_proof",
        ],
        "run_native_pool_live_canaries": ["AppServer", "AppServerError"],
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
        "validator_source_sha256": _source_sha256(CONTRACTS._validator_contract_sha256),
        "path_lists": paths,
        "legacy_alias_is_v1": CONTRACTS.VALIDATOR_CONTRACT_PATHS is CONTRACTS.VALIDATOR_CONTRACT_PATHS_V1,
        "verdicts": verdicts,
    }


# --- Generation 11 runner-source binding ----------------------------------------------


def _generation11_rebound(proof, bindings, manifest, *, runner, boundary, commit, tree):
    contracts = G12.CONTRACTS
    value = deepcopy(proof.terminal_facts.value)
    value["source_bindings"]["generation11_runner_source_sha256"] = _sha256(runner)
    value["source_bindings"]["generation11_session_boundary_source_sha256"] = _sha256(boundary)
    value["source_root_sha256"] = contracts.canonical_sha256(value["source_bindings"])
    value["identity"]["candidate_commit"] = commit
    value["identity"]["candidate_tree"] = tree
    snapshot = G12.Generation12ContractTests._reseal(value, "canonical_terminal_facts_sha256")
    rebound_manifest = deepcopy(manifest)
    rebound_manifest["candidate"] = {"commit": commit, "tree": tree}
    rebound_bindings = deepcopy(bindings)
    rebound_bindings.update({
        "predecessor_terminal_facts_file_sha256": snapshot.raw_sha256,
        "predecessor_terminal_facts_canonical_sha256": snapshot.value["canonical_terminal_facts_sha256"],
        "predecessor_generation11_runner_source_sha256": _sha256(runner),
        "predecessor_generation11_session_boundary_source_sha256": _sha256(boundary),
    })
    rebound_proof = replace(
        proof,
        terminal_facts=snapshot,
        generation11_runner_source_bytes=runner,
        generation11_session_boundary_source_bytes=boundary,
    )
    return snapshot, rebound_bindings, rebound_proof, rebound_manifest


def generation11_section() -> dict:
    contracts = G12.CONTRACTS
    counter = itertools.count(1)
    with mock.patch("uuid.uuid4", side_effect=lambda: uuid.UUID(int=next(counter))):
        proof, bindings, authorization, manifest, failure, _hashes = (
            G12.Generation12ContractTests("run").terminal_facts_fixture()
        )
    historical_runner = _git_blob(GENERATION11_COMMIT, RUNNER_PATH)
    historical_boundary = _git_blob(GENERATION11_COMMIT, BOUNDARY_PATH)
    baseline_runner = _git_blob(BASELINE_COMMIT, RUNNER_PATH)
    cases = {
        "historical-record-repo-bound": dict(
            runner=historical_runner, boundary=historical_boundary,
            commit=GENERATION11_COMMIT, tree=GENERATION11_TREE, repo=True),
        "historical-record-without-repo": dict(
            runner=historical_runner, boundary=historical_boundary,
            commit=GENERATION11_COMMIT, tree=GENERATION11_TREE, repo=False),
        "relabelled-to-baseline-commit": dict(
            runner=historical_runner, boundary=historical_boundary,
            commit=BASELINE_COMMIT, tree=BASELINE_TREE, repo=True),
        "unknown-commit": dict(
            runner=historical_runner, boundary=historical_boundary,
            commit="f" * 40, tree="e" * 40, repo=True),
        "baseline-runner-bytes-rebound": dict(
            runner=baseline_runner, boundary=historical_boundary,
            commit=GENERATION11_COMMIT, tree=GENERATION11_TREE, repo=True),
        "tampered-runner-byte-rebound": dict(
            runner=historical_runner + b"\n", boundary=historical_boundary,
            commit=GENERATION11_COMMIT, tree=GENERATION11_TREE, repo=True),
    }
    verdicts = {}
    for label, case in cases.items():
        snapshot, rebound_bindings, rebound_proof, rebound_manifest = _generation11_rebound(
            proof, bindings, manifest, runner=case["runner"], boundary=case["boundary"],
            commit=case["commit"], tree=case["tree"])
        # Only source identity inputs differ from production; the full real
        # semantic, canonical-binding and Git-blob validation remains active.
        with mock.patch.multiple(contracts,
                GENERATION11_RUNNER_SOURCE_SHA256=_sha256(historical_runner),
                GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256=_sha256(historical_boundary)):
            errors = contracts._validate_generation11_terminal_facts(
                snapshot,
                bindings=rebound_bindings,
                proof=rebound_proof,
                authorization=authorization,
                manifest=rebound_manifest,
                failure=failure,
                repo_root=FIXTURE.root if case["repo"] else None,
            )
        verdicts[label] = {
            "input": {
                "runner_source_sha256": _sha256(case["runner"]),
                "session_boundary_source_sha256": _sha256(case["boundary"]),
                "candidate_commit": case["commit"],
                "repo_bound": case["repo"],
                "terminal_facts_canonical_sha256": snapshot.value["canonical_terminal_facts_sha256"],
            },
            "errors": errors,
        }
    return {
        "validator_source_sha256": _source_sha256(contracts._validate_generation11_terminal_facts),
        "recorded_runner_source_sha256": _sha256(historical_runner),
        "production_source_sha256": {"runner": contracts.GENERATION11_RUNNER_SOURCE_SHA256,
                                     "boundary": contracts.GENERATION11_SESSION_BOUNDARY_SOURCE_SHA256},
        "recorded_session_boundary_source_sha256": _sha256(historical_boundary),
        "history_runner_blob_sha256": _sha256(historical_runner),
        "history_session_boundary_blob_sha256": _sha256(historical_boundary),
        "verdicts": verdicts,
    }


# --- Historical full-auto authorization and campaign manifest records ------------------


def historical_record_section() -> dict:
    fixtures = ROOT / "tests" / "fixtures"
    authorization_raw = (fixtures / "historical-full-auto-authorization-v4.json").read_bytes()
    manifest_raw = (fixtures / "historical-live-campaign-manifest-v1.json").read_bytes()
    authorization = json.loads(authorization_raw)
    manifest = json.loads(manifest_raw)
    nonce = authorization["bindings"]["campaign_nonce"]
    tampered = deepcopy(authorization)
    tampered["live_generation"] = 99

    def runner_entry(value, *, operative):
        with mock.patch("subprocess.Popen", side_effect=_EffectReached) as popen:
            result = _outcome(LIVE.validate_full_auto_authorization, value, nonce,
                              operative=operative, repo_root=ROOT)
        if result["outcome"] == "returned":
            authorization_id, _head = result["value"]
            result["value"] = [authorization_id, "<HEAD>"]
        result["popen_calls"] = popen.call_count
        return result

    return {
        "inputs": {
            "historical-full-auto-authorization-v4.json": _sha256(authorization_raw),
            "historical-live-campaign-manifest-v1.json": _sha256(manifest_raw),
        },
        "validator_source_sha256": {
            "LIVE.validate_full_auto_authorization": _source_sha256(LIVE.validate_full_auto_authorization),
            "CONTRACTS.validate_full_auto_authorization": _source_sha256(CONTRACTS.validate_full_auto_authorization),
            "CONTRACTS.validate_operative_full_auto_authorization": _source_sha256(CONTRACTS.validate_operative_full_auto_authorization),
            "CONTRACTS.validate_campaign_manifest": _source_sha256(CONTRACTS.validate_campaign_manifest),
        },
        "verdicts": {
            "authorization-v4-historical-read": CONTRACTS.validate_full_auto_authorization(
                authorization, expected_campaign_nonce=nonce),
            "authorization-v4-operative": CONTRACTS.validate_operative_full_auto_authorization(
                authorization, expected_campaign_nonce=nonce),
            "authorization-v4-tampered-historical-read": CONTRACTS.validate_full_auto_authorization(
                tampered, expected_campaign_nonce=nonce),
            "manifest-v1-historical-read": CONTRACTS.validate_campaign_manifest(manifest),
            "runner-entry-authorization-v4-read": runner_entry(authorization, operative=False),
            "runner-entry-authorization-v4-operative": runner_entry(authorization, operative=True),
        },
    }


# --- Operative authorization consumer: the live launcher's main() ----------------------

# Fixed Git dates and UUIDs make the synthetic historical authorization reproducible.
_FIXED_GIT_DATE = "2026-07-17T12:00:00+00:00"
# Contained-session counts of a complete Generation 12 proof path set.
_LAUNCHER_SESSION_COUNTS = {
    "failed_predecessor_contained_session": 5,
    "predecessor_contained_session": 1,
    "ancestor_contained_session": 1,
    "grandancestor_contained_session": 1,
}
# Optional outputs main() derives from --output when they are not supplied.
_LAUNCHER_DERIVED_OUTPUTS = {"output", "campaign_nonce", "authorization_state", "steering_registry"}
_LAUNCHER_OUTPUTS = {
    "evidence_basename": "evidence.json",
    "authorization_state_basename": "authorization-state.json",
    "steering_registry_basename": "steering-registry.json",
    "allocation_ledger_basename": "allocation-ledger",
}
# Every effect main() can cause after authorization: durable writes, the
# machine-global claim, process launch and the thread/start request.
_LAUNCHER_WRITE_EFFECTS = (
    "validate_and_acquire_global_campaign_claim", "write_private_artifact",
    "transition_global_campaign_state", "consume_steering_receipt",
)


class _GateReached(Exception):
    """Raised by a control stub; never escapes main()."""


def _historical_v5_authorization(directory: Path) -> tuple[dict, dict, dict]:
    """A synthetic authorization v5 and manifest v2 bound to a throwaway repository.

    Built by the runner tests' own builders. The historical read accepts the
    authorization against that repository.
    """

    from tests import test_run_native_pool_live_canaries as RUNNER_TESTS

    builder = RUNNER_TESTS.FullAutoAuthorizationLauncherTests("run")
    repository = directory / "historical-repository"
    repository.mkdir()
    counter = itertools.count(1)
    environment = {
        "GIT_AUTHOR_DATE": _FIXED_GIT_DATE, "GIT_COMMITTER_DATE": _FIXED_GIT_DATE,
        "GIT_AUTHOR_NAME": "CWO Test", "GIT_COMMITTER_NAME": "CWO Test",
        "GIT_AUTHOR_EMAIL": "test@example.com", "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    with mock.patch.dict(os.environ, environment), \
            mock.patch("uuid.uuid4", side_effect=lambda: uuid.UUID(int=next(counter))):
        head, _orphan = builder.make_repo(repository)
        authorization = builder.authorization(repository, head)
        manifest = builder.manifest(authorization, head, LIVE.run_git(repository, "rev-parse", "HEAD^{tree}"))
        nonce = authorization["bindings"]["campaign_nonce"]
        historical_read = _outcome(LIVE.validate_full_auto_authorization, authorization, nonce,
                                   repo_root=repository)
        helper_operative = _outcome(LIVE.validate_full_auto_authorization, authorization, nonce,
                                    operative=True, repo_root=repository)
    if historical_read["outcome"] == "returned":
        authorization_id, read_head = historical_read["value"]
        historical_read["value"] = {
            "authorization_id_matches": authorization_id == authorization["authorization_id"],
            "head_is_checkpoint": read_head == head,
        }
    reads = {
        "contract-historical-read": CONTRACTS.validate_full_auto_authorization(
            authorization, expected_campaign_nonce=nonce, repo_root=repository),
        "runner-helper-historical-read": historical_read,
        "runner-helper-operative": helper_operative,
    }
    return authorization, manifest, {"reads": reads, "input_sha256": _canonical(_mask_digests(authorization)),
                                     "head": head}


def _mask_digests(value):
    """Mask sha256 values: the builders derive predecessor digests from wall-clock times."""

    if isinstance(value, dict):
        return {key: _mask_digests(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_digests(item) for item in value]
    if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return "<sha256>"
    return value


def _tree_state(root: Path) -> dict[str, str]:
    state = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        state[relative] = _sha256(path.read_bytes()) if path.is_file() else "<dir>"
    return state


def _drive_launcher(directory: Path, authorization: dict, manifest: dict, nonce: str, *,
                    operative_validator=None) -> dict:
    """Run the real runner main() offline against private input files.

    ``operative_validator`` is None for the real validator (wrapped, call-through)
    or a stub; only the positive control passes a stub.
    """

    import argparse
    import contextlib
    import io

    inputs = directory / "inputs"
    outputs = directory / "outputs"
    for path in (directory, inputs, outputs):
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    output = outputs / _LAUNCHER_OUTPUTS["evidence_basename"]
    contents = {"authorization": authorization, "campaign_manifest": manifest}
    real_parse_args = argparse.ArgumentParser.parse_args
    before: dict[str, str] = {}
    # Optional inputs a Generation 12 proof path set must not mix in.
    forbidden = {label.replace("-", "_") for label in LIVE.GENERATION8_FORBIDDEN_MIXED_PROOF_PATHS}

    def input_file(dest: str, index: int | None = None) -> str:
        name = dest if index is None else f"{dest}-{index}"
        path = inputs / f"{name}.json"
        path.write_text(json.dumps(contents.get(dest, {"w20ac_w13_placeholder": name})), encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def parse_args(self, args=None, namespace=None):
        argv = ["--output", str(output), "--campaign-nonce", nonce]
        for action in self._actions:
            if (not action.option_strings or action.dest == "help" or action.dest in _LAUNCHER_DERIVED_OUTPUTS
                    or action.dest in forbidden):
                continue
            if isinstance(action, argparse._AppendAction):
                for index in range(_LAUNCHER_SESSION_COUNTS.get(action.dest, 0)):
                    argv += [action.option_strings[0], input_file(action.dest, index)]
            else:
                argv += [action.option_strings[0], input_file(action.dest)]
        before.update(_tree_state(directory))
        return real_parse_args(self, argv, namespace)

    real_popen = subprocess.Popen
    counts = {"process_launch_calls": 0, "git_calls": 0}

    def popen(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and argv and Path(str(argv[0])).name == "git":
            counts["git_calls"] += 1
            return real_popen(argv, *args, **kwargs)
        counts["process_launch_calls"] += 1
        raise _EffectReached("process-launch")

    stderr = io.StringIO()
    refusals: list[dict] = []
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(LIVE, "ROOT", FIXTURE.root))
        stack.enter_context(mock.patch.object(CONTRACTS, "_V6_PRE_MOVE_IDENTITY_PAIRS", FIXTURE.pairs))
        stack.enter_context(mock.patch.object(argparse.ArgumentParser, "parse_args", parse_args))
        stack.enter_context(mock.patch("subprocess.Popen", side_effect=popen))
        request = stack.enter_context(mock.patch.object(LIVE.AppServer, "request", side_effect=_EffectReached))
        writes = {name: stack.enter_context(mock.patch.object(LIVE, name, side_effect=_EffectReached))
                  for name in _LAUNCHER_WRITE_EFFECTS}
        writes["CanaryAuthorizationStore.initialize"] = stack.enter_context(
            mock.patch.object(LIVE.CanaryAuthorizationStore, "initialize", side_effect=_EffectReached))
        if operative_validator is None:
            real_validator = LIVE.validate_full_auto_authorization

            def recording_validator(*args, **kwargs):
                try:
                    return real_validator(*args, **kwargs)
                except Exception as exc:
                    prefix, _, errors = str(exc).partition(":")
                    refusals.append({"error_type": type(exc).__name__, "prefix": prefix,
                                     "errors": sorted(errors.split(";")) if errors else []})
                    raise

            validator = stack.enter_context(mock.patch.object(
                LIVE, "validate_full_auto_authorization", side_effect=recording_validator))
        else:
            validator = stack.enter_context(mock.patch.object(
                LIVE, "validate_full_auto_authorization", side_effect=operative_validator))
        stack.enter_context(contextlib.redirect_stderr(stderr))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        try:
            return_code = LIVE.main()
        except SystemExit as exc:  # argparse refusal: recorded, not a pass
            return_code = f"system-exit:{exc.code}"
    lines = [line for line in stderr.getvalue().splitlines() if line.startswith("{")]
    report = json.loads(lines[-1]) if lines else {}
    after = _tree_state(directory)
    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    return {
        "return_code": return_code,
        "failure_code": report.get("failure_code"),
        "failure_evidence_persisted": report.get("failure_evidence_persisted"),
        "operative_validator_calls": validator.call_count,
        "operative_validator_refusals": refusals,
        "process_launch_calls": counts["process_launch_calls"],
        "git_calls": counts["git_calls"],
        "thread_start_requests": request.call_count,
        "write_effect_calls": {name: spy.call_count for name, spy in sorted(writes.items())},
        "files_created_or_changed": changed,
    }


def launcher_authorization_section() -> dict:
    """Historical-valid authorization against the operative consumer, the runner's main().

    main() is the only caller of the runner's ``validate_full_auto_authorization``
    (with ``operative=True``). The cases differ only in the authorization and the
    validator outcome; every other input file is the same placeholder set.
    """

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        authorization, manifest, built = _historical_v5_authorization(root)
        nonce = authorization["bindings"]["campaign_nonce"]
        # The same authorization with only its version relabelled to the operative
        # one (seal not refreshed), and its manifest relabelled to manifest v8.
        relabelled = deepcopy(authorization)
        relabelled["version"] = 12
        relabelled["bindings"]["checkpoint_tree"] = BASELINE_TREE
        relabelled_manifest = deepcopy(manifest)
        relabelled_manifest["version"] = 8
        relabelled_manifest["outputs"] = dict(_LAUNCHER_OUTPUTS)

        def accept(value, *_args, **_kwargs):  # control stub: the operative validator accepts
            return str(value["authorization_id"]), "<HEAD>"

        cases = {
            "historical-v5-valid": _drive_launcher(root / "case-historical", authorization, manifest, nonce),
            "historical-v5-relabelled-v12": _drive_launcher(
                root / "case-relabelled", relabelled, relabelled_manifest, nonce),
            "control-operative-validator-accepts": _drive_launcher(
                root / "case-control", relabelled, relabelled_manifest, nonce, operative_validator=accept),
        }
    return {
        "caller_source_sha256": {
            "LIVE.main": _source_sha256(LIVE.main),
            "LIVE.require_operative_campaign_contract": _source_sha256(LIVE.require_operative_campaign_contract),
            "LIVE.validate_full_auto_authorization": _source_sha256(LIVE.validate_full_auto_authorization),
        },
        "historical_input": {
            "version": authorization["version"],
            "manifest_version": manifest["version"],
            "authorization_sha256_digests_masked": built["input_sha256"],
            **built["reads"],
        },
        "launcher": cases,
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
        with mock.patch.object(LIVE, "ROOT", root), mock.patch.object(LIVE, "__file__", str(root / RUNNER_PATH)):
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
            "CONTRACTS.EXACT_OPERATIVE_MODEL": CONTRACTS.EXACT_OPERATIVE_MODEL,
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
    "generation11_runner_source": generation11_section,
    "historical_records": historical_record_section,
    "launcher_authorization": launcher_authorization_section,
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
    # Native availability adds exactly two constructor holds to the transport.
    # Prove that removing those additions reproduces the previously bound
    # source; keep all historical golden/source-pin resources unchanged.
    manifest = ROOT / "tests/fixtures/affected_contract_compatibility/EXAMPLE-manifest.json"
    manifest_value = json.loads(manifest.read_bytes())
    current_app_server = manifest_value["current_app_server_source_sha256"]
    identities = document["sections"]["identities"]["source_sha256"]
    identities["codex_tool_surface-module"] = _r5_surface_source_identity(
        identities["codex_tool_surface-module"], manifest_value["files"]["scripts/cwo_core/codex_tool_surface.py"])
    # The full-module reversal above verifies the former validator bytes too.
    document["sections"]["tool_surface"]["validator_source_sha256"]["require_capture_binding"] = (
        _source_sha256(SURFACE.require_capture_binding))
    source = inspect.getsource(LIVE.AppServer)
    transport = Path(inspect.getfile(LIVE.AppServer)).read_bytes()
    if _sha256(transport) != manifest_value["files"]["scripts/cwo_core/supervision/transport/app_server.py"]:
        raise AssertionError("current-transport-source-binding-drift")
    # 7a adds entry/wire N1 checks, including the separate turn writer. Reverse
    # only those exact additions in their named methods, then retain the full
    # original launch/hold lineage checks below. No historical pins/outcomes change.
    historical_source = source
    for name, count in (("notify", 1), ("request", 2), ("request_once_with_guard", 2)):
        current = inspect.getsource(getattr(LIVE.AppServer, name))
        gate = "_require_native_rpc(method)\n"
        if current.count(gate) != count:
            raise AssertionError("native RPC gate occurrence count changed: " + name)
        previous = "".join(line for line in current.splitlines(keepends=True) if line.strip() != gate.strip())
        historical_source = historical_source.replace(current, previous)
    current = inspect.getsource(LIVE.AppServer.start_turn)
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
    source = inspect.getsource(LIVE.main)
    historical = source
    for name in ('campaign', 'pool', 'n1'):
        gate = "        live_availability.require_" + name + "_live()\n"
        if source.count(gate) != 1:
            raise AssertionError("f5-held-route-launcher-gate-drift")
        historical = historical.replace(gate, "")
    historical = historical.replace("server = _start_campaign_server()", "server = AppServer()")
    expected = document["sections"]["launcher_authorization"]["caller_source_sha256"]
    if _sha256(historical) != expected["LIVE.main"]:
        raise AssertionError("f5-held-route-launcher-lineage-drift")
    expected["LIVE.main"] = _sha256(source)
    return document


class GoldenVerdictTests(unittest.TestCase):
    """Each section preserves its contract outcomes under neutral fixture identities."""

    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.golden = load_golden()["sections"]

    def check(self, name: str) -> dict:
        observed = compute([name])[name]
        self.assertEqual(observed, self.golden[name])
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

    def test_generation11_runner_source_binding_is_unchanged(self) -> None:
        observed = self.check("generation11_runner_source")
        self.assertEqual(observed["production_source_sha256"], contract_evidence()["production_generation11_sources"])
        self.assertEqual(observed["recorded_runner_source_sha256"], observed["history_runner_blob_sha256"])
        self.assertEqual(observed["verdicts"]["historical-record-repo-bound"]["errors"], [])
        for label in ("relabelled-to-baseline-commit", "unknown-commit",
                      "baseline-runner-bytes-rebound", "tampered-runner-byte-rebound"):
            self.assertTrue(observed["verdicts"][label]["errors"], label)

    def test_template_records_are_recorded_as_observed(self) -> None:
        # The two template fixtures fail their header check under the current read
        # API. They are invalid inputs, recorded as observed; they are not
        # historical-valid evidence. That case is the launcher test below.
        observed = self.check("historical_records")
        verdicts = observed["verdicts"]
        self.assertEqual(verdicts["authorization-v4-historical-read"], ["authorization-header-invalid"])
        self.assertEqual(verdicts["manifest-v1-historical-read"], ["campaign-manifest-header-invalid"])
        self.assertEqual(verdicts["authorization-v4-operative"], ["authorization-version-historical-only"])

    def test_launcher_refuses_historical_authorization_with_zero_effects(self) -> None:
        observed = self.check("launcher_authorization")
        historical = observed["historical_input"]
        # Historical-valid: the contract read and the runner helper accept it.
        self.assertEqual(historical["contract-historical-read"], [])
        self.assertEqual(historical["runner-helper-historical-read"]["outcome"], "returned")
        self.assertTrue(all(historical["runner-helper-historical-read"]["value"].values()))
        self.assertEqual(historical["runner-helper-operative"]["message"],
                         "full-auto-authorization-invalid:authorization-version-historical-only")
        launcher = observed["launcher"]
        no_writes = {name: 0 for name in launcher["historical-v5-valid"]["write_effect_calls"]}
        for label in ("historical-v5-valid", "historical-v5-relabelled-v12"):
            with self.subTest(label=label):
                record = launcher[label]
                self.assertEqual(record["return_code"], 1)
                self.assertIs(record["failure_evidence_persisted"], False)
                self.assertEqual(record["process_launch_calls"], 0)
                self.assertEqual(record["thread_start_requests"], 0)
                self.assertEqual(record["write_effect_calls"], no_writes)
                self.assertEqual(record["files_created_or_changed"], [])
        # Current-refused at the version gate, before the operative validator or Git runs.
        valid = launcher["historical-v5-valid"]
        self.assertEqual(valid["failure_code"], "campaign-authorization-version-historical-only")
        self.assertEqual(valid["operative_validator_calls"], 0)
        self.assertEqual(valid["git_calls"], 0)
        # Relabelled to the operative version: passes the gate, the real operative
        # validator refuses it.
        relabelled = launcher["historical-v5-relabelled-v12"]
        self.assertEqual(relabelled["operative_validator_calls"], 1)
        self.assertEqual(len(relabelled["operative_validator_refusals"]), 1)
        refusal = relabelled["operative_validator_refusals"][0]
        self.assertEqual(refusal["prefix"], "full-auto-authorization-invalid")
        self.assertIn("authorization-v12-canonical-sha256-mismatch", refusal["errors"])
        # Control: with the operative validator accepting, main() reaches the first
        # effect after authorization, the machine-global campaign claim, so the
        # write spy is wired on this path.
        control = launcher["control-operative-validator-accepts"]
        self.assertEqual(control["operative_validator_calls"], 1)
        self.assertEqual(control["write_effect_calls"]["validate_and_acquire_global_campaign_claim"], 1)
        self.assertEqual(control["failure_code"], "_EffectReached")

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
        observed = self.check("adapter_digest_coverage")
        changes = observed["digest_changes_when_file_changes"]
        for label in ("runner", "AppServer", "AppServerError", "load_private_bytes"):
            self.assertTrue(changes[label], label)
        self.assertTrue(observed["digest_stable_when_restored"])

    def test_code_pins_still_cover_the_moved_code(self) -> None:
        observed = compute(["code_pins"])["code_pins"]
        golden = self.golden["code_pins"]
        # The move may add pins; it may not drop one or stop covering moved code.
        self.assertLessEqual(set(golden["pin_paths"]), set(observed["pin_paths"]))
        self.assertEqual(observed["covers"], golden["covers"])
        self.assertEqual(observed["interpreter_pinned"], golden["interpreter_pinned"])
        self.assertTrue(all(observed["covers"].values()))

    def test_f5_held_route_identities_keep_historical_lineage_with_explicit_gates(self) -> None:
        self.check("identities")


class ConsumerCompatibilityTests(unittest.TestCase):
    """Preserve baseline observations and check explicitly moved current owners."""

    def test_baseline_imports_resolve_to_the_same_objects(self) -> None:
        for consumer_name, sources in BASELINE_IMPORTS.items():
            consumer = importlib.import_module(consumer_name)
            for source_name, names in sources.items():
                source = importlib.import_module(source_name)
                for name in names:
                    with self.subTest(consumer=consumer_name, source=source_name, name=name):
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
                self.assertEqual(old.__module__, "run_native_pool_live_canaries")
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
        self.assertEqual(observed, load_golden()["sections"]["lazy_imports"])
        self.assertIn("cwo_core.maintenance_qualification", observed["consumers"])
        resolved = {binding.split("=", 1)[1] for binding in observed["bindings"]}
        for consumer_name, sources in BASELINE_LAZY_IMPORTS.items():
            for source_name, names in sources.items():
                for name in names:
                    with self.subTest(consumer=consumer_name, source=source_name, name=name):
                        self.assertTrue({f"{source_name}.{name}", f"run_native_pool_live_canaries.{name}"} & resolved)

    def test_lazy_imports_execute_in_the_changed_function(self) -> None:
        # observe_qualification runs its lazy imports first, then refuses the
        # non-capability operation before any effect.
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
    "one_app_server": CHECK.AppServer is LIVE.AppServer is PREVIEW.AppServer is RUNTIME.AppServer,
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
            self.assertEqual(len(list((ROOT / "policy").glob("*.yaml"))), 22)
            self.assertIn("policy/qualification-target.yaml", manifest["registered_current_resources"])
            for name in manifest["registered_current_resources"]:
                if name.startswith("policy/"):
                    source = ROOT / name
                    (root / name).write_bytes(source.read_bytes())
            with self.assertRaisesRegex(checkpoint.CompatibilityRefusal, "dependency/artifact missing"):
                checkpoint.verify_fixture_checkpoint(root=root)
            self.assertEqual(len(list((root / "policy").glob("*.yaml"))), 22)
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
