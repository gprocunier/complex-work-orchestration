"""Project the protected ordinary cohort into the original contained runtime."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING
from uuid import NAMESPACE_URL, uuid4, uuid5

from cwo_core import native_live_availability as availability
from cwo_core import native_pool_qualification_stage as stage
from cwo_core.invocation_ledger import InvocationLedger, MAX_UNITS
from cwo_core.native_pool_admission import BeadsClaimAdapter, PoolAdmissionReservation, canonical_admission_sha256
from cwo_core.native_pool_config import ADMITTED_RENDER_REQUEST_SCHEMA, RENDER_REQUEST_TYPE
from cwo_core.native_pool_contracts import (
    POOL_POLL_INTERVAL_MS,
    canonical_sha256,
    default_completion_evidence_policy,
)
from cwo_core.native_pool_preflight import (
    ADMITTED_PREFLIGHT_REQUEST_SCHEMA,
    default_callback_certification,
    effective_child_packet_sha256,
)
from cwo_core.native_pool_transaction import (
    PLAN_SCHEMA,
    PLAN_TYPE,
    PLAN_VERSION,
    TRANSACTION_CALL_GRAPH_SHA256,
    AdmittedPoolLaunch,
    NativePoolTransactionError,
    build_readiness_record,
    execution_authoritative_bead_sha256,
    seal_transaction_plan,
)
from cwo_core.native_pool_workspace import capture_workspace_snapshot
from cwo_core.native_stop_scope import build_stop_metadata, policy_scope_authority
from cwo_core.native_tool_isolation import (
    ContainedPoolChildBinding,
    scan_prompt_against_policy,
    contained_pool_tool_policy,
    contained_pool_tool_surface,
)
from cwo_core.outbound_screen import OutboundRefused
from cwo_core.private_artifact import PrivateDirectory
from cwo_core.supervision.transport.app_server import prepare_native_request_frame as _prepare_native_frame
from cwo_core.workspace_capture import pin_private_directory, read_at
from registered_n1_qualification import EFFORT, MODEL, TIER
from registered_pool_configuration import PoolContainmentError, thread_start_selectors
from registered_pool_containment import read_pool_patch_file
from registered_pool_qualification import (
    CALIBRATION_POOL_MODE as _CALIBRATION_MODE,
    CALLBACK_OPPORTUNITY_FIELD as _OPPORTUNITY_FIELD,
    ORDINARY_POOL_MODE as _ORDINARY_MODE,
    ORDINARY_POOL_SCOPE as _ORDINARY_SCOPE,
    _retain_transport_failures,
    build_pool_qualification_runtime,
    require_original_pool_admission as _check_admission,
)
from registered_pool_qualification_calibration import _measure_original_controls, _registered_parent
from registered_pool_qualification_capability import (
    ConnectedPoolCallbackCapability,
    begin_ordinary_connected_callback_calibration,
    callback_implementation_sha256,
)

if TYPE_CHECKING:
    from registered_contained_pool_host import OrdinaryPoolChild

_STARTUP_BOUNDS = {
    "pre_allocation_ms": 4_000,
    "per_allocation_ms": 15_000,
    "runtime_binding_ms": 5_000,
    "admission_ms": 5_000,
    "dispatch_and_first_observation_ms": 10_000,
    "safety_margin_ms": 5_000,
}
_BINDING_FIELDS = (
    "bead_id", "work_unit_id", "candidate_sha256", "work_estimate_sha256",
    "worker_commitment_sha256", "lease_scope_sha256", "worktree_identity_sha256",
    "requested_model", "admitted_child_sha256",
)
_BUDGET_PREFIX = "registered-contained-pool:"
_PATCH_DIGEST_FIELDS = ("patch_preimage_sha256", "request_sha256", "diff_sha256", "content_sha256")
_PATCH_OBSERVATION_FIELDS = {*_PATCH_DIGEST_FIELDS, "path", "call_id"}


def _require(condition, reason):
    if not condition:
        raise NativePoolTransactionError("registered-contained-pool-" + reason)


def require_ordinary_custody(approved):
    from registered_contained_pool_host import ApprovedOrdinaryPool

    availability.require_registered_contained_pool_live()
    _require(type(approved) is ApprovedOrdinaryPool and type(approved.ledger) is InvocationLedger,
             "original-ordinary-approval-required")
    approved.require_current()
    require_ordinary_runtime_source(approved)
    _require((approved.model, approved.effort, approved.service_tier) == (MODEL, EFFORT, TIER),
             "unsupported-run-selection")


def require_ordinary_runtime_source(approved):
    source = stage._registered_factory_path()
    stage._registered_factory_source(str(source), approved.runtime_adapter_sha256)
    _require(approved.callback_implementation_sha256 == callback_implementation_sha256(),
             "callback-implementation-digest-mismatch")


def _hard_budget(estimate):
    limits = estimate["aggregate_allowance"]
    return {"tool_calls": limits["tool_calls_hard"], "runtime_seconds": limits["runtime_seconds_hard"],
            "compactions": limits["max_compactions"], "full_suite_runs": 0, "mutations": 1}


def build_registered_contained_pool_packet(child_id, child, work_estimate):
    """Bind the original ordinary task and one-file scope before claiming the cohort."""
    prospective = f"{child_id}-prospective"
    policy = contained_pool_tool_policy()
    prompt_preflight = scan_prompt_against_policy(child.prompt, policy)
    _require(prompt_preflight["accepted"], "ordinary-prompt-refused")
    _screen_worker_start(child.worktree, patch_mode=child.patch_preimage_sha256 is not None)
    packet = {
        "child_id": child_id, "packet_id": str(uuid4()), "lease_id": str(uuid4()),
        "attempt_nonce": str(uuid4()), "session_id": prospective, "agent_id": prospective,
        "worktree": str(child.worktree), "isolation_class": "mutable-isolated",
        "completion_evidence_policy": default_completion_evidence_policy("mutable-isolated"),
        "tool_policy": policy, "prompt": child.prompt, "prompt_preflight": prompt_preflight,
        "tool_surface": contained_pool_tool_surface(), "hard_budget": _hard_budget(work_estimate),
        "declared_write_paths": [child.write_path], "integration_target_paths": [child.write_path],
    }
    return {**packet, "packet_sha256": effective_child_packet_sha256(packet)}


def _screen_worker_start(worktree, *, patch_mode: bool = False):
    try:
        params = thread_start_selectors(worktree, patch_mode=patch_mode)
        _prepare_native_frame({"id": 1, "method": "thread/start", "params": params}, "thread/start")
    except OutboundRefused as error:
        raise NativePoolTransactionError("registered-contained-pool-worker-start-screening-refused") from error


def ordinary_pool_tasks(approved, children, authority):
    """Select the same signed checkout and callback input used by both phases."""
    selected = approved.children
    _require({row["child_id"] for row in children} == selected.keys(), "ordinary-child-set-drift")
    _require(authority["fixture_root"] == str(approved.root / "workspaces")
             and authority["host"] == dict(approved.host_inputs)
             and authority["render_request"]["control_turn_id"] == approved.control_turn_id
             and authority["spools"] == _spools(approved, authority["mode"]), "ordinary-phase-scope-drift")
    tasks = {}
    for row in children:
        child = selected[row["child_id"]]
        _require((row["bead_id"], row["worktree_identity_sha256"], row["write_paths"], row["requested_model"])
                 == (child.bead_id, child.worktree_identity_sha256, [child.write_path], approved.model),
                 "ordinary-child-scope-drift")
        task = {"worker_slot": child.worktree.name, "prompt": child.prompt,
                "write_path": child.write_path, "expected_utf8": child.expected_utf8,
                "completion_marker": child.completion_marker}
        if child.patch_preimage_sha256 is not None:
            task["patch_preimage_sha256"] = child.patch_preimage_sha256
        tasks[row["child_id"]] = task
    return tasks


def _spools(approved, mode):
    field = "calibration_spool" if mode == _CALIBRATION_MODE else "productive_spool"
    return {child_id: str(getattr(child, field)) for child_id, child in approved.children.items()}


def _iso(when):
    return datetime.fromtimestamp(when, timezone.utc).isoformat()


def _private_json(records, name, payload):
    raw = json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")
    with PrivateDirectory.open(records) as directory:
        path = directory.write(name, raw)
    return str(path), sha256(raw).hexdigest()


def _original_packets(approved, admission, packets):
    receipt = admission.receipt
    bindings = receipt["child_bindings"]
    _require(tuple(row["child_id"] for row in packets) == tuple(row["child_id"] for row in bindings),
             "ordinary-packet-order-drift")
    claims = {row["bead_id"]: row["claim_sha256"] for row in receipt["claims"]}
    return tuple(_original_packet(approved, packet, binding, claims) for packet, binding in zip(packets, bindings, strict=True))


def _original_packet(approved, packet, binding, claims):
    child = approved.children[binding["child_id"]]
    estimate = approved.work_estimates[child.bead_id]
    expected = (child.bead_id, child.worktree_identity_sha256, child.prompt, str(child.worktree), [child.write_path],
                [child.write_path], _hard_budget(estimate), contained_pool_tool_policy(), contained_pool_tool_surface())
    observed = (binding["bead_id"], binding["worktree_identity_sha256"], packet["prompt"], packet["worktree"],
                packet["declared_write_paths"], packet["integration_target_paths"], packet["hard_budget"],
                packet["tool_policy"], packet["tool_surface"])
    _require(observed == expected and binding["requested_model"] == approved.model
             and binding["packet_sha256"] == packet["packet_sha256"] == effective_child_packet_sha256(packet),
             "ordinary-admitted-packet-drift")
    return {**deepcopy(packet), **{key: binding[key] for key in _BINDING_FIELDS}, "claim_sha256": claims[child.bead_id]}


def _initial_state(packet):
    return {**{key: packet[key] for key in ("packet_id", "packet_sha256", "agent_id", "session_id")},
            "result_type": "cwo-native-supervision-state", "version": 1,
            "schema": "schemas/native-supervision-state.schema.json", "status": "created",
            "control_turn_id": None, "poll_interval_ms": POOL_POLL_INTERVAL_MS,
            "control_adapter": "native-multi-agent-v1", "required_capabilities": ["interrupt", "close", "wait"],
            **build_stop_metadata("child", authority=policy_scope_authority(
                "registered-contained-pool-worker", authorized_scope="child"))}


def _render_child(packet, controls):
    child_id = packet["child_id"]
    return {key: value for key, value in packet.items() if key not in {"prompt", "prompt_preflight", "tool_surface"}} | {
        "control_turn_id": f"{child_id}-control", "state_file": str(controls / f"{child_id}.state.json"),
        "control_contract_file": str(controls / f"{child_id}.control.json"),
    }


def _request_templates(approved, receipt, packets, controls, records):
    width = len(packets)
    budget = {key: sum(packet["hard_budget"][key] for packet in packets) for key in packets[0]["hard_budget"]}
    pool_id = str(uuid5(NAMESPACE_URL, _ORDINARY_SCOPE + ":" + approved.binding_sha256))
    common = {"pool_id": pool_id, "pool_epoch": str(uuid4()), "integration_root": str(approved.integration_root),
              "aggregate_hard_budget": budget, "admission_reservation": receipt}
    render = {**common, "request_type": RENDER_REQUEST_TYPE, "version": 2, "schema": ADMITTED_RENDER_REQUEST_SCHEMA,
              "control_turn_id": approved.control_turn_id, "created_at": _iso(approved.ledger.current_time()),
              "max_active_workers": width, "completion_policy": "all-or-nothing",
              "children": [_render_child(packet, controls) for packet in packets]}
    preflight = {**common, "preflight_type": "cwo-native-supervision-pool-preflight-request", "version": 2,
                 "schema": ADMITTED_PREFLIGHT_REQUEST_SCHEMA, "stage": "pre-dispatch",
                 "launch_id": str(uuid4()), "campaign_nonce": str(uuid4()), "artifact_directories": [str(records)],
                 "requested_workers": width, "released_capacity": width, "children": list(packets),
                 "fallback": {"main_thread": "main-thread", "recovery": "operator"},
                 "productive_dogfood_delivery_prerequisite": False, "callback_certification": default_callback_certification(),
                 "poll_interval_ms": POOL_POLL_INTERVAL_MS, "overrides": []}
    return render, preflight


def _child_release(approved, packet, bead, records, mode):
    child_id = packet["child_id"]
    child = {key: packet[key] for key in ("child_id", "bead_id", "work_unit_id", "requested_model",
                                          "worktree_identity_sha256")}
    child.update(segment_id=f"{child_id}-segment", packet_blueprint_sha256=packet["packet_sha256"],
                 bead_projection_sha256=execution_authoritative_bead_sha256(bead),
                 work_plan_sha256=packet["work_estimate_sha256"], write_paths=packet["declared_write_paths"])
    _, digest = _private_json(records, f"{child_id}.release.json", {
        "ordinary_approval_sha256": approved.binding_sha256, "phase": mode, "child": child,
        "claim_sha256": packet["claim_sha256"],
    })
    binding = {"child_id": child_id, "packet_sha256": packet["packet_sha256"],
               "precommit_receipt_sha256": digest, "work_plan_sha256": child["work_plan_sha256"]}
    dependency = {"child_id": child_id, "kind": "operative-release", "evidence_sha256": digest,
                  "issued_at": approved.issued_at, "expires_at": _iso(approved.expires_at)}
    return child, binding, dependency


def _beads(claim):
    return {"directory": str(claim.directory), "database": claim.database, "actor": claim.actor, "timeout": claim.timeout}


def _phase_authority(approved, admission, packets, beads, mode, controls, records, opportunity):
    receipt = admission.receipt
    render, preflight = _request_templates(approved, receipt, packets, controls, records)
    releases = (_child_release(approved, packet, beads[packet["bead_id"]], records, mode) for packet in packets)
    children, bindings, dependencies = map(list, zip(*releases))
    artifact_values = {"candidate_manifest": {"ordinary_approval_sha256": approved.binding_sha256,
                                              "admission": receipt["reservation_sha256"], "children": children},
                       "controller_overlay": {"render_request": render, "fixed_host": dict(approved.host_inputs)}}
    artifacts, hashes = {}, {}
    for key, value in artifact_values.items():
        artifacts[key], hashes[key + "_sha256"] = _private_json(records, key + ".json", value)
    authority = {"scope": _ORDINARY_SCOPE, "mode": mode, "fixture_root": str(approved.root / "workspaces"),
                 "journal_path": str(controls / "run.jsonl"), "control_root": str(controls),
                 "spools": _spools(approved, mode), "host": dict(approved.host_inputs), "artifacts": artifacts,
                 "reservation_sha256": receipt["reservation_sha256"], "render_request": render, "preflight_template": preflight,
                 "release_artifacts": {"packet_bindings": bindings, "release_dependencies": dependencies},
                 "readiness_evidence": dict(approved.readiness_evidence), "work_estimates": dict(approved.work_estimates),
                 "initial_states": {packet["child_id"]: _initial_state(packet) for packet in packets},
                 "beads": _beads(admission.claim_adapter)}
    if opportunity is not None:
        authority[_OPPORTUNITY_FIELD] = opportunity
    return authority, hashes, children


def _seal_phase(approved, admission, packets, mode, *, capability=None, opportunity=None):
    require_ordinary_custody(approved)
    beads = _current_beads(approved, admission)
    phase = approved.root / mode
    phase.mkdir(mode=0o700)
    controls, records = phase / "control", phase / "records"
    controls.mkdir(mode=0o700)
    records.mkdir(mode=0o700)
    authority, hashes, children = _phase_authority(approved, admission, packets, beads, mode, controls, records, opportunity)
    path, digest = _private_json(records, "authority.json", authority)
    factory = Path(build_pool_qualification_runtime.__code__.co_filename).resolve(strict=True)
    width = len(children)
    plan = seal_transaction_plan({
        "plan_type": PLAN_TYPE, "version": PLAN_VERSION, "schema": PLAN_SCHEMA,
        "transaction_id": "ordinary-" + canonical_sha256({"binding": approved.binding_sha256, "phase": mode}),
        "phase_id": mode, "created_at": _iso(approved.ledger.current_time()), **hashes, "authority_sha256": digest,
        "call_graph_sha256": TRANSACTION_CALL_GRAPH_SHA256, "runtime_adapter_path": str(factory),
        "runtime_adapter_sha256": approved.runtime_adapter_sha256, "selected_model": approved.model,
        "prelude_session_count": 0, "required_session_count": width,
        "budget": {"cumulative_before": 0, "cumulative_ceiling": width, "reserved_sessions": width,
                   "infrastructure_failures_before": 0, "maximum_infrastructure_failures": 3},
        "startup_bounds_ms": _STARTUP_BOUNDS, "children": children,
    })
    build_readiness_record(plan, beads, **authority["release_artifacts"], now=datetime.now(timezone.utc))
    selection = stage.select_contained_pool_runtime(plan, build_pool_qualification_runtime, authority_path=Path(path),
                                                   admission=admission, capability=capability, ordinary=approved)
    original = _registered_parent(selection.runtime)
    run = stage.make_pool_qualification_run(plan, selection, journal_path=original.journal.path, fixture_root=original.fixture_root)
    policy = {child_id: ContainedPoolChildBinding(
        str(child.worktree), child.worktree_identity_sha256, child.write_path, child.prompt,
    ) for child_id, child in approved.children.items()}
    return replace(run, ordinary_policy_children=policy)


def calibration_limits(approved):
    return {"sessions": len(approved.children), "tool_calls": 1, "runtime_seconds": approved.calibration_seconds}


def ordinary_budget_id(approved):
    return _BUDGET_PREFIX + approved.binding_sha256


def ordinary_calibration_operation(approved, plan):
    return canonical_sha256({"scope": "ordinary-contained-callback-calibration", "approval_sha256": approved.binding_sha256,
                             "plan_sha256": plan["plan_sha256"], "control_turn_id": approved.control_turn_id})


def _productive_limits(packets):
    return {"sessions": len(packets), **{key: sum(row["hard_budget"][key] for row in packets)
                                       for key in ("tool_calls", "runtime_seconds")}}


def _allowance(approved, run, productive):
    calibration = calibration_limits(approved)
    _require(all(type(approved.limits[key]) is int and 0 < calibration[key] + productive[key] <= approved.limits[key] <= MAX_UNITS
                 for key in calibration), "finite-ordinary-aggregate-limit-exceeded")
    accounting = stage.PoolQualificationAccounting(approved.ledger, approved.expires_at)
    root = stage._ledger_root(accounting)
    approved.require_current()
    root.mkdir(mode=0o700)
    allowance = stage._open_stage_allowance(accounting, root, approved.binding_sha256, approved.limits, (run,),
                                           frozenset({run.fixture_root}), availability.require_registered_contained_pool_live,
                                           budget_prefix=_BUDGET_PREFIX)
    return replace(allowance, ordinary=approved)


def _fresh_baselines(approved):
    snapshots = {}
    for child in approved.children.values():
        _require_original_output(child)
        snapshot = capture_workspace_snapshot(child.worktree, allowed_paths=[child.write_path])
        _require(canonical_sha256(snapshot["identity"]) == child.worktree_identity_sha256,
                 "ordinary-worktree-identity-drift")
        snapshots[child.worker_id] = snapshot
    return snapshots


def _require_original_output(child: OrdinaryPoolChild) -> None:
    if child.patch_preimage_sha256 is None:
        _require(not os.path.lexists(child.worktree / child.write_path), "ordinary-writer-target-already-present")
        return
    from registered_contained_pool_host import require_patch_preimage

    try:
        require_patch_preimage(child)
    except (OSError, ValueError) as error:
        raise NativePoolTransactionError("registered-contained-pool-ordinary-patch-preimage-drift") from error


def _calibrate(approved, run, allowance, baseline):
    parent = _registered_parent(run.runtime)
    operation = ordinary_calibration_operation(approved, run.plan)

    def drive(plan, allocations, context, require_release_horizon):
        parent.bind_calibration_controls(plan, allocations, context)
        require_release_horizon()
        return _measure_original_controls(parent, begin_ordinary_connected_callback_calibration(parent, operation))

    def verify_workspaces():
        _require(_fresh_baselines(approved) == baseline, "ordinary-calibration-workspace-changed")

    calibration = stage._QualificationCalibration(operation, drive, verify_workspaces)
    result = _run_phase(run, run.runtime, replace(allowance, calibration=calibration), calibration_limits(approved))
    _require(type(calibration.result) is ConnectedPoolCallbackCapability
             and result["qualification_accounting"]["state"] == "terminal", "original-calibration-settlement-refused")
    return calibration.result, operation, result["qualification_accounting"]


def _read_output(child):
    pinned = pin_private_directory(str(child.worktree))
    _require(pinned is not None, "ordinary-output-custody-lost")
    directory, _ = pinned
    expected = child.expected_utf8.encode("utf-8")
    try:
        kind, data, info = read_at(directory, child.write_path, len(expected))
        return kind == "file" and info is not None and info.st_uid == os.geteuid() and info.st_nlink == 1 and data == expected
    finally:
        os.close(directory)


def _original_patch_observation(child: OrdinaryPoolChild, worker: object) -> dict[str, str]:
    host = worker.get("host") if type(worker) is dict else None
    _require(type(host) is dict and (host.get("worker_id"), host.get("worktree"), host.get("spool"))
             == (child.worker_id, str(child.worktree), str(child.productive_spool)), "ordinary-patch-worker-custody-lost")
    observations = host.get("observations")
    _require(type(observations) is list and all(type(row) is dict for row in observations),
             "ordinary-patch-writer-observations-required")
    output = [row.get("observation") for row in observations if row.get("stage") == "writer-output"]
    _require(len(output) == 1 and type(output[0]) is dict and output[0].keys() == _PATCH_OBSERVATION_FIELDS,
             "ordinary-patch-writer-observation-required")
    receipt = output[0]
    _require(receipt["path"] == child.write_path and receipt["patch_preimage_sha256"] == child.patch_preimage_sha256
             and type(receipt["call_id"]) is str and bool(receipt["call_id"])
             and all(type(receipt[key]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[key]) for key in _PATCH_DIGEST_FIELDS),
             "ordinary-patch-writer-observation-drift")
    return receipt


def _read_productive_output(child: OrdinaryPoolChild, workers: object) -> bool:
    if child.patch_preimage_sha256 is None:
        return _read_output(child)
    _require(type(workers) is dict, "ordinary-patch-worker-custody-lost")
    receipt = _original_patch_observation(child, workers.get(child.worker_id, {}))
    _require(receipt["content_sha256"] != child.patch_preimage_sha256, "ordinary-patch-output-unchanged")
    data = read_pool_patch_file(child.worktree, child.write_path)
    _require(sha256(data).hexdigest() == receipt["content_sha256"], "ordinary-patch-output-digest-drift")
    return True


def _bound_productive_runtime(approved, run, limits):
    original = run.runtime
    settlement = None

    def bind(plan, allocations, context):
        nonlocal settlement
        launch = original.bind_admitted_launch(plan, allocations, context)
        _require(type(launch) is AdmittedPoolLaunch and launch.keyword_arguments.get("activation_capability") is None,
                 "ordinary-launch-not-original")
        budget = launch.contract["aggregate_hard_budget"]
        _require(all(budget[key] == limits[key] for key in ("tool_calls", "runtime_seconds"))
                 and launch.task_inputs == {key: child.prompt for key, child in approved.children.items()},
                 "ordinary-dispatch-binding-drift")
        settlement = stage._bind_settlement(launch, frozenset({run.fixture_root}), run.journal_path)
        _require(settlement.registry_path == approved.lease_registry_path, "ordinary-shared-lease-registry-drift")
        return launch

    def validate(launched, context, *, before_artifact_checks):
        validation = original.validate(deepcopy(dict(launched)), context)
        before_artifact_checks(validation)
        _settle_productive_validation(approved, settlement, launched, validation)
        return validation

    return replace(original, bind_admitted_launch=bind, validate=validate)


def _settle_productive_validation(approved, settlement, launched, validation):
    try:
        _require(settlement is not None, "ordinary-original-settlement-required")
        validation["qualification_settlement"] = stage._verify_settlement(settlement, launched)
        if validation.get("accepted") is True:
            workers = validation.get("worker_observations", {})
            validation["accepted"] = all(_read_productive_output(child, workers) for child in approved.children.values())
    except (OSError, NativePoolTransactionError, PoolContainmentError) as error:
        validation.update(accepted=False, qualification_settlement={"outcome": "refused", "reason": str(error)})


def _run_phase(run, runtime, allowance, limits):
    require_ordinary_custody(allowance.ordinary)
    try:
        return stage._accounted_run(run, runtime, allowance, limits)
    finally:
        _retain_transport_failures(run.runtime.start_worker_session)


def _current_beads(approved, admission):
    rows = {}
    for claim in admission.receipt["claims"]:
        approved.require_current()
        bead_id = claim["bead_id"]
        original = dict(admission.claim_adapter.show_exact(bead_id))
        _require(canonical_admission_sha256(original) == claim["post_show_sha256"], "ordinary-beads-claim-drift")
        rows[bead_id] = original
    return rows


def _require_ordinary_admission(approved, admission):
    _require(type(admission) is PoolAdmissionReservation and type(admission.claim_adapter) is BeadsClaimAdapter,
             "original-ordinary-admission-required")
    base, attempt = approved.claim_adapter, admission.claim_adapter
    _require(attempt._before_claim is base._before_claim and attempt.directory == base.directory
             and attempt.database == base.database and attempt.timeout == base.timeout
             and attempt.actor.startswith(base.actor + "-cwo-") and admission.receipt["claim_actor"] == attempt.actor
             and admission.receipt["admission_nonce"] == approved.binding_sha256,
             "original-ordinary-admission-actor-drift")
    _check_admission(admission, {"reservation_sha256": admission.receipt["reservation_sha256"], "beads": _beads(attempt)})


def run_registered_contained_pool(approved, admission, *, packets):
    """Run one writer-held calibration and one productive cohort under one signed limit."""
    require_ordinary_custody(approved)
    _require_ordinary_admission(approved, admission)
    packets = _original_packets(approved, admission, packets)
    baseline = _fresh_baselines(approved)
    calibration_run = _seal_phase(approved, admission, packets, _CALIBRATION_MODE)
    limits = _productive_limits(packets)
    allowance = _allowance(approved, calibration_run, limits)
    capability, opportunity, calibration = _calibrate(approved, calibration_run, allowance, baseline)
    productive = _seal_phase(approved, admission, packets, _ORDINARY_MODE, capability=capability, opportunity=opportunity)
    runtime = _bound_productive_runtime(approved, productive, limits)
    result = _run_phase(productive, runtime, allowance, limits)
    result["request_pool_id"] = approved.pool_id
    result["ordinary_pool_accounting"] = {"calibration": calibration, "productive": result["qualification_accounting"],
                                          "aggregate": approved.ledger.summary(allowance.budget_id)}
    return result
