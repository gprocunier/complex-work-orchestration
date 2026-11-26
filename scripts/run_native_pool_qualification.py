#!/usr/bin/env python3
"""Run a signed contained qualification from the original protected parent.

A protected host calls main([], parent=...) or run_protected_pool_qualification(parent).
Its owner-private request contains a manifest and the operator's signed directive.
The parent retains the verification context, registered factory and original
reservations in process.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from time import time
from typing import TYPE_CHECKING

from cwo_core.invocation_ledger import InvocationLedger, MAX_UNITS
from cwo_core.native_authority import AuthorityProvenanceError, canonical_authority_sha256, verify_operator_directive
from cwo_core.native_live_availability import NativeLiveUnavailable, require_registered_n1_live
from cwo_core.native_pool_admission import (
    FixedCohortAdmissionCapability,
    PoolAdmissionReservation,
    canonical_admission_sha256,
    validate_reservation_receipt,
)
from cwo_core.native_pool_contracts import canonical_sha256
from cwo_core.native_pool_deferred_context import QUALIFICATION_PROFILE
from cwo_core.native_pool_qualification_budget import campaign_start_snapshot, valid_start_limit
from cwo_core.native_pool_qualification_fixtures import POOL_QUALIFICATION_COHORT_SIZES, fixed_pool_qualification_cohorts
from cwo_core.native_pool_qualification_stage import (
    CAMPAIGN_BUDGET_ID, CAMPAIGN_START_CAP, PoolQualificationRun, _CAMPAIGN_APPROVAL_TOKEN, _CampaignApproval,
)
from cwo_core.native_pool_transaction import PLAN_VERSION, validate_transaction_plan
from cwo_core.policy_schema import strict_json_loads
from cwo_core.workspace_capture import BudgetExhausted, _pin_directory, read_at

if TYPE_CHECKING:
    from registered_pool_qualification_capability import ConnectedPoolCallbackCapability

APPROVAL_SCOPE = "cwo-contained-pool-qualification-v1"
_AUTHORITY_SCOPE = "stock-codex-contained-pool"
_MAX_INPUT_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MANIFEST_FIELDS = {"schema", "preparation", "runs", "expires_at", "stage_binding_sha256"}
_OPPORTUNITY = "capability_opportunity_sha256"
_RUN_FIELDS = {"plan", "authority_path", "reservation_sha256", "journal_path", "fixture_root"}
_CALIBRATION_FIELDS = {"scope", "calibration_plan_sha256", "adapter_scope_sha256", "expires_at", "runtime_seconds"}


class QualificationControllerError(ValueError):
    """The original protected approval or qualification inputs were refused."""


@dataclass(frozen=True, slots=True)
class ProtectedPoolQualificationParent:
    """In-process attachment selected by the original protected host."""

    request_path: Path
    verification_key: bytes = field(repr=False)
    actor_id: str
    identity_source: str
    admissions: tuple[PoolAdmissionReservation, ...] = field(repr=False)
    factory: Callable[..., tuple] = field(repr=False)
    capabilities: tuple[ConnectedPoolCallbackCapability, ...] = field(default=(), repr=False)
    calibration_admissions: tuple[PoolAdmissionReservation, ...] = field(default=(), repr=False)
    campaign_start_limit: int = CAMPAIGN_START_CAP


def _require(condition, reason):
    if not condition:
        raise QualificationControllerError(reason)


def _require_source():
    try:
        from cwo_core.native_live_availability import require_pool_qualification
    except ImportError as exc:
        raise NativeLiveUnavailable("native-pool-qualification-unavailable") from exc
    require_pool_qualification()
    require_registered_n1_live()


def _path(raw):
    _require(type(raw) is str and 0 < len(raw) <= 4096 and "\0" not in raw, "protected-path-invalid")
    path = Path(raw)
    _require(path.is_absolute() and path != path.parent and ".." not in path.parts and str(path) == raw,
             "protected-path-invalid")
    return path


def _owner_private(info, *, file):
    return (info.st_uid == os.geteuid() and (info.st_mode & 0o077) == 0
            and (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 if file else stat.S_ISDIR(info.st_mode)))


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_owner_json(path):
    pinned = _pin_directory(str(path.parent))
    _require(pinned is not None, "protected-directory-unavailable")
    directory, ancestry = pinned
    try:
        _require(_owner_private(os.fstat(directory), file=False), "protected-directory-permissions")
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        _require(_owner_private(named, file=True), "protected-file-permissions")
        kind, raw, observed = read_at(directory, path.name, _MAX_INPUT_BYTES)
        _require(kind == "file" and raw and len(raw) == named.st_size
                 and _file_identity(observed) == _file_identity(named), "protected-file-changed")
        _require_current_input(path, ancestry, observed)
    except (OSError, BudgetExhausted) as exc:
        raise QualificationControllerError("protected-file-unavailable") from exc
    finally:
        os.close(directory)
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise QualificationControllerError("protected-json-invalid") from exc
    _require(type(value) is dict, "protected-json-object-required")
    return value, sha256(raw).hexdigest()


def _require_current_input(path, ancestry, observed):
    current = _pin_directory(str(path.parent))
    _require(current is not None, "protected-directory-changed")
    descriptor, current_ancestry = current
    try:
        named = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        _require(current_ancestry == ancestry and _owner_private(os.fstat(descriptor), file=False)
                 and _file_identity(named) == _file_identity(observed),
                 "protected-file-changed")
    finally:
        os.close(descriptor)


def _manifest_start_limit(manifest):
    return manifest.get("campaign_start_limit", CAMPAIGN_START_CAP)


def qualification_action_sha256(manifest):
    """Bind the complete fixed stage request in the existing operator directive."""
    return canonical_authority_sha256({"scope": APPROVAL_SCOPE, "manifest": manifest,
                                       "campaign": CAMPAIGN_BUDGET_ID, "start_limit": _manifest_start_limit(manifest)})


def _approved_campaign(request, parent):
    from registered_pool_qualification_capability import calibration_action_sha256

    _require(type(parent) is ProtectedPoolQualificationParent, "protected-parent-attachment-required")
    manifest = _verify_approval(request, parent)
    start_limit = _manifest_start_limit(manifest)
    calibrations = manifest.get("calibrations", [])
    _require(type(calibrations) is list and len(calibrations) <= CAMPAIGN_START_CAP,
             "approved-calibration-start-cap-invalid")
    try:
        bindings = tuple((calibration_action_sha256(row["manifest"]), row["plan"]["plan_sha256"],
                          row["journal_path"], row["fixture_root"], row["manifest"]["expires_at"])
                         for row in calibrations)
    except (KeyError, TypeError) as exc:
        raise QualificationControllerError("approved-calibration-fields-invalid") from exc
    approval = _CampaignApproval(manifest["stage_binding_sha256"], qualification_action_sha256(manifest),
                                manifest["expires_at"], bindings, os.getpid(), parent, _CAMPAIGN_APPROVAL_TOKEN,
                                campaign_start_limit=start_limit)
    return manifest, approval


def _verify_approval(request, parent):
    _require(set(request) == {"manifest", "directive"}, "protected-request-fields-invalid")
    manifest, directive = request["manifest"], request["directive"]
    _require(type(manifest) is dict and _MANIFEST_FIELDS <= manifest.keys()
             <= _MANIFEST_FIELDS | {"calibrations", "campaign_start_limit"}
             and manifest["schema"] == APPROVAL_SCOPE and type(directive) is dict, "protected-request-schema-invalid")
    _verify_campaign_directive(parent, directive, manifest)
    _require(_digest(manifest["stage_binding_sha256"]), "approved-stage-binding-required")
    return manifest


def _verify_campaign_directive(parent, directive, manifest):
    _verify_directive(parent, directive, qualification_action_sha256(manifest), manifest["expires_at"])
    start_limit = _manifest_start_limit(manifest)
    _require(valid_start_limit(start_limit)
             and start_limit == parent.campaign_start_limit, "approved-campaign-start-limit-invalid")


def _digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _verify_directive(parent, directive, action, expires):
    try:
        authority = verify_operator_directive(directive, verification_key=parent.verification_key,
            expected_actor_id=parent.actor_id, expected_identity_source=parent.identity_source,
            expected_action_sha256=action)
        issued = datetime.fromisoformat(directive["issued_at"].replace("Z", "+00:00"))
    except (AuthorityProvenanceError, ValueError, RecursionError) as exc:
        raise QualificationControllerError("original-operator-directive-required") from exc
    _require(authority.authorized_scope == "complete-task" and directive["parent_receipt_sha256"] is None
             and issued.tzinfo is not None, "qualification-directive-scope-invalid")
    _require(type(expires) is int and issued.timestamp() <= time() < expires,
             "qualification-directive-expired-or-future")


def _validate_roster(manifest, admissions, stage):
    preparation, runs = manifest["preparation"], manifest["runs"]
    _require(type(preparation) is dict and type(runs) is list and 0 < len(runs) <= stage.CAMPAIGN_START_CAP
             and len(runs) == len(admissions), "approved-cohort-set-invalid")
    repeats, limits = stage._stage_limits(preparation, len(runs))
    stage._signed_failure_isolation(preparation, repeats)
    tasks = stage._stage_tasks(preparation)
    stage._stage_model(preparation)
    _require(limits["tool_calls"] >= max(POOL_QUALIFICATION_COHORT_SIZES), "approved-tool-capacity-required")
    sizes = tuple(size for size in POOL_QUALIFICATION_COHORT_SIZES for _ in range(repeats))
    for run, size, admission in zip(runs, sizes, admissions):
        _validate_run(run, tasks[size], admission, model=stage.QUALIFICATION_MODEL, sessions=limits["sessions"])
    _require_distinct_runs(runs, admissions)
    return runs


def _require_distinct_runs(runs, admissions):
    for values in ([run["plan"]["transaction_id"] for run in runs], [run["journal_path"] for run in runs],
                   [run["authority_path"] for run in runs],
                   [run["fixture_root"] for run in runs], [run["reservation_sha256"] for run in runs],
                   [id(item.capability) for item in admissions]):
        _require(len(set(values)) == len(runs), "approved-cohort-identity-reused")


def _validate_run(run, tasks, admission, *, model, sessions):
    _require(type(run) is dict and set(run) == _RUN_FIELDS | {_OPPORTUNITY} and type(run["plan"]) is dict
             and _digest(run[_OPPORTUNITY]),
             "approved-run-fields-invalid")
    plan = run["plan"]
    paths = {(task["write_path"],) for task in tasks}
    _require(not validate_transaction_plan(plan) and plan["version"] == PLAN_VERSION
             and plan["selected_model"] == model and plan["prelude_session_count"] == 0
             and plan["budget"]["cumulative_before"] == 0 and len(plan["children"]) == len(paths)
             and plan["budget"]["reserved_sessions"] <= sessions, "approved-run-plan-invalid")
    _require({tuple(child["write_paths"]) for child in plan["children"]} == paths, "approved-run-write-scope-invalid")
    for key in ("authority_path", "journal_path", "fixture_root"):
        _path(run[key])
    _validate_admission(admission, run["reservation_sha256"], plan)


def _validate_admission(admission, digest, plan):
    _require(type(admission) is PoolAdmissionReservation
             and type(admission.capability) is FixedCohortAdmissionCapability
             and admission.capability.state == "available" and type(admission.receipt) is dict
             and admission.admitted, "original-pool-reservation-required")
    capability, receipt = admission.capability, admission.receipt
    _require(not validate_reservation_receipt(receipt), "original-reservation-receipt-invalid")
    bindings = receipt["child_bindings"]
    _require(receipt["reservation_sha256"] == capability._reservation_sha256 == digest
             and receipt["fixed_cohort_sha256"] == capability._fixed_cohort_sha256
             and canonical_admission_sha256(bindings) == capability._child_bindings_sha256,
             "original-reservation-binding-mismatch")
    planned = {(child["child_id"], child["bead_id"], child["worktree_identity_sha256"]) for child in plan["children"]}
    reserved = {(child["child_id"], child["bead_id"], child["worktree_identity_sha256"]) for child in bindings}
    _require(planned == reserved, "reservation-cohort-mismatch")


def _load_run_authority(run):
    path = _path(run["authority_path"])
    data, digest = _read_owner_json(path)
    _require(digest == run["plan"]["authority_sha256"] and data.get("scope") == _AUTHORITY_SCOPE
             and all(data.get(key) == run[key] for key in ("fixture_root", "journal_path", "reservation_sha256")),
             "approved-run-authority-mismatch")
    _require("capability_receipt" not in data, "serialized-connected-capability-refused")
    return path, data


def _authority_for_run(run):
    path, data = _load_run_authority(run)
    _require(data.get("mode") == "qualification" and data.get(_OPPORTUNITY) == run[_OPPORTUNITY],
             "signed-calibration-opportunity-mismatch")
    return path


def _check_capability_objects(capabilities, count):
    from registered_pool_qualification_capability import ConnectedPoolCallbackCapability

    _require(len(capabilities) == count and all(type(value) is ConnectedPoolCallbackCapability for value in capabilities),
             "original-connected-capability-required")


def _calibration_action(row, parent, admission, model):
    from registered_pool_qualification_capability import calibration_action_sha256

    _require(type(row) is dict and set(row) == _RUN_FIELDS | {"manifest", "directive"}
             and type(row["plan"]) is dict, "approved-calibration-fields-invalid")
    plan, manifest = row["plan"], row["manifest"]
    _require(not validate_transaction_plan(plan) and plan["version"] == PLAN_VERSION
             and plan["prelude_session_count"] == 0 and plan["selected_model"] == model
             and len(plan["children"]) in POOL_QUALIFICATION_COHORT_SIZES, "approved-calibration-plan-invalid")
    _require(type(manifest) is dict and set(manifest) == _CALIBRATION_FIELDS
             and manifest["scope"] == "contained-pool-callback-calibration-v1"
             and manifest["calibration_plan_sha256"] == plan["plan_sha256"]
             and _digest(manifest["adapter_scope_sha256"]), "approved-calibration-manifest-invalid")
    _require(type(manifest["runtime_seconds"]) is int and 0 < manifest["runtime_seconds"] <= MAX_UNITS,
             "approved-calibration-runtime-unbounded")
    for key in ("authority_path", "journal_path", "fixture_root"):
        _path(row[key])
    action = calibration_action_sha256(manifest)
    _verify_directive(parent, row["directive"], action, manifest["expires_at"])
    _validate_admission(admission, row["reservation_sha256"], plan)
    return action


def _select_calibrations(manifest, parent, rows, stage):
    selected = manifest.get("calibrations", [])
    admissions = parent.calibration_admissions
    _require(type(selected) is list and len(selected) == len(admissions)
             and len(rows) + len(selected) <= stage.CAMPAIGN_START_CAP, "approved-calibration-start-cap-invalid")
    if not selected:
        _check_capability_objects(parent.capabilities, len(rows))
        return ()
    _require(not parent.capabilities, "mixed-callback-capability-sources-refused")
    actions = tuple(_calibration_action(row, parent, admission, stage.QUALIFICATION_MODEL)
                    for row, admission in zip(selected, admissions))
    _require(all(row["manifest"]["expires_at"] <= manifest["expires_at"] for row in selected),
             "approved-calibration-expiry-outside-campaign")
    _require(len(set(actions)) == len(actions) and set(actions) == {row[_OPPORTUNITY] for row in rows},
             "signed-calibration-opportunity-mismatch")
    _require_distinct_runs(rows + selected, parent.admissions + admissions)
    return tuple(zip(actions, selected, admissions))


def _execute_calibrations(stage, parent, selected, accounting, rows):
    from registered_pool_qualification_calibration import (
        run_protected_callback_calibration, verify_protected_callback_calibration_request,
    )

    requests = tuple((action, _calibration_inputs(row, parent, admission)) for action, row, admission in selected)
    for action, inputs in requests:
        _require(verify_protected_callback_calibration_request(parent, **inputs) == action,
                 "signed-calibration-opportunity-mismatch")
    with stage._campaign_custody(accounting.ledger.root):
        stage._require_campaign_budget(accounting, len(rows) + len(selected))
    issued = {}
    for action, inputs in requests:
        _require_source()
        issued[action] = run_protected_callback_calibration(parent, **inputs, _campaign_approval=accounting._approval)
        _check_capability_objects((issued[action],), 1)
    return tuple(issued[row[_OPPORTUNITY]] for row in rows)


def _calibration_inputs(row, parent, admission):
    path, data = _load_run_authority(row)
    fixture = _path(row["fixture_root"])
    _require(data.get("mode") == "callback-calibration" and _OPPORTUNITY not in data
             and not parent.request_path.is_relative_to(fixture), "approved-calibration-authority-invalid")
    return {"plan": row["plan"], "authority_path": path, "admission": admission,
            "manifest": row["manifest"], "directive": row["directive"]}


def _run_approved_stage(manifest, parent, *, approval, include_pass_record):
    from cwo_core import native_pool_qualification_stage as stage

    rows = _validate_roster(manifest, parent.admissions, stage)
    preparation = manifest["preparation"]
    report_inputs = _report_inputs(preparation, approval.campaign_start_limit) if include_pass_record else None
    _require(all(not parent.request_path.is_relative_to(_path(row["fixture_root"])) for row in rows),
             "protected-request-overlaps-fixture")
    calibrations = _select_calibrations(manifest, parent, rows, stage)
    authority_paths = tuple(_authority_for_run(row) for row in rows)

    accounting = stage.PoolQualificationAccounting(InvocationLedger(stage.contained_campaign_ledger_root()),
                                                     manifest["expires_at"], approval)
    binding = manifest["stage_binding_sha256"]
    planned = tuple((row["plan"], _path(row["journal_path"]), _path(row["fixture_root"])) for row in rows)
    _require(stage.contained_pool_qualification_binding(preparation, planned, accounting=accounting) == binding,
             "approved-stage-binding-mismatch")
    with stage._campaign_custody(accounting.ledger.root):
        capabilities = (_execute_calibrations(stage, parent, calibrations, accounting, rows)
                        if calibrations else parent.capabilities)
        _require(time() < manifest["expires_at"], "qualification-directive-expired-or-future")
        runs = tuple(_select_run(stage, row, path, admission, capability, parent.factory)
                     for row, path, admission, capability in zip(rows, authority_paths, parent.admissions, capabilities))
        _require(stage.pool_qualification_binding(preparation, runs, accounting=accounting) == binding,
                 "approved-stage-binding-mismatch")
        _require_source()
        result = stage.run_contained_pool_qualification_stage(preparation, runs, approved_binding=binding,
                                                              accounting=accounting)
        if report_inputs is not None:
            result = {**result, "pass_record": _pass_record(stage, result, rows, accounting, report_inputs)}
    try:
        _retain_stopped_transport(runs, result)
    except Exception:
        # Optional diagnostic custody cannot replace a completed stage result.
        pass
    return result


def _retain_stopped_transport(runs, result):
    transactions = result["transactions"]
    if result["outcome"] != "stopped" or not 0 < len(transactions) <= len(runs):
        return
    terminal = transactions[-1]
    run = runs[len(transactions) - 1]
    if (type(run) is not PoolQualificationRun or terminal.get("state") != "CONTAINED"
            or terminal.get("accepted") is not False or terminal.get("transaction_id") != run.plan["transaction_id"]):
        return
    from registered_pool_qualification import _retain_transport_failures

    _retain_transport_failures(run.runtime.start_worker_session)


def _select_run(stage, row, authority_path, admission, capability, builder):
    plan = row["plan"]
    selection = stage.select_contained_pool_runtime(plan, builder, authority_path=authority_path,
                                                    admission=admission, capability=capability)
    return stage.make_pool_qualification_run(plan, selection, journal_path=_path(row["journal_path"]),
                                            fixture_root=_path(row["fixture_root"]))


def run_protected_pool_qualification(parent, *, include_pass_record=False):
    """Verify the original signed approval, then invoke the exact held stage."""
    _require_source()
    _require(type(parent) is ProtectedPoolQualificationParent and type(parent.admissions) is tuple
             and type(parent.capabilities) is tuple and type(parent.calibration_admissions) is tuple
             and isinstance(parent.request_path, Path) and callable(parent.factory),
             "protected-parent-attachment-required")
    request, _digest = _read_owner_json(_path(str(parent.request_path)))
    manifest, approval = _approved_campaign(request, parent)
    return _run_approved_stage(manifest, parent, approval=approval, include_pass_record=include_pass_record)


def _report_inputs(preparation, cap):
    from cwo_core.native_pool_qualification_evidence import build_pass_record
    from cwo_core.paths import REPO_ROOT

    target = preparation.get("qualification_record")
    _require(type(target) is dict, "approved-qualification-record-required")
    inputs = {"cwo_version": (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip(),
              "minimum_codex_version": target.get("minimum_codex_version"),
              "date": datetime.now(timezone.utc).date(), "run_cap": cap}
    build_pass_record(**inputs, runs_consumed=0, outcomes={}, worker_tools={})
    return inputs


def _started_campaign_runs(stage, ledger, approved_cap):
    """Order every campaign intent by its durable sequence across allowances."""
    with stage._campaign_custody(ledger.root), ledger._locked() as (_root, document):
        status = campaign_start_snapshot(document)
        _require(status["cap"] == approved_cap, "qualification-record-budget-drift")
        attempts = {row["reservation_id"]: row for row in document["attempts"].values()}
        started = sorted((row for row in attempts.values() if row["budget_id"] in status["budget_ids"]
                          and any(entry["state"] == "invocation-intent" for entry in row["history"])),
                         key=lambda row: row["sequence"])
        _require(all(row["charge"] == {"starts": 1} for row in started), "qualification-record-start-charge-drift")
    return {row["reservation_id"]: index for index, row in enumerate(started, 1)}, attempts


def _pass_record(stage, result, rows, accounting, inputs):
    from cwo_core.native_pool_qualification_evidence import OutcomeObservation, build_pass_record

    started, attempts = _started_campaign_runs(stage, accounting.ledger, inputs["run_cap"])
    plans = {row["plan"]["transaction_id"]: row["plan"] for row in rows}
    observations, worker_tools, catalog_modes = {}, {}, {}
    for transaction in result["transactions"]:
        plan = plans.pop(transaction["transaction_id"], None)
        campaign = transaction.get("qualification_campaign", {})
        reservation = campaign.get("reservation_id")
        ordinal = started.get(reservation)
        request = "contained-cohort:" + canonical_sha256({"transaction_id": transaction["transaction_id"]})
        _require(plan is not None and transaction["plan_sha256"] == plan["plan_sha256"] and ordinal is not None
                 and attempts[reservation]["request_id"] == request,
                 "qualification-record-original-run-required")
        tools, behaviors, catalog = _run_observations(plan, transaction, attempts)
        if tools:
            worker_tools[ordinal] = tools
        if catalog is not None:
            catalog_modes[ordinal] = catalog
        for name, passed in behaviors.items():
            observations.setdefault(name, {}).setdefault(passed, []).append(ordinal)
    outcomes = {name: _behavior_outcome(witnesses, OutcomeObservation) for name, witnesses in observations.items()}
    return build_pass_record(**inputs, runs_consumed=len(started), outcomes=outcomes, worker_tools=worker_tools,
                             catalog_modes=catalog_modes)


def _behavior_outcome(witnesses, observation):
    if False in witnesses:
        return observation("failed", tuple(witnesses[False]))
    return observation("passed", tuple(witnesses[True]))


def _run_observations(plan, transaction, attempts):
    validation = transaction.get("validation", {})
    workers = validation.get("worker_observations", {})
    children = tuple(child["child_id"] for child in plan["children"])
    _require(workers.keys() <= set(children), "qualification-record-worker-binding-drift")
    ordered = tuple(workers.get(child, {}) for child in children)
    hosts = tuple(worker.get("host") or {} for worker in ordered)
    complete = all(host.get("worker_id") == child for host, child in zip(hosts, children))
    performed = _active_run_observations(transaction, attempts, validation, len(children), bool(workers))
    if "qualification_failure_isolation" in transaction:
        performed["failure_isolation"] = _observed_failure_isolation(plan, transaction["qualification_failure_isolation"])
    catalog = None
    if complete:
        tasks = _observation_tasks(plan)
        mounts = tuple(_host_observation(worker, "appserver-contained") for worker in ordered)
        performed.update(_complete_worker_observations(ordered, mounts, tasks, validation))
        catalog = _observed_catalog(hosts, mounts)
    return _worker_tool_observations(children, workers), performed, catalog


def _active_run_observations(transaction, attempts, validation, size, has_workers):
    checks = validation.get("qualification_active_limits", {})
    performed = {}
    if checks.get("effects_complete") is True:
        performed[f"n{size}_concurrency"] = True
        budget = _observed_budget(transaction, attempts)
        if budget is not None:
            performed["shared_budget"] = budget
    if has_workers and checks.get("cleanup_confirmed") is False:
        performed["cleanup"] = False
    return performed


def _observed_budget(transaction, attempts):
    proof = transaction.get("qualification_accounting", {})
    attempt = attempts.get(proof.get("reservation_id"), {})
    request = "pool-qualification-run:" + canonical_sha256({"transaction_id": transaction["transaction_id"]})
    if proof.get("mode") == "active" and attempt.get("request_id") == request:
        return (attempt.get("state") == "terminal" and attempt.get("charge") == attempt.get("amount")
                and all(attempt.get(key) == proof.get(key) for key in
                        ("budget_id", "request_sha256", "state", "outcome", "charge", "observed_usage")))
    return None


def _observed_failure_isolation(plan, receipt):
    target = next((child["child_id"] for child in plan["children"]
                   if child["write_paths"] == ["result-n3-worker-1.txt"]), None)
    _require(len(plan["children"]) == 3 and target is not None and type(receipt) is dict
             and receipt.keys() == {"target_child_id", "outcome"} and receipt["target_child_id"] == target
             and receipt["outcome"] in ("passed", "failed"), "qualification-record-failure-isolation-binding-drift")
    return receipt["outcome"] == "passed"


def _host_observation(worker, stage):
    host = worker.get("host") or {}
    original = [row["observation"] for row in host.get("observations", ()) if row["stage"] == stage]
    return original[0] if len(original) == 1 else {}


def _observation_tasks(plan):
    size = len(plan["children"])
    cohort = next(row for row in fixed_pool_qualification_cohorts() if row["size"] == size)
    tasks = {row["write_path"]: row for row in cohort["tasks"]}
    return tuple(tasks[child["write_paths"][0]] for child in plan["children"])


def _complete_worker_observations(workers, mounts, tasks, validation):
    writers = tuple(_host_observation(worker, "tool-contained") for worker in workers)
    fixture = validation.get("qualification_fixture", {})
    fixture_verified = fixture.get("outcome") == "verified" and fixture.get("worker_output_count") == len(workers)
    observed = {
        "readonly_workspace": _observed_mount_access(mounts, readonly=True),
        "registered_writer": _observed_writes(workers, tasks, writers, fixture_verified),
        "cross_worker_isolation": _observed_peer_isolation(mounts, writers, fixture_verified),
        "provider_only_egress": _observed_egress(mounts, writers),
        "dedicated_logins": _observed_dedicated_logins(workers, mounts, tasks),
        "cleanup": _observed_cleanup(workers, validation),
        **_observed_profiles(workers, mounts),
    }
    return {key: status for key, status in observed.items() if status is not None}


def _observed_mount_access(mounts, *, readonly):
    if all(mount.get("filesystem_ready") is True and type(mount.get("worktree_readonly")) is bool for mount in mounts):
        return all(mount["worktree_readonly"] is readonly for mount in mounts)
    return None


def _observed_writes(workers, tasks, writers, fixture_verified):
    access = _observed_mount_access(writers, readonly=False)
    outputs = tuple(_host_observation(worker, "writer-output") for worker in workers)
    if fixture_verified and access is not None and all(outputs):
        return access and all(_writer_output_matches(output, task) for output, task in zip(outputs, tasks))
    return None


def _writer_output_matches(output, task):
    return (bool(output.get("call_id")) and output.get("path") == task["write_path"]
            and output.get("content_sha256") == sha256(task["expected_utf8"].encode()).hexdigest())


def _isolated_namespaces(mounts, writers, namespace):
    identities = tuple(mount.get("namespaces", {}).get(namespace) for mount in mounts + writers)
    if all(type(identity) is str and re.fullmatch(rf"{namespace}:\[[0-9]+\]", identity) for identity in identities):
        apps, tools = identities[:len(mounts)], identities[len(mounts):]
        # All app servers start together. A writer is guaranteed to overlap
        # its own app server. Linux may reuse a settled writer's namespace inode.
        return len(set(apps)) == len(apps) and all(app != tool for app, tool in zip(apps, tools))
    return None


def _observed_peer_isolation(mounts, writers, fixture_verified):
    peers = tuple(mount.get("peer_worktrees_hidden") for mount in mounts + writers)
    separate = _isolated_namespaces(mounts, writers, "mnt")
    if separate is not None and all(type(count) is int for count in peers):
        if not separate or peers != (len(mounts) - 1,) * len(peers):
            return False
        if fixture_verified:
            return True
    return None


def _observed_egress(mounts, writers):
    app_network = tuple(mount.get("network") for mount in mounts)
    tool_network = tuple(writer.get("network") for writer in writers)
    separate = _isolated_namespaces(mounts, writers, "net")
    if separate is not None and all(app_network + tool_network):
        return separate and all(value == "registered-provider-tunnel" for value in app_network) and all(
            value == "isolated" for value in tool_network)
    return None


def _observed_dedicated_logins(workers, mounts, tasks):
    slots = tuple(worker["host"].get("login_slot") for worker in workers)
    projections = tuple(mount.get("managed_login_projection") for mount in mounts)
    if all(type(slot) is int for slot in slots) and all(type(projection) is bool for projection in projections):
        expected = tuple(int(task["worker_slot"].rsplit("-", 1)[1]) for task in tasks)
        return slots == expected and all(projections)
    return None


def _observed_profiles(workers, mounts):
    profiles = tuple(worker.get("thread_profile") or {} for worker in workers)
    if not all(_observed_profile(profile, mount) for profile, mount in zip(profiles, mounts)):
        return {}
    checks = {"named_profile": all(profile["id"] == QUALIFICATION_PROFILE for profile in profiles)}
    if all(type(profile.get("widening_refused")) is bool for profile in profiles):
        checks["profile_cannot_widen"] = all(profile["widening_refused"] for profile in profiles)
    login_policy = _observed_login_policy(workers, mounts, profiles)
    if checks["named_profile"] and login_policy is not None:
        checks["login_path_denied"] = login_policy
    return checks


def _observed_profile(profile, mount):
    owner = profile.get("owner_identity_sha256")
    return (type(profile.get("id")) is str and type(owner) is str and _DIGEST.fullmatch(owner) is not None
            and owner == mount.get("owner_identity_sha256"))


def _observed_login_policy(workers, mounts, profiles):
    configuration_verified = all(_observed_mounted_configuration(worker["host"], mount)
                                 for worker, mount in zip(workers, mounts))
    rules = tuple(_host_observation(worker, "named-profile-config") for worker in workers)
    if configuration_verified and all(rule.get("id") == profile["id"] and "managed_login_access" in rule
                                      for rule, profile in zip(rules, profiles)):
        return all(rule["managed_login_access"] == "deny" for rule in rules)
    return None


def _observed_cleanup(workers, validation):
    if (validation.get("qualification_active_limits", {}).get("cleanup_confirmed") is True
            and validation.get("qualification_settlement", {}).get("outcome") == "verified"
            and all((worker.get("host") or {}).get("cleanup_confirmed") is True
                    and worker.get("wire_settled") is True for worker in workers)):
        return True
    return None


def _observed_catalog(hosts, mounts):
    catalog = {host.get("model_catalog_sha256", "missing") for host in hosts}
    if len(catalog) != 1 or not all(_observed_mounted_configuration(host, mount) for host, mount in zip(hosts, mounts)):
        return None
    digest, = catalog
    if digest is None:
        return "stock-fallback"
    return "trimmed" if type(digest) is str and _DIGEST.fullmatch(digest) is not None else None


def _observed_mounted_configuration(host, mount):
    pin = host.get("config_sha256")
    return mount.get("filesystem_ready") is True and type(pin) is str and _DIGEST.fullmatch(pin) is not None


def _worker_tool_observations(children, workers):
    from cwo_core.native_pool_qualification_evidence import WorkerToolObservation

    names = {entry.name for entry in fields(WorkerToolObservation)}
    observed = {}
    for ordinal, child in enumerate(children, 1):
        worker = workers.get(child, {})
        if (worker.get("host") or {}).get("worker_id") != child:
            continue
        tools = worker.get("tools")
        if _observed_tool_rows(tools, names):
            observed[ordinal] = WorkerToolObservation(**{key: tuple(items) for key, items in tools.items()})
    return observed


def _observed_tool_rows(tools, names):
    return (type(tools) is dict and tools.keys() == names
            and all(type(items) in (list, tuple) and all(type(item) is str for item in items) for items in tools.values())
            and any(tools[key] for key in names - {"limitations"}))


def main(argv=None, *, parent=None):
    """Public invocation preserves the hold and accepts no trust inputs."""
    argparse.ArgumentParser(description=__doc__, allow_abbrev=False).parse_args(argv)
    try:
        result = run_protected_pool_qualification(parent, include_pass_record=True)
    except (QualificationControllerError, NativeLiveUnavailable) as exc:
        print(f"run_native_pool_qualification: {exc}", file=sys.stderr)
        return 2
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        print("run_native_pool_qualification: stage refused (" + type(exc).__name__ + ")", file=sys.stderr)
        return 2
    record = result["pass_record"]
    print(json.dumps({"outcome": result["outcome"], "pass_record": record}))
    return 0 if record["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
