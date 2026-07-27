#!/usr/bin/env python3
"""Prepare, approve, or run one fixed native tool-boundary activation preview."""

from __future__ import annotations

import argparse
from copy import deepcopy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_activation_ledger import (  # noqa: E402
    NativeActivationLedgerStore,
    canonical_activation_sha256,
    ensure_private_directory,
    read_private_json,
    write_exclusive_private_json,
)
from cwo_core.native_activation_preview import (  # noqa: E402
    PROFILE,
    RESULT_SCHEMA,
    RESULT_TYPE,
    RESULT_VERSION,
    NativeActivationPreviewError,
    acquire_activation_claim,
    activation_dry_run,
    activation_iso,
    approve_activation_plan,
    generate_activation_key,
    load_activation_plan,
    operator_approval_verifier,
    prepare_activation_plan,
    read_activation_key,
)
from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_pool_admission import (  # noqa: E402
    AdmissionCandidate,
    BeadsClaimAdapter,
    reserve_pool_cohort,
)
from cwo_core.native_pool_admitted import run_admitted_native_pool  # noqa: E402
from cwo_core.native_pool_config import (  # noqa: E402
    ADMITTED_RENDER_REQUEST_SCHEMA,
    build_pool_contract,
)
from cwo_core.native_pool_contracts import (  # noqa: E402
    POOL_POLL_INTERVAL_MS,
    canonical_sha256,
    write_private_artifact,
)
from cwo_core.native_pool_leases import (  # noqa: E402
    PoolLeaseRegistry,
    capture_owner_identity,
)
from cwo_core.native_pool_preflight import (  # noqa: E402
    ADMITTED_PREFLIGHT_REQUEST_SCHEMA,
    default_callback_certification,
    run_pool_preflight,
)
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor  # noqa: E402
from cwo_core.native_stop_scope import (  # noqa: E402
    build_stop_metadata,
    policy_scope_authority,
)
from cwo_core.native_tool_activation import (  # noqa: E402
    verify_tool_enforcement_activation,
)
from cwo_core.native_tool_isolation import (  # noqa: E402
    TOOL_ENFORCEMENT_OVERRIDE_RISK,
    require_unchanged_tool_surface,
)
from cwo_core.policy import load_policy  # noqa: E402
from run_native_pool_live_canaries import (  # noqa: E402
    CONTROL_TURN_ID,
    AppServer,
    AppServerError,
    LiveThreadAdapter,
    calibration,
    capture_server_tool_surface,
    contain_started_threads,
    pool_sleep,
)


PREVIEW_CONTROL_ID = "cwo-native-tool-activation-preview"
RESULT_FIELDS = frozenset(
    {
        "result_type",
        "version",
        "schema",
        "activation_id",
        "profile",
        "live",
        "status",
        "plan_sha256",
        "claim_sha256",
        "action_sha256",
        "approval_sha256",
        "ledger_sha256",
        "reservation_sha256",
        "dispatch_sha256",
        "pool_receipt_sha256",
        "risk_acknowledgement",
        "no_resume_or_salvage",
        "started_at",
        "finished_at",
        "failure_class",
        "failure_message_sha256",
        "result_sha256",
    }
)


def _pool_capability_receipt(
    capability: Mapping[str, Any],
    requested_workers: int,
) -> Mapping[str, Any] | None:
    """Use the concurrency receipt only for a genuinely concurrent pool."""

    return capability if requested_workers > 1 else None


class ActivationLedgerTransport:
    """Record preview intents before delegating each sole worker RPC."""

    def __init__(
        self,
        server: AppServer,
        ledger: NativeActivationLedgerStore,
        *,
        pending_allocation_intents: Mapping[str, str] | None = None,
    ) -> None:
        self.server = server
        self.ledger = ledger
        self.thread_roles: dict[str, str] = {}
        self.pending_allocation_intents = dict(
            pending_allocation_intents or {}
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.server, name)

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
        permitted_tools: list[str] | None = None,
        allowlist_parameter: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        if role is None:
            raise AppServerError("activation-preview-role-required")
        ledger_role = (
            "calibration" if role == "capability-calibration" else role
        )
        intent_id = self.pending_allocation_intents.pop(
            ledger_role,
            None,
        )
        if intent_id is None:
            intent_id = self.ledger.allocation_intent(ledger_role)
        result, latency = self.server.start_thread(
            cwd,
            mutable=mutable,
            role=role,
            permitted_tools=permitted_tools,
            allowlist_parameter=allowlist_parameter,
        )
        thread = result.get("thread")
        thread_id = thread.get("id") if isinstance(thread, Mapping) else None
        if not isinstance(thread_id, str):
            raise AppServerError("activation-preview-thread-id-invalid")
        self.ledger.bind_thread(intent_id, ledger_role, thread_id)
        self.thread_roles[thread_id] = ledger_role
        return result, latency

    def start_turn(
        self,
        thread_id: str,
        prompt: str,
        *,
        timeout: float = 30,
        ambiguity_timeout: float = 5,
    ) -> tuple[dict[str, Any], float]:
        role = self.thread_roles.get(thread_id)
        if role is None:
            raise AppServerError("activation-preview-thread-role-missing")
        intent_id = self.ledger.turn_intent(role, thread_id, prompt)
        turn, latency = self.server.start_turn(
            thread_id,
            prompt,
            timeout=timeout,
            ambiguity_timeout=ambiguity_timeout,
        )
        turn_id = turn.get("id")
        if not isinstance(turn_id, str):
            raise AppServerError("activation-preview-turn-id-invalid")
        self.ledger.bind_turn(role, intent_id, turn_id)
        return turn, latency


class ActivationThreadAdapter(LiveThreadAdapter):
    """Use the certified live adapter with preview-local record labels."""

    def mark_dispatched(
        self,
        *,
        submission_id: str,
        **_kwargs: Any,
    ) -> dict[str, str]:
        if submission_id != self.turn_id:
            raise AppServerError("submission-id-binding-mismatch")
        write_private_artifact(
            self.record_dir / f"{self.thread_id}-dispatch.json",
            {
                "thread_id": self.thread_id,
                "turn_id": self.turn_id,
                "prompt_sha256": hashlib.sha256(
                    self.prompt.encode("utf-8")
                ).hexdigest(),
                "control_turn_id": PREVIEW_CONTROL_ID,
            },
        )
        return {"ack": "dispatched"}

    def finalize(
        self,
        *,
        control_action: str,
        **_kwargs: Any,
    ) -> dict[str, str]:
        write_private_artifact(
            self.record_dir
            / f"{self.thread_id}-finalize-{control_action}.json",
            {
                "thread_id": self.thread_id,
                "turn_id": self.turn_id,
                "control_action": control_action,
                "control_turn_id": PREVIEW_CONTROL_ID,
            },
        )
        return {"ack": control_action}


def _aggregate_budget(tasks: list[Mapping[str, Any]]) -> dict[str, int]:
    return {
        field: sum(int(task["hard_budget"][field]) for task in tasks)
        for field in (
            "tool_calls",
            "runtime_seconds",
            "compactions",
            "full_suite_runs",
            "mutations",
        )
    }


def _write_worker_contracts(
    plan: Mapping[str, Any],
    reservation: Mapping[str, Any],
    transport: ActivationLedgerTransport,
    server: AppServer,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, ActivationThreadAdapter],
]:
    records = Path(plan["paths"]["records"])
    claims = {
        item["bead_id"]: item
        for item in reservation["claims"]
        if item.get("owned") is True
    }
    bindings = {
        item["bead_id"]: item for item in reservation["child_bindings"]
    }
    render_children: list[dict[str, Any]] = []
    child_contracts: dict[str, dict[str, Any]] = {}
    adapters: dict[str, ActivationThreadAdapter] = {}
    for task in plan["tasks"]:
        tool_policy = task["tool_policy"]
        preflight_surface = capture_server_tool_surface(
            server,
            tool_policy,
        )
        if preflight_surface != task["tool_surface"]:
            raise AppServerError(
                "activation-preview-tool-surface-plan-mismatch"
            )
        current_surface = capture_server_tool_surface(server, tool_policy)
        require_unchanged_tool_surface(
            preflight_surface,
            current_surface,
        )
        kwargs: dict[str, Any] = {
            "mutable": task["isolation_class"] == "mutable-isolated",
            "role": task["role"],
        }
        if current_surface["server_allowlist_supported"]:
            kwargs.update(
                {
                    "permitted_tools": list(
                        tool_policy["permitted_tools"]
                    ),
                    "allowlist_parameter": current_surface[
                        "allowlist_parameter"
                    ],
                }
            )
        result, _latency = transport.start_thread(
            Path(task["worktree"]),
            **kwargs,
        )
        thread_id = str(result["thread"]["id"])
        child_id = str(task["child_id"])
        state_file = records / f"{child_id}-worker-state.json"
        control_file = records / f"{child_id}-control-contract.json"
        control_turn_id = (
            f"{PREVIEW_CONTROL_ID}:{plan['activation_id']}:{task['ordinal']}"
        )
        control = build_control_turn_contract(
            state_file=str(state_file),
            agent_id=thread_id,
            control_turn_id=control_turn_id,
            task_sha256=hashlib.sha256(
                task["prompt"].encode("utf-8")
            ).hexdigest(),
            poll_interval_ms=POOL_POLL_INTERVAL_MS,
        )
        state = {
            "result_type": "cwo-native-supervision-state",
            "version": 1,
            "schema": "schemas/native-supervision-state.schema.json",
            "packet_id": task["packet_id"],
            "packet_sha256": task["packet_sha256"],
            "agent_id": thread_id,
            "session_id": thread_id,
            "status": "created",
            "control_turn_id": None,
            "poll_interval_ms": POOL_POLL_INTERVAL_MS,
            "control_adapter": "native-multi-agent-v1",
            "required_capabilities": ["interrupt", "close", "wait"],
            **build_stop_metadata(
                "child",
                authority=policy_scope_authority(
                    "activation-preview-child-state-v1",
                    authorized_scope="child",
                ),
            ),
        }
        write_private_artifact(control_file, control)
        write_private_artifact(state_file, state)
        binding = bindings[task["bead_id"]]
        claim = claims[task["bead_id"]]
        admission_fields = {
            field: deepcopy(binding[field])
            for field in (
                "bead_id",
                "work_unit_id",
                "candidate_sha256",
                "work_estimate_sha256",
                "worker_commitment_sha256",
                "lease_scope_sha256",
                "worktree_identity_sha256",
                "requested_model",
                "admitted_child_sha256",
            )
        }
        render_child = {
            "child_id": child_id,
            "packet_id": task["packet_id"],
            "attempt_nonce": task["attempt_nonce"],
            "session_id": thread_id,
            "agent_id": thread_id,
            "control_turn_id": control_turn_id,
            "packet_sha256": task["packet_sha256"],
            "control_contract_file": str(control_file),
            "state_file": str(state_file),
            "worktree": task["worktree"],
            "isolation_class": task["isolation_class"],
            "completion_evidence_policy": deepcopy(
                task["completion_evidence_policy"]
            ),
            "tool_policy": deepcopy(tool_policy),
            "declared_write_paths": list(task["declared_write_paths"]),
            "integration_target_paths": list(
                task["integration_target_paths"]
            ),
            "lease_id": task["lease_id"],
            "claim_sha256": claim["claim_sha256"],
            "hard_budget": deepcopy(task["hard_budget"]),
            **admission_fields,
        }
        render_children.append(render_child)
        child_contracts[child_id] = control
        target = (
            str(task["integration_target_paths"][0])
            if task["integration_target_paths"]
            else None
        )
        adapters[child_id] = ActivationThreadAdapter(
            transport,
            result,
            prompt=task["prompt"],
            expected_token=task["expected_token"],
            worktree=Path(task["worktree"]),
            mutable=task["isolation_class"] == "mutable-isolated",
            expected_mutation=target,
            completion_evidence_policy=task[
                "completion_evidence_policy"
            ],
            tool_policy=tool_policy,
            prompt_preflight_receipt=task["prompt_preflight"],
            preflight_tool_surface=preflight_surface,
            tool_surface_reader=(
                lambda policy=tool_policy: capture_server_tool_surface(
                    server,
                    policy,
                )
            ),
            record_dir=records,
        )
    return render_children, child_contracts, adapters


def _predispatch_child(
    task: Mapping[str, Any],
    render_child: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "child_id": task["child_id"],
        "packet_id": task["packet_id"],
        "packet_sha256": task["packet_sha256"],
        "attempt_nonce": task["attempt_nonce"],
        "session_id": render_child["session_id"],
        "agent_id": render_child["agent_id"],
        "lease_id": task["lease_id"],
        "worktree": task["worktree"],
        "isolation_class": task["isolation_class"],
        "completion_evidence_policy": deepcopy(
            task["completion_evidence_policy"]
        ),
        "tool_policy": deepcopy(task["tool_policy"]),
        "prompt": task["prompt"],
        "prompt_preflight": deepcopy(task["prompt_preflight"]),
        "tool_surface": deepcopy(task["tool_surface"]),
        "hard_budget": deepcopy(task["hard_budget"]),
        "declared_write_paths": list(task["declared_write_paths"]),
        "integration_target_paths": list(
            task["integration_target_paths"]
        ),
        **{
            field: deepcopy(render_child[field])
            for field in (
                "bead_id",
                "work_unit_id",
                "candidate_sha256",
                "claim_sha256",
                "work_estimate_sha256",
                "worker_commitment_sha256",
                "lease_scope_sha256",
                "worktree_identity_sha256",
                "requested_model",
                "admitted_child_sha256",
            )
        },
    }


def _result(
    plan: Mapping[str, Any],
    *,
    status: str,
    started_at: str,
    claim_sha256: str | None,
    approval_sha256: str,
    ledger_sha256: str | None,
    reservation_sha256: str | None = None,
    dispatch_sha256: str | None = None,
    pool_receipt_sha256: str | None = None,
    failure: BaseException | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "result_type": RESULT_TYPE,
        "version": RESULT_VERSION,
        "schema": RESULT_SCHEMA,
        "activation_id": plan["activation_id"],
        "profile": plan["profile"],
        "live": True,
        "status": status,
        "plan_sha256": plan["plan_sha256"],
        "claim_sha256": claim_sha256,
        "action_sha256": plan["activation_artifacts"]["action_sha256"],
        "approval_sha256": approval_sha256,
        "ledger_sha256": ledger_sha256,
        "reservation_sha256": reservation_sha256,
        "dispatch_sha256": dispatch_sha256,
        "pool_receipt_sha256": pool_receipt_sha256,
        "risk_acknowledgement": TOOL_ENFORCEMENT_OVERRIDE_RISK,
        "no_resume_or_salvage": True,
        "started_at": started_at,
        "finished_at": activation_iso(),
        "failure_class": type(failure).__name__ if failure is not None else None,
        "failure_message_sha256": (
            hashlib.sha256(str(failure).encode("utf-8")).hexdigest()
            if failure is not None
            else None
        ),
    }
    value["result_sha256"] = canonical_activation_sha256(value)
    if set(value) != RESULT_FIELDS:
        raise NativeActivationPreviewError(
            "activation-result-fields-invalid"
        )
    return value


def _require_accepting_pool_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        receipt.get("accepting") is not True
        or receipt.get("pool_disposition") != "accepted"
        or receipt.get("reasons") != []
        or receipt.get("first_protected_fault") is not None
    ):
        raise NativeActivationPreviewError(
            "activation-pool-not-accepting"
        )
    return dict(receipt)


def _persist_pool_outcome(
    records: Path,
    launched: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    dispatch = dict(launched["dispatch_receipt"])
    dispatch_sha256 = str(dispatch["dispatch_sha256"])
    pool_receipt = dict(launched["pool_receipt"])
    pool_receipt_sha256 = canonical_sha256(pool_receipt)
    write_private_artifact(
        records / "activation-dispatch-receipt.json",
        dispatch,
    )
    write_private_artifact(
        records / "activation-pool-receipt.json",
        pool_receipt,
    )
    return (
        dispatch,
        pool_receipt,
        dispatch_sha256,
        pool_receipt_sha256,
    )


def _contain_allocated_threads(
    server: AppServer | None,
    ledger: NativeActivationLedgerStore | None,
) -> dict[str, Any]:
    preview_summary = (
        ledger.summary()
        if ledger is not None
        else {
            "phase": None,
            "pending_allocation": False,
            "pending_turn": False,
            "terminal": False,
        }
    )
    preview_unresolved = bool(
        preview_summary["pending_allocation"]
        or preview_summary["pending_turn"]
    )
    try:
        containment = (
            contain_started_threads(
                server,
                allow_same_process_proofs=not preview_unresolved,
            )
            if server is not None
            else {
                "allocated_count": 0,
                "identified_thread_count": 0,
                "interrupted_count": 0,
                "archived_count": 0,
                "already_contained_count": 0,
                "unresolved_allocation_intent_count": 0,
                "unresolved_turn_intent_count": 0,
                "ambiguous_count": 0,
                "all_contained": True,
                "ledger_consistent": True,
                "ledger_error_sha256": [],
            }
        )
        proof_reader = getattr(
            server,
            "same_process_containment_proofs",
            None,
        )
        proof_objects = proof_reader() if callable(proof_reader) else []
    except BaseException as exc:
        containment = {
            "allocated_count": 0,
            "identified_thread_count": 0,
            "interrupted_count": 0,
            "archived_count": 0,
            "already_contained_count": 0,
            "unresolved_allocation_intent_count": 0,
            "unresolved_turn_intent_count": 0,
            "ambiguous_count": 1,
            "all_contained": False,
            "ledger_consistent": False,
            "ledger_error_sha256": [
                hashlib.sha256(
                    f"{type(exc).__name__}:{exc}".encode("utf-8")
                ).hexdigest()
            ],
        }
        proof_objects = []
    return {
        **containment,
        "same_process_containment_proofs": proof_objects,
        "preview_phase": preview_summary["phase"],
        "preview_pending_allocation": preview_summary[
            "pending_allocation"
        ],
        "preview_pending_turn": preview_summary["pending_turn"],
        "preview_terminal": preview_summary["terminal"],
        "all_contained": (
            containment.get("all_contained") is True
            and not preview_unresolved
        ),
    }


def run_live_activation(
    plan_path: Path,
    approval_path: Path,
    *,
    control_root: Path,
    actor_id: str,
    identity_source: str,
) -> dict[str, Any]:
    started_at = activation_iso()
    control_root = ensure_private_directory(control_root, create=False)
    plan = load_activation_plan(
        plan_path,
        check_live_source=True,
        now=dt.datetime.now(dt.timezone.utc),
    )
    if Path(plan["control_root"]) != control_root:
        raise NativeActivationPreviewError(
            "activation-control-root-mismatch"
        )
    approval = read_private_json(
        approval_path,
        label="activation-approval",
    )
    approval_sha256 = canonical_activation_sha256(approval)
    key = read_activation_key(control_root)
    owner = capture_owner_identity(os.getpid())
    claim: dict[str, Any] | None = None
    ledger: NativeActivationLedgerStore | None = None
    server: AppServer | None = None
    reservation: Mapping[str, Any] | None = None
    dispatch_sha256: str | None = None
    pool_receipt_sha256: str | None = None
    try:
        # A bad or expired approval still consumes this prepared attempt.
        claim = acquire_activation_claim(
            plan,
            approval,
            controller_identity=owner,
        )
        ledger = NativeActivationLedgerStore.create(
            Path(plan["paths"]["ledger"]),
            profile=plan["profile"],
            plan_sha256=plan["plan_sha256"],
            claim_sha256=claim["claim_sha256"],
            action_sha256=plan["activation_artifacts"]["action_sha256"],
            campaign_nonce=plan["campaign_nonce"],
        )
        ledger.append(
            "approval-consume-intent",
            detail={"approval_sha256": approval_sha256},
        )
        verifier = operator_approval_verifier(
            plan,
            key=key,
            actor_id=actor_id,
            identity_source=identity_source,
            now=dt.datetime.now(dt.timezone.utc),
        )
        activation = verify_tool_enforcement_activation(
            plan["activation_request"],
            approval_receipt=approval,
            operator_approval_verifier=verifier,
        )
        ledger.append(
            "approval-verified",
            detail={"action_sha256": activation.action_sha256},
        )
        ledger.append(
            "activation-dispatch-intent",
            detail={"profile": plan["profile"]},
        )

        candidate = AdmissionCandidate(
            plan["readiness_evidence"],
            plan["work_estimates"],
            plan["proportionality_assessment"],
            {
                binding["bead_id"]: binding
                for binding in plan["child_bindings"]
            },
        )
        claim_adapter = BeadsClaimAdapter(
            directory=Path(plan["paths"]["beads_directory"]),
            database=Path(plan["paths"]["beads_database"]),
            actor="native-activation-preview-live",
            timeout=20,
        )
        reserved = reserve_pool_cohort(
            candidate,
            claim_adapter=claim_adapter,
            admission_nonce=plan["activation_id"],
            live_revalidate=lambda binding: dict(binding),
            rebuild=None,
            policy_document=load_policy("native-worker-execution"),
            productive=True,
        )
        if not reserved.admitted:
            raise NativeActivationPreviewError(
                "activation-cohort-not-admitted"
            )
        reservation = reserved.receipt
        action = plan["activation_artifacts"]["action"]
        if (
            reservation["fixed_cohort_sha256"]
            != action["fixed_cohort_sha256"]
            or reservation["child_bindings_sha256"]
            != action["child_bindings_sha256"]
        ):
            raise NativeActivationPreviewError(
                "activation-reservation-binding-mismatch"
            )

        # The calibration allocation intent also precedes app-server
        # initialization, so every possible live RPC follows durable intent.
        calibration_intent = ledger.allocation_intent("calibration")
        server = AppServer()
        transport = ActivationLedgerTransport(
            server,
            ledger,
            pending_allocation_intents={
                "calibration": calibration_intent,
            },
        )
        capability, _calibration_evidence = calibration(
            transport,
            Path(plan["paths"]["integration"]),
            Path(plan["paths"]["records"]),
            owner,
            run_nonce=plan["activation_id"],
            phase_nonce=plan["campaign_nonce"],
        )
        render_children, child_contracts, adapters = (
            _write_worker_contracts(
                plan,
                reservation,
                transport,
                server,
            )
        )
        aggregate_budget = _aggregate_budget(plan["tasks"])
        policy = load_policy("native-worker-execution")
        pool_capability_receipt = _pool_capability_receipt(
            capability,
            plan["requested_workers"],
        )
        render_request = {
            "request_type": (
                "cwo-native-supervision-pool-render-request"
            ),
            "version": 2,
            "schema": ADMITTED_RENDER_REQUEST_SCHEMA,
            "pool_id": plan["pool_id"],
            "pool_epoch": plan["pool_epoch"],
            # The capability receipt certifies this exact shared adapter
            # control turn; child records retain preview-local identities.
            "control_turn_id": CONTROL_TURN_ID,
            "created_at": activation_iso(),
            "max_active_workers": plan["requested_workers"],
            "aggregate_hard_budget": aggregate_budget,
            "integration_root": plan["paths"]["integration"],
            "children": render_children,
            "completion_policy": "all-or-nothing",
            "admission_reservation": reservation,
        }
        contract = build_pool_contract(
            render_request,
            capability_receipt=pool_capability_receipt,
            enable_concurrency=True,
            owner_pid=os.getpid(),
            now=dt.datetime.now(dt.timezone.utc),
            policy_document=policy,
        )
        predispatch_children = [
            _predispatch_child(task, render_child)
            for task, render_child in zip(
                plan["tasks"],
                render_children,
            )
        ]
        preflight_request = {
            "preflight_type": (
                "cwo-native-supervision-pool-preflight-request"
            ),
            "version": 2,
            "schema": ADMITTED_PREFLIGHT_REQUEST_SCHEMA,
            "stage": "pre-dispatch",
            "launch_id": plan["launch_id"],
            "campaign_nonce": plan["campaign_nonce"],
            "pool_id": plan["pool_id"],
            "pool_epoch": plan["pool_epoch"],
            "integration_root": plan["paths"]["integration"],
            "artifact_directories": [plan["paths"]["records"]],
            "requested_workers": plan["requested_workers"],
            "released_capacity": policy["native_supervision_pool"][
                "capacity"
            ]["released_max_active_workers"],
            "aggregate_hard_budget": aggregate_budget,
            "children": predispatch_children,
            "fallback": {
                "main_thread": "operator-main-thread",
                "recovery": "operator-fresh-activation-only",
            },
            "productive_dogfood_delivery_prerequisite": False,
            "callback_certification": default_callback_certification(),
            "poll_interval_ms": POOL_POLL_INTERVAL_MS,
            "pool_contract": contract,
            "overrides": [],
            "admission_reservation": reservation,
        }
        preflight = run_pool_preflight(
            preflight_request,
            activation_capability=activation,
            policy_document=policy,
        )
        if (
            preflight.get("accepted") is not True
            or preflight.get("decision") != "accept"
        ):
            raise NativeActivationPreviewError(
                "activation-predispatch-preflight-rejected"
            )
        write_private_artifact(
            Path(plan["paths"]["records"]) / "predispatch-preflight.json",
            preflight,
        )
        monitor = PoolWorkspaceMonitor(
            contract,
            integration_root=Path(plan["paths"]["integration"]),
            child_worktrees={
                child_id: adapter.worktree
                for child_id, adapter in adapters.items()
            },
            policy_document=policy,
        )

        def read_child_evidence(
            *,
            child_id: str,
            state_file: str,
        ) -> dict[str, Any]:
            contract_child = next(
                child
                for child in contract["children"]
                if child["child_id"] == child_id
            )
            if state_file != contract_child["state_file"]:
                raise AppServerError(
                    "activation-preview-state-file-mismatch"
                )
            return adapters[child_id].evidence()

        launched = run_admitted_native_pool(
            reservation,
            reserved.capability,
            contract,
            preflight_request,
            preflight,
            child_contracts,
            {
                task["child_id"]: task["prompt"]
                for task in plan["tasks"]
            },
            {
                child_id: adapter.callbacks()
                for child_id, adapter in adapters.items()
            },
            claim_adapter=reserved.claim_adapter,
            live_revalidate=lambda binding: dict(binding),
            pool_callbacks={
                "monotonic_ns": time.monotonic_ns,
                "sleep": pool_sleep,
                "now_utc": activation_iso,
                "read_child_evidence": read_child_evidence,
                "compare_workspaces": monitor.compare,
            },
            lease_registry=PoolLeaseRegistry(
                Path(plan["paths"]["leases"])
            ),
            capability_receipt=pool_capability_receipt,
            activation_capability=activation,
            state_file=Path(plan["paths"]["pool_state"]),
            decision_file=Path(plan["paths"]["pool_decision"]),
            policy_document=policy,
        )
        (
            dispatch,
            raw_pool_receipt,
            dispatch_sha256,
            pool_receipt_sha256,
        ) = _persist_pool_outcome(
            Path(plan["paths"]["records"]),
            launched,
        )
        _require_accepting_pool_receipt(raw_pool_receipt)
        ledger.append(
            "terminal",
            subject_id=pool_receipt_sha256,
            detail={
                "outcome": "accepted",
                "pool_receipt_sha256": pool_receipt_sha256,
            },
        )
        ledger_state = ledger.load()
        result = _result(
            plan,
            status="accepted",
            started_at=started_at,
            claim_sha256=claim["claim_sha256"],
            approval_sha256=approval_sha256,
            ledger_sha256=ledger_state["ledger_sha256"],
            reservation_sha256=reservation["reservation_sha256"],
            dispatch_sha256=dispatch_sha256,
            pool_receipt_sha256=pool_receipt_sha256,
        )
        write_exclusive_private_json(
            Path(plan["paths"]["result"]),
            result,
            label="activation-result",
        )
        return result
    except BaseException as exc:
        containment = _contain_allocated_threads(server, ledger)
        try:
            write_private_artifact(
                Path(plan["paths"]["records"])
                / "activation-containment.json",
                containment,
            )
        except BaseException as containment_write_error:
            containment = {
                **containment,
                "all_contained": False,
                "containment_artifact_error_sha256": hashlib.sha256(
                    (
                        f"{type(containment_write_error).__name__}:"
                        f"{containment_write_error}"
                    ).encode("utf-8")
                ).hexdigest(),
            }
        failure: BaseException = exc
        if containment["all_contained"] is not True:
            failure = NativeActivationPreviewError(
                "activation-containment-unproven"
            )
        ledger_sha256: str | None = None
        if ledger is not None:
            try:
                ledger.append(
                    "terminal",
                    subject_id=hashlib.sha256(
                        str(failure).encode("utf-8")
                    ).hexdigest(),
                    detail={
                        "outcome": "rejected",
                        "failure_class": type(failure).__name__,
                        "original_failure_sha256": hashlib.sha256(
                            str(exc).encode("utf-8")
                        ).hexdigest(),
                        "containment_sha256": canonical_activation_sha256(
                            containment
                        ),
                        "all_contained": containment["all_contained"],
                    },
                )
            except Exception:
                pass
            try:
                ledger_sha256 = ledger.load()["ledger_sha256"]
            except Exception:
                pass
        failure_result = _result(
            plan,
            status="rejected",
            started_at=started_at,
            claim_sha256=(
                claim["claim_sha256"] if claim is not None else None
            ),
            approval_sha256=approval_sha256,
            ledger_sha256=ledger_sha256,
            reservation_sha256=(
                reservation.get("reservation_sha256")
                if isinstance(reservation, Mapping)
                else None
            ),
            dispatch_sha256=dispatch_sha256,
            pool_receipt_sha256=pool_receipt_sha256,
            failure=failure,
        )
        result_path = Path(plan["paths"]["result"])
        if not result_path.exists():
            try:
                write_exclusive_private_json(
                    result_path,
                    failure_result,
                    label="activation-result",
                )
            except Exception:
                pass
        if failure is exc:
            raise
        raise failure from exc
    finally:
        if server is not None:
            server.close()


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description=(
            "Disabled-by-default one-shot native pool activation preview."
        )
    )
    subcommands = command.add_subparsers(dest="command", required=True)

    keygen = subcommands.add_parser("keygen")
    keygen.add_argument("--control-root", type=Path, required=True)

    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--control-root", type=Path, required=True)
    prepare.add_argument(
        "--profile",
        choices=tuple(PROFILE),
        required=True,
    )
    prepare.add_argument("--source-repo", type=Path, required=True)

    approve = subcommands.add_parser("approve")
    approve.add_argument("--control-root", type=Path, required=True)
    approve.add_argument("--prepared", type=Path, required=True)
    approve.add_argument("--operator-id", required=True)
    approve.add_argument("--identity-source", required=True)
    approve.add_argument(
        "--ttl-seconds",
        type=int,
        default=600,
    )
    approve.add_argument(
        "--accept-risk",
        choices=(TOOL_ENFORCEMENT_OVERRIDE_RISK,),
        required=True,
    )

    run = subcommands.add_parser("run")
    run.add_argument("--control-root", type=Path, required=True)
    run.add_argument("--prepared", type=Path, required=True)
    run.add_argument("--approval", type=Path, required=True)
    run.add_argument("--operator-id", required=True)
    run.add_argument("--identity-source", required=True)
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--enable-tech-preview", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "keygen":
            result = generate_activation_key(args.control_root)
        elif args.command == "prepare":
            path, plan = prepare_activation_plan(
                args.control_root,
                profile=args.profile,
                source_repository=args.source_repo,
            )
            result = {
                "status": "prepared",
                "prepared": str(path),
                "activation_id": plan["activation_id"],
                "profile": plan["profile"],
                "plan_sha256": plan["plan_sha256"],
                "live": False,
            }
        elif args.command == "approve":
            path, receipt = approve_activation_plan(
                args.prepared,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
                ttl_seconds=args.ttl_seconds,
                risk_acknowledgement=args.accept_risk,
            )
            result = {
                "status": "approved",
                "approval": str(path),
                "approval_id": receipt["approval_id"],
                "expires_at": receipt["expires_at"],
                "live": False,
            }
        elif args.dry_run:
            result = activation_dry_run(
                args.prepared,
                args.approval,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
            )
        else:
            result = run_live_activation(
                args.prepared,
                args.approval,
                control_root=args.control_root,
                actor_id=args.operator_id,
                identity_source=args.identity_source,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as exc:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "failure_class": type(exc).__name__,
                    "failure_message_sha256": hashlib.sha256(
                        str(exc).encode("utf-8")
                    ).hexdigest(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
