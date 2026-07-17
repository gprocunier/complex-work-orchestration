#!/usr/bin/env python3
"""Run disposable exact-Spark app-server canaries for supervisor concurrency.

This ignored work-packet harness persists only sanitized, hash-bound evidence.
Raw model messages and reasoning remain in Codex-owned session telemetry and are
never copied into the result artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cwo_core.native_control import build_control_turn_contract  # noqa: E402
from cwo_core.native_canary_contracts import (  # noqa: E402
    CanaryAuthorizationStore,
    MATERIALIZATION_EVIDENCE_SCHEMA,
    MATERIALIZATION_EVIDENCE_TYPE,
    NativeCanaryContractError,
    canonical_sha256 as domain_sha256,
    consume_steering_receipt,
    materialization_execution_correlation,
    new_authorization_state,
    seal_materialization_evidence,
    validate_capability_rendered_command,
    validate_materialization_evidence,
)
from cwo_core.native_pool import NativePoolCoordinator  # noqa: E402
from cwo_core.native_live_allocation_ledger import (  # noqa: E402
    EXPECTED_ROLES,
    NativeLiveAllocationLedgerError,
    NativeLiveAllocationLedgerStore,
)
from cwo_core.native_pool_config import build_pool_contract  # noqa: E402
from cwo_core.native_pool_contracts import (  # noqa: E402
    CAPABILITY_CERTIFICATION_ENVELOPE,
    CAPABILITY_CERTIFICATION_VERSION,
    CAPABILITY_OBSERVATION_AUTHORITY,
    CAPABILITY_RESPONSE_TIME_EQUATION,
    CAPABILITY_SCHEDULER_MODEL,
    CAPABILITY_RECEIPT_SCHEMA,
    CAPABILITY_RECEIPT_TYPE,
    CERTIFIED_CALLBACK_MAX_MS,
    CERTIFIED_SCHEDULER_OVERHEAD_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    canonical_sha256,
    callback_certification_policy_sha256,
    seal_artifact,
    validate_capability_receipt,
    validate_pool_receipt,
    write_private_artifact,
    zero_token_usage,
)
from cwo_core.native_pool_leases import PoolLeaseRegistry, capture_owner_identity  # noqa: E402
from cwo_core.native_pool_scheduler import select_earliest_deadline  # noqa: E402
from cwo_core.native_pool_workspace import PoolWorkspaceMonitor  # noqa: E402
from cwo_core.native_session_boundary import (  # noqa: E402
    NativeSessionBoundaryError,
    capture_unique_boundary,
    telemetry_markers,
    trusted_turn_context,
)


EXACT_MODEL = "gpt-5.3-codex-spark"
CONTROL_TURN_ID = "complex-work-orchestration-18w.6-live-canary-control-turn"
POST_SUBMISSION_MATERIALIZATION_GRACE_MS = POOL_POLL_LAG_TOLERANCE_MS
FULL_AUTO_AUTHORIZATION_SCHEMA = "cwo-full-auto-run-authorization:v3"
FULL_AUTO_AUTHORIZATION_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
OPERATIVE_ITEM_TYPES = {
    "commandExecution",
    "fileChange",
    "mcpToolCall",
    "dynamicToolCall",
    "collabAgentToolCall",
    "webSearch",
    "imageView",
    "sleep",
    "imageGeneration",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def run_git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def require_repository_checkpoint(repo_root: Path, expected_head: str) -> None:
    if run_git(repo_root, "rev-parse", "HEAD") != expected_head:
        raise AppServerError("full-auto-repository-head-changed")
    if run_git(repo_root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise AppServerError("full-auto-repository-not-clean")


def percentile(values: list[float], ratio: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("capability-stat-samples-missing")
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * ratio) - 1))
    return ordered[index]


def stats(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(percentile(values, 0.50), 3),
        "p90_ms": round(percentile(values, 0.90), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def callback_certification_policy() -> dict[str, Any]:
    try:
        document = json.loads(
            (ROOT / "policy" / "native-worker-execution.yaml").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError("callback-certification-policy-unreadable") from exc
    pool = document.get("native_supervision_pool") if isinstance(document, Mapping) else None
    certification = pool.get("callback_certification") if isinstance(pool, Mapping) else None
    expected = {
        "version": CAPABILITY_CERTIFICATION_VERSION,
        "envelope": CAPABILITY_CERTIFICATION_ENVELOPE,
        "scheduler_model": CAPABILITY_SCHEDULER_MODEL,
        "response_time_equation": CAPABILITY_RESPONSE_TIME_EQUATION,
        "observation_authority": CAPABILITY_OBSERVATION_AUTHORITY,
        "certified_callback_max_ms": CERTIFIED_CALLBACK_MAX_MS,
        "certified_scheduler_overhead_ms": CERTIFIED_SCHEDULER_OVERHEAD_MS,
    }
    if not isinstance(certification, Mapping) or dict(certification) != expected:
        raise AppServerError("callback-certification-policy-invalid")
    return dict(certification)


def capability_certification() -> dict[str, Any]:
    policy = callback_certification_policy()
    return {
        **policy,
        "policy_sha256": callback_certification_policy_sha256(policy),
        "adapter_implementation_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }


def validate_full_auto_authorization(
    authorization: Mapping[str, Any],
    campaign_nonce: str,
    *,
    repo_root: Path,
) -> tuple[str, str]:
    if not isinstance(authorization, Mapping):
        raise AppServerError("full-auto-authorization-invalid-not-object")
    if authorization.get("schema") != FULL_AUTO_AUTHORIZATION_SCHEMA:
        raise AppServerError("full-auto-authorization-schema-invalid")
    canonical_authorization_sha256 = authorization.get("canonical_authorization_sha256")
    unsigned_authorization = dict(authorization)
    unsigned_authorization.pop("canonical_authorization_sha256", None)
    if (
        not isinstance(canonical_authorization_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", canonical_authorization_sha256)
        or sha256_bytes(
            json.dumps(unsigned_authorization, sort_keys=True, separators=(",", ":")).encode()
        )
        != canonical_authorization_sha256
    ):
        raise AppServerError("full-auto-authorization-canonical-hash-invalid")
    generation = authorization.get("run_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise AppServerError("full-auto-authorization-generation-invalid")
    if authorization.get("initial_state") != "active":
        raise AppServerError("full-auto-authorization-state-invalid")
    forbidden = authorization.get("forbidden")
    if not isinstance(forbidden, Mapping) or any(
        forbidden.get(field) is not True
        for field in ("glm_5_2", "model_synthesis", "release_before_live_acceptance")
    ):
        raise AppServerError("full-auto-authorization-forbidden-invalid")
    bindings = authorization.get("bindings")
    if not isinstance(bindings, Mapping) or bindings.get("campaign_nonce") != campaign_nonce:
        raise AppServerError("full-auto-authorization-binding-invalid")
    budgets = authorization.get("budgets")
    if not isinstance(budgets, Mapping) or (
        budgets.get("spark_live_turn_starts_per_generation_exact") != 7
        or isinstance(budgets.get("spark_live_campaign_generations_hard"), bool)
        or not isinstance(budgets.get("spark_live_campaign_generations_hard"), int)
        or budgets.get("spark_live_campaign_generations_hard", 0) < 1
    ):
        raise AppServerError("full-auto-authorization-live-budget-invalid")
    executors = authorization.get("executors")
    steering = executors.get("steering") if isinstance(executors, Mapping) else None
    operative = executors.get("operative") if isinstance(executors, Mapping) else None
    if (
        not isinstance(steering, Mapping)
        or steering.get("model") != "gpt-5.6-sol"
        or steering.get("effort") != "max"
        or not isinstance(operative, Mapping)
        or operative.get("model") != EXACT_MODEL
    ):
        raise AppServerError("full-auto-authorization-executor-invalid")
    mandatory = authorization.get("mandatory_gates")
    if not isinstance(mandatory, Mapping) or any(
        mandatory.get(field) is not True
        for field in (
            "fresh_exact_sol_pre_mutation_receipt",
            "fresh_exact_sol_pre_live_receipt",
            "single_shot_per_generation_live_campaign",
        )
    ):
        raise AppServerError("full-auto-authorization-gates-invalid")
    authorization_id = str(authorization.get("authorization_id", ""))
    try:
        uuid.UUID(authorization_id)
    except ValueError as exc:
        raise AppServerError("full-auto-authorization-id-invalid") from exc
    checkpoint_commit = bindings.get("checkpoint_commit")
    if not isinstance(checkpoint_commit, str) or not FULL_AUTO_AUTHORIZATION_COMMIT_RE.fullmatch(
        checkpoint_commit
    ):
        raise AppServerError("full-auto-checkpoint-commit-invalid")
    try:
        run_git(repo_root, "rev-parse", "--verify", checkpoint_commit)
    except subprocess.CalledProcessError as exc:
        raise AppServerError("full-auto-checkpoint-commit-invalid") from exc
    head_commit = run_git(repo_root, "rev-parse", "HEAD")
    try:
        run_git(repo_root, "merge-base", "--is-ancestor", checkpoint_commit, head_commit)
    except subprocess.CalledProcessError as exc:
        raise AppServerError("full-auto-checkpoint-not-ancestor") from exc
    require_repository_checkpoint(repo_root, head_commit)
    return authorization_id, head_commit


def plan_steering_receipt_consumptions(
    campaign_nonce: str,
    authorization_id: str,
    authorization_sha256: str,
    *,
    registry_file: Path,
    repo_head: str,
    pre_mutation_receipt: Mapping[str, Any],
    pre_mutation_adjudication: Mapping[str, Any],
    pre_mutation_adjudication_sha256: str,
    pre_live_receipt: Mapping[str, Any],
    pre_live_adjudication: Mapping[str, Any],
    pre_live_adjudication_sha256: str,
) -> dict[str, tuple[str, dict[str, Any]]]:
    bundles = (
        (
            "pre-mutation",
            pre_mutation_receipt,
            pre_mutation_adjudication,
            pre_mutation_adjudication_sha256,
        ),
        (
            "pre-live",
            pre_live_receipt,
            pre_live_adjudication,
            pre_live_adjudication_sha256,
        ),
    )
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        if (
            receipt.get("gate") != label
            or receipt.get("authorization_id") != authorization_id
            or receipt.get("authorization_sha256") != authorization_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", adjudication_sha256)
        ):
            raise AppServerError(f"{label}-steering-binding-invalid")
        if adjudication.get("main_architect_decision") != "go":
            raise AppServerError(f"{label}-adjudication-decision-invalid")

    steering_prepared: dict[str, tuple[str, dict[str, Any]]] = {}
    for label, receipt, adjudication, adjudication_sha256 in bundles:
        phase_nonce = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{campaign_nonce}:{label}:{receipt.get('canonical_receipt_sha256')}",
            )
        )
        kwargs: dict[str, Any] = {
            "phase_nonce": phase_nonce,
            "architect_adjudication_sha256": adjudication_sha256,
            "architect_decision": "go",
        }
        if label == "pre-mutation" and receipt.get("opinion", {}).get("recommendation") == "stop":
            kwargs.update(
                {
                    "allow_resolved_stop": True,
                    "resolved_stop_adjudication": adjudication.get("resolved_stop"),
                    "resolved_stop_post_resolution_commit": repo_head,
                }
            )
        try:
            consume_steering_receipt(
                receipt,
                registry_file,
                dry_run=True,
                **kwargs,
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"{label}-steering-not-accepting") from exc
        steering_prepared[label] = (receipt["canonical_receipt_sha256"], kwargs)
    return steering_prepared


class AppServerError(RuntimeError):
    pass


class LivePoolProtectedFault(AppServerError):
    def __init__(self, first_protected_fault: Mapping[str, Any] | None) -> None:
        self.first_protected_fault = (
            dict(first_protected_fault)
            if isinstance(first_protected_fault, Mapping)
            else {
                "code": "unknown",
                "operation": None,
                "observed_callback_latency_ms": None,
                "certified_callback_max_ms": None,
                "latched_state_sequence": 0,
            }
        )
        super().__init__(f"live-pool-protected-fault:{self.first_protected_fault['code']}")


class AppServer:
    """Minimal stdlib JSON-RPC client for one trusted Codex app-server."""

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            ["codex", "app-server", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise AppServerError("app-server-pipes-unavailable")
        self._condition = threading.Condition()
        self._responses: dict[int, dict[str, Any]] = {}
        self._notifications: list[tuple[int, dict[str, Any]]] = []
        self._request_id = 0
        self._reader_error: str | None = None
        self._stderr_line_count = 0
        self.connection_epoch_sha256 = domain_sha256(
            {"epoch": str(uuid.uuid4())}, domain="app-server-stdio-connection-epoch"
        )
        self.rpc_latencies: dict[str, list[float]] = {}
        self.started_threads: dict[str, str | None] = {}
        self.allocation_ledger: NativeLiveAllocationLedgerStore | None = None
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        result, _ = self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "cwo-supervisor-concurrency-canary",
                    "title": "CWO supervisor concurrency canary",
                    "version": "1.0.0",
                },
                "capabilities": {"experimentalApi": True},
            },
            timeout=10,
        )
        if not isinstance(result, Mapping) or not result.get("codexHome"):
            raise AppServerError("app-server-initialize-invalid")
        self.codex_home = Path(str(result["codexHome"])).resolve()
        self.notify("initialized", {})

    def attach_allocation_ledger(self, ledger: NativeLiveAllocationLedgerStore) -> None:
        if self.started_threads or self.allocation_ledger is not None:
            raise AppServerError("allocation-ledger-attach-state-invalid")
        ledger.load()
        self.allocation_ledger = ledger

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for raw in self.process.stdout:
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    with self._condition:
                        self._reader_error = "app-server-non-json-output"
                        self._condition.notify_all()
                    continue
                with self._condition:
                    if isinstance(message.get("id"), int) and (
                        "result" in message or "error" in message
                    ):
                        self._responses[int(message["id"])] = message
                    elif isinstance(message.get("method"), str):
                        self._notifications.append((time.monotonic_ns(), message))
                    self._condition.notify_all()
        finally:
            with self._condition:
                if self.process.poll() is None:
                    self._reader_error = "app-server-output-closed"
                self._condition.notify_all()

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for _line in self.process.stderr:
            self._stderr_line_count += 1

    def notify(self, method: str, params: Mapping[str, Any]) -> None:
        payload = {"method": method, "params": dict(params)}
        assert self.process.stdin is not None
        with self._condition:
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()

    def request(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        timeout: float = 30,
    ) -> tuple[dict[str, Any], float]:
        assert self.process.stdin is not None
        with self._condition:
            self._request_id += 1
            request_id = self._request_id
            payload = {"id": request_id, "method": method, "params": dict(params)}
            started = time.monotonic_ns()
            self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while request_id not in self._responses:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AppServerError(f"app-server-request-timeout:{method}")
                if self.process.poll() is not None:
                    raise AppServerError(f"app-server-exited:{method}:{self.process.returncode}")
                if self._reader_error:
                    raise AppServerError(self._reader_error)
                self._condition.wait(timeout=remaining)
            message = self._responses.pop(request_id)
        latency_ms = (time.monotonic_ns() - started) / 1_000_000
        self.rpc_latencies.setdefault(method, []).append(latency_ms)
        if "error" in message:
            error = message.get("error") if isinstance(message.get("error"), Mapping) else {}
            code = error.get("code", "unknown")
            raise AppServerError(f"app-server-request-failed:{method}:{code}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise AppServerError(f"app-server-result-invalid:{method}")
        return result, latency_ms

    def model_discovery(self) -> dict[str, Any]:
        result, latency = self.request("model/list", {"includeHidden": True})
        models = result.get("data")
        if not isinstance(models, list):
            raise AppServerError("model-list-data-invalid")
        matches = [item for item in models if isinstance(item, Mapping) and item.get("id") == EXACT_MODEL]
        if len(matches) != 1 or matches[0].get("model") != EXACT_MODEL:
            raise AppServerError("exact-spark-model-unavailable")
        return {
            "id": matches[0]["id"],
            "model": matches[0]["model"],
            "display_name": matches[0].get("displayName"),
            "latency_ms": round(latency, 3),
        }

    def start_thread(
        self,
        cwd: Path,
        *,
        mutable: bool,
        role: str | None = None,
    ) -> tuple[dict[str, Any], float]:
        allocation_intent_id: str | None = None
        if self.allocation_ledger is not None:
            if role not in EXPECTED_ROLES:
                raise AppServerError("allocation-ledger-role-required")
            allocation_intent_id = self.allocation_ledger.allocation_intent(str(role))
        result, latency = self.request(
            "thread/start",
            {
                "model": EXACT_MODEL,
                "allowProviderModelFallback": False,
                "cwd": str(cwd.resolve()),
                "runtimeWorkspaceRoots": [str(cwd.resolve())],
                "approvalPolicy": "never",
                "sandbox": "workspace-write" if mutable else "read-only",
                "ephemeral": False,
                "historyMode": "legacy",
                "developerInstructions": (
                    "This is a bounded CWO live canary. Do not spawn subagents, use network access, "
                    "or access paths outside the supplied workspace. Follow the user task exactly."
                ),
            },
            timeout=30,
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or not thread.get("id"):
            raise AppServerError("thread-start-response-invalid")
        thread_id = str(thread["id"])
        self.started_threads[thread_id] = None
        if self.allocation_ledger is not None and allocation_intent_id is not None:
            self.allocation_ledger.bind_thread(allocation_intent_id, thread_id)
        if result.get("model") != EXACT_MODEL:
            raise AppServerError("thread-start-model-mismatch")
        return dict(result), latency

    def read_thread(self, thread_id: str) -> tuple[dict[str, Any], float]:
        result, latency = self.request(
            "thread/read", {"threadId": thread_id, "includeTurns": True}, timeout=15
        )
        thread = result.get("thread")
        if not isinstance(thread, Mapping) or thread.get("id") != thread_id:
            raise AppServerError("thread-read-response-invalid")
        return dict(thread), latency

    def start_turn(self, thread_id: str, prompt: str) -> tuple[dict[str, Any], float]:
        turn_intent_id: str | None = None
        if self.allocation_ledger is not None:
            turn_intent_id = self.allocation_ledger.turn_intent(thread_id)
        result, latency = self.request(
            "turn/start",
            {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt, "text_elements": []}],
                "model": EXACT_MODEL,
                "effort": "low",
                "clientUserMessageId": str(uuid.uuid4()),
                "responsesapiClientMetadata": {
                    "cwo_bead": "complex-work-orchestration-18w.6",
                    "cwo_control_turn": CONTROL_TURN_ID,
                },
            },
            timeout=30,
        )
        turn = result.get("turn")
        if not isinstance(turn, Mapping) or not turn.get("id"):
            raise AppServerError("turn-start-response-invalid")
        turn_id = str(turn["id"])
        self.started_threads[thread_id] = turn_id
        if self.allocation_ledger is not None and turn_intent_id is not None:
            self.allocation_ledger.bind_turn(thread_id, turn_intent_id, turn_id)
        return dict(turn), latency

    def interrupt_turn(self, thread_id: str, turn_id: str) -> float:
        _result, latency = self.request(
            "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15
        )
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "interrupt-observed", "interrupt-request-accepted"
            )
        return latency

    def archive_thread(self, thread_id: str) -> float:
        _result, latency = self.request("thread/archive", {"threadId": thread_id}, timeout=15)
        if self.allocation_ledger is not None:
            self.allocation_ledger.record_lifecycle(
                thread_id, "archive-observed", "archive-request-accepted"
            )
        return latency

    def notifications(self, thread_id: str, method: str | None = None) -> list[dict[str, Any]]:
        with self._condition:
            values = []
            for _timestamp, message in self._notifications:
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id:
                    continue
                if method is not None and message.get("method") != method:
                    continue
                values.append(message)
            return values

    def notification_cursor(self) -> int:
        """Return the current connection-local receive sequence."""

        with self._condition:
            return len(self._notifications)

    def notification_events(
        self,
        thread_id: str,
        turn_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        """Snapshot trusted stdio notifications with connection-local provenance."""

        with self._condition:
            values: list[dict[str, Any]] = []
            for sequence, (received_ns, message) in enumerate(self._notifications, 1):
                if sequence <= after_sequence:
                    continue
                params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
                    continue
                values.append(
                    {
                        "connection_epoch_sha256": self.connection_epoch_sha256,
                        "sequence": sequence,
                        "received_monotonic_ns": received_ns,
                        "method": message.get("method"),
                        "params": dict(params),
                    }
                )
            return values

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def turn_from_thread(thread: Mapping[str, Any], turn_id: str | None) -> Mapping[str, Any] | None:
    turns = thread.get("turns")
    if not isinstance(turns, list):
        return None
    for item in turns:
        if isinstance(item, Mapping) and item.get("id") == turn_id:
            return item
    return None


def turn_status(thread: Mapping[str, Any], turn_id: str | None) -> str | None:
    turn = turn_from_thread(thread, turn_id)
    return str(turn.get("status")) if isinstance(turn, Mapping) and turn.get("status") else None


def turn_items(thread: Mapping[str, Any], turn_id: str | None) -> list[Mapping[str, Any]]:
    turn = turn_from_thread(thread, turn_id)
    items = turn.get("items") if isinstance(turn, Mapping) else None
    return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []


def final_message_hash_and_match(
    thread: Mapping[str, Any], turn_id: str | None, expected_token: str
) -> tuple[str | None, bool]:
    messages = [
        str(item.get("text", ""))
        for item in turn_items(thread, turn_id)
        if item.get("type") == "agentMessage" and item.get("phase") in {"finalAnswer", "final_answer", None}
    ]
    if not messages:
        return None, False
    final = messages[-1]
    return sha256_text(final), final.strip() == expected_token


def session_boundary_summary(
    codex_home: Path,
    thread_id: str,
    reported: str | None,
    *,
    baseline: Mapping[str, Any] | None = None,
    allow_unmaterialized: bool = False,
    expected_source_identity_sha256: str | None = None,
) -> dict[str, Any]:
    try:
        located, boundary, records = capture_unique_boundary(
            codex_home,
            thread_id,
            reported_path=reported,
            baseline=baseline,
        )
        if (
            expected_source_identity_sha256 is not None
            and located.source_identity_sha256 != expected_source_identity_sha256
        ):
            raise NativeSessionBoundaryError(
                "trusted session source identity changed after materialization"
            )
    except NativeSessionBoundaryError as exc:
        boundary_error = str(exc)
        if not allow_unmaterialized or boundary_error not in {
            "trusted session file is missing",
            "session file has no complete records",
        }:
            raise AppServerError(f"session-boundary-invalid:{exc}") from exc
        return {
            "available": False,
            "record_count": 0,
            "byte_offset": 0,
            "boundary_sha256": None,
            "token_snapshot": None,
            "source_identity_sha256": None,
            "trailing_partial": False,
            "attested_models": [],
            "attested_efforts": [],
            "compactions": 0,
            "reroutes": 0,
            "observation_type": "unmaterialized-nonattesting",
        }
    models: list[str] = []
    efforts: list[str] = []
    compactions = 0
    reroutes = 0
    for record in records:
        record_type = record.get("type")
        payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
        if record_type == "turn_context":
            if isinstance(payload.get("model"), str):
                models.append(str(payload["model"]))
            effort = payload.get("effort") or payload.get("reasoning_effort")
            if isinstance(effort, str):
                efforts.append(effort)
        payload_type = str(payload.get("type", ""))
        marker = f"{record_type}:{payload_type}".lower()
        if "compact" in marker:
            compactions += 1
        if "rerout" in marker:
            reroutes += 1
    return {
        "available": True,
        "record_count": boundary["record_count"],
        "byte_offset": boundary["byte_offset"],
        "boundary_sha256": boundary["boundary_sha256"],
        "token_snapshot": boundary.get("token_snapshot"),
        "source_identity_sha256": located.source_identity_sha256,
        "trailing_partial": False,
        "attested_models": sorted(set(models)),
        "attested_efforts": sorted(set(efforts)),
        "compactions": compactions,
        "reroutes": reroutes,
        "observation_type": "trusted-complete-boundary",
    }


class LiveThreadAdapter:
    def __init__(
        self,
        server: AppServer,
        thread_response: Mapping[str, Any],
        *,
        prompt: str,
        expected_token: str,
        worktree: Path,
        mutable: bool,
        expected_mutation: str | None,
        force_interrupt_after_checks: int | None = None,
        record_dir: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.server = server
        self.thread_response = dict(thread_response)
        self.thread = dict(thread_response["thread"])
        self.thread_id = str(self.thread["id"])
        self.reported_session_path = self.thread.get("path")
        self.prompt = prompt
        self.expected_token = expected_token
        self.worktree = worktree
        self.mutable = mutable
        self.expected_mutation = expected_mutation
        self.force_interrupt_after_checks = force_interrupt_after_checks
        self.record_dir = record_dir
        self.turn_id: str | None = None
        self.send_started_ns: int | None = None
        self.last_thread: dict[str, Any] = dict(self.thread)
        self.check_count = 0
        self.interrupted = False
        self.archived = False
        self._boundary_phase = "pre-dispatch"
        self._boundary_lock = threading.RLock()
        self._monotonic_ns = monotonic_ns
        self._materialization_deadline_ns: int | None = None
        self._session_boundary_baseline: dict[str, Any] | None = None
        self._session_source_identity_sha256: str | None = None
        self.callback_latencies: dict[str, list[float]] = {}
        self._evidence_sequence = 0

    def _timed(self, name: str, action: Callable[[], Any]) -> Any:
        started = time.monotonic_ns()
        try:
            return action()
        finally:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            self.callback_latencies.setdefault(name, []).append(elapsed)

    def arm(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if self.thread_response.get("model") != EXACT_MODEL:
                raise AppServerError("prearmed-thread-model-mismatch")
            if self.thread.get("id") != self.thread_id or self.thread.get("turns"):
                raise AppServerError("prearmed-thread-is-not-fresh")
            return {"ack": "armed"}

        return self._timed("arm", action)

    def send_input(self, *, message: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if message != self.prompt:
                raise AppServerError("turn-prompt-binding-mismatch")
            with self._boundary_lock:
                # Revoke the pre-dispatch allowance before the RPC. Failed or
                # ambiguous submission can never recover it from a missing id.
                self._boundary_phase = "dispatch-attempted"
                turn, _latency = self.server.start_turn(self.thread_id, message)
                returned_ns = self._monotonic_ns()
                turn_id = turn.get("id") if isinstance(turn, Mapping) else None
                if not isinstance(turn_id, str) or not turn_id:
                    raise AppServerError("turn-start-response-invalid")
                if self.server.started_threads.get(self.thread_id) != turn_id:
                    raise AppServerError("trusted-turn-start-binding-mismatch")
                self.turn_id = turn_id
                self.send_started_ns = returned_ns
                self._materialization_deadline_ns = returned_ns + (
                    POST_SUBMISSION_MATERIALIZATION_GRACE_MS * 1_000_000
                )
                self._boundary_phase = "submission-acknowledged-awaiting-materialization"
                return {"submission_id": self.turn_id}

        return self._timed("send_input", action)

    def mark_dispatched(self, *, submission_id: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            if submission_id != self.turn_id:
                raise AppServerError("submission-id-binding-mismatch")
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-dispatch.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "prompt_sha256": sha256_text(self.prompt),
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": "dispatched"}

        return self._timed("mark_dispatched", action)

    def check(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self.check_count += 1
            thread, _latency = self.server.read_thread(self.thread_id)
            self.last_thread = thread
            self.reported_session_path = thread.get("path") or self.reported_session_path
            status = turn_status(thread, self.turn_id)
            if (
                self.force_interrupt_after_checks is not None
                and self.check_count >= self.force_interrupt_after_checks
                and status == "inProgress"
            ):
                return {"decision": "interrupt"}
            if status == "completed":
                _message_hash, matches = final_message_hash_and_match(
                    thread, self.turn_id, self.expected_token
                )
                return {"decision": "complete" if matches else "control-lost"}
            if status == "interrupted":
                return {"decision": "interrupt"}
            if status == "failed":
                return {"decision": "control-lost"}
            if status in {"inProgress", None}:
                return {"decision": "continue"}
            return {"decision": "control-lost"}

        return self._timed("check", action)

    def interrupt(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if self.turn_id is None:
                    raise AppServerError("interrupt-turn-id-missing")
                # Interrupt wins locally before the control RPC is attempted;
                # unavailable telemetry can never be accepted after this point.
                self._boundary_phase = "interrupt-requested"
                self.server.interrupt_turn(self.thread_id, self.turn_id)
                self.interrupted = True
                return {"ack": "interrupt-requested"}

        return self._timed("interrupt", action)

    def finalize(self, *, control_action: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-finalize-{control_action}.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "control_action": control_action,
                    "control_turn_id": CONTROL_TURN_ID,
                },
            )
            return {"ack": control_action}

        return self._timed("finalize", action)

    def close(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                self._boundary_phase = "closing"
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = thread.get("path") or self.reported_session_path
                status = turn_status(thread, self.turn_id)
                if status not in {"completed", "interrupted", "failed"}:
                    raise AppServerError(f"close-before-terminal:{status}")
                self.server.archive_thread(self.thread_id)
                self.archived = True
                return {"ack": "closed"}

        return self._timed("close", action)

    @staticmethod
    def sleep(*, seconds: float) -> None:
        time.sleep(seconds)

    def callbacks(self) -> dict[str, Callable[..., Any]]:
        return {
            "arm": self.arm,
            "send_input": self.send_input,
            "mark_dispatched": self.mark_dispatched,
            "check": self.check,
            "interrupt": self.interrupt,
            "close": self.close,
            "finalize": self.finalize,
            "sleep": self.sleep,
        }

    def _workspace_mutations(self) -> list[str]:
        output = run_git(self.worktree, "status", "--porcelain=v1", "--untracked-files=all")
        values = []
        for line in output.splitlines():
            if len(line) >= 4:
                values.append(line[3:].strip())
        return sorted(set(values))

    def _pending_window_is_open_locked(self) -> None:
        if self._boundary_phase != "submission-acknowledged-awaiting-materialization":
            raise AppServerError("post-submission-materialization-phase-invalid")
        if not self.turn_id or self.server.started_threads.get(self.thread_id) != self.turn_id:
            raise AppServerError("trusted-turn-start-binding-mismatch")
        if self._materialization_deadline_ns is None:
            raise AppServerError("post-submission-materialization-deadline-missing")
        if self._monotonic_ns() >= self._materialization_deadline_ns:
            raise AppServerError("post-submission-materialization-deadline-exceeded")

    def _record_complete_boundary_locked(self, boundary: Mapping[str, Any]) -> dict[str, Any]:
        if self._boundary_phase == "submission-acknowledged-awaiting-materialization":
            self._pending_window_is_open_locked()
            self._boundary_phase = "materialized"
        self._session_boundary_baseline = {
            "record_count": boundary.get("record_count"),
            "byte_offset": boundary.get("byte_offset"),
            "boundary_sha256": boundary.get("boundary_sha256"),
            "token_snapshot": boundary.get("token_snapshot"),
        }
        source_identity = boundary.get("source_identity_sha256")
        if not isinstance(source_identity, str) or not source_identity:
            raise AppServerError("trusted-session-source-identity-missing")
        if (
            self._session_source_identity_sha256 is not None
            and source_identity != self._session_source_identity_sha256
        ):
            raise AppServerError("trusted-session-source-identity-changed")
        self._session_source_identity_sha256 = source_identity
        return dict(boundary)

    def _fresh_nonterminal_thread_locked(self) -> None:
        self._pending_window_is_open_locked()
        thread, _latency = self.server.read_thread(self.thread_id)
        if thread.get("id") != self.thread_id:
            raise AppServerError("post-submission-thread-read-identity-mismatch")
        self.last_thread = thread
        self.reported_session_path = thread.get("path") or self.reported_session_path
        status = turn_status(thread, self.turn_id)
        if status != "inProgress":
            raise AppServerError(f"post-submission-materialization-status-invalid:{status}")
        self._pending_window_is_open_locked()

    def _capture_trusted_boundary(self, *, allow_pending: bool) -> dict[str, Any]:
        with self._boundary_lock:
            pending_phase = self._boundary_phase in {
                "pre-dispatch",
                "submission-acknowledged-awaiting-materialization",
            }
            containment_phase = self._boundary_phase in {
                "interrupt-requested",
                "closing",
            }
            allow_unmaterialized = (
                (allow_pending and pending_phase or containment_phase)
                and self._session_boundary_baseline is None
            )
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                self.reported_session_path,
                baseline=self._session_boundary_baseline,
                allow_unmaterialized=allow_unmaterialized,
                expected_source_identity_sha256=self._session_source_identity_sha256,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            if self._boundary_phase == "pre-dispatch":
                boundary["observation_type"] = (
                    "pre-dispatch-unmaterialized-nonattesting-nonaccepting"
                )
                return boundary
            if containment_phase:
                boundary["observation_type"] = (
                    "containment-unmaterialized-nonattesting-rejected"
                )
                return boundary

            # The trusted file was absent or exactly zero bytes. Re-read the
            # control plane after that observation, retry the boundary once,
            # then re-read status immediately before emitting a pending marker.
            self._fresh_nonterminal_thread_locked()
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                self.reported_session_path,
                baseline=None,
                allow_unmaterialized=True,
                expected_source_identity_sha256=None,
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            self._fresh_nonterminal_thread_locked()
            boundary["observation_type"] = (
                "post-submission-unmaterialized-nonattesting-nonaccepting"
            )
            return boundary

    def _trusted_summary(self, *, allow_pending: bool = True) -> dict[str, Any]:
        boundary = self._capture_trusted_boundary(allow_pending=allow_pending)
        items = turn_items(self.last_thread, self.turn_id)
        item_types = [str(item.get("type")) for item in items if item.get("type")]
        tool_calls = sum(item_type in OPERATIVE_ITEM_TYPES for item_type in item_types)
        compactions = item_types.count("contextCompaction") + len(
            self.server.notifications(self.thread_id, "thread/compacted")
        )
        final_hash, final_matches = final_message_hash_and_match(
            self.last_thread, self.turn_id, self.expected_token
        )
        reroutes = self.server.notifications(self.thread_id, "model/rerouted")
        token_events = self.server.notifications(self.thread_id, "thread/tokenUsage/updated")
        token_total = None
        if token_events:
            params = token_events[-1].get("params", {})
            token_usage = params.get("tokenUsage", {}) if isinstance(params, Mapping) else {}
            total = token_usage.get("total", {}) if isinstance(token_usage, Mapping) else {}
            if isinstance(total, Mapping):
                token_total = {
                    "input": total.get("inputTokens"),
                    "cached_input": total.get("cachedInputTokens"),
                    "output": total.get("outputTokens"),
                    "reasoning": total.get("reasoningOutputTokens"),
                    "total": total.get("totalTokens"),
                }
        models = boundary.get("attested_models", [])
        efforts = boundary.get("attested_efforts", [])
        model_exact = (
            boundary.get("available") is True
            and models == [EXACT_MODEL]
            and efforts == ["low"]
        )
        return {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "thread_start_model": self.thread_response.get("model"),
            "thread_start_model_provider": self.thread_response.get("modelProvider"),
            "turn_status": turn_status(self.last_thread, self.turn_id),
            "session_boundary": boundary,
            "model_exact": model_exact,
            "reroute_count": len(reroutes),
            "compactions": compactions,
            "tool_calls": tool_calls,
            "item_types": sorted(set(item_types)),
            "token_telemetry": {
                "availability": "available" if token_total is not None else "unavailable",
                "total": token_total,
            },
            "final_response_sha256": final_hash,
            "expected_final_token_observed": final_matches,
            "workspace_mutations": self._workspace_mutations(),
            "interrupted": self.interrupted,
            "archived": self.archived,
        }

    def evidence(self) -> dict[str, Any]:
        self._evidence_sequence += 1
        summary = self._trusted_summary()
        status = summary["turn_status"]
        terminal = status in {"completed", "interrupted", "failed"}
        reasons: list[str] = []
        if terminal and not summary["model_exact"]:
            reasons.append("trusted-model-attestation-mismatch")
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            reasons.append("containment-unmaterialized-nonattesting-rejected")
        if summary["reroute_count"]:
            reasons.append("model-reroute-observed")
        if summary["compactions"]:
            reasons.append("compaction-observed")
        if terminal and summary["session_boundary"].get("trailing_partial"):
            reasons.append("terminal-session-boundary-partial")
        if status == "completed" and not summary["expected_final_token_observed"]:
            reasons.append("invalid-final-response")
        mutations = summary["workspace_mutations"]
        if self.mutable:
            if any(path != self.expected_mutation for path in mutations):
                reasons.append("mutable-workspace-attribution-mismatch")
        elif mutations:
            reasons.append("read-only-workspace-mutation")
        runtime = 0
        if self.send_started_ns is not None:
            runtime = int(max(0, time.monotonic_ns() - self.send_started_ns) / 1_000_000_000)
        usage = {
            "tool_calls": int(summary["tool_calls"]),
            "runtime_seconds": runtime,
            "compactions": int(summary["compactions"]),
            "full_suite_runs": 0,
            "mutations": len(mutations),
            "tokens": zero_token_usage("pool-v1-token-ingest-not-bound"),
        }
        state_payload = {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "status": status,
            "boundary_sha256": summary["session_boundary"].get("boundary_sha256"),
            "boundary_observation": summary["session_boundary"].get("observation_type"),
            "tool_calls": usage["tool_calls"],
            "runtime_seconds": usage["runtime_seconds"],
            "mutations": usage["mutations"],
            "compactions": usage["compactions"],
            "evidence_sequence": self._evidence_sequence,
        }
        if (
            summary["session_boundary"].get("observation_type")
            == "containment-unmaterialized-nonattesting-rejected"
        ):
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        elif summary["session_boundary"].get("available") is not True:
            session_disposition = "accepted-with-warning"
            artifact_disposition = "independent-validation-required"
        elif self.interrupted:
            session_disposition = "accepted-with-warning" if not reasons else "quarantined"
            artifact_disposition = "rejected"
        elif status == "completed" and not reasons:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        elif terminal:
            session_disposition = "quarantined"
            artifact_disposition = "rejected"
        else:
            session_disposition = "accepted"
            artifact_disposition = "accepted"
        return {
            "state_sha256": canonical_sha256(state_payload),
            "usage": usage,
            "protected_fault": bool(reasons),
            "control_loss": status == "failed" or "trusted-model-attestation-mismatch" in reasons,
            "reasons": reasons,
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def final_summary(self) -> dict[str, Any]:
        summary = self._trusted_summary(allow_pending=False)
        summary["callback_stats"] = {
            name: stats(values) for name, values in sorted(self.callback_latencies.items())
        }
        summary["prompt_sha256"] = sha256_text(self.prompt)
        return summary


def guarded_measure(
    samples: dict[str, list[float]],
    name: str,
    action: Callable[[], Any],
    *,
    guard_seconds: float = 0.20,
) -> Any:
    started = time.monotonic_ns()
    result = action()
    time.sleep(guard_seconds)
    samples.setdefault(name, []).append((time.monotonic_ns() - started) / 1_000_000)
    return result


def calibration(
    server: AppServer,
    cwd: Path,
    record_dir: Path,
    owner: Mapping[str, Any],
    *,
    run_nonce: str,
    phase_nonce: str,
    materialization_timeout_seconds: float = 10.0,
) -> tuple[dict[str, Any], dict[str, Any]]:
    samples: dict[str, list[float]] = {}
    result, preallocation_latency = server.start_thread(
        cwd, mutable=False, role="capability-calibration"
    )
    thread_id = str(result["thread"]["id"])
    reported_path = result["thread"].get("path")
    guarded_measure(
        samples,
        "arm",
        lambda: (
            result.get("model") == EXACT_MODEL
            and result.get("thread", {}).get("id") == thread_id
            and not result.get("thread", {}).get("turns")
        )
        or (_ for _ in ()).throw(AppServerError("prearmed-thread-binding-invalid")),
        guard_seconds=0.0,
    )
    prompt = (
        "Use the exec_command tool exactly once to run `sleep 20`. After it finishes, return "
        "exactly CAPABILITY_LONG_DONE. Do not use any other tool."
    )
    notification_floor = server.notification_cursor()
    turn = guarded_measure(
        samples,
        "send_input",
        lambda: server.start_turn(thread_id, prompt),
        guard_seconds=0.0,
    )[0]
    turn_id = str(turn["id"])
    attempt_nonce = str(uuid.uuid4())
    guarded_measure(
        samples,
        "mark_dispatched",
        lambda: write_private_artifact(
            record_dir / "calibration-mark.json",
            {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "control_turn_id": CONTROL_TURN_ID,
                "attempt_nonce": attempt_nonce,
                "phase_nonce": phase_nonce,
            },
        ),
        guard_seconds=0.0,
    )

    strict_baseline = {
        "record_count": 0,
        "byte_offset": 0,
        "boundary_sha256": sha256_bytes(b""),
        "token_snapshot": None,
    }
    trusted_source_identity: str | None = None
    observed_prefix: dict[str, Any] = dict(strict_baseline)

    def public_boundary(value: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "record_count": int(value["record_count"]),
            "byte_offset": int(value["byte_offset"]),
            "boundary_sha256": str(value["boundary_sha256"]),
            "invalid_record_count": 0,
            "trailing_partial": False,
        }

    def observe() -> tuple[dict[str, Any], dict[str, Any] | None]:
        thread, _latency = server.read_thread(thread_id)
        nonlocal reported_path, trusted_source_identity, observed_prefix
        reported_path = thread.get("path") or reported_path
        status = turn_status(thread, turn_id)
        if status in {"completed", "failed", "interrupted"}:
            raise AppServerError(f"capability-completed-before-deliberate-interrupt:{status}")
        try:
            located, boundary, records = capture_unique_boundary(
                server.codex_home,
                thread_id,
                reported_path=reported_path,
                baseline=observed_prefix,
            )
        except NativeSessionBoundaryError as exc:
            if str(exc) == "trusted session file is missing":
                return thread, None
            raise AppServerError(f"capability-session-boundary-invalid:{exc}") from exc
        if trusted_source_identity is None:
            trusted_source_identity = located.source_identity_sha256
        elif trusted_source_identity != located.source_identity_sha256:
            raise AppServerError("capability-session-source-identity-changed")
        observed_prefix = dict(boundary)
        contexts = [
            (index, record["payload"])
            for index, record in enumerate(records)
            if record.get("type") == "turn_context"
            and isinstance(record.get("payload"), Mapping)
            and (record["payload"].get("turn_id") or record["payload"].get("turnId")) == turn_id
        ]
        if contexts and any(
            context.get("model") != EXACT_MODEL
            or (context.get("effort") or context.get("reasoning_effort")) != "low"
            for _index, context in contexts
        ):
            raise AppServerError("capability-trusted-model-effort-mismatch")
        if len(contexts) > 1:
            raise AppServerError("capability-current-turn-context-not-singular")
        markers = telemetry_markers(records, turn_id=turn_id)
        if markers["compaction_indices"] or markers["reroute_indices"]:
            raise AppServerError("capability-session-containment-failed")
        if markers["terminal_indices"]:
            raise AppServerError("capability-terminal-event-before-interrupt")
        events = server.notification_events(
            thread_id,
            turn_id,
            after_sequence=notification_floor,
        )
        started_commands = []
        completed_commands = []
        for event in events:
            params = event["params"]
            item = params.get("item") if isinstance(params.get("item"), Mapping) else {}
            if item.get("type") != "commandExecution":
                continue
            if event.get("method") == "item/started":
                started_commands.append((event, item))
            elif event.get("method") == "item/completed":
                completed_commands.append((event, item))
        if len(started_commands) > 1:
            raise AppServerError("capability-command-start-not-singular")
        if completed_commands:
            raise AppServerError("capability-command-completed-before-interrupt")
        if not contexts or not started_commands:
            return thread, None
        context_index, _context = trusted_turn_context(
            records,
            turn_id=turn_id,
            model=EXACT_MODEL,
            effort="low",
        )
        start_event, command = started_commands[0]
        if start_event.get("connection_epoch_sha256") != server.connection_epoch_sha256:
            raise AppServerError("capability-notification-connection-epoch-mismatch")
        started_at_ms = start_event["params"].get("startedAtMs")
        if (
            isinstance(started_at_ms, bool)
            or not isinstance(started_at_ms, int)
            or started_at_ms < 0
        ):
            raise AppServerError("capability-command-start-time-invalid")
        item_id = command.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise AppServerError("capability-command-item-identity-invalid")
        if "source" not in command:
            raise AppServerError("capability-command-source-missing")
        if command.get("source") != "unifiedExecStartup":
            raise AppServerError("capability-command-source-invalid")
        if command.get("status") in {"completed", "failed", "declined"}:
            raise AppServerError(
                f"capability-command-terminal-before-interrupt:{command.get('status')}"
            )
        if command.get("status") != "inProgress":
            return thread, None
        function_calls: list[tuple[int, Mapping[str, Any]]] = []
        function_outputs: list[tuple[int, Mapping[str, Any]]] = []
        competing_calls: list[int] = []
        for index, record in enumerate(records[context_index + 1 :], context_index + 1):
            if record.get("type") != "response_item" or not isinstance(
                record.get("payload"), Mapping
            ):
                continue
            payload = record["payload"]
            if payload.get("type") in {"function_call", "functionCall"}:
                if payload.get("name") == "exec_command":
                    function_calls.append((index, payload))
                else:
                    competing_calls.append(index)
            elif payload.get("type") in {"function_call_output", "functionCallOutput"}:
                function_outputs.append((index, payload))
        if competing_calls or len(function_calls) > 1:
            raise AppServerError("capability-function-call-not-singular")
        if function_outputs:
            raise AppServerError("capability-function-output-before-interrupt")
        if not function_calls:
            return thread, None
        function_call_index, function_call = function_calls[0]
        call_id = function_call.get("call_id") or function_call.get("callId")
        if not isinstance(call_id, str) or not call_id:
            raise AppServerError("capability-function-call-identity-invalid")
        arguments = function_call.get("arguments")
        if not isinstance(arguments, str):
            raise AppServerError("capability-function-call-arguments-invalid")
        try:
            parsed_arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise AppServerError("capability-function-call-arguments-invalid") from exc
        if not isinstance(parsed_arguments, Mapping) or not isinstance(
            parsed_arguments.get("cmd"), str
        ):
            raise AppServerError("capability-function-call-command-missing")
        if sha256_text(str(parsed_arguments["cmd"])) != sha256_text("sleep 20"):
            raise AppServerError("capability-function-call-command-digest-mismatch")
        try:
            rendered_command_sha256 = validate_capability_rendered_command(
                command.get("command"), raw_command=str(parsed_arguments["cmd"])
            )
        except NativeCanaryContractError as exc:
            raise AppServerError(f"capability-{exc}") from exc
        command_cwd = command.get("cwd")
        if not isinstance(command_cwd, str) or not command_cwd:
            raise AppServerError("capability-notification-workspace-missing")
        try:
            notification_workspace = Path(command_cwd).resolve(strict=True)
            expected_workspace = cwd.resolve(strict=True)
        except OSError as exc:
            raise AppServerError("capability-notification-workspace-unresolvable") from exc
        if notification_workspace != expected_workspace:
            raise AppServerError("capability-notification-workspace-mismatch")
        command_item_id_sha256 = domain_sha256(
            {"item_id": item_id}, domain="app-server-command-item-id"
        )
        function_call_id_sha256 = domain_sha256(
            {"call_id": call_id}, domain="session-exec-command-call-id"
        )
        raw_command_sha256 = sha256_text(str(parsed_arguments["cmd"]))
        execution_correlation_sha256 = materialization_execution_correlation(
            connection_epoch_sha256=str(start_event["connection_epoch_sha256"]),
            session_id=thread_id,
            thread_id=thread_id,
            turn_id=turn_id,
            command_item_id_sha256=command_item_id_sha256,
            function_call_id_sha256=function_call_id_sha256,
            notification_sequence=int(start_event["sequence"]),
            notification_received_monotonic_ns=int(
                start_event["received_monotonic_ns"]
            ),
            notification_started_at_ms=started_at_ms,
            turn_context_record_index=context_index,
            function_call_record_index=function_call_index,
            rendered_command_sha256=rendered_command_sha256,
            raw_command_sha256=raw_command_sha256,
        )
        return thread, {
            "observed_at": iso(),
            "boundary": public_boundary(boundary),
            "session_source_identity_sha256": located.source_identity_sha256,
            "connection_epoch_sha256": str(start_event["connection_epoch_sha256"]),
            "notification_sequence": int(start_event["sequence"]),
            "notification_received_monotonic_ns": int(
                start_event["received_monotonic_ns"]
            ),
            "notification_started_at_ms": started_at_ms,
            "turn_context_record_index": context_index,
            "function_call_record_index": function_call_index,
            "command_item_id_sha256": command_item_id_sha256,
            "function_call_id_sha256": function_call_id_sha256,
            "rendered_command_sha256": rendered_command_sha256,
            "execution_correlation_sha256": execution_correlation_sha256,
            "notification_command_semantic_match": True,
            "notification_workspace_match": True,
            "command_source": "unifiedExecStartup",
            "command_status": "inProgress",
            "started_event_count": 1,
            "function_call_count": 1,
            "completed_event_count": 0,
            "paired_result_count": 0,
            "competing_call_count": 0,
            "terminal_event_count": 0,
            "failed_event_count": 0,
            "declined_event_count": 0,
            "ambiguous_event_count": 0,
        }

    observations: list[dict[str, Any]] = []
    last_threads: dict[str, dict[str, Any]] = {}
    poll_started: list[float] = []
    if materialization_timeout_seconds < 1.0:
        raise AppServerError("capability-materialization-timeout-invalid")
    deadline = time.monotonic() + materialization_timeout_seconds
    while time.monotonic() < deadline and len(observations) < 2:
        poll_start = time.monotonic()
        poll_started.append(poll_start)
        thread, observation = guarded_measure(
            samples,
            "check",
            observe,
            guard_seconds=0.0,
        )
        last_threads[thread_id] = thread
        if observation is not None:
            if not observations:
                observations.append(observation)
            else:
                first_time = dt.datetime.fromisoformat(
                    observations[0]["observed_at"].replace("Z", "+00:00")
                )
                current_time = dt.datetime.fromisoformat(
                    observation["observed_at"].replace("Z", "+00:00")
                )
                if (current_time - first_time).total_seconds() >= 1.0:
                    if any(
                        observations[0][field] != observation[field]
                        for field in (
                            "session_source_identity_sha256",
                            "connection_epoch_sha256",
                            "notification_sequence",
                            "notification_received_monotonic_ns",
                            "notification_started_at_ms",
                            "turn_context_record_index",
                            "function_call_record_index",
                            "command_item_id_sha256",
                            "function_call_id_sha256",
                            "rendered_command_sha256",
                            "execution_correlation_sha256",
                        )
                    ):
                        raise AppServerError("capability-observation-identity-changed")
                    observations.append(observation)
        elapsed = time.monotonic() - poll_start
        if len(observations) < 2:
            time.sleep(max(0.0, 0.20 - elapsed))
    if len(observations) != 2:
        raise AppServerError("capability-materialization-deadline-exceeded")
    if any(
        later - earlier > 0.250
        for earlier, later in zip(poll_started, poll_started[1:])
    ):
        raise AppServerError("capability-poll-interval-exceeded")

    pre_thread, pre_interrupt = guarded_measure(
        samples,
        "check",
        observe,
        guard_seconds=0.0,
    )
    last_threads[thread_id] = pre_thread
    if pre_interrupt is None or any(
        pre_interrupt[field] != observations[-1][field]
        for field in (
            "session_source_identity_sha256",
            "connection_epoch_sha256",
            "notification_sequence",
            "notification_received_monotonic_ns",
            "notification_started_at_ms",
            "turn_context_record_index",
            "function_call_record_index",
            "command_item_id_sha256",
            "function_call_id_sha256",
            "rendered_command_sha256",
            "execution_correlation_sha256",
        )
    ):
        raise AppServerError("capability-immediate-revalidation-failed")
    interrupt_requested_at = iso()
    guarded_measure(
        samples,
        "interrupt",
        lambda: server.interrupt_turn(thread_id, turn_id),
        guard_seconds=0.0,
    )
    interrupt_request_accepted_at = iso()
    interrupt_deadline = time.monotonic() + 5.0
    interrupt_confirmed_at: str | None = None
    while time.monotonic() < interrupt_deadline:
        thread, _latency = server.read_thread(thread_id)
        last_threads[thread_id] = thread
        if turn_status(thread, turn_id) == "interrupted":
            interrupt_confirmed_at = iso()
            break
        if turn_status(thread, turn_id) in {"completed", "failed"}:
            raise AppServerError("capability-interrupt-race-lost")
        time.sleep(0.05)
    if interrupt_confirmed_at is None:
        raise AppServerError("capability-interrupt-not-confirmed")

    guarded_measure(
        samples,
        "finalize",
        lambda: write_private_artifact(
            record_dir / "calibration-finalize.json",
            {"thread_id": thread_id, "turn_id": turn_id, "control_turn_id": CONTROL_TURN_ID},
        ),
        guard_seconds=0.0,
    )
    guarded_measure(
        samples,
        "close",
        lambda: server.archive_thread(thread_id),
        guard_seconds=0.0,
    )
    try:
        terminal_location, terminal_boundary, terminal_records = capture_unique_boundary(
            server.codex_home,
            thread_id,
            baseline=observed_prefix,
        )
    except NativeSessionBoundaryError as exc:
        raise AppServerError(f"capability-terminal-boundary-invalid:{exc}") from exc
    terminal_markers = telemetry_markers(terminal_records, turn_id=turn_id)
    if terminal_location.source_identity_sha256 != trusted_source_identity:
        raise AppServerError("capability-terminal-session-source-identity-changed")
    if terminal_markers["compaction_indices"] or terminal_markers["reroute_indices"]:
        raise AppServerError("capability-terminal-containment-failed")
    materialization = seal_materialization_evidence(
        {
            "evidence_type": MATERIALIZATION_EVIDENCE_TYPE,
            "version": 3,
            "schema": MATERIALIZATION_EVIDENCE_SCHEMA,
            "evidence_id": f"materialization-{uuid.uuid4()}",
            "run_nonce": run_nonce,
            "attempt_nonce": attempt_nonce,
            "phase_nonce": phase_nonce,
            "session_id": thread_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "requested_model": EXACT_MODEL,
            "attested_model": EXACT_MODEL,
            "attested_effort": "low",
            "attestation_source": (
                "initialized-codex-home-session-jsonl-and-local-app-server-stdio-notifications"
            ),
            "connection_epoch_sha256": server.connection_epoch_sha256,
            "command_sha256": sha256_text("sleep 20"),
            "baseline": public_boundary(strict_baseline),
            "liveness_observations": observations,
            "pre_interrupt_observation": pre_interrupt,
            "interrupt": {
                "requested_at": interrupt_requested_at,
                "request_accepted_at": interrupt_request_accepted_at,
                "confirmed_at": interrupt_confirmed_at,
                "session_id": thread_id,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "request_outcome": "accepted",
                "outcome": "interrupt-confirmed",
            },
            "terminal": public_boundary(terminal_boundary),
            "status": "interrupt-confirmed",
            "disposition": "accepted",
        }
    )
    materialization_errors = validate_materialization_evidence(
        materialization, require_accepting=True
    )
    if materialization_errors:
        raise AppServerError(
            "capability-materialization-evidence-invalid:" + ";".join(materialization_errors)
        )

    scheduler_samples: list[float] = []
    children = [
        {"child_id": "a", "next_deadline_ns": 1_000_000_000},
        {"child_id": "b", "next_deadline_ns": 1_000_000_000},
    ]
    cursor = 0
    for _index in range(4):
        started = time.monotonic_ns()
        selected = select_earliest_deadline(children, cursor=cursor)
        if selected is None:
            raise AppServerError("scheduler-calibration-selection-missing")
        cursor = selected.next_cursor
        time.sleep(0.05)
        scheduler_samples.append((time.monotonic_ns() - started) / 1_000_000)

    measured_at = utc_now()
    receipt = seal_artifact(
        {
            "receipt_type": CAPABILITY_RECEIPT_TYPE,
            "version": 1,
            "schema": CAPABILITY_RECEIPT_SCHEMA,
            "adapter_id": "native-multi-agent-v1",
            "adapter_version": "codex-app-server-0.144.5",
            "execution_surface": "connected-codex",
            "host_identity": dict(owner),
            "control_turn_id": CONTROL_TURN_ID,
            "measured_at": iso(measured_at),
            "expires_at": iso(measured_at + dt.timedelta(minutes=55)),
            "sample_count": min(len(values) for values in samples.values()),
            "requested_cap": 2,
            "clock": "monotonic_ns",
            "callbacks": {name: stats(samples[name]) for name in sorted(samples)},
            "scheduler_overhead": stats(scheduler_samples),
            "certification": capability_certification(),
            "capabilities": {
                "interrupt": True,
                "close": True,
                "wait": True,
                "trusted_telemetry": True,
            },
            "attestation_source": "trusted-control-plane-session-metadata",
            "validation_outcome": "accepted",
        },
        "receipt_sha256",
    )
    errors = validate_capability_receipt(receipt, now=utc_now())
    if errors:
        raise AppServerError("capability-receipt-invalid:" + ";".join(errors))
    ceilings = receipt["certification"]["certified_callback_max_ms"]
    check_max = ceilings["check"]
    lifecycle_max = max(ceilings.values())
    overhead_max = receipt["certification"]["certified_scheduler_overhead_ms"]
    if lifecycle_max + 2 * check_max + overhead_max > 1000:
        raise AppServerError("capability-response-time-bound-failed")

    thread = last_threads[thread_id]
    boundary = session_boundary_summary(
        server.codex_home,
        thread_id,
        thread.get("path") or result["thread"].get("path"),
        baseline=strict_baseline,
    )
    summary = {
        "thread_id": thread_id,
        "turn_id": turn_id,
        "thread_start_model": result.get("model"),
        "thread_start_model_provider": result.get("modelProvider"),
        "turn_status": turn_status(thread, turn_id),
        "session_boundary": boundary,
        "final_response_sha256": None,
        "expected_final_token_observed": False,
        "reroute_count": len(server.notifications(thread_id, "model/rerouted")),
        "compactions": len(server.notifications(thread_id, "thread/compacted"))
        + int(boundary.get("compactions", 0)),
    }
    if summary["turn_status"] != "interrupted":
        raise AppServerError("capability-interrupt-summary-invalid")
    if summary["thread_start_model"] != EXACT_MODEL:
        raise AppServerError("capability-thread-start-model-mismatch")
    if summary["session_boundary"].get("attested_models") != [EXACT_MODEL]:
        raise AppServerError("capability-session-model-mismatch")
    if summary["session_boundary"].get("attested_efforts") != ["low"]:
        raise AppServerError("capability-session-effort-mismatch")
    if summary["compactions"] or summary["reroute_count"]:
        raise AppServerError("capability-session-containment-failed")

    evidence = {
        "thread_preallocation_stats": stats([preallocation_latency]),
        "guard_band_ms": {"callbacks": 0, "scheduler_overhead": 50},
        "sessions": [summary],
        "materialization_evidence": materialization,
        "materialization_evidence_sha256": materialization["evidence_sha256"],
        "poll_interval_max_ms": round(
            max(
                (later - earlier) * 1000
                for earlier, later in zip(poll_started, poll_started[1:])
            ),
            3,
        ) if len(poll_started) > 1 else 0.0,
        "interrupt_confirmed": True,
        "peer_completion_deferred_to_coordinator_interrupt_canary": True,
        "scheduler_inequality_lhs_ms": round(
            lifecycle_max + 2 * check_max + overhead_max, 3
        ),
        "scheduler_inequality_rhs_ms": 1000,
    }
    return receipt, evidence


def make_git_layout(root: Path) -> dict[str, Path]:
    integration = root / "integration"
    integration.mkdir()
    run_git(integration, "init", "-q")
    run_git(integration, "config", "user.name", "CWO Live Canary")
    run_git(integration, "config", "user.email", "cwo-canary@example.invalid")
    (integration / "data").mkdir()
    (integration / "targets").mkdir()
    (integration / "data" / "shared.txt").write_text("trusted-read-only-baseline\n", encoding="utf-8")
    (integration / "targets" / "child_0.txt").write_text("baseline-0\n", encoding="utf-8")
    (integration / "targets" / "child_1.txt").write_text("baseline-1\n", encoding="utf-8")
    run_git(integration, "add", ".")
    run_git(integration, "commit", "-qm", "canary baseline")
    paths: dict[str, Path] = {"integration": integration}
    for name in ("read-shared", "mutable-0", "mutable-1", "interrupt-shared"):
        target = root / name
        run_git(
            integration,
            "worktree",
            "add",
            "-q",
            "-b",
            f"cwo-18w6-{name}",
            str(target),
            "HEAD",
        )
        paths[name] = target
    return paths


def build_pool_inputs(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    interrupt_after: list[int | None] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, LiveThreadAdapter],
    PoolWorkspaceMonitor,
]:
    record_dir = root / f"{pool_name}-records"
    record_dir.mkdir(mode=0o700)
    thread_results = []
    for index, worktree in enumerate(worktrees):
        role = f"{pool_name}-{index}"
        result, _latency = server.start_thread(worktree, mutable=mutable, role=role)
        thread_results.append(result)
    children = []
    child_contracts: dict[str, dict[str, Any]] = {}
    adapters: dict[str, LiveThreadAdapter] = {}
    for index, (result, worktree, prompt, expected_token) in enumerate(
        zip(thread_results, worktrees, prompts, expected_tokens)
    ):
        child_id = f"{pool_name}-child-{index}"
        thread_id = str(result["thread"]["id"])
        state_file = record_dir / f"{child_id}-worker-state.json"
        control_file = record_dir / f"{child_id}-control-contract.json"
        control_turn_id = f"{CONTROL_TURN_ID}:{pool_name}:{index}"
        packet_sha256 = sha256_text(
            json.dumps(
                {
                    "pool": pool_name,
                    "child": index,
                    "prompt_sha256": sha256_text(prompt),
                    "thread_id": thread_id,
                },
                sort_keys=True,
            )
        )
        control = build_control_turn_contract(
            state_file=str(state_file),
            agent_id=thread_id,
            control_turn_id=control_turn_id,
            task_sha256=sha256_text(prompt),
            poll_interval_ms=1000,
        )
        state = {
            "result_type": "cwo-native-supervision-state",
            "version": 1,
            "schema": "schemas/native-supervision-state.schema.json",
            "packet_id": f"{pool_name}-packet-{uuid.uuid4()}",
            "packet_sha256": packet_sha256,
            "agent_id": thread_id,
            "session_id": thread_id,
            "status": "created",
            "control_turn_id": None,
            "poll_interval_ms": 1000,
            "control_adapter": "native-multi-agent-v1",
            "required_capabilities": ["interrupt", "close", "wait"],
        }
        write_private_artifact(control_file, control)
        write_private_artifact(state_file, state)
        target = f"targets/child_{index}.txt" if mutable else None
        child = {
            "child_id": child_id,
            "packet_id": state["packet_id"],
            "attempt_nonce": f"{pool_name}-attempt-{uuid.uuid4()}",
            "session_id": thread_id,
            "agent_id": thread_id,
            "control_turn_id": control_turn_id,
            "packet_sha256": packet_sha256,
            "control_contract_file": str(control_file),
            "state_file": str(state_file),
            "worktree": str(worktree),
            "isolation_class": "mutable-isolated" if mutable else "read-only-shared",
            "declared_write_paths": [target] if target else [],
            "integration_target_paths": [target] if target else [],
            "lease_id": f"{pool_name}-lease-{uuid.uuid4()}",
        }
        children.append(child)
        child_contracts[child_id] = control
        adapters[child_id] = LiveThreadAdapter(
            server,
            result,
            prompt=prompt,
            expected_token=expected_token,
            worktree=worktree,
            mutable=mutable,
            expected_mutation=target,
            force_interrupt_after_checks=(interrupt_after or [None, None])[index],
            record_dir=record_dir,
        )
    request = {
        "request_type": "cwo-native-supervision-pool-render-request",
        "version": 1,
        "schema": "schemas/native-supervision-pool-render-request.schema.json",
        "pool_id": f"18w6-{pool_name}-{uuid.uuid4()}",
        "pool_epoch": f"18w6-{pool_name}-epoch-{uuid.uuid4()}",
        "control_turn_id": CONTROL_TURN_ID,
        "created_at": iso(),
        "max_active_workers": 2,
        "aggregate_hard_budget": {
            "tool_calls": 20,
            "runtime_seconds": 300,
            "compactions": 0,
            "full_suite_runs": 0,
            "mutations": 2 if mutable else 0,
        },
        "integration_root": str(integration),
        "children": children,
    }
    contract = build_pool_contract(
        request,
        capability_receipt=capability_receipt,
        enable_concurrency=True,
        owner_pid=os.getpid(),
        now=utc_now(),
    )
    monitor = PoolWorkspaceMonitor(
        contract,
        integration_root=integration,
        child_worktrees={child_id: adapter.worktree for child_id, adapter in adapters.items()},
    )
    return contract, child_contracts, adapters, monitor


def run_pool_canary(
    server: AppServer,
    capability_receipt: Mapping[str, Any],
    *,
    root: Path,
    integration: Path,
    pool_name: str,
    worktrees: list[Path],
    mutable: bool,
    prompts: list[str],
    expected_tokens: list[str],
    interrupt_after: list[int | None] | None = None,
) -> dict[str, Any]:
    contract, child_contracts, adapters, monitor = build_pool_inputs(
        server,
        capability_receipt,
        root=root,
        integration=integration,
        pool_name=pool_name,
        worktrees=worktrees,
        mutable=mutable,
        prompts=prompts,
        expected_tokens=expected_tokens,
        interrupt_after=interrupt_after,
    )
    child_ids = list(adapters)

    def read_child_evidence(*, child_id: str, state_file: str) -> dict[str, Any]:
        if state_file != next(
            child["state_file"] for child in contract["children"] if child["child_id"] == child_id
        ):
            raise AppServerError("child-evidence-state-file-mismatch")
        return adapters[child_id].evidence()

    coordinator = NativePoolCoordinator(
        contract,
        child_contracts,
        {child_id: adapters[child_id].prompt for child_id in child_ids},
        {child_id: adapters[child_id].callbacks() for child_id in child_ids},
        pool_callbacks={
            "monotonic_ns": time.monotonic_ns,
            "sleep": time.sleep,
            "now_utc": iso,
            "read_child_evidence": read_child_evidence,
            "compare_workspaces": monitor.compare,
        },
        lease_registry=PoolLeaseRegistry(root / f"{pool_name}-leases.json"),
        capability_receipt=capability_receipt,
        state_file=root / f"{pool_name}-pool-state.json",
        decision_file=root / f"{pool_name}-pool-decision.json",
    )
    started = time.monotonic_ns()
    receipt = coordinator.run()
    elapsed = (time.monotonic_ns() - started) / 1_000_000_000
    terminal_state = coordinator.progress()["state"]
    receipt_errors = validate_pool_receipt(
        receipt, contract=contract, terminal_state=terminal_state
    )
    if receipt_errors:
        raise AppServerError("live-pool-receipt-invalid:" + ";".join(receipt_errors))
    if interrupt_after is None and receipt.get("accepting") is not True:
        first_fault = receipt.get("first_protected_fault")
        raise LivePoolProtectedFault(first_fault)
    summaries = [adapters[child_id].final_summary() for child_id in child_ids]
    worker_seconds = float(receipt["worker_seconds"])
    improvement = (
        (worker_seconds - float(receipt["pool_wall_seconds"])) / worker_seconds
        if worker_seconds > 0
        else 0.0
    )
    return {
        "pool_name": pool_name,
        "pool_id": contract["pool_id"],
        "pool_epoch": contract["pool_epoch"],
        "contract_sha256": contract["contract_sha256"],
        "receipt": receipt,
        "receipt_validation_errors": receipt_errors,
        "terminal_state_sha256": terminal_state["state_sha256"],
        "elapsed_seconds": round(elapsed, 3),
        "elapsed_improvement_ratio": round(improvement, 6),
        "sessions": summaries,
        "workspace": {
            "evidence": monitor.last_report["evidence"] if monitor.last_report else None,
            "phase": monitor.last_report["phase"] if monitor.last_report else None,
        },
    }


def validate_campaign(
    capability: Mapping[str, Any],
    calibration_evidence: Mapping[str, Any],
    canaries: list[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    capability_errors = validate_capability_receipt(capability, now=utc_now())
    errors.extend(f"capability:{item}" for item in capability_errors)
    certification = capability["certification"]
    ceilings = certification["certified_callback_max_ms"]
    check_max = ceilings["check"]
    overhead = certification["certified_scheduler_overhead_ms"]
    lifecycle_max = max(ceilings.values())
    if check_max > 200:
        errors.append("capability-check-max-exceeded")
    if lifecycle_max + 2 * check_max + overhead > 1000:
        errors.append("capability-response-time-bound-failed")
    all_sessions = list(calibration_evidence.get("sessions", []))
    for canary in canaries:
        all_sessions.extend(canary.get("sessions", []))
    thread_ids = [session.get("thread_id") for session in all_sessions]
    if len(thread_ids) != 7 or len(thread_ids) != len(set(thread_ids)):
        errors.append("fresh-session-cardinality-or-uniqueness-failed")
    for session in all_sessions:
        boundary = session.get("session_boundary", {})
        if session.get("thread_start_model") != EXACT_MODEL:
            errors.append("session-thread-start-model-mismatch")
        if boundary.get("attested_models") != [EXACT_MODEL]:
            errors.append("session-trusted-model-mismatch")
        if boundary.get("attested_efforts") != ["low"]:
            errors.append("session-trusted-effort-mismatch")
        if boundary.get("trailing_partial"):
            errors.append("session-terminal-boundary-partial")
        if session.get("compactions"):
            errors.append("session-compaction-observed")
        if session.get("reroute_count"):
            errors.append("session-model-reroute-observed")
    by_name = {str(item.get("pool_name")): item for item in canaries}
    for name in ("read-only", "mutable"):
        canary = by_name.get(name, {})
        receipt = canary.get("receipt", {})
        if receipt.get("accepting") is not True or receipt.get("pool_disposition") != "accepted":
            errors.append(f"{name}-pool-not-accepting")
        if receipt.get("reasons"):
            errors.append(f"{name}-protected-reasons-observed")
        if canary.get("elapsed_improvement_ratio", 0) <= 0:
            errors.append(f"{name}-elapsed-improvement-not-positive")
        for session in canary.get("sessions", []):
            if not session.get("expected_final_token_observed"):
                errors.append(f"{name}-invalid-final-response")
    mutable = by_name.get("mutable", {})
    expected_mutations = [["targets/child_0.txt"], ["targets/child_1.txt"]]
    if [session.get("workspace_mutations") for session in mutable.get("sessions", [])] != expected_mutations:
        errors.append("mutable-workspace-attribution-failed")
    read_only = by_name.get("read-only", {})
    if any(session.get("workspace_mutations") for session in read_only.get("sessions", [])):
        errors.append("read-only-workspace-mutation-observed")
    interrupted = by_name.get("interrupt", {})
    receipt = interrupted.get("receipt", {})
    if receipt.get("accepting") is not False or receipt.get("pool_disposition") != "partial":
        errors.append("interrupt-pool-disposition-invalid")
    if receipt.get("reasons"):
        errors.append("interrupt-protected-reasons-observed")
    sessions = interrupted.get("sessions", [])
    if len(sessions) != 2:
        errors.append("interrupt-session-count-invalid")
    else:
        if sessions[0].get("turn_status") != "interrupted" or not sessions[0].get("interrupted"):
            errors.append("independent-interrupt-not-confirmed")
        if sessions[1].get("turn_status") != "completed" or not sessions[1].get(
            "expected_final_token_observed"
        ):
            errors.append("interrupt-peer-did-not-complete")
    if interrupted.get("elapsed_improvement_ratio", 0) <= 0:
        errors.append("interrupt-elapsed-improvement-not-positive")
    for canary in canaries:
        evidence = canary.get("workspace", {}).get("evidence")
        if evidence != {
            "integration_root_clean": True,
            "shared_read_only_clean": True,
            "child_worktrees_clean": True,
        }:
            errors.append(f"{canary.get('pool_name')}-workspace-evidence-not-clean")
        if canary.get("receipt_validation_errors"):
            errors.append(f"{canary.get('pool_name')}-receipt-validation-failed")
    return sorted(set(errors))


def contain_started_threads(server: AppServer) -> dict[str, Any]:
    """Idempotently interrupt, archive, and audit every allocated thread."""

    interrupted: list[str] = []
    archived: list[str] = []
    already_contained: list[str] = []
    ambiguous: list[str] = []
    ledger_errors: list[str] = []
    ledger = getattr(server, "allocation_ledger", None)

    def audit_containment(thread_id: str, outcome: str, status: str | None) -> None:
        if ledger is None:
            return
        try:
            ledger.record_containment_audit(
                thread_id,
                outcome=outcome,
                evidence={
                    "thread_id_sha256": sha256_text(thread_id),
                    "turn_status": status,
                    "outcome": outcome,
                },
            )
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))

    for thread_id, turn_id in list(server.started_threads.items()):
        try:
            thread, _latency = server.read_thread(thread_id)
            status = turn_status(thread, turn_id) if turn_id else None
            if turn_id and status == "inProgress":
                server.interrupt_turn(thread_id, turn_id)
                interrupted.append(thread_id)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    thread, _latency = server.read_thread(thread_id)
                    status = turn_status(thread, turn_id)
                    if status in {"interrupted", "completed", "failed"}:
                        break
                    time.sleep(0.05)
            if turn_id is None or status in {"interrupted", "completed", "failed"}:
                server.archive_thread(thread_id)
                archived.append(thread_id)
                audit_containment(thread_id, "contained", status)
            else:
                ambiguous.append(thread_id)
        except Exception:
            try:
                archived_in_ledger = bool(
                    ledger is not None
                    and ledger.has_lifecycle(thread_id, "archive-observed")
                )
            except Exception as exc:
                archived_in_ledger = False
                ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
            if archived_in_ledger:
                already_contained.append(thread_id)
                audit_containment(thread_id, "already-contained", None)
            else:
                ambiguous.append(thread_id)
    unresolved_allocations = 0
    unresolved_turns = 0
    ledger_allocation_count = len(server.started_threads)
    if ledger is not None:
        try:
            ledger_summary = ledger.summary()
            unresolved_allocations = int(
                ledger_summary["unresolved_allocation_intent_count"]
            )
            unresolved_turns = int(ledger_summary["unresolved_turn_intent_count"])
            ledger_allocation_count = int(ledger_summary["allocation_intent_count"])
        except Exception as exc:
            ledger_errors.append(sha256_text(f"{type(exc).__name__}:{exc}"))
    ambiguous_count = len(set(ambiguous)) + unresolved_allocations
    return {
        "allocated_count": ledger_allocation_count,
        "identified_thread_count": len(server.started_threads),
        "interrupted_count": len(set(interrupted)),
        "archived_count": len(set(archived)),
        "already_contained_count": len(set(already_contained)),
        "unresolved_allocation_intent_count": unresolved_allocations,
        "unresolved_turn_intent_count": unresolved_turns,
        "ambiguous_count": ambiguous_count,
        "all_contained": ambiguous_count == 0,
        "ledger_consistent": not ledger_errors and not unresolved_allocations and not unresolved_turns,
        "ledger_error_sha256": sorted(set(ledger_errors)),
    }


def load_private_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AppServerError(f"{label}-file-invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AppServerError(f"{label}-file-unreadable") from exc
    if not isinstance(value, dict):
        raise AppServerError(f"{label}-not-object")
    return value


def safe_allocation_ledger_summary(
    ledger: NativeLiveAllocationLedgerStore | None,
) -> dict[str, Any] | None:
    if ledger is None:
        return None
    try:
        return {"available": True, **ledger.summary()}
    except Exception as exc:
        return {
            "available": False,
            "summary_error_sha256": sha256_text(f"{type(exc).__name__}:{exc}"),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--pre-mutation-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-mutation-adjudication", type=Path, required=True)
    parser.add_argument("--pre-live-steering-receipt", type=Path, required=True)
    parser.add_argument("--pre-live-adjudication", type=Path, required=True)
    parser.add_argument("--campaign-nonce", required=True)
    parser.add_argument("--authorization-state", type=Path)
    parser.add_argument("--steering-registry", type=Path)
    args = parser.parse_args()
    output = Path(args.output).absolute()
    started_at = utc_now()
    server: AppServer | None = None
    authorization_store: CanaryAuthorizationStore | None = None
    authorization_state: dict[str, Any] | None = None
    steering_consumptions: dict[str, str] = {}
    allocation_ledger: NativeLiveAllocationLedgerStore | None = None
    try:
        try:
            uuid.UUID(args.campaign_nonce)
        except ValueError as exc:
            raise AppServerError("campaign-nonce-invalid") from exc
        authorization = load_private_json(args.authorization.absolute(), "authorization")
        authorization_sha256 = sha256_bytes(args.authorization.read_bytes())
        authorization_id, repo_head = validate_full_auto_authorization(
            authorization,
            args.campaign_nonce,
            repo_root=ROOT,
        )
        state_path = (
            args.authorization_state.absolute()
            if args.authorization_state
            else output.with_suffix(output.suffix + ".authorization-state.json")
        )
        registry_path = (
            args.steering_registry.absolute()
            if args.steering_registry
            else output.with_suffix(output.suffix + ".steering-consumption.json")
        )
        authorization_store = CanaryAuthorizationStore(state_path)
        authorization_state = authorization_store.initialize(
            new_authorization_state(
                authorization_id=authorization_id,
                run_nonce=args.campaign_nonce,
                now=iso(),
            )
        )
        pre_mutation_receipt = load_private_json(
            args.pre_mutation_steering_receipt.absolute(), "pre-mutation-steering-receipt"
        )
        pre_live_receipt = load_private_json(
            args.pre_live_steering_receipt.absolute(), "pre-live-steering-receipt"
        )
        pre_mutation_adjudication = load_private_json(
            args.pre_mutation_adjudication.absolute(), "pre-mutation-adjudication"
        )
        pre_mutation_adjudication_sha256 = sha256_bytes(
            args.pre_mutation_adjudication.absolute().read_bytes()
        )
        pre_live_adjudication = load_private_json(
            args.pre_live_adjudication.absolute(), "pre-live-adjudication"
        )
        pre_live_adjudication_sha256 = sha256_bytes(args.pre_live_adjudication.absolute().read_bytes())
        prepared = plan_steering_receipt_consumptions(
            args.campaign_nonce,
            authorization_id,
            authorization_sha256,
            registry_file=registry_path,
            repo_head=repo_head,
            pre_mutation_receipt=pre_mutation_receipt,
            pre_mutation_adjudication=pre_mutation_adjudication,
            pre_mutation_adjudication_sha256=pre_mutation_adjudication_sha256,
            pre_live_receipt=pre_live_receipt,
            pre_live_adjudication=pre_live_adjudication,
            pre_live_adjudication_sha256=pre_live_adjudication_sha256,
        )
        require_repository_checkpoint(ROOT, repo_head)
        for label in ("pre-mutation", "pre-live"):
            _, params = prepared[label]
            if label == "pre-mutation":
                receipt = pre_mutation_receipt
            else:
                receipt = pre_live_receipt
            steering_consumptions[label] = consume_steering_receipt(receipt, registry_path, **params)
        require_repository_checkpoint(ROOT, repo_head)
        authorization_store.require_action("tracked-mutation")
        with tempfile.TemporaryDirectory(prefix="cwo-18w6-live-") as temporary:
            temp_root = Path(temporary)
            temp_root.chmod(0o700)
            layout = make_git_layout(temp_root)
            record_dir = temp_root / "capability-records"
            record_dir.mkdir(mode=0o700)
            server = AppServer()
            discovery = server.model_discovery()
            owner = capture_owner_identity(os.getpid())
            budgets = authorization.get("budgets")
            consumed_generation = (
                budgets.get("spark_live_campaign_generations_consumed_before_v9")
                if isinstance(budgets, Mapping)
                else None
            )
            if consumed_generation != 3:
                raise AppServerError("allocation-ledger-predecessor-generation-invalid")
            authorization_bindings = authorization.get("bindings")
            if not isinstance(authorization_bindings, Mapping):
                raise AppServerError("allocation-ledger-authorization-bindings-invalid")
            certification_policy = callback_certification_policy()
            allocation_ledger = NativeLiveAllocationLedgerStore(
                output.parent / f".{output.name}.allocation-ledger"
            )
            allocation_ledger.initialize(
                {
                    "bead_id": "complex-work-orchestration-18w.6.14.6",
                    "authorization_id": authorization_id,
                    "authorization_raw_sha256": authorization_sha256,
                    "authorization_canonical_sha256": authorization[
                        "canonical_authorization_sha256"
                    ],
                    "campaign_nonce": args.campaign_nonce,
                    "live_generation": consumed_generation + 1,
                    "predecessor_generation": consumed_generation,
                    "checkpoint_commit": repo_head,
                    "guarded_primary_diff_sha256": authorization_bindings[
                        "guarded_primary_diff_sha256"
                    ],
                    "predecessor_containment_sha256": authorization_bindings[
                        "contained_failure_analysis_canonical_sha256"
                    ],
                    "pre_mutation_steering_receipt_sha256": pre_mutation_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "pre_live_steering_receipt_sha256": pre_live_receipt[
                        "canonical_receipt_sha256"
                    ],
                    "certification_policy_sha256": callback_certification_policy_sha256(
                        certification_policy
                    ),
                    "controller_identity": owner,
                    "connection_epoch_sha256": server.connection_epoch_sha256,
                    "retention_class": "private-local-until-bead-closure",
                    "expected_roles": list(EXPECTED_ROLES),
                }
            )
            server.attach_allocation_ledger(allocation_ledger)
            capability, calibration_evidence = calibration(
                server,
                layout["read-shared"],
                record_dir,
                owner,
                run_nonce=authorization_id,
                phase_nonce=args.campaign_nonce,
            )
            allocation_ledger.bind_certification(capability["receipt_sha256"])

            read_prompts = [
                (
                    f"Use exec_command to run `sleep 2`, then use exec_command to run "
                    f"`sha256sum data/shared.txt`. Do not mutate any file. Return exactly "
                    f"READ_ONLY_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            read_canary = run_pool_canary(
                server,
                capability,
                root=temp_root,
                integration=layout["integration"],
                pool_name="read-only",
                worktrees=[layout["read-shared"], layout["read-shared"]],
                mutable=False,
                prompts=read_prompts,
                expected_tokens=["READ_ONLY_CHILD_0_OK", "READ_ONLY_CHILD_1_OK"],
            )

            mutable_prompts = [
                (
                    f"Use apply_patch to append the exact line `spark-canary-{index}` to "
                    f"targets/child_{index}.txt and do not modify any other file. Then use "
                    f"exec_command to run `sleep 2`. Return exactly MUTABLE_CHILD_{index}_OK."
                )
                for index in range(2)
            ]
            mutable_canary = run_pool_canary(
                server,
                capability,
                root=temp_root,
                integration=layout["integration"],
                pool_name="mutable",
                worktrees=[layout["mutable-0"], layout["mutable-1"]],
                mutable=True,
                prompts=mutable_prompts,
                expected_tokens=["MUTABLE_CHILD_0_OK", "MUTABLE_CHILD_1_OK"],
            )

            interrupt_prompts = [
                (
                    "Use exec_command to run `sleep 20`. After it finishes, return exactly "
                    "INTERRUPT_LONG_UNEXPECTED_COMPLETION. Do not use any other tool."
                ),
                (
                    "Use exec_command to run `sleep 3`. After it finishes, return exactly "
                    "INTERRUPT_PEER_OK. Do not use any other tool."
                ),
            ]
            interrupt_canary = run_pool_canary(
                server,
                capability,
                root=temp_root,
                integration=layout["integration"],
                pool_name="interrupt",
                worktrees=[layout["interrupt-shared"], layout["interrupt-shared"]],
                mutable=False,
                prompts=interrupt_prompts,
                expected_tokens=["INTERRUPT_LONG_UNEXPECTED_COMPLETION", "INTERRUPT_PEER_OK"],
                interrupt_after=[2, None],
            )
            canaries = [read_canary, mutable_canary, interrupt_canary]
            campaign_errors = validate_campaign(capability, calibration_evidence, canaries)
            if campaign_errors:
                raise AppServerError("campaign-validation-failed:" + ";".join(campaign_errors))
            authorization_state = authorization_store.transition(
                "complete", reason="seven-turn-campaign-accepted", now=iso()
            )
            value = seal_artifact(
                {
                    "result_type": "cwo-native-supervision-pool-live-canary-evidence",
                    "version": 1,
                    "bead_id": "complex-work-orchestration-18w.6",
                    "control_turn_id": CONTROL_TURN_ID,
                    "exact_model": EXACT_MODEL,
                    "attestation_source": "trusted-control-plane-session-metadata",
                    "execution_surface": "connected-codex",
                    "app_server_transport": "stdio",
                    "model_discovery": discovery,
                    "started_at": iso(started_at),
                    "completed_at": iso(),
                    "capability_receipt": capability,
                    "capability_calibration": calibration_evidence,
                    "materialization_evidence_sha256": calibration_evidence[
                        "materialization_evidence_sha256"
                    ],
                    "authorization_sha256": authorization_sha256,
                    "authorization_state_sha256": authorization_state["state_sha256"],
                    "steering_consumptions": steering_consumptions,
                    "allocation_ledger": allocation_ledger.summary(),
                    "canaries": canaries,
                    "fresh_session_count": 7,
                    "no_resume_or_salvage": True,
                    "campaign_errors": campaign_errors,
                    "validation_outcome": "accepted",
                    "release_gate_passed": True,
                    "temporary_workspace_disposition": "deleted-after-evidence-capture",
                    "glm_5_2_used": False,
                    "model_synthesis_used": False,
                },
                "evidence_sha256",
            )
            write_private_artifact(output, value)
            print(
                json.dumps(
                    {
                        "release_gate_passed": value["release_gate_passed"],
                        "evidence_sha256": value["evidence_sha256"],
                        "fresh_session_count": value["fresh_session_count"],
                        "campaign_errors": value["campaign_errors"],
                        "observed_check_max_ms": capability["callbacks"]["check"]["max_ms"],
                        "certified_check_max_ms": capability["certification"][
                            "certified_callback_max_ms"
                        ]["check"],
                        "scheduler_inequality_lhs_ms": calibration_evidence[
                            "scheduler_inequality_lhs_ms"
                        ],
                        "canaries": [
                            {
                                "name": item["pool_name"],
                                "accepting": item["receipt"]["accepting"],
                                "disposition": item["receipt"]["pool_disposition"],
                                "elapsed_improvement_ratio": item[
                                    "elapsed_improvement_ratio"
                                ],
                            }
                            for item in canaries
                        ],
                    },
                    sort_keys=True,
                )
            )
            return 0
    except Exception as exc:
        containment = (
            contain_started_threads(server)
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
        if authorization_store is not None and authorization_state is not None:
            try:
                current = authorization_store.load()
                if current["state"] == "active":
                    authorization_state = authorization_store.transition(
                        "containment-only", reason="evidence-bearing-protected-fault", now=iso()
                    )
                else:
                    authorization_state = current
            except Exception:
                containment["authorization_transition_failed"] = True
        raw_failure = str(exc)
        safe_failure_code = (
            raw_failure
            if raw_failure
            and len(raw_failure) <= 240
            and all(character.isalnum() or character in "-_:;." for character in raw_failure)
            else type(exc).__name__
        )
        failure = seal_artifact(
            {
                "result_type": "cwo-native-supervision-pool-live-canary-failure",
                "version": 1,
                "bead_id": "complex-work-orchestration-18w.6",
                "control_turn_id": CONTROL_TURN_ID,
                "exact_model": EXACT_MODEL,
                "started_at": iso(started_at),
                "failed_at": iso(),
                "failure_class": type(exc).__name__,
                "failure_code": safe_failure_code,
                "failure_message_sha256": sha256_text(str(exc)),
                "validation_outcome": "rejected",
                "release_gate_passed": False,
                "no_resume_or_salvage": True,
                "containment": containment,
                "authorization_state_sha256": (
                    authorization_state.get("state_sha256")
                    if isinstance(authorization_state, Mapping)
                    else None
                ),
                "steering_consumptions": steering_consumptions,
                "first_protected_fault": getattr(exc, "first_protected_fault", None),
                "allocation_ledger": safe_allocation_ledger_summary(allocation_ledger),
            },
            "evidence_sha256",
        )
        write_private_artifact(output, failure)
        print(
            json.dumps(
                {
                    "release_gate_passed": False,
                    "failure_class": type(exc).__name__,
                    "failure_code": safe_failure_code,
                    "failure_message_sha256": failure["failure_message_sha256"],
                    "evidence_sha256": failure["evidence_sha256"],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if server is not None:
            server.close()


if __name__ == "__main__":
    raise SystemExit(main())
