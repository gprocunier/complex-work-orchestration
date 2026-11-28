"""Original live thread adapter and its finite control callbacks."""

from __future__ import annotations

import copy
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from cwo_core import native_live_availability as live_availability
from cwo_core.codex_tool_surface import (
    DIRECT_TOOL_TRANSPORT,
    NAMESPACED_EXEC_TOOL_TRANSPORT,
)
from cwo_core.native_pool_contracts import (
    POOL_POLL_INTERVAL_MS,
    POOL_POLL_LAG_TOLERANCE_MS,
    canonical_sha256,
    default_completion_evidence_policy,
    validate_completion_evidence_policy,
    write_private_artifact,
    zero_token_usage,
)
from cwo_core.native_session_boundary import (
    NativeSessionBoundaryError,
    locate_unique_session,
)
from cwo_core.native_tool_isolation import (
    NativeToolIsolationError,
    default_tool_policy,
    forbidden_tool_activity,
    normalize_tool_policy,
    require_prompt_preflight,
    require_unchanged_tool_surface,
    validate_tool_surface_snapshot,
)
from cwo_core.native_worker_contracts import canonical_argument_hash
from cwo_core.supervision.callback_timing import (
    PROVISIONAL_TERMINAL_GRACE_SECONDS,
    stats,
)
from cwo_core.supervision.containment import (
    STAGED_ARCHIVE_TERMINAL_POLL_SECONDS,
    STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS,
    StagedThreadArchive,
)
from cwo_core.supervision.session_evidence import (
    normalize_expected_tool_trace,
    normalize_read_only_command_authority,
    capture_server_tool_surface,
    final_message_hash_and_match,
    session_boundary_summary,
    turn_items,
    turn_status,
)
from cwo_core.supervision.transport.app_server import (
    AppServer,
    CONTROL_TURN_ID,
    EXACT_MODEL,
    canonical_controller_workdir as _canonical_controller_workdir,
    sha256_text,
)
from cwo_core.supervision.transport.errors import (
    AppServerError,
    AppServerRpcError,
)
from cwo_core.workspace import (
    capture_tracked_workspace_state,
    capture_workspace_baseline,
    cleanliness_established,
    compare_workspace_baseline,
    status_path,
)


POST_SUBMISSION_MATERIALIZATION_GRACE_MS = POOL_POLL_LAG_TOLERANCE_MS


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
        expected_tool_trace: list[Mapping[str, Any]] | None = None,
        read_only_command_authority: list[Mapping[str, Any]] | None = None,
        completion_evidence_policy: Mapping[str, Any] | None = None,
        tool_policy: Mapping[str, Any] | None = None,
        prompt_preflight_receipt: Mapping[str, Any] | None = None,
        preflight_tool_surface: Mapping[str, Any] | None = None,
        tool_surface_reader: Callable[[], Mapping[str, Any]] | None = None,
        force_interrupt_after_checks: int | None = None,
        record_dir: Path,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        campaign_live_route: bool = True,
    ) -> None:
        self.campaign_live_route = campaign_live_route
        self.server = server
        self.thread_response = copy.deepcopy(dict(thread_response))
        self.thread = copy.deepcopy(dict(thread_response["thread"]))
        self.thread_id = str(self.thread["id"])
        self.reported_session_path = self.thread.get("path")
        self.prompt = prompt
        self.expected_token = expected_token
        self.worktree = _canonical_controller_workdir(worktree)
        self.mutable = mutable
        self.expected_mutation = expected_mutation
        transport_reader = getattr(server, "operative_tool_transport", None)
        self.tool_transport = (
            str(transport_reader())
            if callable(transport_reader)
            else DIRECT_TOOL_TRANSPORT
        )
        if self.tool_transport not in {
            DIRECT_TOOL_TRANSPORT,
            NAMESPACED_EXEC_TOOL_TRANSPORT,
        }:
            raise AppServerError("operative-tool-transport-invalid")
        if expected_tool_trace is not None and read_only_command_authority is not None:
            raise AppServerError("tool-authority-contract-ambiguous")
        self.expected_tool_trace = normalize_expected_tool_trace(
            expected_tool_trace
        )
        self.expected_tool_trace_sha256 = (
            canonical_sha256(self.expected_tool_trace)
            if self.expected_tool_trace is not None
            else None
        )
        self.read_only_command_authority = (
            normalize_read_only_command_authority(
                read_only_command_authority,
                worktree=self.worktree,
                tool_transport=self.tool_transport,
            )
        )
        if self.mutable and self.read_only_command_authority is not None:
            raise AppServerError("read-only-command-authority-mutable-forbidden")
        self.read_only_command_authority_sha256 = (
            canonical_sha256(self.read_only_command_authority)
            if self.read_only_command_authority is not None
            else None
        )
        isolation_class = "mutable-isolated" if mutable else "read-only-shared"
        raw_policy = (
            default_completion_evidence_policy(isolation_class)
            if completion_evidence_policy is None
            else completion_evidence_policy
        )
        policy_errors = validate_completion_evidence_policy(
            raw_policy,
            isolation_class=isolation_class,
        )
        if policy_errors:
            raise AppServerError(
                "completion-evidence-policy-invalid:" + ";".join(policy_errors)
            )
        required = raw_policy["required_evidence"]
        self.completion_evidence_policy = {
            "minimum_tool_calls": int(raw_policy["minimum_tool_calls"]),
            "required_evidence": {
                "predicates": list(required["predicates"]),
                "sha256": list(required["sha256"]),
            },
            "allow_zero_tool_completion": bool(
                raw_policy["allow_zero_tool_completion"]
            ),
            "expected_mutation_mode": str(raw_policy["expected_mutation_mode"]),
        }
        self.completion_evidence_policy_sha256 = canonical_sha256(
            self.completion_evidence_policy
        )
        raw_tool_policy = (
            default_tool_policy(
                mutable=mutable,
                workload_class="safety-canary",
            )
            if tool_policy is None
            else tool_policy
        )
        try:
            self.tool_policy = normalize_tool_policy(raw_tool_policy)
            observed_prompt_preflight = require_prompt_preflight(
                prompt, self.tool_policy
            )
        except NativeToolIsolationError as exc:
            raise AppServerError(str(exc)) from exc
        if (
            prompt_preflight_receipt is not None
            and dict(prompt_preflight_receipt) != observed_prompt_preflight
        ):
            raise AppServerError("prompt-preflight-receipt-mismatch")
        self.prompt_preflight = observed_prompt_preflight
        self.tool_policy_sha256 = canonical_sha256(self.tool_policy)
        self._tool_surface_reader = tool_surface_reader or (
            lambda: capture_server_tool_surface(self.server, self.tool_policy)
        )
        initial_surface = (
            dict(preflight_tool_surface)
            if preflight_tool_surface is not None
            else dict(self._tool_surface_reader())
        )
        surface_errors = validate_tool_surface_snapshot(
            initial_surface, self.tool_policy
        )
        if surface_errors:
            raise AppServerError(
                "preflight-tool-surface-invalid:" + ";".join(surface_errors)
            )
        self.preflight_tool_surface = initial_surface
        self.pre_dispatch_tool_surface: dict[str, Any] | None = None
        self._forbidden_tool_activity: list[dict[str, str]] = []
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
        self._projection_started_ns: int | None = None
        self._durable_terminal_status: str | None = None
        self._session_boundary_baseline: dict[str, Any] | None = None
        self._session_source_identity_sha256: str | None = None
        self.callback_latencies: dict[str, list[float]] = {}
        self.callback_subphase_latencies: dict[str, list[float]] = {}
        self._evidence_sequence = 0
        self._staged_archive: StagedThreadArchive | None = None
        self._archive_terminal_evidence_sha256: str | None = None
        self._archive_observation_deadline_ns: int | None = None
        self._effective_boundary_sources: dict[str, Any] | None = None
        self._effective_boundary: dict[str, Any] | None = None
        self._effective_boundary_sha256: str | None = None
        self._effective_boundary_arm_in_progress = False
        self._effective_boundary_armed = False
        self._effective_boundary_send_reserved = False
        self._workspace_baseline: dict[str, Any] | None = None
        self._workspace_baseline_sha256: str | None = None

    @staticmethod
    def _sealed_mapping_matches(value: Mapping[str, Any], field: str) -> bool:
        observed = value.get(field)
        if not isinstance(observed, str):
            return False
        body = dict(value)
        body.pop(field, None)
        return observed == canonical_sha256(body)

    def _current_effective_boundary(self) -> dict[str, Any]:
        sources = self._effective_boundary_sources
        if not isinstance(sources, Mapping):
            raise AppServerError("effective-boundary-unbound")
        evidence_by_thread = getattr(
            self.server, "_effective_thread_start_evidence", None
        )
        evidence = (
            evidence_by_thread.get(self.thread_id)
            if isinstance(evidence_by_thread, Mapping)
            else None
        )
        if not isinstance(evidence, Mapping):
            raise AppServerError("effective-boundary-thread-start-missing")
        return {
            "thread_start": copy.deepcopy(dict(evidence)),
            "thread_response": copy.deepcopy(self.thread_response),
            "thread": copy.deepcopy(self.thread),
            "planned_child": copy.deepcopy(dict(sources["planned_child"])),
            "runtime_child": copy.deepcopy(dict(sources["runtime_child"])),
            "pool_contract": copy.deepcopy(dict(sources["pool_contract"])),
            "control_contract": copy.deepcopy(dict(sources["control_contract"])),
            "predispatch_proof": copy.deepcopy(dict(sources["predispatch_proof"])),
            "adapter": {
                "requested_model": getattr(
                    self.server, "requested_model", EXACT_MODEL
                ),
                "prompt": self.prompt,
                "worktree": str(self.worktree),
                "mutable": self.mutable,
                "return_contract": {
                    "expected_token": self.expected_token,
                    "expected_mutation": self.expected_mutation,
                    "expected_tool_trace": copy.deepcopy(
                        self.expected_tool_trace
                    ),
                    "read_only_command_authority": copy.deepcopy(
                        self.read_only_command_authority
                    ),
                    "completion_evidence_policy": copy.deepcopy(
                        self.completion_evidence_policy
                    ),
                },
                "prompt_preflight": copy.deepcopy(self.prompt_preflight),
                "tool_policy": copy.deepcopy(self.tool_policy),
                "tool_surface": copy.deepcopy(self.preflight_tool_surface),
                "workspace_baseline_sha256": (
                    canonical_sha256(self._workspace_baseline)
                    if self._workspace_baseline is not None
                    else None
                ),
                "writable_roots": list(sources["writable_roots"]),
            },
        }

    def _validate_effective_boundary(self, boundary: Mapping[str, Any]) -> None:
        expected_fields = {
            "thread_start",
            "thread_response",
            "thread",
            "planned_child",
            "runtime_child",
            "pool_contract",
            "control_contract",
            "predispatch_proof",
            "adapter",
        }
        if set(boundary) != expected_fields:
            raise AppServerError("effective-boundary-malformed")
        start = boundary.get("thread_start")
        response = boundary.get("thread_response")
        thread = boundary.get("thread")
        planned = boundary.get("planned_child")
        child = boundary.get("runtime_child")
        pool = boundary.get("pool_contract")
        control = boundary.get("control_contract")
        proof = boundary.get("predispatch_proof")
        adapter = boundary.get("adapter")
        if any(
            not isinstance(value, Mapping)
            for value in (
                start,
                response,
                thread,
                planned,
                child,
                pool,
                control,
                proof,
                adapter,
            )
        ):
            raise AppServerError("effective-boundary-malformed")
        request = start.get("request")
        trusted_response = start.get("response")
        if not isinstance(request, Mapping) or not isinstance(
            trusted_response, Mapping
        ):
            raise AppServerError("effective-boundary-thread-start-malformed")
        if trusted_response != response or trusted_response.get("thread") != thread:
            raise AppServerError("effective-boundary-thread-start-response-mismatch")
        worktree = str(self.worktree)
        requested_model = getattr(self.server, "requested_model", EXACT_MODEL)
        provider = trusted_response.get("modelProvider")
        request_provider = request.get("modelProvider")
        expected_sandbox_type = "workspaceWrite" if self.mutable else "readOnly"
        expected_sandbox_request = "workspace-write" if self.mutable else "read-only"
        sandbox = trusted_response.get("sandbox")
        if (
            request.get("model") != requested_model
            or request.get("allowProviderModelFallback") is not False
            or request.get("sandbox") != expected_sandbox_request
            or request.get("approvalPolicy") != "never"
            or request.get("cwd") != worktree
            or request.get("runtimeWorkspaceRoots") != [worktree]
            or trusted_response.get("model") != requested_model
            or not isinstance(provider, str)
            or not provider.strip()
            or request_provider not in (None, provider)
            or trusted_response.get("approvalPolicy") != "never"
            or trusted_response.get("cwd") != worktree
            or trusted_response.get("runtimeWorkspaceRoots") != [worktree]
            or not isinstance(sandbox, Mapping)
            or sandbox.get("type") != expected_sandbox_type
            or sandbox.get("networkAccess", False) is not False
            or thread.get("id") != self.thread_id
            or type(thread.get("turns")) is not list
            or thread.get("turns") != []
        ):
            raise AppServerError("effective-boundary-thread-start-mismatch")
        sandbox_roots = sandbox.get("writableRoots", [])
        if type(sandbox_roots) is not list or any(
            not isinstance(root, str) for root in sandbox_roots
        ):
            raise AppServerError("effective-boundary-writable-roots-malformed")
        try:
            explicit_roots = [
                str(_canonical_controller_workdir(root)) for root in sandbox_roots
            ]
        except AppServerError as exc:
            raise AppServerError("effective-boundary-writable-root-invalid") from exc
        effective_roots = sorted(
            set(([worktree] if self.mutable else []) + explicit_roots)
        )
        if (
            explicit_roots != sorted(set(explicit_roots))
            or effective_roots != adapter.get("writable_roots")
            or (not self.mutable and explicit_roots)
        ):
            raise AppServerError("effective-boundary-writable-root-mismatch")
        if (
            adapter.get("requested_model") != requested_model
            or adapter.get("prompt") != self.prompt
            or adapter.get("worktree") != worktree
            or adapter.get("mutable") is not self.mutable
            or adapter.get("return_contract")
            != {
                "expected_token": self.expected_token,
                "expected_mutation": self.expected_mutation,
                "expected_tool_trace": self.expected_tool_trace,
                "read_only_command_authority": self.read_only_command_authority,
                "completion_evidence_policy": self.completion_evidence_policy,
            }
            or adapter.get("prompt_preflight") != self.prompt_preflight
            or adapter.get("tool_policy") != self.tool_policy
            or adapter.get("tool_surface") != self.preflight_tool_surface
            or adapter.get("workspace_baseline_sha256")
            != self._workspace_baseline_sha256
        ):
            raise AppServerError("effective-boundary-adapter-mismatch")
        common_fields = (
            "child_id",
            "packet_id",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "packet_sha256",
            "lease_id",
            "isolation_class",
            "completion_evidence_policy",
            "tool_policy",
            "declared_write_paths",
            "integration_target_paths",
        )
        if any(planned.get(field) != child.get(field) for field in common_fields):
            raise AppServerError("effective-boundary-planned-child-mismatch")
        if (
            planned.get("session_id") != self.thread_id
            or planned.get("agent_id") != self.thread_id
            or planned.get("worktree") != worktree
            or planned.get("prompt") != self.prompt
            or planned.get("prompt_preflight") != self.prompt_preflight
            or planned.get("tool_surface") != self.preflight_tool_surface
            or planned.get("completion_evidence_policy")
            != self.completion_evidence_policy
            or planned.get("tool_policy") != self.tool_policy
            or child.get("worktree") != worktree
            or child.get("session_id") != self.thread_id
            or child.get("agent_id") != self.thread_id
        ):
            raise AppServerError("effective-boundary-child-identity-mismatch")
        expected_paths = [self.expected_mutation] if self.expected_mutation else []
        hard_budget = planned.get("hard_budget")
        if (
            planned.get("declared_write_paths") != expected_paths
            or planned.get("integration_target_paths") != expected_paths
            or child.get("declared_write_paths") != expected_paths
            or child.get("integration_target_paths") != expected_paths
            or child.get("isolation_class")
            != ("mutable-isolated" if self.mutable else "read-only-shared")
            or not isinstance(hard_budget, Mapping)
            or set(hard_budget)
            != {
                "tool_calls",
                "runtime_seconds",
                "compactions",
                "full_suite_runs",
                "mutations",
            }
            or any(
                type(value) is not int or value < 0
                for value in hard_budget.values()
            )
        ):
            raise AppServerError("effective-boundary-scope-mismatch")
        if (
            not self._sealed_mapping_matches(control, "contract_sha256")
            or control.get("agent_id") != self.thread_id
            or control.get("state_file") != child.get("state_file")
            or control.get("control_turn_id") != child.get("control_turn_id")
            or control.get("task_sha256") != sha256_text(self.prompt)
            or control.get("poll_interval_ms") != POOL_POLL_INTERVAL_MS
        ):
            raise AppServerError("effective-boundary-control-contract-mismatch")
        if not self._sealed_mapping_matches(pool, "contract_sha256"):
            raise AppServerError("effective-boundary-pool-contract-invalid")
        pool_children = pool.get("children")
        matches = (
            [item for item in pool_children if item.get("child_id") == child.get("child_id")]
            if isinstance(pool_children, list)
            and all(isinstance(item, Mapping) for item in pool_children)
            else []
        )
        if len(matches) != 1:
            raise AppServerError("effective-boundary-pool-child-missing")
        pool_child = matches[0]
        pool_fields = (
            "child_id",
            "packet_id",
            "attempt_nonce",
            "session_id",
            "agent_id",
            "control_turn_id",
            "packet_sha256",
            "state_file",
            "isolation_class",
            "completion_evidence_policy",
            "tool_policy",
            "declared_write_paths",
            "integration_target_paths",
            "lease_id",
        )
        worktree_identity = pool_child.get("worktree_identity")
        if (
            any(pool_child.get(field) != child.get(field) for field in pool_fields)
            or pool_child.get("control_contract_sha256")
            != control.get("contract_sha256")
            or not isinstance(worktree_identity, Mapping)
            or worktree_identity.get("canonical_path_sha256")
            != sha256_text(worktree)
        ):
            raise AppServerError("effective-boundary-pool-child-mismatch")
        if (
            proof.get("accepted") is not True
            or proof.get("decision") != "accept"
            or proof.get("stage") != "pre-dispatch"
            or proof.get("contract_sha256") != pool.get("contract_sha256")
            or not self._sealed_mapping_matches(proof, "result_sha256")
        ):
            raise AppServerError("effective-boundary-predispatch-proof-mismatch")

    def bind_effective_boundary(
        self,
        *,
        planned_child: Mapping[str, Any],
        runtime_child: Mapping[str, Any],
        pool_contract: Mapping[str, Any],
        control_contract: Mapping[str, Any],
        predispatch_proof: Mapping[str, Any],
        writable_roots: Iterable[Path | str],
    ) -> None:
        """Bind all controller-owned pre-turn evidence exactly once."""

        with self._boundary_lock:
            if self._effective_boundary_sources is not None:
                raise AppServerError("effective-boundary-already-bound")
            roots = sorted(
                {str(_canonical_controller_workdir(root)) for root in writable_roots}
            )
            self._effective_boundary_sources = {
                "planned_child": planned_child,
                "runtime_child": runtime_child,
                "pool_contract": pool_contract,
                "control_contract": control_contract,
                "predispatch_proof": predispatch_proof,
                "writable_roots": roots,
            }
            try:
                boundary = self._current_effective_boundary()
                self._validate_effective_boundary(boundary)
            except BaseException:
                self._effective_boundary_sources = None
                raise
            self._effective_boundary = copy.deepcopy(boundary)
            self._effective_boundary_sha256 = canonical_sha256(boundary)

    def bind_workspace_baseline(self, baseline: Mapping[str, Any]) -> None:
        """Bind one complete controller-owned pre-dispatch workspace baseline."""

        with self._boundary_lock:
            if self._workspace_baseline is not None:
                raise AppServerError("workspace-baseline-already-bound")
            if (
                self._effective_boundary_sources is not None
                or self._boundary_phase != "pre-dispatch"
                or self._effective_boundary_arm_in_progress
                or self._effective_boundary_armed
                or self._effective_boundary_send_reserved
            ):
                raise AppServerError("workspace-baseline-binding-too-late")
            value = copy.deepcopy(dict(baseline))
            caps = value.get("caps")
            if (
                value.get("workspace_evidence_type")
                != "content-aware-baseline"
                or value.get("version") != 2
                or value.get("baseline_complete") is not True
                or value.get("incomplete") is not False
                or value.get("include_untracked") is not True
                or value.get("tracked_paths_complete") is not True
                or not isinstance(value.get("tracked_status"), list)
                or not isinstance(value.get("tracked_paths"), list)
                or not isinstance(value.get("preexisting_dirty_paths"), list)
                or not isinstance(value.get("content_fingerprints"), Mapping)
                or not isinstance(value.get("allowed_paths"), list)
                or not isinstance(caps, Mapping)
                or type(caps.get("max_files")) is not int
                or caps["max_files"] < 1
                or type(caps.get("max_bytes")) is not int
                or caps["max_bytes"] < 0
                or type(caps.get("max_seconds")) not in {int, float}
                or caps["max_seconds"] <= 0
            ):
                raise AppServerError("workspace-baseline-invalid")
            try:
                baseline_root = Path(str(value.get("cwd", ""))).resolve()
            except (OSError, RuntimeError, ValueError) as exc:
                raise AppServerError("workspace-baseline-root-invalid") from exc
            if baseline_root != self.worktree:
                raise AppServerError("workspace-baseline-root-mismatch")
            self._workspace_baseline = value
            self._workspace_baseline_sha256 = canonical_sha256(value)

    def _require_effective_boundary(
        self,
        *,
        current_tool_surface: Mapping[str, Any] | None = None,
    ) -> None:
        if self._effective_boundary is None or self._effective_boundary_sha256 is None:
            raise AppServerError("effective-boundary-unbound")
        if canonical_sha256(self._effective_boundary) != self._effective_boundary_sha256:
            raise AppServerError("effective-boundary-receipt-mutated")
        current = self._current_effective_boundary()
        self._validate_effective_boundary(current)
        if current != self._effective_boundary:
            raise AppServerError("effective-boundary-source-mutated")
        if current_tool_surface is not None:
            surface = dict(current_tool_surface)
            surface_errors = validate_tool_surface_snapshot(
                surface, self.tool_policy
            )
            if surface_errors:
                raise AppServerError(
                    "effective-boundary-tool-surface-invalid:"
                    + ";".join(surface_errors)
                )
            try:
                require_unchanged_tool_surface(
                    self.preflight_tool_surface, surface
                )
            except NativeToolIsolationError as exc:
                raise AppServerError(str(exc)) from exc

    def _timed(self, name: str, action: Callable[[], Any]) -> Any:
        started = time.monotonic_ns()
        try:
            return action()
        finally:
            elapsed = (time.monotonic_ns() - started) / 1_000_000
            self.callback_latencies.setdefault(name, []).append(elapsed)

    def _record_callback_subphase(self, name: str, started_ns: int) -> None:
        elapsed = max(0, self._monotonic_ns() - started_ns) / 1_000_000
        self.callback_subphase_latencies.setdefault(name, []).append(elapsed)

    def arm(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if (
                    self._effective_boundary_arm_in_progress
                    or self._effective_boundary_armed
                ):
                    raise AppServerError("effective-boundary-already-armed")
                self._effective_boundary_arm_in_progress = True
                try:
                    current_surface = dict(self._tool_surface_reader())
                    self._require_effective_boundary(
                        current_tool_surface=current_surface
                    )
                    if self.thread_response.get("model") != getattr(
                        self.server, "requested_model", EXACT_MODEL
                    ):
                        raise AppServerError("prearmed-thread-model-mismatch")
                    if (
                        self.thread.get("id") != self.thread_id
                        or self.thread.get("turns")
                    ):
                        raise AppServerError("prearmed-thread-is-not-fresh")
                except BaseException:
                    self._effective_boundary_arm_in_progress = False
                    raise
                self._effective_boundary_arm_in_progress = False
                self._effective_boundary_armed = True
            return {"ack": "armed"}

        return self._timed("arm", action)

    def send_input(self, *, message: str, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self._require_campaign_live_route()
            with self._boundary_lock:
                if self._effective_boundary_arm_in_progress:
                    raise AppServerError("effective-boundary-arm-in-progress")
                if not self._effective_boundary_armed:
                    raise AppServerError("effective-boundary-not-armed")
                if self._effective_boundary_send_reserved:
                    raise AppServerError("effective-boundary-send-not-one-shot")
                self._effective_boundary_send_reserved = True
                self._require_effective_boundary()
                if message != self.prompt:
                    raise AppServerError("turn-prompt-binding-mismatch")
                subphase_started = self._monotonic_ns()
                try:
                    current_prompt_preflight = require_prompt_preflight(
                        message, self.tool_policy
                    )
                except NativeToolIsolationError as exc:
                    raise AppServerError(str(exc)) from exc
                finally:
                    self._record_callback_subphase(
                        "send_input.prompt_preflight", subphase_started
                    )
                if current_prompt_preflight != self.prompt_preflight:
                    raise AppServerError("prompt-preflight-changed-before-dispatch")
                subphase_started = self._monotonic_ns()
                try:
                    current_surface = dict(self._tool_surface_reader())
                finally:
                    self._record_callback_subphase(
                        "send_input.tool_surface_capture", subphase_started
                    )
                subphase_started = self._monotonic_ns()
                try:
                    surface_errors = validate_tool_surface_snapshot(
                        current_surface, self.tool_policy
                    )
                    if surface_errors:
                        raise AppServerError(
                            "pre-dispatch-tool-surface-invalid:"
                            + ";".join(surface_errors)
                        )
                    try:
                        require_unchanged_tool_surface(
                            self.preflight_tool_surface, current_surface
                        )
                    except NativeToolIsolationError as exc:
                        raise AppServerError(str(exc)) from exc
                finally:
                    self._record_callback_subphase(
                        "send_input.tool_surface_validation", subphase_started
                    )
                self.pre_dispatch_tool_surface = current_surface
                # The surface reader is a reentrant callback. Rebind all
                # controller-owned identity and scope inputs after it returns,
                # immediately before irrevocably attempting the RPC.
                self._require_effective_boundary(
                    current_tool_surface=current_surface
                )
                lock_started = self._monotonic_ns()
                self._record_callback_subphase(
                    "send_input.boundary_lock_wait", lock_started
                )
                # Revoke the pre-dispatch allowance before the RPC. Failed or
                # ambiguous submission can never recover it from a missing id.
                self._boundary_phase = "dispatch-attempted"
                subphase_started = self._monotonic_ns()
                try:
                    self._require_campaign_live_route()
                    turn, _latency = self.server.start_turn(self.thread_id, message)
                finally:
                    self._record_callback_subphase(
                        "send_input.turn_start_rpc", subphase_started
                    )
                subphase_started = self._monotonic_ns()
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
                self._record_callback_subphase(
                    "send_input.acknowledgement_binding", subphase_started
                )
                return {"submission_id": self.turn_id}

        return self._timed("send_input", action)

    def _require_campaign_live_route(self) -> None:
        # Omission keeps the campaign contract; noncampaign constructors select
        # False explicitly and retain their own N1/preview admission contract.
        if self.campaign_live_route:
            live_availability.require_campaign_live()
            live_availability.require_pool_live()
            live_availability.require_n1_live()

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
                    "control_turn_id": self.control_turn_identity(),
                },
            )
            return {"ack": "dispatched"}

        return self._timed("mark_dispatched", action)

    def check(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            self.check_count += 1
            boundary = self._capture_trusted_boundary(allow_pending=True)
            if boundary.get("available") is True:
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = (
                    thread.get("path") or self.reported_session_path
                )
            status = turn_status(self.last_thread, self.turn_id)
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            if durable_status in {"completed", "failed", "interrupted"}:
                self._durable_terminal_status = str(durable_status)
            terminal = durable_status in {
                "completed",
            }
            trace_observation = self._exact_tool_trace_observation(
                boundary.get("trusted_tool_receipts", []),
                terminal=terminal,
            )
            if (
                trace_observation["required"]
                and trace_observation["mismatch"]
            ):
                return {"decision": "interrupt"}
            if self._observe_forbidden_tool_activity(boundary):
                return {"decision": "interrupt"}
            if durable_status == "completed":
                _message_hash, matches = self.final_message_observation()
                if not matches:
                    return {"decision": "control-lost"}
                if self._known_completion_evidence_missing(boundary):
                    return {"decision": "interrupt"}
                return {"decision": "complete"}
            if durable_status == "interrupted":
                return {"decision": "interrupt"}
            if durable_status == "failed":
                return {"decision": "control-lost"}
            now_ns = self._monotonic_ns()
            if status in {"completed", "failed", "interrupted"}:
                if self._projection_started_ns is None:
                    self._projection_started_ns = now_ns
                elif (
                    now_ns - self._projection_started_ns
                    > int(PROVISIONAL_TERMINAL_GRACE_SECONDS * 1_000_000_000)
                ):
                    return {"decision": "control-lost"}
            elif status in {"inProgress", "in_progress", "running"}:
                if boundary.get("available") is True:
                    self._projection_started_ns = None
            if (
                self.force_interrupt_after_checks is not None
                and self.check_count >= self.force_interrupt_after_checks
            ):
                return {"decision": "interrupt"}
            if status in {
                "inProgress",
                "in_progress",
                "running",
                "completed",
                "failed",
                "interrupted",
                None,
            }:
                return {"decision": "continue"}
            return {"decision": "control-lost"}

        return self._timed("check", action)

    def _observe_forbidden_tool_activity(
        self, boundary: Mapping[str, Any]
    ) -> list[dict[str, str]]:
        trusted_activity = list(boundary.get("trusted_tool_activity", []))
        authority_observation = self._read_only_command_authority_observation(
            boundary.get("trusted_tool_authority_receipts", []),
            terminal=(
                isinstance(boundary.get("terminal_event"), Mapping)
                and boundary["terminal_event"].get("status")
                in {"completed", "failed", "interrupted"}
            ),
        )
        if authority_observation["required"] and authority_observation["mismatch"]:
            trusted_activity.append(
                {
                    "tool": "security_violation.read_only_command_authority",
                    "evidence_sha256": canonical_sha256(
                        {
                            "expected_sha256": authority_observation[
                                "expected_sha256"
                            ],
                            "observed_sha256": authority_observation[
                                "observed_sha256"
                            ],
                            "reason": authority_observation["reason"],
                        }
                    ),
                }
            )
        if (
            self.tool_policy["workload_class"] == "operative"
            and self.tool_policy["enforcement_mode"]
            == "trusted-detect-and-contain"
        ):
            item_types = [
                str(item.get("type"))
                for item in turn_items(self.last_thread, self.turn_id)
                if item.get("type")
            ]
            projected_tool_calls = sum(
                item_type in OPERATIVE_ITEM_TYPES for item_type in item_types
            )
            terminal_event = boundary.get("terminal_event")
            durable_status = (
                terminal_event.get("status")
                if isinstance(terminal_event, Mapping)
                else None
            )
            trusted_tool_calls = int(boundary.get("trusted_tool_calls", 0))
            terminal = durable_status in {
                "completed",
                "failed",
                "interrupted",
            }
            for item in list(trusted_activity):
                if (
                    terminal
                    and isinstance(item, Mapping)
                    and item.get("pairing_status") == "unpaired"
                    and item.get("result_kind") == "unpaired-call"
                ):
                    reported_tool = str(item.get("tool") or "unknown")
                    trusted_activity.append(
                        {
                            "tool": (
                                "telemetry_anomaly."
                                + (
                                    reported_tool
                                    if re.fullmatch(
                                        r"[a-z][a-z0-9_.:-]{0,96}",
                                        reported_tool,
                                    )
                                    else "unknown"
                                )
                            ),
                            "evidence_sha256": canonical_sha256(
                                {
                                    "reported_activity": dict(item),
                                    "reason": "terminal-unpaired-call",
                                }
                            ),
                        }
                    )
            if (
                terminal
                and projected_tool_calls > trusted_tool_calls
            ):
                trusted_activity.append(
                    {
                        "tool": "telemetry_anomaly.missing_call_receipt",
                        "evidence_sha256": canonical_sha256(
                            {
                                "thread_id": self.thread_id,
                                "turn_id": self.turn_id,
                                "projected_tool_calls": projected_tool_calls,
                                "trusted_tool_calls": trusted_tool_calls,
                            }
                        ),
                    }
                )
        try:
            observed = forbidden_tool_activity(
                trusted_activity, self.tool_policy
            )
        except NativeToolIsolationError as exc:
            raise AppServerError(str(exc)) from exc
        combined = {
            (item["tool"], item["evidence_sha256"]): item
            for item in [*self._forbidden_tool_activity, *observed]
        }
        self._forbidden_tool_activity = [
            combined[key] for key in sorted(combined)
        ]
        return list(self._forbidden_tool_activity)

    def _read_only_command_authority_observation(
        self,
        observed_value: Any,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        expected = self.read_only_command_authority
        observed = (
            [dict(item) for item in observed_value]
            if isinstance(observed_value, list)
            and all(isinstance(item, Mapping) for item in observed_value)
            else []
        )
        observed_sha256 = canonical_sha256(observed)
        if expected is None:
            return {
                "required": False,
                "status": "not-required",
                "mismatch": False,
                "satisfied": True,
                "reason": None,
                "expected_sha256": None,
                "observed_sha256": observed_sha256,
            }
        reason: str | None = None
        pending_sessions: dict[int, str] = {}
        for sequence, observed_step in enumerate(observed):
            if sequence >= len(expected):
                reason = "extra-call"
                break
            expected_step = expected[sequence]
            if observed_step.get("sequence") != sequence:
                reason = f"step-{sequence}-sequence-mismatch"
                break
            if observed_step.get("tool") != expected_step["tool"]:
                reason = f"step-{sequence}-tool-mismatch"
                break
            if (
                observed_step.get("raw_pairing_status") != "exact"
                or observed_step.get("raw_receipt_alignment") != "exact"
                or observed_step.get("call_id_sha256") is None
            ):
                reason = f"step-{sequence}-raw-receipt-binding-invalid"
                break
            if expected_step["tool"] == "exec_command":
                allowed_hashes = {
                    canonical_argument_hash(item)
                    for item in expected_step["argument_alternatives"]
                }
                if observed_step.get("canonical_argument_hash") not in allowed_hashes:
                    reason = f"step-{sequence}-canonical-argument-mismatch"
                    break
            else:
                allowed_hashes = {
                    canonical_argument_hash(item)
                    for item in expected_step["argument_alternatives"]
                }
                if observed_step.get("continuation_argument_hash") not in allowed_hashes:
                    reason = f"step-{sequence}-continuation-argument-mismatch"
                    break
                parent = expected_step["continuation_of"]
                if (
                    not isinstance(parent, int)
                    or pending_sessions.get(parent) is None
                    or observed_step.get("operation_session_id_sha256")
                    != pending_sessions[parent]
                ):
                    reason = f"step-{sequence}-pending-parent-mismatch"
                    break
            pairing_status = observed_step.get("pairing_status")
            result_kind = observed_step.get("result_kind")
            if pairing_status == "unpaired":
                if terminal or sequence != len(observed) - 1:
                    reason = f"step-{sequence}-unpaired"
                    break
                continue
            if pairing_status != "paired":
                reason = f"step-{sequence}-pairing-mismatch"
                break
            if result_kind in {"paired-pending", "paired-deferred"}:
                session_sha256 = observed_step.get("operation_session_id_sha256")
                if session_sha256 is None:
                    reason = f"step-{sequence}-pending-session-missing"
                    break
                if expected_step["tool"] == "exec_command":
                    pending_sessions[sequence] = session_sha256
            elif result_kind not in {"paired-success", "paired-failure"}:
                reason = f"step-{sequence}-result-invalid"
                break
        complete = reason is None and len(observed) == len(expected)
        successful = complete and all(
            item.get("pairing_status") == "paired"
            and item.get("result_kind") in {"paired-success", "paired-deferred"}
            and (
                item.get("exit_code") == 0
                or item.get("result_kind") == "paired-deferred"
            )
            for item in observed
        )
        if reason is None and terminal and not complete:
            reason = "terminal-cardinality-mismatch"
        mismatch = reason is not None
        return {
            "required": True,
            "status": (
                "mismatch"
                if mismatch
                else "satisfied"
                if successful and terminal
                else "authorized-failure"
                if complete and terminal
                else "pending"
            ),
            "mismatch": mismatch,
            "satisfied": successful and terminal,
            "reason": reason,
            "expected_sha256": self.read_only_command_authority_sha256,
            "observed_sha256": observed_sha256,
        }

    def control_turn_identity(self) -> str:
        """Identity fixed by the controller before any dispatch evidence write."""
        return CONTROL_TURN_ID

    def final_message_observation(self) -> tuple[str | None, bool]:
        """Controller-selected final contract; token canaries retain exact equality.

        Product adapters may override this with strict native-return validation
        bound before arming. Both supervision and evidence use this one method;
        no post-turn replacement of expected_token is permitted.
        """
        return final_message_hash_and_match(
            self.last_thread, self.turn_id, self.expected_token)

    def _exact_tool_trace_observation(
        self,
        observed_value: Any,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        expected = self.expected_tool_trace
        observed = (
            [dict(item) for item in observed_value]
            if isinstance(observed_value, list)
            and all(isinstance(item, Mapping) for item in observed_value)
            else []
        )
        observed_sha256 = canonical_sha256(observed)
        if expected is None:
            return {
                "required": False,
                "status": "not-required",
                "mismatch": False,
                "satisfied": True,
                "reason": None,
                "expected_sha256": None,
                "observed_sha256": observed_sha256,
            }
        reason: str | None = None
        for sequence, observed_step in enumerate(observed):
            if sequence >= len(expected):
                reason = "extra-call"
                break
            expected_step = expected[sequence]
            for field in (
                "sequence",
                "tool",
                "action_class",
                "determinable_target_paths",
            ):
                if observed_step.get(field) != expected_step[field]:
                    reason = f"step-{sequence}-{field}-mismatch"
                    break
            if reason is not None:
                break
            if (
                observed_step.get("canonical_argument_hash")
                not in expected_step["canonical_argument_hashes"]
            ):
                reason = f"step-{sequence}-canonical-argument-mismatch"
                break
            pairing_status = observed_step.get("pairing_status")
            if pairing_status == "unpaired":
                if terminal or sequence != len(observed) - 1:
                    reason = f"step-{sequence}-unpaired"
                continue
            if pairing_status != expected_step["pairing_status"]:
                reason = f"step-{sequence}-pairing-mismatch"
                break
            if (
                observed_step.get("result_kind")
                != expected_step["result_kind"]
                or observed_step.get("exit_code")
                != expected_step["exit_code"]
            ):
                reason = f"step-{sequence}-result-mismatch"
                break
        trace_complete = (
            reason is None
            and len(observed) == len(expected)
            and all(
                observed_step.get("pairing_status") == "paired"
                and observed_step.get("result_kind") == "paired-success"
                and observed_step.get("exit_code") == 0
                for observed_step in observed
            )
        )
        if reason is None and terminal and not trace_complete:
            reason = "terminal-cardinality-mismatch"
        mismatch = reason is not None
        satisfied = trace_complete and terminal
        return {
            "required": True,
            "status": (
                "mismatch"
                if mismatch
                else "satisfied"
                if satisfied
                else "pending"
            ),
            "mismatch": mismatch,
            "satisfied": satisfied,
            "reason": reason,
            "expected_sha256": self.expected_tool_trace_sha256,
            "observed_sha256": observed_sha256,
        }

    def _known_completion_evidence_missing(
        self,
        boundary: Mapping[str, Any],
    ) -> bool:
        """Detect terminal evidence deficits knowable without another callback."""

        policy = self.completion_evidence_policy
        completed_calls = int(boundary.get("trusted_completed_tool_calls", 0))
        if completed_calls < policy["minimum_tool_calls"]:
            return True
        required = policy["required_evidence"]
        if "trusted-tool-call" in required["predicates"] and completed_calls < 1:
            return True
        observed_hashes = set(boundary.get("trusted_tool_evidence_sha256", []))
        if not set(required["sha256"]).issubset(observed_hashes):
            return True
        trace_observation = self._exact_tool_trace_observation(
            boundary.get("trusted_tool_receipts", []),
            terminal=True,
        )
        return (
            trace_observation["required"]
            and not trace_observation["satisfied"]
        )

    def interrupt(self, **_kwargs: Any) -> dict[str, str]:
        def action() -> dict[str, str]:
            with self._boundary_lock:
                if self.turn_id is None:
                    raise AppServerError("interrupt-turn-id-missing")
                if self._durable_terminal_status in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    return {"ack": "already-terminal"}
                # Interrupt wins locally before the control RPC is attempted;
                # unavailable telemetry can never be accepted after this point.
                self._boundary_phase = "interrupt-requested"
                try:
                    self.server.interrupt_turn(self.thread_id, self.turn_id)
                except AppServerRpcError:
                    # A terminal transition may win the race after the last
                    # check but before turn/interrupt. Adjudicate the trusted
                    # boundary once; never retry the interrupt request.
                    boundary = self._capture_trusted_boundary(
                        allow_pending=True
                    )
                    terminal_event = boundary.get("terminal_event")
                    durable_status = (
                        terminal_event.get("status")
                        if isinstance(terminal_event, Mapping)
                        else None
                    )
                    if durable_status in {
                        "completed",
                        "failed",
                        "interrupted",
                    }:
                        self._durable_terminal_status = str(durable_status)
                        return {"ack": "already-terminal"}
                    raise
                self.interrupted = True
                return {"ack": "interrupt-requested"}

        return self._timed("interrupt", action)

    def _prepare_staged_archive(self) -> None:
        deadline = time.monotonic() + STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS
        while True:
            with self._boundary_lock:
                if self._durable_terminal_status in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    self._bind_archive_terminal_evidence_locked()
                    return
                thread, _latency = self.server.read_thread(self.thread_id)
                self.last_thread = thread
                self.reported_session_path = (
                    thread.get("path") or self.reported_session_path
                )
                boundary = self._capture_trusted_boundary(allow_pending=True)
                terminal_event = boundary.get("terminal_event")
                durable_status = (
                    terminal_event.get("status")
                    if isinstance(terminal_event, Mapping)
                    else None
                )
                if durable_status in {"completed", "failed", "interrupted"}:
                    self._durable_terminal_status = str(durable_status)
                    self._bind_archive_terminal_evidence_locked()
                    return
                if boundary.get("available") is not True and self.interrupted:
                    # Preserve the fail-closed containment path when an accepted
                    # interrupt cannot be materialized in session telemetry.
                    return
            if time.monotonic() >= deadline:
                raise AppServerError(
                    f"archive-before-durable-terminal:{durable_status}"
                )
            time.sleep(STAGED_ARCHIVE_TERMINAL_POLL_SECONDS)

    def _bind_archive_terminal_evidence_locked(self) -> None:
        if (
            self._durable_terminal_status
            not in {"completed", "failed", "interrupted"}
            or self.turn_id is None
            or self._session_source_identity_sha256 is None
            or self._session_boundary_baseline is None
        ):
            raise AppServerError("archive-terminal-evidence-incomplete")
        self._archive_terminal_evidence_sha256 = canonical_sha256(
            {
                "thread_id": self.thread_id,
                "turn_id": self.turn_id,
                "durable_terminal_status": self._durable_terminal_status,
                "session_source_identity_sha256": (
                    self._session_source_identity_sha256
                ),
                "terminal_boundary": dict(self._session_boundary_baseline),
            }
        )

    def _record_staged_archive_containment(self, _latency_ms: float) -> None:
        evidence_sha256 = self._archive_terminal_evidence_sha256
        recorder = getattr(
            self.server,
            "record_terminal_archive_containment",
            None,
        )
        if evidence_sha256 is None or not callable(recorder):
            return
        if self.turn_id is None:
            raise AppServerError("archive-terminal-turn-id-missing")
        recorder(
            self.thread_id,
            self.turn_id,
            terminal_evidence_sha256=evidence_sha256,
        )

    def finalize(self, *, control_action: str, **_kwargs: Any) -> dict[str, Any]:
        def action() -> dict[str, Any]:
            write_private_artifact(
                self.record_dir / f"{self.thread_id}-finalize-{control_action}.json",
                {
                    "thread_id": self.thread_id,
                    "turn_id": self.turn_id,
                    "control_action": control_action,
                    "control_turn_id": self.control_turn_identity(),
                },
            )
            if control_action not in {
                "worker-completed",
                "interrupt-confirmed",
            }:
                return {"ack": control_action}
            with self._boundary_lock:
                if self._staged_archive is not None:
                    raise AppServerError("staged-archive-already-bound")
                self._boundary_phase = "closing"
                staged_archive = StagedThreadArchive(
                    self.server,
                    self.thread_id,
                    prepare=self._prepare_staged_archive,
                    after_archive=self._record_staged_archive_containment,
                )
                self._staged_archive = staged_archive
            staged_archive.start()
            self._archive_observation_deadline_ns = self._monotonic_ns() + int(
                STAGED_ARCHIVE_TERMINAL_TIMEOUT_SECONDS * 1_000_000_000
            )
            return {
                "ack": control_action,
                "close_wait_required": True,
            }

        return self._timed("finalize", action)

    def close(self, **_kwargs: Any) -> dict[str, Any]:
        def action() -> dict[str, Any]:
            if self._staged_archive is None:
                raise AppServerError("close-before-staged-archive")
            if not self._staged_archive.completion_ready():
                return {
                    "ack": "close-pending",
                    "close_wait_required": True,
                }
            self._staged_archive.require_complete(timeout_seconds=0.0)
            if (
                self._session_source_identity_sha256 is None
                and self._session_boundary_baseline is None
            ):
                # An interrupted, never-materialized boundary has no file to
                # relocate. The accepted archive RPC and same-process
                # containment proof remain its only truthful closure evidence.
                self.archived = True
                return {"ack": "closed"}
            try:
                located = locate_unique_session(
                    self.server.codex_home,
                    self.thread_id,
                )
            except NativeSessionBoundaryError as exc:
                if (
                    str(exc) == "trusted session file is missing"
                    and self._archive_observation_deadline_ns is not None
                    and self._monotonic_ns()
                    < self._archive_observation_deadline_ns
                ):
                    return {
                        "ack": "close-pending",
                        "close_wait_required": True,
                    }
                raise AppServerError(
                    f"staged-archive-observation-invalid:{exc}"
                ) from exc
            if located.store != "archived_sessions":
                if (
                    self._archive_observation_deadline_ns is not None
                    and self._monotonic_ns()
                    < self._archive_observation_deadline_ns
                ):
                    return {
                        "ack": "close-pending",
                        "close_wait_required": True,
                    }
                raise AppServerError("staged-archive-relocation-not-observed")
            if (
                self._session_source_identity_sha256 is not None
                and located.source_identity_sha256
                != self._session_source_identity_sha256
            ):
                raise AppServerError("staged-archive-source-identity-changed")
            self.reported_session_path = str(located.path)
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
        if self._workspace_baseline is not None:
            if (
                canonical_sha256(self._workspace_baseline)
                != self._workspace_baseline_sha256
            ):
                raise AppServerError("workspace-baseline-mutated")
            baseline = copy.deepcopy(self._workspace_baseline)
            caps = baseline["caps"]
            current = capture_workspace_baseline(
                self.worktree,
                allowed_paths=list(baseline["allowed_paths"]),
                include_untracked=True,
                max_files=int(caps["max_files"]),
                max_bytes=int(caps["max_bytes"]),
                max_seconds=float(caps["max_seconds"]),
            )
            report = compare_workspace_baseline(
                baseline,
                current,
                allowed_paths=list(baseline["allowed_paths"]),
            )
            if report.get("incomplete") or report.get("attribution_ambiguous"):
                raise AppServerError("workspace-baseline-comparison-incomplete")
            mutations = report.get("mutations")
            if not isinstance(mutations, list) or any(
                not isinstance(item, Mapping)
                or not isinstance(item.get("path"), str)
                or not item["path"]
                for item in mutations
            ):
                raise AppServerError("workspace-baseline-comparison-invalid")
            return sorted({str(item["path"]) for item in mutations})
        # No bound baseline: report dirty paths from an inert capture, never
        # from git status, which would run the worktree's own config.
        state = capture_tracked_workspace_state(
            self.worktree, include_untracked=True, include_content_fingerprints=False
        )
        if state.get("error") or state.get("incomplete"):
            raise AppServerError("workspace-status-incomplete")
        if not cleanliness_established(state):
            # Empty raw status is not a clean worktree when Git conversions
            # could apply; without a bound baseline that cannot be settled.
            raise AppServerError("workspace-cleanliness-unknown")
        return sorted({status_path(line) for line in state["tracked_status"]})

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

    def _turn_started_notification_observed_locked(self) -> bool:
        self._pending_window_is_open_locked()
        for message in self.server.notifications(self.thread_id, "turn/started"):
            params = (
                message.get("params")
                if isinstance(message.get("params"), Mapping)
                else {}
            )
            turn = params.get("turn") if isinstance(params.get("turn"), Mapping) else {}
            if turn.get("id") == self.turn_id:
                return True
        self._pending_window_is_open_locked()
        return False

    def _fresh_nonterminal_thread_locked(self) -> bool:
        self._pending_window_is_open_locked()
        # turn/start acknowledges the submission before the app-server is
        # necessarily ready to project that turn through thread/read.  The
        # exact turn/started notification is the trusted readiness witness.
        # Until it arrives, retain a nonattesting pending boundary and do not
        # race thread/read against the still-initializing turn.
        if not self._turn_started_notification_observed_locked():
            return False
        try:
            thread, _latency = self.server.read_thread(self.thread_id)
        except AppServerRpcError as exc:
            if exc.method != "thread/read" or exc.code != -32603:
                raise
            # turn/started can precede readable thread projection.  While the
            # bounded materialization window remains open, keep this state
            # nonattesting instead of turning the expected startup race into
            # control loss.
            self._pending_window_is_open_locked()
            return False
        if thread.get("id") != self.thread_id:
            raise AppServerError("post-submission-thread-read-identity-mismatch")
        self.last_thread = thread
        self.reported_session_path = thread.get("path") or self.reported_session_path
        self._pending_window_is_open_locked()
        return True

    def _registered_tool_projector(self):
        return None

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
                None,
                turn_id=self.turn_id,
                baseline=self._session_boundary_baseline,
                allow_unmaterialized=allow_unmaterialized,
                expected_source_identity_sha256=self._session_source_identity_sha256,
                tool_transport=self.tool_transport,
                expected_workdir=self.worktree,
                registered_tool_projector=self._registered_tool_projector(),
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
            if not self._fresh_nonterminal_thread_locked():
                boundary["observation_type"] = (
                    "post-submission-turn-start-pending-nonattesting"
                )
                return boundary
            boundary = session_boundary_summary(
                self.server.codex_home,
                self.thread_id,
                None,
                turn_id=self.turn_id,
                baseline=None,
                allow_unmaterialized=True,
                expected_source_identity_sha256=None,
                tool_transport=self.tool_transport,
                expected_workdir=self.worktree,
                registered_tool_projector=self._registered_tool_projector(),
            )
            if boundary["available"]:
                return self._record_complete_boundary_locked(boundary)
            if not self._fresh_nonterminal_thread_locked():
                boundary["observation_type"] = (
                    "post-submission-turn-start-pending-nonattesting"
                )
                return boundary
            boundary["observation_type"] = (
                "post-submission-unmaterialized-nonattesting-nonaccepting"
            )
            return boundary

    def _trusted_summary(self, *, allow_pending: bool = True) -> dict[str, Any]:
        boundary = self._capture_trusted_boundary(allow_pending=allow_pending)
        items = turn_items(self.last_thread, self.turn_id)
        item_types = [str(item.get("type")) for item in items if item.get("type")]
        projected_tool_calls = sum(
            item_type in OPERATIVE_ITEM_TYPES for item_type in item_types
        )
        violations = self._observe_forbidden_tool_activity(boundary)
        compactions = item_types.count("contextCompaction") + len(
            self.server.notifications(self.thread_id, "thread/compacted")
        )
        final_hash, final_matches = self.final_message_observation()
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
        requested_model = getattr(self.server, "requested_model", EXACT_MODEL)
        requested_effort = getattr(self.server, "reasoning_effort", "low")
        model_exact = (
            boundary.get("available") is True
            and models == [requested_model]
            and efforts == [requested_effort]
        )
        projected_status = turn_status(self.last_thread, self.turn_id)
        terminal_event = boundary.get("terminal_event")
        durable_status = (
            terminal_event.get("status")
            if isinstance(terminal_event, Mapping)
            else None
        )
        if durable_status in {"completed", "failed", "interrupted"}:
            self._durable_terminal_status = str(durable_status)
        trusted_tool_calls = int(boundary.get("trusted_tool_calls", 0))
        return {
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "thread_start_model": self.thread_response.get("model"),
            "thread_start_model_provider": self.thread_response.get("modelProvider"),
            "turn_status": durable_status,
            "projected_turn_status": projected_status,
            "durable_terminal_event": terminal_event,
            "session_boundary": boundary,
            "model_exact": model_exact,
            "reroute_count": len(reroutes),
            "compactions": compactions,
            "tool_calls": trusted_tool_calls,
            "completed_tool_calls": int(
                boundary.get("trusted_completed_tool_calls", 0)
            ),
            "projected_tool_calls": projected_tool_calls,
            "trusted_tool_evidence_sha256": list(
                boundary.get("trusted_tool_evidence_sha256", [])
            ),
            "trusted_tool_names": list(boundary.get("trusted_tool_names", [])),
            "trusted_tool_activity": list(
                boundary.get("trusted_tool_activity", [])
            ),
            "trusted_tool_receipts": list(
                boundary.get("trusted_tool_receipts", [])
            ),
            "trusted_tool_trace_sha256": boundary.get(
                "trusted_tool_trace_sha256"
            ),
            "trusted_tool_authority_receipts": list(
                boundary.get("trusted_tool_authority_receipts", [])
            ),
            "trusted_tool_authority_receipts_sha256": boundary.get(
                "trusted_tool_authority_receipts_sha256"
            ),
            "forbidden_tool_activity": violations,
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

    def _completion_evidence_observation(
        self,
        summary: Mapping[str, Any],
    ) -> dict[str, Any]:
        policy = self.completion_evidence_policy
        required = policy["required_evidence"]
        mutations = list(summary["workspace_mutations"])
        completed_calls = int(summary["completed_tool_calls"])
        observed_hashes = set(summary["trusted_tool_evidence_sha256"])
        observed_predicates: set[str] = set()
        terminal_event = summary.get("durable_terminal_event")
        if (
            summary["session_boundary"].get("available") is True
            and isinstance(terminal_event, Mapping)
            and terminal_event.get("status") == "completed"
        ):
            observed_predicates.add("trusted-terminal-boundary")
        if completed_calls:
            observed_predicates.add("trusted-tool-call")
        if policy["expected_mutation_mode"] == "read-only" and not mutations:
            observed_predicates.add("read-only-workspace-clean")
        if (
            policy["expected_mutation_mode"] == "mutable-isolated"
            and self.expected_mutation is not None
            and mutations == [self.expected_mutation]
        ):
            observed_predicates.add("expected-workspace-mutation")
        missing_predicates = sorted(
            set(required["predicates"]) - observed_predicates
        )
        missing_hashes = sorted(set(required["sha256"]) - observed_hashes)
        minimum_met = completed_calls >= policy["minimum_tool_calls"]
        durable_terminal_event = summary.get("durable_terminal_event")
        trace_observation = self._exact_tool_trace_observation(
            summary["trusted_tool_receipts"],
            terminal=(
                isinstance(durable_terminal_event, Mapping)
                and durable_terminal_event.get("status") == "completed"
            ),
        )
        authority_observation = self._read_only_command_authority_observation(
            summary.get("trusted_tool_authority_receipts", []),
            terminal=(
                isinstance(durable_terminal_event, Mapping)
                and durable_terminal_event.get("status") == "completed"
            ),
        )
        observable_action_required = bool(
            policy["minimum_tool_calls"]
            or set(required["predicates"])
            & {"expected-workspace-mutation", "trusted-tool-call"}
            or required["sha256"]
        )
        return {
            "minimum_tool_calls_met": minimum_met,
            "observed_predicates": sorted(observed_predicates),
            "missing_predicates": missing_predicates,
            "missing_evidence_sha256": missing_hashes,
            "observable_action_required": observable_action_required,
            "exact_tool_trace_observation": trace_observation,
            "read_only_command_authority_observation": authority_observation,
            "satisfied": (
                minimum_met
                and not missing_predicates
                and not missing_hashes
                and trace_observation["satisfied"]
                and authority_observation["satisfied"]
            ),
        }

    def _completion_evidence_reasons(
        self,
        summary: Mapping[str, Any],
        observation: Mapping[str, Any],
    ) -> list[str]:
        if (
            summary["turn_status"] != "completed"
            or not summary["expected_final_token_observed"]
        ):
            return []
        policy = self.completion_evidence_policy
        mutations = summary["workspace_mutations"]
        completed_calls = int(summary["completed_tool_calls"])
        reasons: list[str] = []
        if (
            completed_calls == 0
            and not policy["allow_zero_tool_completion"]
            and (
                policy["minimum_tool_calls"] > 0
                or "trusted-tool-call"
                in policy["required_evidence"]["predicates"]
            )
        ):
            reasons.append("zero-tool-completion")
        if (
            observation["observable_action_required"]
            and completed_calls == 0
            and not mutations
        ):
            reasons.append("premature-completion")
        if not observation["satisfied"]:
            reasons.append("required-evidence-missing")
        return reasons

    def evidence(self) -> dict[str, Any]:
        self._evidence_sequence += 1
        summary = self._trusted_summary()
        status = summary["turn_status"]
        terminal = status in {"completed", "interrupted", "failed"}
        reasons: list[str] = []
        completion_observation = self._completion_evidence_observation(
            summary
        )
        trace_observation = completion_observation[
            "exact_tool_trace_observation"
        ]
        authority_observation = completion_observation[
            "read_only_command_authority_observation"
        ]
        if status == "failed":
            reasons.append("trusted-turn-failed")
        if trace_observation["required"] and trace_observation["mismatch"]:
            reasons.append("exact-tool-trace-mismatch")
        if (
            authority_observation["required"]
            and authority_observation["mismatch"]
        ):
            reasons.append("read-only-command-authority-mismatch")
        if summary["forbidden_tool_activity"]:
            reasons.append("forbidden-tool-activity")
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
        reasons.extend(
            self._completion_evidence_reasons(summary, completion_observation)
        )
        if self.mutable:
            expected_mutations = [self.expected_mutation]
            if (
                mutations
                and (
                    self.turn_id is None
                    or mutations != expected_mutations
                )
            ) or (
                status == "completed"
                and mutations != expected_mutations
            ):
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
            "completion_evidence_policy_sha256": self.completion_evidence_policy_sha256,
            "tool_policy_sha256": self.tool_policy_sha256,
            "preflight_tool_surface_sha256": self.preflight_tool_surface[
                "surface_sha256"
            ],
            "pre_dispatch_tool_surface_sha256": (
                self.pre_dispatch_tool_surface.get("surface_sha256")
                if self.pre_dispatch_tool_surface is not None
                else None
            ),
            "trusted_completed_tool_calls": summary["completed_tool_calls"],
            "trusted_tool_evidence_sha256": summary["trusted_tool_evidence_sha256"],
            "expected_tool_trace_sha256": (
                trace_observation["expected_sha256"]
            ),
            "observed_tool_trace_sha256": (
                trace_observation["observed_sha256"]
            ),
            "exact_tool_trace_status": trace_observation["status"],
            "expected_read_only_command_authority_sha256": (
                authority_observation["expected_sha256"]
            ),
            "observed_read_only_command_authority_sha256": (
                authority_observation["observed_sha256"]
            ),
            "read_only_command_authority_status": authority_observation[
                "status"
            ],
            "forbidden_tool_activity": summary["forbidden_tool_activity"],
            "completion_evidence_satisfied": completion_observation["satisfied"],
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
        state_sha256 = canonical_sha256(state_payload)
        control_loss = (
            status == "failed"
            or "trusted-model-attestation-mismatch" in reasons
        )
        pool_wide_reason_codes = {
            "authority-violation",
            "forbidden-tool-activity",
            "mutation-attribution-ambiguous",
            "read-only-workspace-mutation",
            "security-violation",
            "trusted-model-attestation-mismatch",
        }
        failure_class = (
            "control-security-failure"
            if control_loss or any(reason in pool_wide_reason_codes for reason in reasons)
            else "individual-child-failure"
            if reasons
            else None
        )
        return {
            "state_sha256": state_sha256,
            "usage": usage,
            "protected_fault": bool(reasons),
            "control_loss": control_loss,
            "failure_class": failure_class,
            "recovery_evidence_sha256": state_sha256 if reasons else None,
            "reasons": reasons,
            "session_disposition": session_disposition,
            "artifact_disposition": artifact_disposition,
        }

    def final_summary(self) -> dict[str, Any]:
        summary = self._trusted_summary(allow_pending=False)
        completion_observation = self._completion_evidence_observation(summary)
        summary["completion_evidence_policy"] = self.completion_evidence_policy
        summary[
            "completion_evidence_policy_sha256"
        ] = self.completion_evidence_policy_sha256
        summary["completion_evidence_observation"] = completion_observation
        summary["completion_evidence_satisfied"] = completion_observation["satisfied"]
        trace_observation = completion_observation[
            "exact_tool_trace_observation"
        ]
        summary["expected_tool_trace_sha256"] = (
            trace_observation["expected_sha256"]
        )
        summary["exact_tool_trace_observation"] = trace_observation
        summary["exact_tool_trace_satisfied"] = trace_observation["satisfied"]
        authority_observation = completion_observation[
            "read_only_command_authority_observation"
        ]
        summary["expected_read_only_command_authority_sha256"] = (
            authority_observation["expected_sha256"]
        )
        summary["read_only_command_authority_observation"] = (
            authority_observation
        )
        summary["read_only_command_authority_satisfied"] = (
            authority_observation["satisfied"]
        )
        summary["tool_policy"] = self.tool_policy
        summary["tool_policy_sha256"] = self.tool_policy_sha256
        summary["prompt_preflight"] = self.prompt_preflight
        summary["preflight_tool_surface"] = self.preflight_tool_surface
        summary["pre_dispatch_tool_surface"] = self.pre_dispatch_tool_surface
        summary["override_provenance"] = self.tool_policy["override_provenance"]
        summary["callback_stats"] = {
            name: stats(values) for name, values in sorted(self.callback_latencies.items())
        }
        summary["callback_subphase_stats"] = {
            name: stats(values)
            for name, values in sorted(self.callback_subphase_latencies.items())
        }
        summary["archive_staging"] = (
            self._staged_archive.telemetry()
            if self._staged_archive is not None
            else None
        )
        summary["prompt_sha256"] = sha256_text(self.prompt)
        return summary
