"""Trusted workspace topology and mutation evidence for native pools."""

from __future__ import annotations

import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from .native_pool_contracts import (
    canonical_sha256,
    pool_capacity_limits,
    validate_pool_contract,
)
from .workspace import capture_workspace_baseline, compare_workspace_baseline, path_allowed


class PoolWorkspaceError(ValueError):
    """Raised when a pool workspace cannot provide complete attribution."""


_SEALED_BASELINES: ContextVar[dict[str, dict[str, Any]] | None] = ContextVar(
    "cwo_native_pool_sealed_workspace_baselines",
    default=None,
)


def _git_common_dir(root: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--git-common-dir"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise PoolWorkspaceError("workspace-git-common-dir-unavailable")
    value = Path(result.stdout.strip())
    return (root / value).resolve() if not value.is_absolute() else value.resolve()


def _require_clean_complete_baseline(baseline: Mapping[str, Any]) -> None:
    if baseline.get("incomplete") or baseline.get("baseline_complete") is not True:
        raise PoolWorkspaceError("workspace-baseline-incomplete")
    if baseline.get("tracked_status") != []:
        raise PoolWorkspaceError("workspace-baseline-not-clean")


def _require_complete_baseline(baseline: Mapping[str, Any]) -> None:
    if baseline.get("incomplete") or baseline.get("baseline_complete") is not True:
        raise PoolWorkspaceError("workspace-baseline-incomplete")


@contextmanager
def use_sealed_workspace_baselines(
    entries: Mapping[str | Path, Mapping[str, Any]],
):
    """Temporarily admit exact, content-aware baselines with pre-existing dirt.

    The default clean-worktree rule remains unchanged.  This narrowly scoped
    context exists for a controller that has already sealed a dirty candidate
    and must preserve that candidate while attributing only new worker effects.
    Every admitted baseline is re-captured before use, bound to the same root
    and write scope, and rejected on any intervening mutation.
    """

    if _SEALED_BASELINES.get() is not None:
        raise PoolWorkspaceError("sealed-workspace-baseline-context-already-active")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_root, raw_entry in entries.items():
        if not isinstance(raw_entry, Mapping) or set(raw_entry) != {
            "baseline",
            "allowed_paths",
        }:
            raise PoolWorkspaceError("sealed-workspace-baseline-entry-invalid")
        supplied = Path(raw_root).absolute()
        if supplied.is_symlink():
            raise PoolWorkspaceError("workspace-root-is-symlink")
        root = supplied.resolve()
        if not root.is_dir():
            raise PoolWorkspaceError("workspace-root-not-directory")
        baseline = copy.deepcopy(dict(raw_entry["baseline"]))
        allowed = list(raw_entry["allowed_paths"])
        _require_complete_baseline(baseline)
        if Path(str(baseline.get("cwd", ""))).resolve() != root:
            raise PoolWorkspaceError("sealed-workspace-baseline-root-mismatch")
        if list(baseline.get("allowed_paths", [])) != allowed:
            raise PoolWorkspaceError("sealed-workspace-baseline-scope-mismatch")
        key = str(root)
        if key in normalized:
            raise PoolWorkspaceError("sealed-workspace-baseline-root-duplicate")
        normalized[key] = {"baseline": baseline, "allowed_paths": allowed}
    token = _SEALED_BASELINES.set(normalized)
    try:
        yield
    finally:
        _SEALED_BASELINES.reset(token)


def capture_workspace_snapshot(
    path: Path | str,
    *,
    allowed_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Capture a clean complete baseline and its strong physical identity."""
    supplied = Path(path).absolute()
    if supplied.is_symlink():
        raise PoolWorkspaceError("workspace-root-is-symlink")
    root = supplied.resolve()
    if not root.is_dir():
        raise PoolWorkspaceError("workspace-root-not-directory")
    requested_paths = list(allowed_paths)
    sealed = (_SEALED_BASELINES.get() or {}).get(str(root))
    if sealed is None:
        baseline = capture_workspace_baseline(
            root,
            allowed_paths=requested_paths,
            include_untracked=True,
        )
        _require_clean_complete_baseline(baseline)
    else:
        if requested_paths != sealed["allowed_paths"]:
            raise PoolWorkspaceError("sealed-workspace-baseline-scope-mismatch")
        baseline = copy.deepcopy(sealed["baseline"])
        current = capture_workspace_baseline(
            root,
            allowed_paths=requested_paths,
            include_untracked=True,
        )
        report = compare_workspace_baseline(
            baseline,
            current,
            allowed_paths=requested_paths,
        )
        if (
            report.get("incomplete")
            or report.get("mutation_detected")
            or report.get("attribution_ambiguous")
        ):
            raise PoolWorkspaceError("sealed-workspace-baseline-drift")
    stat = root.stat()
    common = _git_common_dir(root)
    identity = {
        "canonical_path_sha256": hashlib.sha256(str(root).encode("utf-8")).hexdigest(),
        "git_common_dir_sha256": hashlib.sha256(str(common).encode("utf-8")).hexdigest(),
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "baseline_sha256": canonical_sha256(baseline),
    }
    return {"root": str(root), "identity": identity, "baseline": baseline}


def _physical_identity(identity: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        identity.get(field)
        for field in ("canonical_path_sha256", "git_common_dir_sha256", "device", "inode")
    )


def _snapshot_cache_key(
    root: str,
    child: Mapping[str, Any],
    *,
    contract_sha256: Any,
    shared_read_only_worktree: Any,
) -> tuple[Any, ...]:
    policy = child.get("completion_evidence_policy")
    mutation_mode = (
        policy.get("expected_mutation_mode")
        if isinstance(policy, Mapping)
        else None
    )
    return (
        root,
        contract_sha256,
        shared_read_only_worktree,
        child.get("isolation_class"),
        mutation_mode,
        tuple(child.get("declared_write_paths", ())),
        tuple(child.get("integration_target_paths", ())),
    )


def validate_integration_target_paths(root: Path | str, paths: Sequence[str]) -> None:
    """Reject target components that escape or traverse a symlink."""
    integration_root = Path(root).resolve()
    for raw in paths:
        relative = Path(raw)
        candidate = integration_root
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise PoolWorkspaceError(f"integration-target-symlink-component:{raw}")
        try:
            candidate.resolve(strict=False).relative_to(integration_root)
        except ValueError as exc:
            raise PoolWorkspaceError(f"integration-target-outside-root:{raw}") from exc


def _mutable_report_is_attributable(report: Mapping[str, Any], allowed: Sequence[str]) -> bool:
    if report.get("incomplete") or report.get("attribution_ambiguous"):
        return False
    mutations = report.get("mutations")
    if not isinstance(mutations, list):
        return False
    for mutation in mutations:
        if not isinstance(mutation, Mapping):
            return False
        category = mutation.get("category")
        path = str(mutation.get("path", ""))
        if category == "scoped":
            continue
        if category == "untracked" and path_allowed(path, list(allowed)):
            continue
        return False
    return True


class PoolWorkspaceMonitor:
    """Own complete baselines and emit hash-bound pool mutation evidence."""

    def __init__(
        self,
        contract: Mapping[str, Any],
        *,
        integration_root: Path | str,
        child_worktrees: Mapping[str, Path | str],
        policy_document: Mapping[str, Any] | None = None,
    ) -> None:
        errors = validate_pool_contract(
            contract,
            capacity_limits=pool_capacity_limits(policy_document),
        )
        if errors:
            raise PoolWorkspaceError("pool-contract-invalid:" + ";".join(errors))
        self.contract = copy.deepcopy(dict(contract))
        children = [dict(child) for child in self.contract["children"]]
        child_ids = [str(child["child_id"]) for child in children]
        if set(child_worktrees) != set(child_ids):
            raise PoolWorkspaceError("child-worktree-set-mismatch")

        self.integration = capture_workspace_snapshot(integration_root)
        if self.integration["identity"] != self.contract["topology"]["integration_root_identity"]:
            raise PoolWorkspaceError("integration-root-identity-mismatch")

        self.children: dict[str, dict[str, Any]] = {}
        snapshots_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        cache_key_by_root: dict[str, tuple[Any, ...]] = {}
        for child in children:
            child_id = str(child["child_id"])
            root = Path(child_worktrees[child_id]).resolve()
            root_key = str(root)
            allowed = list(child["declared_write_paths"])
            validate_integration_target_paths(
                self.integration["root"], child["integration_target_paths"]
            )
            cache_key = _snapshot_cache_key(
                root_key,
                child,
                contract_sha256=self.contract.get("contract_sha256"),
                shared_read_only_worktree=self.contract["topology"].get(
                    "shared_read_only_worktree"
                ),
            )
            previous_key = cache_key_by_root.get(root_key)
            if previous_key is not None and previous_key != cache_key:
                raise PoolWorkspaceError(
                    f"incompatible-physical-worktree-reuse:{child_id}"
                )
            cache_key_by_root[root_key] = cache_key
            snapshot = snapshots_by_key.get(cache_key)
            if snapshot is None:
                snapshot = capture_workspace_snapshot(root, allowed_paths=allowed)
                snapshots_by_key[cache_key] = snapshot
            if snapshot["identity"] != child["worktree_identity"]:
                raise PoolWorkspaceError(f"child-worktree-identity-mismatch:{child_id}")
            if _physical_identity(snapshot["identity"]) == _physical_identity(
                self.integration["identity"]
            ):
                raise PoolWorkspaceError(f"child-worktree-aliases-integration-root:{child_id}")
            self.children[child_id] = {
                "contract": child,
                "snapshot": snapshot,
                "root": root_key,
                "cache_key": cache_key,
            }

        mutable_roots = [
            entry["root"]
            for entry in self.children.values()
            if entry["contract"]["isolation_class"] == "mutable-isolated"
        ]
        if len(mutable_roots) != len(set(mutable_roots)):
            raise PoolWorkspaceError("mutable-children-share-physical-worktree")
        read_only_roots = {
            entry["root"]
            for entry in self.children.values()
            if entry["contract"]["isolation_class"] == "read-only-shared"
        }
        if len(read_only_roots) > 1 and self.contract["topology"]["shared_read_only_worktree"]:
            raise PoolWorkspaceError("shared-read-only-topology-mismatch")
        self.last_report: dict[str, Any] | None = None
        self._observation_history: list[dict[str, Any]] = []

    def observations(self) -> list[dict[str, Any]]:
        """Return an isolated copy of the append-only raw observation chain."""

        return copy.deepcopy(self._observation_history)

    def child_baseline(self, child_id: str) -> dict[str, Any]:
        """Return the exact controller-owned baseline for one admitted child."""

        if not isinstance(child_id, str) or child_id not in self.children:
            raise PoolWorkspaceError("child-workspace-baseline-missing")
        baseline = self.children[child_id]["snapshot"].get("baseline")
        if not isinstance(baseline, Mapping):
            raise PoolWorkspaceError("child-workspace-baseline-invalid")
        _require_complete_baseline(baseline)
        return copy.deepcopy(dict(baseline))

    def _append_observation(self, report: Mapping[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(dict(report))
        value["sequence"] = len(self._observation_history) + 1
        value["previous_observation_sha256"] = (
            self._observation_history[-1]["observation_sha256"]
            if self._observation_history
            else None
        )
        value["observation_sha256"] = canonical_sha256(value)
        self._observation_history.append(copy.deepcopy(value))
        self.last_report = copy.deepcopy(value)
        return value

    def _observation_chain_complete(self) -> bool:
        previous: str | None = None
        for sequence, raw in enumerate(self._observation_history, 1):
            observation = copy.deepcopy(raw)
            digest = observation.pop("observation_sha256", None)
            if (
                observation.get("sequence") != sequence
                or observation.get("previous_observation_sha256") != previous
                or digest != canonical_sha256(observation)
            ):
                return False
            previous = digest
        return bool(self._observation_history)

    def compare(self, *, contract: Mapping[str, Any], phase: str) -> dict[str, Any]:
        if contract.get("contract_sha256") != self.contract.get("contract_sha256"):
            raise PoolWorkspaceError("workspace-contract-hash-mismatch")
        if dict(contract) != self.contract:
            raise PoolWorkspaceError("workspace-contract-content-mismatch")
        if not isinstance(phase, str) or not phase:
            raise PoolWorkspaceError("workspace-comparison-phase-invalid")

        integration_after = capture_workspace_baseline(
            self.integration["root"], allowed_paths=[], include_untracked=True
        )
        integration_report = compare_workspace_baseline(
            self.integration["baseline"], integration_after, allowed_paths=[]
        )
        integration_clean = not (
            integration_report.get("incomplete")
            or integration_report.get("mutation_detected")
            or integration_report.get("attribution_ambiguous")
        )

        reports: dict[str, Any] = {}
        child_clean = True
        after_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
        for child_id, entry in self.children.items():
            child = entry["contract"]
            root = entry["root"]
            allowed = list(child["declared_write_paths"])
            cache_key = entry["cache_key"]
            after = after_by_key.get(cache_key)
            if after is None:
                after = capture_workspace_baseline(
                    root, allowed_paths=allowed, include_untracked=True
                )
                after_by_key[cache_key] = after
            report = compare_workspace_baseline(
                entry["snapshot"]["baseline"], after, allowed_paths=allowed
            )
            reports[child_id] = report
            if child["isolation_class"] == "read-only-shared":
                safe = not (
                    report.get("incomplete")
                    or report.get("mutation_detected")
                    or report.get("attribution_ambiguous")
                )
            else:
                safe = _mutable_report_is_attributable(report, allowed)
            child_clean = child_clean and safe

        booleans = {
            "integration_root_clean": integration_clean,
            "shared_read_only_clean": all(
                not report.get("mutation_detected") and not report.get("incomplete")
                for child_id, report in reports.items()
                if self.children[child_id]["contract"]["isolation_class"]
                == "read-only-shared"
            ),
            "child_worktrees_clean": child_clean,
        }
        self._append_observation({
            "phase": phase,
            "integration": integration_report,
            "children": reports,
            "evidence": dict(booleans),
        })
        return {**booleans, "evidence_sha256": canonical_sha256(booleans)}

    def reconcile_terminal(
        self,
        *,
        contract: Mapping[str, Any],
        no_inflight_tool_calls: bool,
        no_inflight_callbacks: bool,
        no_background_processes: bool,
        no_writable_sessions: bool,
        phase: str = "terminal-reconciliation",
    ) -> dict[str, Any]:
        """Capture one terminal snapshot after an explicit quiescence barrier.

        A clean final filesystem cannot erase an earlier escape or an
        unobservable interval.  The returned control disposition is therefore
        reduced from the complete append-only observation chain.
        """

        quiescence = {
            "no_inflight_tool_calls": no_inflight_tool_calls,
            "no_inflight_callbacks": no_inflight_callbacks,
            "no_background_processes": no_background_processes,
            "no_writable_sessions": no_writable_sessions,
        }
        if any(type(value) is not bool for value in quiescence.values()):
            raise PoolWorkspaceError("terminal-quiescence-values-invalid")
        terminal = self.compare(contract=contract, phase=phase)
        interval_complete = self._observation_chain_complete()
        raw_history = self.observations()
        unobservable = any(
            bool(report.get("integration", {}).get("incomplete"))
            or bool(report.get("integration", {}).get("attribution_ambiguous"))
            or any(
                bool(child.get("incomplete"))
                or bool(child.get("attribution_ambiguous"))
                for child in report.get("children", {}).values()
                if isinstance(child, Mapping)
            )
            for report in raw_history
        )
        escaped = any(
            not all(
                report.get("evidence", {}).get(field) is True
                for field in (
                    "integration_root_clean",
                    "shared_read_only_clean",
                    "child_worktrees_clean",
                )
            )
            for report in raw_history
        )
        quiescent = all(quiescence.values())
        terminal_clean = all(
            terminal[field]
            for field in (
                "integration_root_clean",
                "shared_read_only_clean",
                "child_worktrees_clean",
            )
        )
        if not quiescent or not interval_complete or unobservable:
            disposition = "unobservable"
        elif escaped:
            disposition = "escaped"
        elif terminal_clean:
            disposition = "clean"
        else:
            disposition = "suspected"
        result = {
            "artifact_type": "cwo-native-pool-terminal-workspace-reconciliation",
            "version": 1,
            "contract_sha256": self.contract.get("contract_sha256"),
            "quiescence": quiescence,
            "quiescent": quiescent,
            "observation_interval_complete": interval_complete,
            "observation_count": len(raw_history),
            "first_observation_sha256": (
                raw_history[0]["observation_sha256"] if raw_history else None
            ),
            "last_observation_sha256": (
                raw_history[-1]["observation_sha256"] if raw_history else None
            ),
            "terminal_evidence": terminal,
            "terminal_clean": terminal_clean,
            "historical_escape_observed": escaped,
            "unobservable_interval_observed": unobservable,
            "control_disposition": disposition,
        }
        result["reconciliation_sha256"] = canonical_sha256(result)
        return result
