"""Trusted workspace topology and mutation evidence for native pools."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from .native_pool_contracts import canonical_sha256, validate_pool_contract
from .workspace import capture_workspace_baseline, compare_workspace_baseline, path_allowed


class PoolWorkspaceError(ValueError):
    """Raised when a pool workspace cannot provide complete attribution."""


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
    baseline = capture_workspace_baseline(
        root,
        allowed_paths=list(allowed_paths),
        include_untracked=True,
    )
    _require_clean_complete_baseline(baseline)
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
    ) -> None:
        errors = validate_pool_contract(contract)
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
        self.last_report = {
            "phase": phase,
            "integration": integration_report,
            "children": reports,
            "evidence": dict(booleans),
        }
        return {**booleans, "evidence_sha256": canonical_sha256(booleans)}
