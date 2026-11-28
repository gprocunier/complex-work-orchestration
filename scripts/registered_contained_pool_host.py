"""Protected producer for ordinary contained pool requests."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from types import MappingProxyType

from cwo_core import manual_delivery, native_live_availability, workspace_capture
from cwo_core.beads_ready_set import build_ready_set_evidence, _admission_metadata
from cwo_core.invocation_ledger import InvocationLedger
from cwo_core.native_authority import canonical_authority_sha256, verify_operator_directive
from cwo_core.native_pool_admission import AdmissionCandidate, BeadsClaimAdapter, build_admission_child_binding, reserve_pool_cohort
from cwo_core.native_pool_preflight import effective_child_packet_sha256
from cwo_core.native_pool_proportionality import pool_proportionality_check
from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
from cwo_core.native_pool_workspace import capture_workspace_snapshot
from cwo_core.private_artifact import PrivateDirectory
from delegate_internal_work import PROJECT_CONTROLLER_IDENTITY
from registered_delegation_entry import _protected_store, _read_key
from registered_n1_qualification import EFFORT, MODEL, TIER, pool_worker_login_mount, worker_login_state
from registered_native_pool_client import CONTAINED_EXECUTION_ROUTE, validate_structure
from registered_worker_login_config import read_pool_worker_login_homes


APPROVAL_SCOPE = "cwo-ordinary-contained-pool-v1"
APPROVAL_FILE = "approval.json"
REQUEST_FILE = "request.json"
APPROVAL_MAX_BYTES = 65_536
PATCH_OUTPUT_MODE = "unified-diff"
IDENTITY_SOURCE = PROJECT_CONTROLLER_IDENTITY
SUPPORTED_SELECTION = (MODEL, EFFORT, TIER)
_ISSUER = object()
_SCOPE_FIELDS = {
    "scope", "pool_id", "root_identity", "project", "project_identity", "database", "epic_id", "children",
    "selection", "limits", "productive_limits", "integration_root", "integration_identity_sha256",
    "control_turn_id", "calibration_seconds", "provider", "disclosure", "expires_at", "runtime_adapter_sha256",
    "host_inputs",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def project_root(path):
    project = Path(path).absolute()
    require(project.resolve(strict=True) == project and workspace_capture.worktree_top_level(project) == str(project),
            "Run the pool from its original project checkout.")
    return project


def directory_identity(path):
    info = path.stat(follow_symlinks=False)
    require(path.resolve(strict=True) == path, "An original pool directory changed.")
    return [info.st_dev, info.st_ino]


def database_coordinates(project):
    digest, _ = manual_delivery.project_beads(project)
    arguments = ["-C", str(project)]
    if beads_dir := os.environ.get("BEADS_DIR"):
        arguments.extend(("--db", str((project / beads_dir).resolve(strict=True))))
    selector, storage = manual_delivery._database_location(arguments)
    require(manual_delivery._database_identity(storage) == digest, "The current project Beads database changed.")
    return {"selector": str(selector), "storage": str(storage), "sha256": digest}


def pool_state(store):
    return store.state_root.with_name(store.state_root.name + ".pool")


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def actor():
    return f"uid:{os.getuid()}"


@dataclass(frozen=True, slots=True)
class OrdinaryPoolChild:
    worker_id: str
    bead_id: str
    baseline_sha256: str
    task: str
    prompt: str
    write_path: str
    expected_utf8: str | None
    completion_marker: str
    worktree: Path
    worktree_identity_sha256: str
    login_home: Path
    login_identity: tuple
    calibration_spool: Path
    productive_spool: Path
    bead_projection_sha256: str
    output_mode: str | None = None
    patch_preimage_sha256: str | None = None

    @classmethod
    def from_scope(cls, row):
        if "output_mode" in row or "patch_preimage_sha256" in row:
            from registered_pool_containment import pool_patch_path

            digest = row.get("patch_preimage_sha256")
            require(row.get("output_mode") == PATCH_OUTPUT_MODE and row["expected_utf8"] is None
                    and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "A signed unified-diff assignment requires one exact preimage digest.")
            require(pool_patch_path(row["write_path"]), "A signed unified-diff assignment requires a canonical relative path.")
        paths = ("worktree", "login_home", "calibration_spool", "productive_spool")
        return cls(**{**row, **{key: Path(row[key]) for key in paths}, "login_identity": tuple(row["login_identity"])})


class ApprovedOrdinaryPool:
    """Locally verified signed scope and current host custody, retained in this process."""

    __slots__ = (
        "root", "_raw", "_key", "_scope", "_directive", "pool_id", "binding_sha256", "project", "integration_root",
        "claim_adapter", "control_turn_id", "issued_at", "expires_at", "calibration_seconds", "limits", "model",
        "effort", "service_tier", "ledger", "lease_registry_path", "runtime_adapter_sha256",
        "callback_implementation_sha256", "host_inputs", "children",
        "readiness_evidence", "work_estimates",
    )

    def __init__(self, issuer, root, store, envelope, raw, key):
        require(issuer is _ISSUER, "Original ordinary pool approval required.")
        self.root, self._raw, self._key = root, raw, key
        self._scope = envelope["manifest"]
        self._directive = envelope["directive"]
        scope = self._scope
        self.pool_id = scope["pool_id"]
        self.binding_sha256 = canonical_authority_sha256(scope)
        self.project = Path(scope["project"])
        self.integration_root = Path(scope["integration_root"])
        self.claim_adapter = BeadsClaimAdapter(directory=self.project, database=scope["database"]["selector"],
                                               actor=actor(), before_claim=self._before_claim)
        self.control_turn_id = scope["control_turn_id"]
        self.issued_at, self.expires_at = self._directive["issued_at"], scope["expires_at"]
        self.calibration_seconds = scope["calibration_seconds"]
        self.limits = MappingProxyType(scope["limits"])
        self.model, self.effort, self.service_tier = scope["selection"]
        self.ledger = InvocationLedger(root / "ledger")
        self.lease_registry_path = pool_state(store) / "leases.json"
        self.runtime_adapter_sha256 = scope["runtime_adapter_sha256"]
        self.callback_implementation_sha256 = scope.get("callback_implementation_sha256")
        self.host_inputs = MappingProxyType(scope["host_inputs"])
        self.children = MappingProxyType({row["worker_id"]: OrdinaryPoolChild.from_scope(row) for row in scope["children"]})
        self.readiness_evidence = None
        self.work_estimates = None

    def __setattr__(self, name, value):
        if hasattr(self, name):
            raise AttributeError("The original approved pool configuration is immutable.")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        raise AttributeError("The original approved pool configuration is immutable.")

    def _retain_admission_evidence(self, evidence, estimates):
        require(self.readiness_evidence is None, "Original pool readiness was already retained.")
        object.__setattr__(self, "readiness_evidence", evidence)
        object.__setattr__(self, "work_estimates", estimates)

    @property
    def login_homes(self) -> tuple[Path, ...]:
        return tuple(child.login_home for child in self.children.values())

    def require_current(self):
        native_live_availability.require_registered_contained_pool_live()
        with PrivateDirectory.open(self.root) as directory:
            require(directory.read(APPROVAL_FILE, max_bytes=APPROVAL_MAX_BYTES) == self._raw
                    and directory_identity(self.root) == self._scope["root_identity"],
                    "The original pool approval custody changed.")
        require(directory_identity(self.project) == self._scope["project_identity"],
                "The original project checkout changed.")
        database = self._scope["database"]
        require(manual_delivery._database_identity(Path(database["storage"])) == database["sha256"]
                and str(Path(database["selector"]).resolve(strict=True)) == database["selector"],
                "The original project Beads database changed.")
        homes = read_pool_worker_login_homes()
        selected = self.login_homes
        require(homes[:len(selected)] == selected, "The configured pool worker logins changed.")
        _verify(self._scope, self._directive, self._key, self.ledger.current_time())

    def _before_claim(self, _attempt_actor, bead_id):
        from registered_pool_ordinary_runtime import require_ordinary_runtime_source

        self.require_current()
        require_ordinary_runtime_source(self)
        require(database_coordinates(self.project) == self._scope["database"]
                and bead_id in {child.bead_id for child in self.children.values()},
                "The protected pool claim differs from its signed Beads target.")
        with PrivateDirectory.open(self.root) as directory:
            directory.write(f"claim-{bead_id}.json", encode({"actor": _attempt_actor, "bead_id": bead_id}))
        self.require_current()

    def validate(self, request):
        require(request["pool_id"] == self.root.name and request["workers"] == list(self.children),
                "The request must select the exact signed pool cohort in order.")
        self.require_current()
        snapshot = capture_workspace_snapshot(self.integration_root)["identity"]
        require(canonical_authority_sha256(snapshot) == self._scope["integration_identity_sha256"],
                "The original pool integration checkout changed.")
        homes, state = self.login_homes, worker_login_state()
        for child in self.children.values():
            mount = pool_worker_login_mount(child.login_home, state, homes)
            require(mount.identity == child.login_identity, "A configured pool worker login inode changed.")
            require(_worktree_identity(child) == child.worktree_identity_sha256, "An approved worker worktree changed.")


def _verify(scope, directive, key, now):
    require(type(scope) is dict and set(scope) in (_SCOPE_FIELDS, _SCOPE_FIELDS | {"callback_implementation_sha256"}),
            "The original signed ordinary pool manifest is required.")
    authority = verify_operator_directive(directive, verification_key=key, expected_actor_id=actor(),
        expected_identity_source=IDENTITY_SOURCE, expected_action_sha256=canonical_authority_sha256(scope))
    issued_at = datetime.fromisoformat(directive["issued_at"])
    require(authority.authorized_scope == "complete-task" and directive["parent_receipt_sha256"] is None
            and issued_at.tzinfo is not None and issued_at.timestamp() <= now < scope["expires_at"],
            "The ordinary pool approval expired or does not authorize this cohort.")
    require(scope["scope"] == APPROVAL_SCOPE and tuple(scope["selection"]) == SUPPORTED_SELECTION
            and scope["provider"] == "openai" and scope["disclosure"] == "provider-only",
            "The exact contained pool model, effort, tier and provider disclosure are required.")


def _worktree_identity(child):
    if child.patch_preimage_sha256 is not None:
        require_patch_preimage(child)
    return canonical_authority_sha256(capture_workspace_snapshot(child.worktree, allowed_paths=[child.write_path])["identity"])


def require_patch_preimage(child: OrdinaryPoolChild, *, deadline: float | None = None) -> None:
    from registered_pool_containment import MAX_POOL_PATCH_SOURCE_BYTES, read_pool_patch_file, render_pool_patch_prompt

    current = read_pool_patch_file(child.worktree, child.write_path, maximum_bytes=MAX_POOL_PATCH_SOURCE_BYTES, deadline=deadline)
    digest = sha256(current).hexdigest()
    require(digest == child.patch_preimage_sha256, "The signed worker patch preimage changed.")
    require(child.prompt == render_pool_patch_prompt(child.task, child.write_path, child.completion_marker, current, digest),
            "The signed worker patch prompt differs from the checked source.")


def _cohort(approved):
    items, estimates = [], {}
    digest, run = manual_delivery.project_beads(approved.project)
    require(digest == approved._scope["database"]["sha256"], "The project Beads database changed.")
    ready = manual_delivery.projection(run(["ready", "--json", "--parent", approved._scope["epic_id"],
                                          "--unassigned", "--limit", "0"]), "ready pool Beads")
    require(type(ready) is list and all(type(row) is dict and type(row.get("id")) is str for row in ready),
            "The original project Beads ready set is required.")
    ranks = {row["id"]: rank for rank, row in enumerate(ready)}
    for child in approved.children.values():
        issue = dict(approved.claim_adapter.show_exact(child.bead_id))
        require(child.bead_id in ranks and execution_authoritative_bead_sha256(issue) == child.bead_projection_sha256,
                "An approved Bead changed before pool admission.")
        item = {"id": issue["id"], "raw": issue, "_cwo_canonical_ready_rank": ranks[child.bead_id]}
        metadata = _admission_metadata(item)
        require(metadata is not None and type(metadata.get("work_plan")) is dict,
                "Each Bead needs original pool readiness metadata.")
        estimate = metadata["work_plan"]
        require(estimate["write_paths"] == [child.write_path] and estimate["requested_model"] == approved.model,
                "The Bead's work plan differs from its signed pool assignment.")
        estimates[child.bead_id] = estimate
        items.append(item)
    evidence = build_ready_set_evidence(items, epic_id=approved._scope["epic_id"], requested_workers=len(items))
    assessment = pool_proportionality_check(evidence, estimates, requested_workers=len(items))
    selected = (assessment.get("selected_cohort") or {}).get("issue_ids", [])
    require(set(selected) == set(estimates), "Current readiness and proportionality did not admit the signed cohort.")
    return evidence, estimates, assessment


def _admit(approved, directory, packet_builder):
    evidence, estimates, assessment = _cohort(approved)
    approved._retain_admission_evidence(evidence, estimates)
    by_bead = {child.bead_id: child for child in approved.children.values()}
    packets = tuple(packet_builder(child.worker_id, child, estimates[child.bead_id])
                    for child in (by_bead[bead_id] for bead_id in assessment["selected_cohort"]["issue_ids"]))
    _require_packet_budget(approved, packets)
    indexed = {packet["child_id"]: packet for packet in packets}

    def child_binding(child_id):
        child, packet = approved.children[child_id], indexed[child_id]
        identity = _worktree_identity(child)
        require(identity == child.worktree_identity_sha256, "An approved worker worktree changed.")
        return build_admission_child_binding(evidence, estimates[child.bead_id], bead_id=child.bead_id,
            child_id=child_id, packet_id=packet["packet_id"], packet_sha256=effective_child_packet_sha256(packet),
            worktree_identity_sha256=identity)

    def revalidate(binding):
        approved.require_current()
        return child_binding(binding["child_id"])

    bindings = {child.bead_id: child_binding(key) for key, child in approved.children.items()}
    directory.write("execution-intent.json", encode({"approval_sha256": approved.binding_sha256,
                                                    "beads": sorted(bindings)}))
    admitted = reserve_pool_cohort(AdmissionCandidate(evidence, estimates, assessment, bindings),
        claim_adapter=approved.claim_adapter, admission_nonce=approved.binding_sha256, live_revalidate=revalidate)
    directory.write("admission.json", encode(admitted.receipt))
    require(admitted.admitted, "The original pool Beads claims were not admitted.")
    return admitted, packets


def _require_packet_budget(approved, packets):
    calibration = {"sessions": len(packets), "tool_calls": 1, "runtime_seconds": approved.calibration_seconds}
    productive = approved._scope["productive_limits"]
    for key in ("tool_calls", "runtime_seconds"):
        total = sum(packet["hard_budget"][key] for packet in packets)
        require(0 < total <= productive[key] and total + calibration[key] <= approved.limits[key],
                "The approved aggregate allowance cannot cover the productive and calibration phases.")
    require(approved.limits["sessions"] == 2 * len(packets), "The signed pool session allowance changed.")


class RegisteredContainedPoolHost:
    """Effect-bearing host for exactly one signed ordinary pool request."""

    def __init__(self, approved):
        require(type(approved) is ApprovedOrdinaryPool, "The exact approved ordinary pool is required.")
        self._approved = approved

    def run(self, request):
        structural = validate_structure(request)
        approved = self._approved
        approved.validate(request)
        if request["mode"] == "validate-only":
            return {**structural, "authority_validated": True}
        from registered_pool_ordinary_runtime import (
            build_registered_contained_pool_packet,
            require_ordinary_runtime_source,
            run_registered_contained_pool,
        )

        require_ordinary_runtime_source(approved)
        with PrivateDirectory.open(approved.root) as directory:
            require(directory.contains("execution-intent.json") is False, "The original pool approval was already used.")
            admission, packets = _admit(approved, directory, build_registered_contained_pool_packet)
        result = run_registered_contained_pool(approved, admission, packets=packets)
        return {**result, "execution_route": CONTAINED_EXECUTION_ROUTE, "evidence_directory": str(approved.root)}


def open_approved_pool(project, pool_id):
    """Resolve caller IDs only within the installed controller's private store."""
    native_live_availability.require_registered_contained_pool_live()
    validate_structure({"version": 1, "mode": "validate-only", "pool_id": pool_id, "workers": ["pool"]})
    project = project_root(project)
    database = database_coordinates(project)
    store = _protected_store(project)
    root = pool_state(store) / pool_id
    with PrivateDirectory.open(root) as directory:
        raw = directory.read(APPROVAL_FILE, max_bytes=APPROVAL_MAX_BYTES)
    envelope = manual_delivery.projection(raw.decode("utf-8"), "contained pool approval")
    require(type(envelope) is dict and set(envelope) == {"manifest", "directive"},
            "The original signed ordinary pool approval is required.")
    scope = envelope["manifest"]
    require(type(scope) is dict and scope.get("pool_id") == pool_id and scope.get("project") == str(project)
            and scope.get("database") == database,
            "The signed pool belongs to another project or Beads database.")
    key = _read_key(store, project, database["sha256"])
    _verify(scope, envelope["directive"], key, datetime.now().timestamp())
    return RegisteredContainedPoolHost(ApprovedOrdinaryPool(_ISSUER, root, store, envelope, raw, key))
