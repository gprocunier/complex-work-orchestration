"""Prepare and retain one finite ordinary pool through the existing local controller."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from uuid import uuid4

import everyday_delegation
import registered_contained_pool_host as pool
from cwo_core import manual_delivery, native_live_availability
from cwo_core.beads_ready_set import _admission_metadata
from cwo_core.invocation_ledger import MAX_UNITS
from cwo_core.maintenance_authority import sign_controller_directive
from cwo_core.native_authority import canonical_authority_sha256
from cwo_core.native_pool_admission import BeadsClaimAdapter
from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
from cwo_core.native_pool_workspace import capture_workspace_snapshot
from cwo_core.native_tool_isolation import CONTAINED_POOL_WRITER
from cwo_core.private_artifact import PrivateDirectory
from registered_delegation_preparation import _clone, _custody_ticket, _known_output_data, _project_key, _screen, _text
from registered_n1_factory import _file
from registered_n1_qualification import _login_overlap, pool_worker_login_mount, worker_login_state
from registered_pool_configuration import PoolContainmentError, trim_model_catalog
from registered_pool_containment import _writer_bytes, pool_patch_path, read_pool_patch_file
from registered_pool_qualification_capability import callback_implementation_sha256
from registered_worker_login_config import read_pool_worker_login_homes


_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CALIBRATION_SECONDS = 180
_SETUP_SECONDS = 300

_ASSIGNMENT_PROPERTIES = {
    "task": {"type": "string"},
    "baseline": {"type": "string"},
    "amendments": {"type": "array", "items": {"type": "string"}},
    "output_path": {"type": "string"},
    "output_text": {"type": "string"},
    "output_mode": {"type": "string", "enum": [pool.PATCH_OUTPUT_MODE]},
}
_ASSIGNMENT_REQUIRED = {"task", "baseline", "output_path"}
TOOL = {
    "name": "authorize_pool",
    "description": "Approve one ordered, contained pool of two or three registered assignments.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "epic_id": {"type": "string"},
            "model": {"type": "string", "enum": [pool.SUPPORTED_SELECTION[0]]},
            "effort": {"type": "string", "enum": [pool.SUPPORTED_SELECTION[1]]},
            "service_tier": {"type": "string", "enum": [pool.SUPPORTED_SELECTION[2]]},
            "assignments": {
                "type": "array", "minItems": 2, "maxItems": 3,
                "items": {"type": "object", "properties": _ASSIGNMENT_PROPERTIES,
                          "required": sorted(_ASSIGNMENT_REQUIRED), "additionalProperties": False,
                          "oneOf": [{"required": ["output_text"]}, {"required": ["output_mode"]}]},
            },
        },
        "required": ["epic_id", "model", "effort", "service_tier", "assignments"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True, slots=True)
class PendingOrdinaryPool:
    root: Path
    manifest: bytes


def _proposal(args):
    schema = TOOL["inputSchema"]
    pool.require(type(args) is dict and set(args) == set(schema["required"]),
                 "Supply the exact pool model, effort, tier, epic and assignments.")
    selection = (args["model"], args["effort"], args["service_tier"])
    pool.require(selection == pool.SUPPORTED_SELECTION, "The requested pool model, effort and tier are unavailable.")
    epic, assignments = args["epic_id"], args["assignments"]
    pool.require(type(epic) is str and _IDENTITY.fullmatch(epic) is not None, "Supply the original epic ID.")
    pool.require(type(assignments) is list and len(assignments) in (2, 3), "Supply two or three ordered assignments.")
    return epic, selection, assignments


def _assignment_output(proposal: dict[str, object], task: str) -> dict[str, str | None]:
    if "output_mode" in proposal:
        pool.require(proposal["output_mode"] == pool.PATCH_OUTPUT_MODE and "output_text" not in proposal,
                     "Unified-diff assignments require output_mode and omit output_text.")
        path, _ = _known_output_data(proposal["output_path"], task)
        pool.require(pool_patch_path(path), "A unified diff requires one canonical relative file path.")
        _screen(task, "")
        return {"write_path": path, "expected_utf8": None, "output_mode": pool.PATCH_OUTPUT_MODE}
    pool.require("output_text" in proposal, "Supply exact output_text or choose unified-diff mode.")
    text = proposal["output_text"]
    path, _ = _known_output_data(proposal["output_path"], text)
    _writer_bytes(path, text)
    _screen(task, text)
    return {"write_path": path, "expected_utf8": text}


def _assignment(project, proposal, run, claim):
    pool.require(type(proposal) is dict and _ASSIGNMENT_REQUIRED <= set(proposal) <= set(_ASSIGNMENT_PROPERTIES),
                 "Each assignment needs the original task, baseline and output path.")
    amendments = proposal.get("amendments", [])
    pool.require(type(amendments) is list and all(type(path) is str for path in amendments)
                 and type(proposal["baseline"]) is str, "Supply the original requirement baseline and amendments.")
    task = proposal["task"]
    _text(task)
    pool.require(bool(task.strip()), "The original lead task is required.")
    output = _assignment_output(proposal, task)
    _, _, chain = everyday_delegation._baseline(project / proposal["baseline"], [project / path for path in amendments])
    bead_id = chain["bead_id"]
    pool.require(_IDENTITY.fullmatch(bead_id) is not None, "The requirement baseline needs the exact Bead ID.")
    everyday_delegation._open_task(manual_delivery.Delivery(bead_id, project, chain, {}), run)
    issue = dict(claim.show_exact(bead_id))
    admission = _admission_metadata({"id": bead_id, "raw": issue})
    pool.require(admission is not None, "The Bead lacks original pool readiness metadata.")
    return {
        "bead_id": bead_id, "baseline_sha256": chain["digest"], "task": task, **output,
        "bead_projection_sha256": execution_authoritative_bead_sha256(issue),
    }, admission


def _limits(admissions, size):
    budgets = [admission.get("aggregate_hard_budget") for admission in admissions]
    pool.require(all(type(budget) is dict for budget in budgets) and all(row == budgets[0] for row in budgets),
                 "All approved members must share one existing aggregate Beads allowance.")
    budget = budgets[0]
    tools, seconds = budget.get("tool_calls"), budget.get("runtime_seconds")
    pool.require(type(tools) is int and size <= tools < MAX_UNITS
                 and type(seconds) is int and 0 < seconds <= MAX_UNITS - _CALIBRATION_SECONDS,
                 "The original pool allowance must bound tool calls and runtime.")
    return {"sessions": size, "tool_calls": tools, "runtime_seconds": seconds}


def _mounts(size):
    homes = read_pool_worker_login_homes()[:size]
    pool.require(len(homes) == size, "Configure one distinct dedicated login per concurrent worker.")
    state = worker_login_state()
    mounts = tuple(pool_worker_login_mount(home, state, homes) for home in homes)
    pool.require(len({mount.identity for mount in mounts}) == size, "The pool login homes share a directory identity.")
    pool.require(not any(_login_overlap(home, peer) for index, home in enumerate(homes) for peer in homes[index + 1:]),
                 "The pool login homes overlap.")
    return mounts


def _host_inputs(root):
    binary = shutil.which("codex")
    pool.require(binary is not None, "The installed Codex CLI is required for contained pools.")
    host = {}
    for name, selection in (("executable", binary), ("launcher", "/usr/bin/bwrap"), ("validator", sys.executable)):
        host[name], host[name + "_sha256"], _ = _file(Path(selection).resolve(strict=True))
    catalog = _bundled_catalog(host)
    if catalog is not None:
        with PrivateDirectory.open(root) as directory:
            path = directory.write("model-catalog.json", catalog)
        host["model_catalog"] = {"path": str(path), "sha256": sha256(catalog).hexdigest()}
    return host


def _bundled_catalog(host):
    command = [host["launcher"], "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
               "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
               "--symlink", "usr/lib", "/lib", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/offline",
               "--ro-bind", host["executable"], "/offline/codex", "--setenv", "HOME", "/offline",
               "--setenv", "CODEX_HOME", "/offline", "--chdir", "/offline", "--", "/offline/codex",
               "debug", "models", "--bundled"]
    try:
        raw = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30).stdout
        return trim_model_catalog(raw, source_sha256=sha256(raw).hexdigest())
    except (OSError, subprocess.SubprocessError, PoolContainmentError):
        return None


def _bind_output(worktree: Path, row: dict[str, str | None]) -> dict[str, str | None]:
    path = row["write_path"]
    if row.get("output_mode") == pool.PATCH_OUTPUT_MODE:
        before = read_pool_patch_file(worktree, path)
        return {**row, "patch_preimage_sha256": sha256(before).hexdigest()}
    pool.require(not os.path.lexists(worktree / path), "The contained writer requires a fresh output path.")
    return row


def _worker_prompt(row: dict[str, str | None], marker: str) -> str:
    if row.get("output_mode") == pool.PATCH_OUTPUT_MODE:
        return (f"Approved task: {row['task']}\n"
                f"Inspect {row['write_path']} in your read-only assigned checkout. "
                f"Call only `{CONTAINED_POOL_WRITER}`, exactly once, with a `diff` string containing "
                f"a unified diff against that file. Use its exact repository-relative path in both diff headers. "
                f"Return this exact marker only when the writer reports success:\n{marker}")
    return (f"Approved task: {row['task']}\n"
              f"Call only `{CONTAINED_POOL_WRITER}`, exactly once, with `{{}}`. "
              f"The registered writer creates only {row['write_path']} in your read-only assigned checkout. "
              f"Return this exact marker only when the writer reports success:\n{marker}")


def _workspace(root, project, row, mount, index):
    worker_id = f"worker-{index}"
    worktree = root / "workspaces" / worker_id
    _clone(project, worktree)
    row = _bind_output(worktree, row)
    fingerprint = capture_workspace_snapshot(worktree, allowed_paths=[row["write_path"]])["identity"]
    marker = f"CWO_POOL_WORKER_{index}_DONE"
    spools = {}
    for phase in ("calibration", "productive"):
        custody = root / f"{phase}-spool-{index}"
        custody.mkdir(mode=0o700)
        spool = custody / "spool"
        spool.mkdir(mode=0o700)
        spools[phase + "_spool"] = str(spool)
    return {**row, **spools, "worker_id": worker_id, "worktree": str(worktree),
            "worktree_identity_sha256": canonical_authority_sha256(fingerprint),
            "login_home": str(mount.home), "login_identity": list(mount.identity),
            "prompt": _worker_prompt(row, marker), "completion_marker": marker}


def _manifest(root, project, database, epic, selection, assignments, limits, mounts):
    (root / "workspaces").mkdir(mode=0o700)
    integration = root / "workspaces" / "integration"
    _clone(project, integration)
    integration_identity = canonical_authority_sha256(capture_workspace_snapshot(integration)["identity"])
    children = [_workspace(root, integration, row, mount, index)
                for index, (row, mount) in enumerate(zip(assignments, mounts), 1)]
    host = _host_inputs(root)
    factory = Path(__file__).resolve().with_name("registered_pool_qualification.py")
    total = {"sessions": 2 * limits["sessions"], "tool_calls": limits["tool_calls"] + 1,
             "runtime_seconds": limits["runtime_seconds"] + _CALIBRATION_SECONDS}
    return {"scope": pool.APPROVAL_SCOPE, "pool_id": root.name, "root_identity": pool.directory_identity(root),
            "project": str(project), "project_identity": pool.directory_identity(project), "database": database,
            "epic_id": epic, "children": children, "selection": selection, "limits": total, "productive_limits": limits,
            "integration_root": str(integration), "integration_identity_sha256": integration_identity,
            "control_turn_id": uuid4().hex,
            "calibration_seconds": _CALIBRATION_SECONDS, "provider": "openai", "disclosure": "provider-only",
            "expires_at": int(datetime.now(timezone.utc).timestamp()) + total["runtime_seconds"] + _SETUP_SECONDS,
            "runtime_adapter_sha256": sha256(factory.read_bytes()).hexdigest(),
            "callback_implementation_sha256": callback_implementation_sha256(), "host_inputs": host}


@contextmanager
def prepare_pool(project, args):
    native_live_availability.require_registered_contained_pool_live()
    epic, selection, proposals = _proposal(args)
    project = pool.project_root(project)
    database = pool.database_coordinates(project)
    digest, run = manual_delivery.project_beads(project)
    pool.require(digest == database["sha256"], "The original project Beads database changed.")
    claim = BeadsClaimAdapter(directory=project, database=database["selector"], actor=pool.actor())
    rows, admissions = zip(*(_assignment(project, proposal, run, claim) for proposal in proposals))
    pool.require(all(len({row[field] for row in rows}) == len(rows) for field in ("bead_id", "write_path")),
                 "Pool assignments need distinct Beads and output paths.")
    limits = _limits(admissions, len(rows))
    mounts = _mounts(len(rows))
    store = pool._protected_store(project, *(mount.home for mount in mounts))
    with PrivateDirectory.open(pool.pool_state(store), create=True) as parent:
        root = parent.path / f"pool-{_custody_ticket()}"
        os.mkdir(root.name, 0o700, dir_fd=parent.descriptor)
        os.fsync(parent.descriptor)
        identity = pool.directory_identity(root)
        try:
            manifest = _manifest(root, project, database, epic, selection, rows, limits, mounts)
            yield PendingOrdinaryPool(root, pool.encode(manifest))
        finally:
            with PrivateDirectory.open(root) as directory:
                unused = directory.contains(pool.APPROVAL_FILE) is False
            if unused and pool.directory_identity(root) == identity:
                shutil.rmtree(root.name, dir_fd=parent.descriptor)
                os.fsync(parent.descriptor)


def retain_approved_pool(pending, request_id):
    """Store one signed cohort after the existing local foreground adopted it."""
    pool.require(type(pending) is PendingOrdinaryPool, "The original pool preparation is required.")
    manifest = manual_delivery.projection(pending.manifest.decode(), "prepared pool")
    project = Path(manifest["project"])
    database = pool.database_coordinates(project)
    pool.require(database == manifest["database"], "The project Beads database changed during approval.")
    store = pool._protected_store(project)
    key = _project_key(store, project, database["sha256"])
    directive = sign_controller_directive(verification_key=key, actor_id=pool.actor(),
        identity_source=pool.IDENTITY_SOURCE, action_sha256=canonical_authority_sha256(manifest), directive_id=request_id)
    pool._verify(manifest, directive, key, datetime.now(timezone.utc).timestamp())
    raw = pool.encode({"manifest": manifest, "directive": directive})
    pool.require(len(raw) <= pool.APPROVAL_MAX_BYTES, "The approved pool exceeds its private storage bound.")
    request = {"version": 1, "mode": "execute", "pool_id": manifest["pool_id"],
               "workers": [row["worker_id"] for row in manifest["children"]]}
    with PrivateDirectory.open(pending.root) as directory:
        path = directory.write(pool.REQUEST_FILE, pool.encode(request))
        directory.write(pool.APPROVAL_FILE, raw)
        return path
