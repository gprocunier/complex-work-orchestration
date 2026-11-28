from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .paths import cwo_temp_dir
from .util import artifact_hash, metadata_json

DEFAULT_BEADS_TIMEOUT_SECONDS = 300
BEADS_DEPENDENCY_TYPES = frozenset(
    {
        "blocks",
        "tracks",
        "related",
        "parent-child",
        "discovered-from",
        "until",
        "caused-by",
        "validates",
        "relates-to",
        "supersedes",
    }
)


@dataclass(frozen=True, slots=True)
class BdCommandResult:
    """Structured result for admission-sensitive Beads commands.

    A timeout is deliberately represented instead of raised: a write may have
    committed before the client deadline, so callers must reconcile it with an
    exact ``bd show`` against the same explicit database.
    """

    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    timeout_seconds: int

    @property
    def succeeded(self) -> bool:
        return self.timed_out is False and self.returncode == 0

    @property
    def outcome_ambiguous(self) -> bool:
        return self.timed_out


def run_bd_structured(
    args: Sequence[str],
    *,
    directory: Path | str,
    database: Path | str,
    actor: str,
    timeout: int | None = None,
) -> BdCommandResult:
    """Run ``bd`` at an explicit admission boundary without hiding ambiguity."""

    require_bd()
    target = Path(directory).absolute()
    database_value = str(database).strip()
    actor_value = str(actor).strip()
    if not target.is_dir():
        raise ValueError("beads-directory-must-exist")
    if not database_value:
        raise ValueError("beads-database-must-be-explicit")
    if not actor_value:
        raise ValueError("beads-actor-must-be-explicit")
    if (
        not isinstance(args, Sequence)
        or isinstance(args, (str, bytes))
        or not args
        or any(type(item) is not str or not item for item in args)
    ):
        raise ValueError("beads-args-must-be-nonempty-strings")
    seconds = beads_timeout_seconds(timeout)
    command = (
        "bd",
        "-C",
        str(target),
        "--db",
        database_value,
        "--actor",
        actor_value,
        *args,
    )
    try:
        completed = _bd_process(command, directory=target, seconds=seconds)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return BdCommandResult(command, None, stdout, stderr, timed_out=True, timeout_seconds=seconds)
    return BdCommandResult(command, completed.returncode, completed.stdout, completed.stderr,
                           timed_out=False, timeout_seconds=seconds)


def show_bead_exact_structured(
    bead_id: str,
    *,
    directory: Path | str,
    database: Path | str,
    actor: str,
    timeout: int | None = None,
) -> tuple[BdCommandResult, Mapping[str, Any] | None]:
    """Return one exact issue projection and the command evidence that read it."""

    issue_id = str(bead_id).strip()
    if not issue_id:
        raise ValueError("bead-id-must-be-nonempty")
    result = run_bd_structured(
        ("show", "--json", "--", issue_id),
        directory=directory,
        database=database,
        actor=actor,
        timeout=timeout,
    )
    if not result.succeeded:
        return result, None
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result, None
    if isinstance(decoded, list) and len(decoded) == 1:
        decoded = decoded[0]
    return result, dict(decoded) if isinstance(decoded, Mapping) else None


def require_bd() -> None:
    if not shutil.which("bd"):
        raise SystemExit("bd was not found; install Beads or use --dry-run")


def beads_timeout_seconds(timeout: int | None = None) -> int:
    if timeout is not None:
        return int(timeout)
    configured = os.environ.get("CWO_BEADS_TIMEOUT_SECONDS")
    if configured:
        try:
            value = int(configured)
        except ValueError as exc:
            raise SystemExit("CWO_BEADS_TIMEOUT_SECONDS must be an integer") from exc
        if value <= 0:
            raise SystemExit("CWO_BEADS_TIMEOUT_SECONDS must be positive")
        return value
    return DEFAULT_BEADS_TIMEOUT_SECONDS


def _bd_process(
    command: Sequence[str], *, directory: Path | None, seconds: int, environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env_option = {} if environment is None else {"env": environment}
    return subprocess.run(command, check=False, cwd=directory, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=seconds, **env_option)


def run_bd_explicit(
    args: list[str], timeout: int | None = None, *, directory: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Transport for commands that already carry their database selector."""
    require_bd()
    seconds = beads_timeout_seconds(timeout)
    command = ["bd", *args]
    try:
        completed = _bd_process(command, directory=directory, seconds=seconds, environment=environment)
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"bd command timed out after {seconds}s: {' '.join(command)}") from exc
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "bd command failed")
    return completed.stdout


def database_identity(path: Path) -> str:
    info = path.stat()
    return artifact_hash(f"{path}\0{info.st_dev}\0{info.st_ino}")


@dataclass(frozen=True, slots=True)
class ProjectBeads:
    selector: Path
    storage: Path
    identity: str
    run: Callable[[list[str]], str]


def _project_root(start: Path) -> Path:
    for directory in (start, *start.parents):
        if os.path.lexists(directory / ".git") or os.path.lexists(directory / ".beads"):
            return directory
    return start


def _project_location(run: Callable[[list[str]], str], selection: list[str]) -> tuple[Path, Path]:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("database projection contains duplicate JSON keys")
        return result

    raw = run([*selection, "where", "--json"])
    if len(raw.encode()) > 4 * 1024 * 1024:
        raise ValueError("database projection exceeds the control bound")
    location = json.loads(raw, object_pairs_hook=unique_keys)
    if isinstance(location, dict):
        selector, storage = location.get("path"), location.get("database_path")
        if all(isinstance(path, str) and Path(path).is_absolute() for path in (selector, storage)):
            return Path(selector).resolve(strict=True), Path(storage).resolve(strict=True)
    raise ValueError("Beads did not identify an absolute project database location")


def _bind_project_beads(
    directory: Path | None, environment: dict[str, str], timeout: int | None,
) -> ProjectBeads:
    start = (directory or Path.cwd()).resolve(strict=True)
    if not start.is_dir():
        raise ValueError("Beads project must be a directory")
    root = _project_root(start)
    beads_dir = environment.pop("BEADS_DIR", "")
    seconds = beads_timeout_seconds(timeout)
    # Beads' native cwd discovery respects nested checkout boundaries and worktrees.
    def command(args: list[str]) -> str:
        return run_bd_explicit(args, seconds, directory=root, environment=environment)

    selection = ["--db", str((root / beads_dir).resolve(strict=True))] if beads_dir else []
    selector, storage = _project_location(command, selection)
    pinned = ["--db", str(selector)]
    identity, selector_identity = database_identity(storage), database_identity(selector)
    if _project_location(command, pinned) != (selector, storage):
        raise ValueError("the explicit Beads command selected another database")

    def run(args: list[str]) -> str:
        try:
            current = database_identity(storage), database_identity(selector)
        except OSError as exc:
            raise SystemExit("the project Beads database is no longer available") from exc
        if current != (identity, selector_identity):
            raise SystemExit("the project Beads database changed during this invocation")
        return command([*pinned, *args])

    return ProjectBeads(selector, storage, identity, run)


def bind_project_beads(directory: Path | None = None, *, timeout: int | None = None) -> ProjectBeads:
    """Resolve and verify the caller's project database before any issue operations."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    try:
        return _bind_project_beads(directory, environment, timeout)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"could not bind the project Beads database: {exc}") from exc


def run_bd(
    args: list[str], timeout: int | None = None, *,
    directory: Path | None = None, binding: ProjectBeads | None = None,
) -> str:
    project = bind_project_beads(directory, timeout=timeout) if binding is None else binding
    return project.run(args)


def parse_created_issue_id(output: str) -> str:
    match = re.search(r"Created issue:\s+([^\s]+)", output)
    if match:
        return match.group(1)
    stripped = output.strip()
    return stripped if " " not in stripped else ""


def bead_field_value(value: str | list[str] | None) -> str | None:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None and str(item).strip())
    stripped = str(value).strip() if value is not None else ""
    return stripped or None


def bead_text_value(value: str | None) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text.replace("\\r\\n", "\n").replace("\\n", "\n") if text else None


def create_bead(
    title: str,
    *,
    issue_type: str = "task",
    priority: int = 2,
    parent: str | None = None,
    labels: list[str] | None = None,
    skills: str | list[str] | None = None,
    description: str | None = None,
    acceptance: str | None = None,
    design: str | None = None,
    notes: str | None = None,
    metadata: dict[str, Any] | None = None,
    binding: ProjectBeads | None = None,
) -> dict[str, Any]:
    args = ["create", "--type", issue_type, "--priority", str(priority)]
    temp_paths: list[Path] = []

    def temp_file_arg(prefix: str, suffix: str, content: str) -> str:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", prefix=prefix, suffix=suffix,
            dir=cwo_temp_dir(scope="session", purpose="beads"), delete=False,
        ) as handle:
            handle.write(content)
            temp_paths.append(Path(handle.name))
            return handle.name

    for flag, value in (("--parent", parent), ("--labels", ",".join(labels or [])), ("--skills", bead_field_value(skills))):
        if value:
            args.extend([flag, value])
    text_fields = (
        ("description", description, "--body-file"), ("acceptance", acceptance, None),
        ("design", design, "--design-file"), ("notes", notes, None),
    )
    for field, value, file_flag in text_fields:
        if text := bead_text_value(value):
            if file_flag and len(text) > 4000:
                args.extend([file_flag, temp_file_arg(f"cwo-bd-{field}-", ".md", text)])
            else:
                args.extend([f"--{field}", text])
    if metadata:
        metadata_path = temp_file_arg("cwo-bd-metadata-", ".json", metadata_json(metadata))
        args.extend(["--metadata", f"@{metadata_path}"])
    args.extend(["--", title])
    try:
        output = run_bd(args) if binding is None else run_bd(args, binding=binding)
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)
    return {"id": parse_created_issue_id(output), "title": title, "raw_output": output.strip()}


def show_bead_args(bead_id: str, *, include_comments: bool = False, include_dependents: bool = False) -> list[str]:
    """Return the ``bd`` arguments for one JSON show.

    Every option precedes ``--`` so that the Bead ID after it is always an
    operand, even when it begins with ``-``.
    """

    args = ["show", "--json"]
    if include_comments:
        args.append("--include-comments")
    if include_dependents:
        args.append("--include-dependents")
    return [*args, "--", bead_id]


def show_bead_json(bead_id: str, *, include_comments: bool = False, include_dependents: bool = False,
                   directory: Path | None = None) -> Any:
    args = show_bead_args(bead_id, include_comments=include_comments, include_dependents=include_dependents)
    output = run_bd(args) if directory is None else run_bd(args, directory=directory)
    return json.loads(output)


def bead_id_operand(value: str) -> str:
    """Return a Bead ID for a ``bd`` operand slot, refusing option-like text.

    Repository Bead IDs begin with a letter or digit, so a leading ``-`` is
    never an ordinary ID. ``bd dep add`` (1.3.1) stores an unresolved
    depends-on ID as given for nonblocking types, even after ``--``, so the
    refusal happens here, before ``bd`` runs.
    """

    if value.startswith("-"):
        raise ValueError(f"refusing option-like Bead ID: {value!r}")
    return value


def normalize_dependency_type(value: str) -> str:
    dependency_type = str(value or "").strip().lower().replace("_", "-")
    if dependency_type not in BEADS_DEPENDENCY_TYPES:
        choices = ", ".join(sorted(BEADS_DEPENDENCY_TYPES))
        raise ValueError(f"dependency_type must be one of {choices}")
    return dependency_type


def add_dependency(
    blocked: str,
    blocker: str,
    *,
    dependency_type: str = "blocks",
    binding: ProjectBeads | None = None,
) -> None:
    """Add one explicit typed Beads relationship.

    Only ``blocks`` (and Beads' time-oriented ``until`` relation) should be
    used as readiness prerequisites.  Tracking, validation, publication, and
    provenance relationships must retain their nonblocking type.
    """

    normalized = normalize_dependency_type(dependency_type)
    args = ["dep", "add", "--type", normalized, "--", bead_id_operand(blocked), bead_id_operand(blocker)]
    run_bd(args, binding=binding)
