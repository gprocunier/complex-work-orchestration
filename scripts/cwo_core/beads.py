from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .paths import REPO_ROOT, cwo_temp_dir
from .util import metadata_json

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


def run_bd(args: list[str], timeout: int | None = None) -> str:
    require_bd()
    seconds = beads_timeout_seconds(timeout)
    command = ["bd", *args]
    try:
        completed = subprocess.run(
            command,
            check=False,
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"bd command timed out after {seconds}s: {' '.join(command)}") from exc
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or completed.stdout.strip() or "bd command failed")
    return completed.stdout


def parse_created_issue_id(output: str) -> str:
    match = re.search(r"Created issue:\s+([^\s]+)", output)
    if match:
        return match.group(1)
    stripped = output.strip()
    if stripped and " " not in stripped:
        return stripped
    return ""


def bead_field_value(value: str | list[str] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item is not None and str(item).strip())
    stripped = str(value).strip()
    return stripped or None


def bead_text_value(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = str(value).strip()
    if not stripped:
        return None
    return stripped.replace("\\r\\n", "\n").replace("\\n", "\n")


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
) -> dict[str, Any]:
    args = ["create", title, "--type", issue_type, "--priority", str(priority)]
    temp_paths: list[Path] = []

    def temp_file_arg(prefix: str, suffix: str, content: str) -> str:
        temp_dir = cwo_temp_dir(scope="session", purpose="beads")
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix=prefix,
            suffix=suffix,
            dir=temp_dir,
            delete=False,
        ) as handle:
            handle.write(content)
            temp_paths.append(Path(handle.name))
            return handle.name

    if parent:
        args.extend(["--parent", parent])
    if labels:
        args.extend(["--labels", ",".join(labels)])
    skills_value = bead_field_value(skills)
    if skills_value:
        args.extend(["--skills", skills_value])
    description_value = bead_text_value(description)
    if description_value:
        if len(description_value) > 4000:
            args.extend(["--body-file", temp_file_arg("cwo-bd-description-", ".md", description_value)])
        else:
            args.extend(["--description", description_value])
    acceptance_value = bead_text_value(acceptance)
    if acceptance_value:
        args.extend(["--acceptance", acceptance_value])
    design_value = bead_text_value(design)
    if design_value:
        if len(design_value) > 4000:
            args.extend(["--design-file", temp_file_arg("cwo-bd-design-", ".md", design_value)])
        else:
            args.extend(["--design", design_value])
    notes_value = bead_text_value(notes)
    if notes_value:
        args.extend(["--notes", notes_value])
    if metadata:
        metadata_path = temp_file_arg("cwo-bd-metadata-", ".json", metadata_json(metadata))
        args.extend(["--metadata", f"@{metadata_path}"])
    try:
        output = run_bd(args)
    finally:
        for path in temp_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    return {"id": parse_created_issue_id(output), "title": title, "raw_output": output.strip()}


def show_bead_json(bead_id: str, *, include_comments: bool = False, include_dependents: bool = False) -> Any:
    args = ["show", bead_id, "--json"]
    if include_comments:
        args.append("--include-comments")
    if include_dependents:
        args.append("--include-dependents")
    output = run_bd(args)
    return json.loads(output)


def normalize_dependency_type(value: str) -> str:
    dependency_type = str(value or "").strip().lower().replace("_", "-")
    if dependency_type not in BEADS_DEPENDENCY_TYPES:
        raise ValueError(
            "dependency_type must be one of "
            + ", ".join(sorted(BEADS_DEPENDENCY_TYPES))
        )
    return dependency_type


def add_dependency(
    blocked: str,
    blocker: str,
    *,
    dependency_type: str = "blocks",
) -> None:
    """Add one explicit typed Beads relationship.

    Only ``blocks`` (and Beads' time-oriented ``until`` relation) should be
    used as readiness prerequisites.  Tracking, validation, publication, and
    provenance relationships must retain their nonblocking type.
    """

    normalized = normalize_dependency_type(dependency_type)
    run_bd(["dep", "add", blocked, blocker, "--type", normalized])
