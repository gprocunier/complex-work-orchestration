"""Small byte-preserving copies for caller-owned test workspaces."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


def copy_context_files(
    source_root: Path, workspace: Path, relative_paths: Iterable[str],
) -> Path:
    """Copy only named context files; the real receipt fixture creates Git."""
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative in relative_paths:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts:
            raise ValueError("fixture context must be relative and exclude Git metadata")
        target = workspace / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes((source_root / path).read_bytes())
    return workspace
