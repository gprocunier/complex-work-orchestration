"""Canonical repository-relative path contract for scope checks.

A path is a sequence of components separated by ``/``. Empty and ``.``
components are ignored, so ``./a`` and ``a//b`` mean ``a`` and ``a/b``. Any
``..`` component, an absolute path or a NUL byte makes the path invalid; it is
never rewritten into something allowed. Names are compared exactly: hidden
names keep their dots, ``..cache`` is an ordinary name, and spaces or quotes
are part of the name.

This is a lexical contract. It does not resolve symlinks or protect against a
path being replaced between the check and its use.
"""

from __future__ import annotations


def path_components(path: object) -> tuple[str, ...] | None:
    """Return the components of a valid relative path, or None if invalid."""
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        return None
    components: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        components.append(part)
    return tuple(components) or None


def path_within(path: object, allowed_paths: list[str] | tuple[str, ...] | None) -> bool:
    """True when ``path`` equals or lies under one of ``allowed_paths``, by components."""
    candidate = path_components(path)
    if candidate is None:
        return False
    for raw in allowed_paths or ():
        allowed = path_components(raw)
        if allowed is not None and candidate[: len(allowed)] == allowed:
            return True
    return False
