"""Finite private-root boundary for the registered launcher's directory mounts.

This rejects unsupported layouts; it issues no authority and is not a native
confidentiality observation. Callers supply every actual private custody root.
"""
from __future__ import annotations

import os
from pathlib import Path

import offline_n1_host as host

_RUNTIME = (Path("/usr"), Path("/lib"), Path("/lib64"))


class HostRootBoundaryError(ValueError):
    """A protected root intersects a registered child-visible directory mount."""


def require_private_roots(paths, *, visible_paths=()):
    """Refuse fixed-mount intersections, retaining original directory checks.

    Runtime aliases are resolved on each check. Private inputs must themselves
    pass the original bounded absolute canonical path check. Directory-state
    validation stays with the original callers, including the lazy ledger root.
    """
    visible = (*_RUNTIME, *(host._path(value) for value in visible_paths))
    visible += tuple(Path(os.path.realpath(root)) for root in visible)
    for value in paths:
        path = host._path(value)
        if any(host._within(path, root) or host._within(root, path) for root in visible):
            raise HostRootBoundaryError("Protected roots intersect registered child directory mounts.")
