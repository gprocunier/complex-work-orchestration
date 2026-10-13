"""Pinned inputs for the current controller's independent stage consumer.

The binding is controller-owned state, not worker-provided authority. Reads are
restricted to its frozen inventory and regular, non-symlink paths. This module
observes evidence; it neither grants authority nor issues success receipts.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass
from threading import RLock
from typing import Any

class StageEvidenceError(ValueError):
    pass

def exact(a: Any, b: Any) -> bool:
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(exact(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(exact(x, y) for x, y in zip(a, b))
    return a == b

@dataclass
class StageEvidenceBinding:
    root: Path
    data: dict
    admission_boundary: Any
    exclusion: Any

    def __post_init__(self):
        self.root = self.root.resolve()
        if type(self.data) is not dict or type(self.data.get('files')) is not dict:
            raise StageEvidenceError('stage-binding-inventory-invalid')
        if not hasattr(self.exclusion, '__enter__') or not hasattr(self.exclusion, '__exit__'):
            raise StageEvidenceError('stage-binding-exclusion-required')

def pinned(binding, path: str) -> Path:
    if type(path) is not str:
        raise StageEvidenceError('stage-path-type')
    p = Path(path)
    files = binding.data.get('files')
    if (not p.is_absolute() or '..' in p.parts or not p.is_relative_to(binding.root)
        or any(q.is_symlink() for q in (p, *p.parents)) or not p.is_file()):
        raise StageEvidenceError('stage-file-boundary')
    expected = files.get(path)
    if type(expected) is not str or len(expected) != 64:
        raise StageEvidenceError('stage-file-pin-missing')
    if hashlib.sha256(p.read_bytes()).hexdigest() != expected:
        raise StageEvidenceError('stage-file-pin-drift')
    return p

def read(binding, path: str) -> dict:
    p = pinned(binding, path)
    before = p.read_bytes()
    if hashlib.sha256(before).hexdigest() != binding.data['files'][path]:
        raise StageEvidenceError('stage-read-drift')
    try:
        value = json.loads(before)
    except (ValueError, UnicodeError) as e:
        raise StageEvidenceError('stage-json-invalid') from e
    if type(value) is not dict:
        raise StageEvidenceError('stage-json-object-required')
    if p.read_bytes() != before:
        raise StageEvidenceError('stage-read-drift')
    return value
