"""Private JSON snapshot type for native supervision transport."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping



@dataclass(frozen=True)
class JsonArtifactSnapshot:
    """One immutable byte read and its parsed JSON object."""

    raw: bytes
    value: Mapping[str, Any]

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()
