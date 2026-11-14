"""Private immutable captures of renderer inputs and their screened output."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from .outbound_screen import OutboundRefused, SCREEN_VERSION, ScreenedPayload


def _canonical(source: Any) -> bytes:
    try:
        return json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise OutboundRefused("outbound preparation refused: source cannot be captured") from None


@dataclass(frozen=True)
class PreparedSource:
    """Canonical inputs, including render options, and only explicitly read input files.

    Artifact and snippet paths in a packet are inline descriptions, never files to reopen.
    Original file contents and source bytes stay private, including in repr and diagnostics.
    """

    data: bytes = field(repr=False)
    files: tuple[tuple[str, bytes], ...] = field(default=(), repr=False)

    @classmethod
    def capture(cls, source: Any, files=()) -> PreparedSource:
        return cls(_canonical(source), tuple((str(path), bytes(raw)) for path, raw in files))

    @property
    def sha256(self) -> str:
        # File identity participates without disclosing its path or original contents.
        file_digests = [(path, hashlib.sha256(raw).hexdigest()) for path, raw in self.files]
        return hashlib.sha256(_canonical([self.data.decode("ascii"), file_digests])).hexdigest()

    def value(self) -> Any:
        """A detached rendering input; rendering never revisits a mutable original."""
        return json.loads(self.data)

    def require_unchanged(self, source: Any) -> None:
        if _canonical(source) != self.data:
            raise OutboundRefused("outbound preparation refused: source changed after capture")
        try:
            same = all(Path(path).read_bytes() == raw for path, raw in self.files)
        except OSError:
            same = False
        if not same:
            raise OutboundRefused("outbound preparation refused: input file changed after capture")

    def bind(self, source: Any, screened: ScreenedPayload) -> PreparedOutbound:
        self.require_unchanged(source)
        screened.require_unchanged(screened.data)
        return PreparedOutbound(self, screened)


@dataclass(frozen=True)
class PreparedOutbound:
    source: PreparedSource
    payload: ScreenedPayload = field(repr=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical([self.source.sha256, self.payload.sha256,
                                         self.payload.surface, SCREEN_VERSION])).hexdigest()

    def require_unchanged(self, source: Any, output: bytes | str) -> bytes:
        self.source.require_unchanged(source)
        return self.payload.require_unchanged(output)

    def metadata(self) -> dict[str, Any]:
        return {"outbound_source_sha256": self.source.sha256,
                "outbound_export_sha256": self.payload.sha256,
                "outbound_prepared_sha256": self.sha256,
                "outbound_screen_version": SCREEN_VERSION}
