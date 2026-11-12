"""Bounded raw frames for the inert fake request consumer; unqualified."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

from cwo_core import server_request_preparation as prep


@dataclass(frozen=True)
class _Metadata:
    operative: bool = field(default=False, init=False)
    qualified: bool = field(default=False, init=False)
    effect_authority: bool = field(default=False, init=False)
    production_ready: bool = field(default=False, init=False)
    current_transport_wired: bool = field(default=False, init=False)


@dataclass(frozen=True)
class FrameStatus(_Metadata):
    epoch: str
    received_bytes: int
    completed_frames: int
    delivered_frames: int
    buffered_bytes: int
    closed: bool
    delivering: bool


_Message = prep.Response | prep.Notification | prep.ServerRequest


@dataclass(frozen=True)
class FrameBatch(_Metadata):
    delivered: tuple[_Message, ...]
    status: FrameStatus


class FramePreparationError(prep.PreparationError):
    """A structured refusal with truthful inert prefix data."""

    operative = False
    qualified = False
    effect_authority = False
    production_ready = False
    current_transport_wired = False

    def __init__(
        self, code: str, status: FrameStatus | None, delivered: tuple[_Message, ...] = (),
        *, fatal: bool = True,
    ) -> None:
        self.code = code
        self.status = status
        self.delivered = tuple(delivered)
        self.fatal = fatal
        self.delivered_count = len(self.delivered)
        self.delivered_total = status.delivered_frames if status is not None else 0
        super().__init__(
            f"{code}; delivered_prefix={self.delivered_count};"
            f" delivered_total={self.delivered_total};"
            " operative=false; qualified=false; effect_authority=false;"
            " production_ready=false; current_transport_wired=false"
        )


def _bound(value: Any, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise FramePreparationError("invalid-reader-bound", None, fatal=False)
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise prep.PreparationError("duplicate-textual-key")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise prep.PreparationError("nonfinite-number")


def _check_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > 17:
                raise prep.PreparationError("message-size-or-depth")
        elif character in "]}":
            depth -= 1


def _decode(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        _check_depth(text)
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    except prep.PreparationError:
        raise
    except UnicodeError as error:
        raise prep.PreparationError("invalid-utf8") from error
    except (ValueError, OverflowError, RecursionError) as error:
        raise prep.PreparationError("invalid-json-or-native-limit") from error


class FakeFrameReader:
    """An in-memory frame owner for one existing fake consumer epoch."""

    def __init__(
        self, consumer: prep.FakeRequestPreparer, *,
        max_frame_bytes: int = 65536, max_chunk_bytes: int = 65538,
        max_total_bytes: int = 1048576, max_frames: int = 256,
    ) -> None:
        if type(consumer) is not prep.FakeRequestPreparer:
            raise FramePreparationError("fake-consumer-required", None, fatal=False)
        self._frame_bound = _bound(max_frame_bytes, 65536)
        self._chunk_bound = _bound(max_chunk_bytes, 65538)
        self._total_bound = _bound(max_total_bytes, 16777216)
        self._frame_count_bound = _bound(max_frames, 4096)
        self._consumer = consumer
        self._lock = consumer._lock
        with self._lock:
            self._epoch = consumer._epoch
            self._last_now = consumer._last_now
            self._closed = consumer._closed
            self._buffer = bytearray()
            self._received_bytes = 0
            self._completed_frames = 0
            self._delivered_frames = 0
            self._busy = False
            self._delivering = False

    def _state(self) -> FrameStatus:
        return FrameStatus(
            self._epoch, self._received_bytes, self._completed_frames,
            self._delivered_frames, len(self._buffer), self._closed, self._delivering,
        )

    def snapshot(self) -> FrameStatus:
        """Return inert state, including synchronous delivery observations."""
        with self._lock:
            return self._state()

    def _refuse(self, code: str) -> None:
        raise FramePreparationError(code, self._state(), fatal=False)

    def _check_call(self, epoch: str, now: int) -> None:
        if self._busy:
            self._refuse("reentrant-operation")
        if type(epoch) is not str or epoch != self._epoch:
            self._refuse("closed-or-stale-epoch")
        minimum = max(self._last_now, self._consumer._last_now)
        if type(now) is not int or not minimum <= now <= 2**63 - 1:
            self._refuse("invalid-fake-time")
        if self._consumer._epoch != self._epoch or self._consumer._closed:
            self._closed = True
            self._buffer.clear()
        if self._closed:
            self._refuse("reader-closed")

    def _close(self) -> None:
        self._closed = True
        self._buffer.clear()
        if self._consumer._epoch == self._epoch:
            self._consumer.eof(now=max(self._last_now, self._consumer._last_now))

    def _fail(self, code: str, delivered: list[_Message]) -> None:
        self._close()
        raise FramePreparationError(code, self._state(), tuple(delivered)) from None

    def _finish_line(self) -> _Message:
        raw = bytes(self._buffer)
        self._buffer.clear()
        self._completed_frames += 1
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw.strip(b" \t\r"):
            raise prep.PreparationError("blank-frame")
        value = _decode(raw)
        self._delivering = True
        try:
            message = self._consumer.receive(value, epoch=self._epoch, now=self._last_now)
        finally:
            self._delivering = False
        self._delivered_frames += 1
        return message

    def _advance(self, octet: int) -> _Message | None:
        if self._received_bytes >= self._total_bound:
            raise prep.PreparationError("total-byte-bound")
        if self._completed_frames >= self._frame_count_bound:
            raise prep.PreparationError("message-count-bound")
        if octet == 10:
            self._received_bytes += 1
            return self._finish_line()
        if len(self._buffer) >= self._frame_bound:
            if len(self._buffer) != self._frame_bound or octet != 13:
                raise prep.PreparationError("frame-byte-bound")
        self._buffer.append(octet)
        self._received_bytes += 1
        return None

    def feed(self, chunk: bytes, *, epoch: str, now: int) -> FrameBatch:
        """Consume only supplied bytes; a failure retains its delivered prefix."""
        with self._lock:
            self._check_call(epoch, now)
            if type(chunk) is not bytes:
                self._refuse("byte-chunk-required")
            self._last_now = now
            self._busy = True
            delivered: list[_Message] = []
            try:
                if len(chunk) > self._chunk_bound:
                    raise prep.PreparationError("chunk-byte-bound")
                for octet in chunk:
                    message = self._advance(octet)
                    if message is not None:
                        delivered.append(message)
            except prep.PreparationError as error:
                self._fail(str(error), delivered)
            except (ValueError, OverflowError, RecursionError):
                self._fail("native-preparation-limit", delivered)
            finally:
                self._busy = False
            return FrameBatch(tuple(delivered), self._state())

    def eof(self, *, epoch: str, now: int) -> FrameBatch:
        """Close the fake epoch; every nonempty unfinished line is refused."""
        with self._lock:
            self._check_call(epoch, now)
            self._last_now = now
            self._busy = True
            try:
                if self._buffer:
                    raise prep.PreparationError("partial-eof-frame")
                self._close()
            except prep.PreparationError as error:
                self._fail(str(error), [])
            except (ValueError, OverflowError, RecursionError):
                self._fail("native-preparation-limit", [])
            finally:
                self._busy = False
            return FrameBatch((), self._state())


__all__ = [
    "FramePreparationError", "FrameStatus", "FrameBatch", "FakeFrameReader",
]
