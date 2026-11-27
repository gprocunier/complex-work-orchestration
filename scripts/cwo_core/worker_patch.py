"""Check and apply a bounded, one-file unified text diff in memory."""

from io import BytesIO
import re

from .path_contract import path_components


class WorkerPatchError(ValueError):
    """The proposed diff does not fit the approved file edit."""


MAX_WORKER_DIFF_BYTES = 8_192
MAX_WORKER_PATCH_BYTES = 65_536

_INDEX = re.compile(rb"index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: 100(?:644|755))?\n")
_NUMBER = rb"(0|[1-9][0-9]{0,18})"
_RANGE = _NUMBER + rb"(?:," + _NUMBER + rb")?"
_HUNK = re.compile(rb"@@ -" + _RANGE + rb" \+" + _RANGE + rb" @@(?: [^\r\n]*)?\n")
_BODY_OPERATIONS = (b" ", b"-", b"+")
_NO_NEWLINE = b"\\ No newline at end of file\n"


def _diff_bytes(diff: str, before: bytes, maximum_bytes: int) -> bytes:
    diff_limit = min(maximum_bytes, MAX_WORKER_DIFF_BYTES)
    if type(diff) is not str or type(before) is not bytes:
        raise WorkerPatchError("the diff and its preimage must be text and bytes")
    if len(diff) > diff_limit or len(before) > maximum_bytes:
        raise WorkerPatchError("the diff or preimage exceeds its byte limit")
    try:
        wire = diff.encode("utf-8")
        before.decode("utf-8")
    except UnicodeError as failure:
        raise WorkerPatchError("the diff and preimage must be UTF-8") from failure
    if len(wire) > diff_limit:
        raise WorkerPatchError("the diff exceeds its byte limit")
    if b"\x00" in wire or b"\x00" in before or not wire.endswith(b"\n"):
        raise WorkerPatchError("the diff and preimage must be text and the diff must end with LF")
    return wire


def _target_bytes(target: str, maximum_bytes: int) -> bytes:
    if type(target) is not str or len(target) > maximum_bytes:
        raise WorkerPatchError("the signed patch target is invalid")
    parts = path_components(target)
    if parts is None or "/".join(parts) != target or any(char in target for char in "\r\n\t"):
        raise WorkerPatchError("the signed patch target is not a canonical relative path")
    try:
        return target.encode("utf-8")
    except UnicodeError as failure:
        raise WorkerPatchError("the signed patch target must be UTF-8") from failure


def _headers(lines: list[bytes], target: bytes) -> int:
    before = b"--- a/" + target + b"\n"
    after = b"+++ b/" + target + b"\n"
    if not lines[0].startswith(b"diff --git "):
        direct = [b"--- " + target + b"\n", b"+++ " + target + b"\n"]
        if lines[:2] in ([before, after], direct):
            return 2
        raise WorkerPatchError("both file headers must match the signed target")
    if lines[0] != b"diff --git a/" + target + b" b/" + target + b"\n":
        raise WorkerPatchError("the Git envelope must match the signed target")
    index = 1
    if len(lines) > index and lines[index].startswith(b"index "):
        matched = _INDEX.fullmatch(lines[index])
        if matched is None or any(not blob.strip(b"0") for blob in matched.groups()):
            raise WorkerPatchError("only ordinary file index metadata is supported")
        index += 1
    if lines[index:index + 2] != [before, after]:
        raise WorkerPatchError("both file headers must match the signed target")
    return index + 2


def _coordinates(start: bytes, count: bytes | None) -> tuple[int, int]:
    line = int(start)
    length = 1 if count is None else int(count)
    if length and line == 0:
        raise WorkerPatchError("a nonempty hunk range starts at line one or later")
    return (line - 1 if length else line), length


def _hunk_ranges(header: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    matched = _HUNK.fullmatch(header)
    if matched is None:
        raise WorkerPatchError("a single file with unified diff hunks is required")
    old_start, old_count, new_start, new_count = matched.groups()
    return _coordinates(old_start, old_count), _coordinates(new_start, new_count)


def _body_line(lines: list[bytes], index: int) -> tuple[bytes, bytes, int]:
    current = lines[index]
    index += 1
    operation, content = current[:1], current[1:]
    if index < len(lines) and lines[index] == _NO_NEWLINE:
        if content == b"\n":
            raise WorkerPatchError("an unterminated line must contain text")
        return operation, content[:-1], index + 1
    return operation, content, index


def _apply_hunk(
    lines: list[bytes], index: int, original: list[bytes], old_offset: int, old_end: int, new_count: int,
) -> tuple[int, list[bytes]]:
    result = []
    changed = False
    while index < len(lines) and lines[index][:1] in _BODY_OPERATIONS:
        operation, content, index = _body_line(lines, index)
        if operation != b"+":
            if old_offset >= old_end or original[old_offset] != content:
                raise WorkerPatchError("hunk context or removed bytes differ from the preimage")
            old_offset += 1
        if operation != b"-":
            result.append(content)
            if len(result) > new_count:
                raise WorkerPatchError("hunk counts differ from its body")
        changed |= operation != b" "
    if old_offset != old_end or len(result) != new_count or not changed:
        raise WorkerPatchError("hunk counts or changes differ from its body")
    return index, result


def apply_worker_patch(diff: str, target: str, before: bytes, *, maximum_bytes: int) -> bytes:
    """Apply LF-delimited UTF-8 hunks to one existing file's exact preimage.

    The caller's cap applies to all inputs and the result. The protocol diff
    limit and the file byte limit also apply. File headers name the exact
    canonical target. An unquoted Git envelope may supply ordinary index metadata.
    """
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise WorkerPatchError("a positive patch byte limit is required")
    maximum_bytes = min(maximum_bytes, MAX_WORKER_PATCH_BYTES)
    wire = _diff_bytes(diff, before, maximum_bytes)
    lines = BytesIO(wire).readlines()
    index = _headers(lines, _target_bytes(target, maximum_bytes))
    if index == len(lines):
        raise WorkerPatchError("the patch must contain a hunk")
    original = BytesIO(before).readlines()
    old_cursor = 0
    result = []
    while index < len(lines):
        (old_offset, old_count), (new_offset, new_count) = _hunk_ranges(lines[index])
        old_end = old_offset + old_count
        if old_offset < old_cursor or old_end > len(original):
            raise WorkerPatchError("hunk ranges overlap or exceed the preimage")
        if new_offset != len(result) + old_offset - old_cursor:
            raise WorkerPatchError("hunk output coordinates differ from the preceding lines")
        result.extend(original[old_cursor:old_offset])
        index, replacement = _apply_hunk(lines, index + 1, original, old_offset, old_end, new_count)
        result.extend(replacement)
        old_cursor = old_end
    result.extend(original[old_cursor:])
    if any(not line.endswith(b"\n") for line in result[:-1]):
        raise WorkerPatchError("an unterminated line must be at the end of the result")
    if sum(map(len, result)) > maximum_bytes:
        raise WorkerPatchError("the patched file exceeds its byte limit")
    after = b"".join(result)
    if after == before:
        raise WorkerPatchError("the patch leaves the file unchanged")
    return after
