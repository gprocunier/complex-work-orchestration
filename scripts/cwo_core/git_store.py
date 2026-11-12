"""Git-free reading of repository configuration, references and objects.

Inert inspection must not run Git against a workspace, because Git reopens
repository paths that a concurrent writer can replace. This module reads what
inspection needs from bytes the caller supplies through descriptors it opened
after checking the file type, and it checks every object against its own
identifier before using it.

Supported layouts: loose objects and version 2 pack indexes with offset and
reference deltas, in SHA-1 or SHA-256 repositories, with loose or packed
references. Anything else raises UnsupportedLayout, and an object that is not
present raises MissingObject. Nothing is fetched. Replacement references and
grafts are not applied, as with GIT_NO_REPLACE_OBJECTS.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import zlib
from dataclasses import dataclass
from typing import Callable, Iterator


class StoreError(Exception):
    """The repository cannot be read as this module reads it."""


class UnsupportedLayout(StoreError):
    pass


class MissingObject(StoreError):
    pass


class CorruptObject(StoreError):
    pass


# Configuration ----------------------------------------------------------

# Git's isspace(): space, tab, newline and carriage return; not vertical tab,
# form feed or any non-ASCII space.
GIT_SPACE = " \t\n\r"
GIT_SPACE_BYTES = GIT_SPACE.encode("ascii")
# As get_base_var reads a header: the name right after '[', then optionally
# whitespace and a quoted subsection, then ']' with nothing in between. The
# subsection is read in runs (_section_header): a pattern repeating a
# one-character alternation keeps matching state for every character, about a
# hundred bytes each, so a long subsection would amplify its own size.
_SECTION_NAME = re.compile(r"\[([A-Za-z0-9.-]+)")
_SUBSECTION_RUN = re.compile(r'[^"\\\n]+')
_KEY = re.compile(r"([A-Za-z][A-Za-z0-9-]*)[ \t]*")
_VALUE_ESCAPES = {"n": "\n", "t": "\t", "b": "\b", "\\": "\\", '"': '"'}


# How often the parsers below check the deadline, in loop steps.
TIME_CHECK_INTERVAL = 256
# Runs of characters a config value keeps as they are, outside and inside quotes.
_PLAIN_RUN = re.compile(r'[^\n\\"#; \t\r]+')
_QUOTED_RUN = re.compile(r'[^\n\\"]+')
_BLANK_RUN = re.compile(r"[ \t\r]+")

Charge = Callable[[], None]
ChargeBytes = Callable[[int], None]
# Characters of expanded entry names (section, subsection and key) one config
# file may make the parser build. Each entry repeats its section's prefix, so
# a long subsection over many entries would otherwise amplify a small file.
CONFIG_NAME_CHARACTERS = 4 * 1024 * 1024


def _line_end(text: str, index: int) -> int:
    end = text.find("\n", index)
    return len(text) if end == -1 else end + 1


def _section_header(text: str, index: int, check_time: Charge | None = None) -> tuple[str, int]:
    """The section a header at ``index`` opens and the index after its ``]``.

    The name is lowered; a quoted subsection is kept as written, each
    backslash escaping the character after it (not a newline). Plain runs
    are matched whole and written to one buffer, and ``check_time`` runs as
    they are, so the work and memory follow the header's size.
    """
    match = _SECTION_NAME.match(text, index)
    if match is None:
        raise UnsupportedLayout("config section header")
    name = match.group(1).lower()
    position = match.end()
    blanks = _BLANK_RUN.match(text, position)
    if blanks is None:
        if text.startswith("]", position):
            return name, position + 1
        raise UnsupportedLayout("config section header")
    position = blanks.end()
    if not text.startswith('"', position):
        raise UnsupportedLayout("config section header")
    position += 1
    subsection = io.StringIO()
    steps = 0
    while True:
        steps += 1
        if check_time is not None and not steps % TIME_CHECK_INTERVAL:
            check_time()
        run = _SUBSECTION_RUN.match(text, position)
        if run is not None:
            subsection.write(run.group())
            position = run.end()
            continue
        character = text[position:position + 1]
        if character == '"':
            position += 1
            break
        if character == "\\":
            following = text[position + 1:position + 2]
            if following in {"", "\n"}:
                raise UnsupportedLayout("config section header")
            subsection.write(following)
            position += 2
            continue
        raise UnsupportedLayout("config section header")  # a newline, or the end of the text
    if not text.startswith("]", position):
        raise UnsupportedLayout("config section header")
    return name + "." + subsection.getvalue(), position + 1


def parse_config(
    data: bytes, *, charge_entry: Charge | None = None, check_time: Charge | None = None,
    charge_bytes: ChargeBytes | None = None, max_name_characters: int = CONFIG_NAME_CHARACTERS,
) -> list[tuple[str, str | None]]:
    """Entries of a Git config file in order, as ``(name, value)``.

    Names are ``section.key`` or ``section.subsection.key``, with the section
    and key in lower case and the subsection as written. A key written without
    ``=`` has the value None (boolean true). Quoting, the escapes Git accepts,
    comments and backslash continuations are interpreted, and whitespace is
    Git's (space, tab, carriage return). Anything Git rejects, and text after
    a section header on its line, which Git would accept, raises
    UnsupportedLayout rather than being guessed at.

    ``charge_entry`` is called for each entry before anything of it is built,
    and raises when the caller's entry budget is spent; ``check_time`` is
    called periodically, within long values too, and raises after the
    caller's deadline. Before an entry's name is built, its length is passed
    to ``charge_bytes`` and counted against ``max_name_characters`` for the
    whole file; past that, UnsupportedLayout is raised before the name
    exists. The section prefix is built once per header and shared by
    reference until then.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedLayout("config is not UTF-8") from exc
    text = text.removeprefix("\ufeff").replace("\r\n", "\n")
    entries: list[tuple[str, str | None]] = []
    section: str | None = None
    name_characters = 0
    index = 0
    steps = 0
    while index < len(text):
        steps += 1
        if check_time is not None and not steps % TIME_CHECK_INTERVAL:
            check_time()
        blanks = _BLANK_RUN.match(text, index)
        if blanks is not None:
            index = blanks.end()
        if index >= len(text):
            break
        character = text[index]
        if character == "\n":
            index += 1
            continue
        if character in "#;":
            index = _line_end(text, index)
            continue
        if character == "[":
            # Built once per header; entries refer to it until their names are built.
            section, end = _section_header(text, index, check_time)
            blanks = _BLANK_RUN.match(text, end)
            after = blanks.end() if blanks is not None else end
            if after < len(text) and text[after] not in "\n#;":
                raise UnsupportedLayout("config text after a section header")
            index = _line_end(text, after)
            continue
        if section is None:
            raise UnsupportedLayout("config entry outside a section")
        match = _KEY.match(text, index)
        if match is None:
            raise UnsupportedLayout("config key")
        # Charged before the entry's name or value is built, and the name's size before the name.
        if charge_entry is not None:
            charge_entry()
        length = len(section) + 1 + match.end(1) - match.start(1)
        name_characters += length
        if name_characters > max_name_characters:
            raise UnsupportedLayout("config entry names would exceed the size this reader builds")
        if charge_bytes is not None:
            charge_bytes(length)
        name = f"{section}.{match.group(1).lower()}"
        index = match.end()
        if index >= len(text) or text[index] == "\n":
            entries.append((name, None))
            index += 1
            continue
        if text[index] != "=":
            # Git accepts only a newline or '=' here, not even a comment.
            raise UnsupportedLayout("config key not followed by '=' or the end of its line")
        value, index = _config_value(text, index + 1, check_time)
        entries.append((name, value))
    return entries


def _config_value(text: str, index: int, check_time: Charge | None = None) -> tuple[str, int]:
    """One config value starting at ``index``; returns it and the index after its line.

    Leading and trailing whitespace outside quotes is dropped and internal
    whitespace kept, as Git does. The value is read in runs and written to
    one buffer, so its size, not its character count, bounds what is
    allocated; the deadline is checked as the runs are read.
    """
    out = io.StringIO()
    pending_space = ""
    quoted = False
    started = False
    steps = 0
    while index < len(text):
        steps += 1
        if check_time is not None and not steps % TIME_CHECK_INTERVAL:
            check_time()
        character = text[index]
        if character == "\n":
            if quoted:
                raise UnsupportedLayout("unterminated quote in config value")
            index += 1
            break
        if character == "\\":
            following = text[index + 1:index + 2]
            if following == "\n":
                index += 2  # a continuation line
                continue
            if following not in _VALUE_ESCAPES:
                raise UnsupportedLayout("unsupported escape in config value")
            out.write(pending_space)
            out.write(_VALUE_ESCAPES[following])
            pending_space = ""
            started = True
            index += 2
            continue
        if character == '"':
            quoted = not quoted
            out.write(pending_space)
            pending_space = ""
            started = True
            index += 1
            continue
        if not quoted and character in "#;":
            index = _line_end(text, index)
            break
        if not quoted and character in " \t\r":
            blanks = _BLANK_RUN.match(text, index)
            if started:
                pending_space += blanks.group()
            index = blanks.end()
            continue
        run = (_QUOTED_RUN if quoted else _PLAIN_RUN).match(text, index)
        out.write(pending_space)
        out.write(run.group())
        pending_space = ""
        started = True
        index = run.end()
    if quoted:
        raise UnsupportedLayout("unterminated quote in config value")
    return out.getvalue(), index


# Git's integer syntax (strtoimax with base 0, then an optional unit), as git_parse_int reads it.
_C_INTEGER = re.compile(r"[ \t\n\v\f\r]*([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)([kKmMgG]?)")
_UNIT_FACTORS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
_INT_MAX = (1 << 31) - 1
# More significant digits than any value in range can have, in any base; a
# longer number is out of range for Git too and is never handed to int().
_MAX_SIGNIFICANT_DIGITS = 24


def config_int(value: str | None) -> int | None:
    """``value`` as Git's ``git_parse_int`` reads it; None where Git finds no integer or one out of range."""
    if value is None:
        return None
    match = _C_INTEGER.fullmatch(value)
    if match is None:
        return None
    sign, digits, unit = match.groups()
    if digits[:2] in {"0x", "0X"}:
        body, base = digits[2:], 16
    else:
        body, base = digits, 8 if digits.startswith("0") else 10
    body = body.lstrip("0") or "0"
    if len(body) > _MAX_SIGNIFICANT_DIGITS:
        return None
    number = int(body, base)
    number = -number if sign == "-" else number
    factor = _UNIT_FACTORS[unit.lower()]
    limit = _INT_MAX // factor
    if number > limit or number < -limit:
        return None
    return number * factor


def config_maybe_bool(value: str | None) -> bool | None:
    """Git's ``git_parse_maybe_bool``: a valueless key is true, an empty value false, then the
    words true/yes/on and false/no/off in any case, then any integer (nonzero is true); None when
    the value is none of these."""
    if value is None:
        return True
    if value == "":
        return False
    lowered = value.lower() if value.isascii() else ""
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    number = config_int(value)
    return None if number is None else number != 0


def config_bool(value: str | None) -> bool:
    """Git's ``git_config_bool``: the boolean ``value`` stands for, or UnsupportedLayout where Git would refuse it."""
    result = config_maybe_bool(value)
    if result is None:
        raise UnsupportedLayout(f"invalid boolean config value {value!r}")
    return result


# References -------------------------------------------------------------

ReadFile = Callable[[str], "bytes | None"]
PER_WORKTREE_REFS = ("refs/bisect/", "refs/worktree/", "refs/rewritten/")


def object_id_pattern(hash_length: int) -> re.Pattern[str]:
    return re.compile(rf"[0-9a-f]{{{hash_length * 2}}}")


_FORBIDDEN_IN_REFERENCE = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//")


def valid_reference_name(name: str) -> bool:
    """A full reference name under ``refs/`` that Git's ``check_refname_format`` accepts."""
    if not name.startswith("refs/") or name.endswith(("/", ".")) or _FORBIDDEN_IN_REFERENCE.search(name):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in name.split("/"))


def packed_references(
    data: bytes, hash_length: int, *, charge_entry: Charge | None = None, check_time: Charge | None = None
) -> dict[str, str]:
    """Every reference in ``packed-refs``, as Git reads the file.

    An optional ``# pack-refs with:`` header comes first; every other line is
    ``<object> <name>`` or a ``^<object>`` peel of the line before it, and the
    file ends with a newline. Git refuses any other line, so this does too:
    UnsupportedLayout, never a skipped line. Lines are read one at a time;
    ``charge_entry`` is called for each before it is sliced or decoded, and
    ``check_time`` periodically.
    """
    oid = object_id_pattern(hash_length)
    references: dict[str, str] = {}
    if not data:
        return references
    if not data.endswith(b"\n"):
        raise UnsupportedLayout("packed-refs ends inside a line")
    position = 0
    if data.startswith(b"# pack-refs with: "):
        position = data.index(b"\n") + 1
    peelable = False
    steps = 0
    while position < len(data):
        steps += 1
        if check_time is not None and not steps % TIME_CHECK_INTERVAL:
            check_time()
        if charge_entry is not None:
            charge_entry()
        end = data.index(b"\n", position)
        line = data[position:end].decode("utf-8", errors="surrogateescape")
        position = end + 1
        if line.startswith("^"):
            if not peelable or not oid.fullmatch(line[1:]):
                raise UnsupportedLayout("packed-refs has a peeled line that follows no reference")
            peelable = False
            continue
        value, separator, name = line.partition(" ")
        if not separator or not oid.fullmatch(value) or not valid_reference_name(name):
            raise UnsupportedLayout("packed-refs has a line Git does not accept")
        references[name] = value
        peelable = True
    return references


def symbolic_target(data: bytes) -> str | None:
    """The reference a ``ref:`` file (such as HEAD) names, read as Git reads it; None for any other content.

    Git removes trailing whitespace, then ``ref:`` and the whitespace after it,
    using its own ASCII whitespace; every other byte belongs to the name, which
    is decoded with surrogateescape so that it maps back to the same bytes.
    """
    content = data.rstrip(GIT_SPACE_BYTES)
    if not content.startswith(b"ref:"):
        return None
    return content[4:].lstrip(GIT_SPACE_BYTES).decode("utf-8", errors="surrogateescape")


def _object_line(data: bytes) -> str:
    """A loose reference's content without Git's trailing whitespace; nothing else is removed."""
    return data.rstrip(GIT_SPACE_BYTES).decode("ascii", errors="replace")


def resolve_reference(
    read_file: ReadFile, git_dir: str, common_dir: str, name: str, hash_length: int, *,
    charge_entry: Charge | None = None, check_time: Charge | None = None,
) -> str | None:
    """The object a reference names, from a loose file or ``packed-refs``; None when it does not exist.

    ``charge_entry`` and ``check_time`` bound the reading of ``packed-refs``.
    """
    if not valid_reference_name(name):
        raise UnsupportedLayout(f"invalid reference name {name!r}")
    oid = object_id_pattern(hash_length)
    # As Git lays them out: per-worktree references in the worktree's gitdir,
    # every other reference in the common directory.
    per_worktree = name.startswith(PER_WORKTREE_REFS)
    data = read_file(os.path.join(git_dir if per_worktree else common_dir, name))
    if data is not None:
        value = _object_line(data)
        if oid.fullmatch(value):
            return value
        raise UnsupportedLayout(f"reference {name!r} is not a plain object identifier")
    if per_worktree:
        return None
    packed = read_file(os.path.join(common_dir, "packed-refs"))
    if packed is None:
        return None
    return packed_references(packed, hash_length, charge_entry=charge_entry, check_time=check_time).get(name)


def resolve_head(
    read_file: ReadFile, git_dir: str, common_dir: str, hash_length: int, *,
    charge_entry: Charge | None = None, check_time: Charge | None = None,
) -> tuple[str | None, str | None]:
    """``(reference, object)`` for HEAD: the reference is None when HEAD is detached, the object None when unborn.

    HEAD is unborn only when it names a branch (``refs/heads/``) that does not
    exist yet; a missing reference anywhere else raises UnsupportedLayout.
    """
    data = read_file(os.path.join(git_dir, "HEAD"))
    if data is None:
        raise UnsupportedLayout("HEAD is missing")
    name = symbolic_target(data)
    if name is not None:
        if not valid_reference_name(name):
            raise UnsupportedLayout("HEAD names an invalid reference")
        target = resolve_reference(read_file, git_dir, common_dir, name, hash_length, charge_entry=charge_entry,
                                    check_time=check_time)
        if target is None and not name.startswith("refs/heads/"):
            raise UnsupportedLayout(f"HEAD names a missing reference outside refs/heads/: {name!r}")
        return name, target
    value = _object_line(data)
    if object_id_pattern(hash_length).fullmatch(value):
        return None, value
    raise UnsupportedLayout("HEAD is neither a reference nor an object identifier")


# Objects ----------------------------------------------------------------

_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA, _REF_DELTA = 6, 7
_NEXT_OBJECT_LINE = {"commit": ("tree ", "commit without a tree line"), "tag": ("object ", "tag without an object line")}
MAX_DELTA_DEPTH = 4096
DELTA_TIME_CHECK_INTERVAL = 4096
# Any number of leading zeros, as Git accepts, then at most six octal digits.
_OCTAL_MODE = re.compile(rb"0*([0-7]{1,6})")
# A loose object's size as Git writes it: canonical decimal, at most 20 digits.
_DECIMAL_SIZE = re.compile(r"0|[1-9][0-9]{0,19}")
_MAX_LOOSE_HEADER = 64
# Objects are inflated in steps of at most this many bytes, straight into a
# buffer of their declared (and already charged) size.
_INFLATE_STEP = 1 << 20
# Compressed input one object may take beyond its size before it is refused;
# zlib adds a few bytes per block.
_COMPRESSED_SLACK = 1 << 20


class _Stream:
    """One zlib stream fed by ``chunks`` and inflated in bounded steps."""

    def __init__(self, chunks: Iterator[bytes], check_time: Callable[[], None], input_limit: int) -> None:
        self._chunks = chunks
        self._check_time = check_time
        self._input_limit = input_limit
        self._inflater = zlib.decompressobj()
        self._pending = b""
        self._consumed = 0
        self._exhausted = False

    @property
    def done(self) -> bool:
        return self._inflater.eof

    def step(self, most: int) -> bytes:
        """At most ``most`` (at least 1) further bytes; empty only once the stream has ended."""
        while True:
            self._check_time()
            if not self._pending and not self._exhausted:
                self._pending = next(self._chunks, b"")
                self._exhausted = not self._pending
                self._consumed += len(self._pending)
                if self._consumed > self._input_limit:
                    raise CorruptObject("compressed object far larger than its size")
            try:
                piece = self._inflater.decompress(self._pending, most)
            except zlib.error as exc:
                raise CorruptObject("invalid zlib data") from exc
            self._pending = self._inflater.unconsumed_tail
            if piece or self._inflater.eof:
                return piece
            if self._exhausted and not self._pending:
                raise CorruptObject("zlib stream ends early")


def _fill(stream: _Stream, size: int, start: bytes = b"") -> bytearray:
    """The rest of ``stream``, which must end exactly at ``size`` bytes, in a buffer of that size."""
    if len(start) > size:
        raise CorruptObject("object larger than its header says")
    out = bytearray(size)
    # Written through a memoryview: assigning to a bytearray slice copies the value first.
    with memoryview(out) as view:
        view[:len(start)] = start
        filled = len(start)
        while not stream.done:
            piece = stream.step(min(_INFLATE_STEP, size + 1 - filled))
            if filled + len(piece) > size:
                raise CorruptObject("object larger than its header says")
            view[filled:filled + len(piece)] = piece
            filled += len(piece)
    if filled != size:
        raise CorruptObject("object smaller than its header says")
    return out


@dataclass
class _Pack:
    name: str
    idx: int
    pack: int
    count: int
    fanout: tuple[int, ...]
    size: int


class ObjectStore:
    """Objects of one repository, read through caller-checked descriptors.

    ``open_regular(path)`` returns a readable descriptor for a regular file
    (FileNotFoundError when absent); ``list_names(path)`` lists a directory;
    ``charge(count)`` accounts for decompressed bytes and raises when a budget
    is spent; ``check_time()`` raises after the deadline.
    """

    def __init__(
        self,
        objects_dir: str,
        *,
        hash_name: str,
        open_regular: Callable[[str], int],
        list_names: Callable[[str], list[str]],
        charge: Callable[[int], None],
        check_time: Callable[[], None],
        max_object_bytes: int,
    ) -> None:
        if hash_name not in {"sha1", "sha256"}:
            raise UnsupportedLayout(f"object format {hash_name}")
        self.objects_dir = objects_dir
        self.hash_name = hash_name
        self.hash_length = hashlib.new(hash_name).digest_size
        self._open = open_regular
        self._list = list_names
        self._charge = charge
        self._check_time = check_time
        self.max_object_bytes = max_object_bytes
        self._packs: list[_Pack] | None = None
        self._by_offset: dict[tuple[str, int], tuple[str, bytes | bytearray]] = {}

    def close(self) -> None:
        for pack in self._packs or []:
            for fd in (pack.idx, pack.pack):
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._packs = []

    # Reading -------------------------------------------------------------

    def read(self, oid: str) -> tuple[str, bytes | bytearray]:
        """``(type, content)`` of the object ``oid`` (hex), verified against its identifier.

        Malformed input of any kind raises CorruptObject (a StoreError), so a
        caller's incomplete-result handling covers it. Every object's declared
        size is checked against the object size limit and charged before its
        content is built, in a buffer of exactly that size that is returned
        without a copy.
        """
        self._check_time()
        if not object_id_pattern(self.hash_length).fullmatch(oid):
            raise CorruptObject("malformed object identifier")
        try:
            found = self._loose(oid)
            if found is None:
                found = self._packed(bytes.fromhex(oid))
        except (ValueError, IndexError, OverflowError) as exc:
            raise CorruptObject(f"object {oid} cannot be parsed: {exc}") from exc
        if found is None:
            raise MissingObject(oid)
        kind, content = found
        digest = hashlib.new(self.hash_name)
        digest.update(f"{kind} {len(content)}\0".encode("ascii"))
        digest.update(content)
        if digest.hexdigest() != oid:
            raise CorruptObject(f"object {oid} does not match its identifier")
        return kind, content

    def _loose(self, oid: str) -> tuple[str, bytearray] | None:
        """A loose object: its header is inflated first, and the size it declares is checked and
        charged before the body is."""
        try:
            fd = self._open(os.path.join(self.objects_dir, oid[:2], oid[2:]))
        except FileNotFoundError:
            return None

        def chunks() -> Iterator[bytes]:
            while chunk := os.read(fd, 1 << 16):
                yield chunk

        try:
            stream = _Stream(chunks(), self._check_time, self.max_object_bytes + _COMPRESSED_SLACK)
            head = bytearray()
            while b"\0" not in head:
                if stream.done or len(head) >= _MAX_LOOSE_HEADER:
                    raise CorruptObject(f"loose object {oid} has a malformed header")
                head += stream.step(_MAX_LOOSE_HEADER - len(head))
            header, _, start = bytes(head).partition(b"\0")
            kind, _, size_text = header.decode("ascii", errors="replace").partition(" ")
            if kind not in _TYPES.values() or not _DECIMAL_SIZE.fullmatch(size_text):
                raise CorruptObject(f"loose object {oid} has a malformed header")
            size = int(size_text)
            if size > self.max_object_bytes:
                raise CorruptObject("loose object exceeds the object size limit")
            self._charge(size)
            return kind, _fill(stream, size, start)
        finally:
            os.close(fd)

    def _load_packs(self) -> list[_Pack]:
        if self._packs is not None:
            return self._packs
        packs: list[_Pack] = []
        directory = os.path.join(self.objects_dir, "pack")
        try:
            names = self._list(directory)
        except FileNotFoundError:
            names = []
        try:
            for name in sorted(names):
                self._check_time()
                if not name.endswith(".idx"):
                    continue
                stem = name[: -len(".idx")]
                # Both descriptors stay owned here until _read_index has succeeded and the pack
                # is in ``packs``; every failure before that closes both.
                idx = self._open(os.path.join(directory, name))
                try:
                    pack = self._open(os.path.join(directory, stem + ".pack"))
                except BaseException:
                    os.close(idx)
                    raise
                try:
                    entry = self._read_index(stem, idx, pack)
                except BaseException:
                    os.close(idx)
                    os.close(pack)
                    raise
                packs.append(entry)
        except BaseException:
            for pack in packs:
                os.close(pack.idx)
                os.close(pack.pack)
            raise
        self._packs = packs
        return packs

    def _read_index(self, name: str, idx: int, pack: int) -> _Pack:
        """The pack's index header, checked against the pack's; the caller owns both descriptors
        and closes them if this raises."""
        header = os.pread(idx, 8 + 256 * 4, 0)
        if len(header) != 8 + 256 * 4 or header[:4] != b"\xfftOc" or int.from_bytes(header[4:8], "big") != 2:
            raise UnsupportedLayout(f"pack index {name} is not version 2")
        fanout = tuple(int.from_bytes(header[8 + 4 * i:12 + 4 * i], "big") for i in range(256))
        pack_header = os.pread(pack, 12, 0)
        if len(pack_header) != 12 or pack_header[:4] != b"PACK" or int.from_bytes(pack_header[4:8], "big") not in {2, 3} \
                or int.from_bytes(pack_header[8:12], "big") != fanout[255]:
            raise CorruptObject(f"pack {name} does not match its index")
        return _Pack(name, idx, pack, fanout[255], fanout, os.fstat(pack).st_size)

    def _packed(self, oid: bytes) -> tuple[str, bytes | bytearray] | None:
        located = self._locate(oid)
        return None if located is None else self._object_at(*located)

    def _locate(self, oid: bytes) -> tuple[_Pack, int] | None:
        for pack in self._load_packs():
            offset = self._find(pack, oid)
            if offset is not None:
                return pack, offset
        return None

    def _index_word(self, pack: _Pack, size: int, position: int) -> int:
        raw = os.pread(pack.idx, size, position)
        if len(raw) != size:
            raise CorruptObject(f"pack index {pack.name} is truncated")
        return int.from_bytes(raw, "big")

    def _find(self, pack: _Pack, oid: bytes) -> int | None:
        names = 8 + 256 * 4
        low = pack.fanout[oid[0] - 1] if oid[0] else 0
        high = pack.fanout[oid[0]]
        while low < high:
            middle = (low + high) // 2
            candidate = os.pread(pack.idx, self.hash_length, names + middle * self.hash_length)
            if len(candidate) != self.hash_length:
                raise CorruptObject(f"pack index {pack.name} is truncated")
            if candidate == oid:
                offsets = names + pack.count * (self.hash_length + 4)
                value = self._index_word(pack, 4, offsets + middle * 4)
                if value & 0x80000000:
                    value = self._index_word(pack, 8, offsets + pack.count * 4 + (value & 0x7FFFFFFF) * 8)
                return value
            if candidate < oid:
                low = middle + 1
            else:
                high = middle
        return None

    def _entry_header(self, pack: _Pack, offset: int) -> tuple[int, int, int, int | bytes | None]:
        """``(type, size, data offset, base)`` of the pack entry at ``offset``; ``base`` is the base
        entry's offset for an offset delta, the base object's identifier for a reference delta."""
        if not 12 <= offset < pack.size:
            raise CorruptObject(f"pack {pack.name} has no entry at offset {offset}")
        header = os.pread(pack.pack, 32 + self.hash_length, offset)
        if not header:
            raise CorruptObject(f"pack {pack.name} is truncated")
        byte = header[0]
        kind = (byte >> 4) & 7
        size = byte & 15
        shift = 4
        position = 1
        while byte & 0x80:
            if position >= len(header):
                raise CorruptObject("pack object header truncated or too long")
            byte = header[position]
            size |= (byte & 0x7F) << shift
            shift += 7
            position += 1
        if size > self.max_object_bytes:
            raise CorruptObject("pack object exceeds the object size limit")
        if kind in _TYPES:
            return kind, size, offset + position, None
        if kind == _OFS_DELTA:
            if position >= len(header):
                raise CorruptObject("delta base offset truncated")
            byte = header[position]
            position += 1
            distance = byte & 0x7F
            while byte & 0x80:
                if position >= len(header):
                    raise CorruptObject("delta base offset truncated or too long")
                byte = header[position]
                position += 1
                distance = ((distance + 1) << 7) | (byte & 0x7F)
            if distance <= 0 or distance > offset:
                raise CorruptObject("delta base offset out of range")
            return kind, size, offset + position, offset - distance
        if kind == _REF_DELTA:
            base_id = header[position:position + self.hash_length]
            if len(base_id) != self.hash_length:
                raise CorruptObject("delta base identifier truncated")
            return kind, size, offset + position + self.hash_length, base_id
        raise CorruptObject(f"pack object type {kind}")

    def _object_at(self, pack: _Pack, offset: int) -> tuple[str, bytes | bytearray]:
        """The object at ``offset``; delta chains are followed in a loop, not by recursion."""
        chain: list[tuple[_Pack, int, int, int]] = []
        location = (pack, offset)
        while True:
            self._check_time()
            current, at = location
            cached = self._by_offset.get((current.name, at))
            if cached is not None:
                kind, content = cached
                break
            if len(chain) > MAX_DELTA_DEPTH:
                raise CorruptObject("delta chain too deep")
            code, size, data_offset, base = self._entry_header(current, at)
            if base is None:
                kind, content = _TYPES[code], self._inflate(current, data_offset, size)
                self._remember(current, at, kind, content)
                break
            chain.append((current, at, data_offset, size))
            if isinstance(base, int):
                location = (current, base)
                continue
            # A reference delta's base may be loose or in any pack; the result is
            # verified against its own identifier, so the base needs no check here.
            loose = self._loose(base.hex())
            if loose is not None:
                kind, content = loose
                break
            found = self._locate(base)
            if found is None:
                raise MissingObject(base.hex())
            location = found
        for current, at, data_offset, size in reversed(chain):
            delta = self._inflate(current, data_offset, size)
            content = apply_delta(content, delta, max_size=self.max_object_bytes, charge=self._charge,
                                  check_time=self._check_time)
            self._remember(current, at, kind, content)
        return kind, content

    def _remember(self, pack: _Pack, offset: int, kind: str, content: bytes | bytearray) -> None:
        if kind in {"tree", "commit", "tag"}:
            self._by_offset[(pack.name, offset)] = (kind, content)

    def _inflate(self, pack: _Pack, offset: int, size: int) -> bytearray:
        """The zlib stream at ``offset``, which must inflate to exactly ``size`` bytes; ``size`` (already
        checked against the object size limit) is charged before anything is inflated."""
        self._charge(size)

        def chunks() -> Iterator[bytes]:
            position = offset
            while chunk := os.pread(pack.pack, 1 << 16, position):
                position += len(chunk)
                yield chunk

        return _fill(_Stream(chunks(), self._check_time, size + _COMPRESSED_SLACK), size)

    # Trees ---------------------------------------------------------------

    def peel_to_tree(self, oid: str) -> str:
        """The tree a commit (or a tag that leads to one) names."""
        for _ in range(64):
            kind, content = self.read(oid)
            if kind == "tree":
                return oid
            if kind not in _NEXT_OBJECT_LINE:
                raise CorruptObject(f"{kind} object where a commit was expected")
            label, missing = _NEXT_OBJECT_LINE[kind]
            # Only the start is sliced: the line naming the next object is short, and
            # splitting the whole object would copy it.
            first = bytes(content[:len(label) + 2 * self.hash_length + 1]).split(b"\n", 1)[0].decode("ascii", errors="replace")
            if not first.startswith(label):
                raise CorruptObject(missing)
            oid = first[len(label):]
        raise CorruptObject("tag chain too long")

    def tree_manifest(
        self, tree: str, charge_entry: Callable[[], None], charge_bytes: ChargeBytes | None = None
    ) -> dict[str, tuple[str, str]]:
        """Every non-tree entry under ``tree`` as ``path: (mode, object)``, modes as ``ls-tree`` prints them.

        Modes are octal as Git requires and canonicalized as Git does (a
        regular file is executable when its owner-execute bit is set). A mode
        Git would not read as a file, symlink, directory or gitlink, and a
        name repeated within one tree, raise CorruptObject.

        Every path is a new string holding its whole directory prefix, so a
        deep tree of long names expands far beyond its object bytes. Before
        each path (or directory prefix) is built, ``charge_bytes`` is charged
        the memory its characters will take: its length in characters times
        the widest character's storage width (1, 2 or 4 bytes), the way
        Python stores the string.
        """
        manifest: dict[str, tuple[str, str]] = {}
        # (prefix, its length in characters, its character width, tree object)
        stack: list[tuple[str, int, int, str]] = [("", 0, 1, tree)]
        while stack:
            prefix, prefix_length, prefix_width, oid = stack.pop()
            kind, content = self.read(oid)
            if kind != "tree":
                raise CorruptObject(f"{kind} object where a tree was expected")
            names: set[str] = set()
            position = 0
            while position < len(content):
                charge_entry()
                space = content.find(b" ", position)
                nul = content.find(b"\0", space + 1)
                if space == -1 or nul == -1 or nul + 1 + self.hash_length > len(content):
                    raise CorruptObject("malformed tree entry")
                octal = _OCTAL_MODE.fullmatch(content, position, space)
                if octal is None or int(octal.group(1), 8) > 0o177777:
                    raise CorruptObject("malformed tree mode")
                name = content[space + 1:nul].decode("utf-8", errors="surrogateescape")
                if not name or "/" in name or name in {".", ".."}:
                    raise CorruptObject("malformed tree entry name")
                if name in names:
                    raise CorruptObject("tree names an entry twice")
                names.add(name)
                child = content[nul + 1:nul + 1 + self.hash_length].hex()
                position = nul + 1 + self.hash_length
                mode = int(octal.group(1), 8)
                directory = stat.S_ISDIR(mode)
                length = prefix_length + len(name) + (1 if directory else 0)
                width = max(prefix_width, character_width(name))
                if charge_bytes is not None:
                    # Charged before the path exists.
                    charge_bytes(length * width)
                if directory:
                    stack.append((f"{prefix}{name}/", length, width, child))
                    continue
                path = f"{prefix}{name}"
                if mode & 0o170000 == 0o160000:
                    manifest[path] = ("160000", child)
                elif stat.S_ISLNK(mode):
                    manifest[path] = ("120000", child)
                elif stat.S_ISREG(mode):
                    manifest[path] = ("100755" if mode & 0o100 else "100644", child)
                else:
                    raise CorruptObject("unsupported tree entry mode")
        return manifest


def character_width(text: str) -> int:
    """How many bytes Python stores each character of ``text`` in: 1, 2 or 4.

    A path built from strings is as wide as its widest part, so its size is
    known (length times width) before it is built.
    """
    if text.isascii():
        return 1
    widest = ord(max(text))
    return 1 if widest < 0x100 else 2 if widest < 0x10000 else 4


def _varint(data: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if position >= len(data):
            raise CorruptObject("delta header truncated")
        if shift > 63:
            raise CorruptObject("delta header size too large")
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, position


def apply_delta(
    base: bytes | bytearray,
    delta: bytes | bytearray,
    *,
    max_size: int,
    charge: Callable[[int], None] | None = None,
    check_time: Callable[[], None] | None = None,
) -> bytearray:
    """Git's delta format applied to ``base``; malformed or inconsistent deltas raise CorruptObject.

    The declared result size is checked against ``max_size`` and charged
    before the result buffer, of exactly that size, is allocated. Each copy
    or insert is checked against the space left before it is written, so a
    dishonest declared size cannot make the result grow past it, and
    ``check_time`` runs while the result is assembled.
    """
    source_size, position = _varint(delta, 0)
    target_size, position = _varint(delta, position)
    if source_size != len(base):
        raise CorruptObject("delta base size mismatch")
    if target_size > max_size:
        raise CorruptObject("delta result exceeds the object size limit")
    if charge is not None:
        charge(target_size)
    out = bytearray(target_size)
    with memoryview(base) as source, memoryview(delta) as stream, memoryview(out) as view:
        filled = _apply_instructions(source, stream, position, view, check_time)
    if filled != target_size:
        raise CorruptObject("delta result size mismatch")
    return out


def _apply_instructions(source: memoryview, delta: memoryview, position: int, out: memoryview,
                        check_time: Callable[[], None] | None) -> int:
    """Copy and insert into ``out`` (written through a memoryview, so nothing is copied twice); return
    how much was written. Each instruction is checked against the space left before it is written."""
    target_size = len(out)
    filled = 0
    instructions = 0
    while position < len(delta):
        if check_time is not None and not instructions % DELTA_TIME_CHECK_INTERVAL:
            check_time()
        instructions += 1
        opcode = delta[position]
        position += 1
        if opcode & 0x80:
            offset = 0
            size = 0
            for bit in range(4):
                if opcode & (1 << bit):
                    if position >= len(delta):
                        raise CorruptObject("delta copy truncated")
                    offset |= delta[position] << (8 * bit)
                    position += 1
            for bit in range(3):
                if opcode & (1 << (4 + bit)):
                    if position >= len(delta):
                        raise CorruptObject("delta copy truncated")
                    size |= delta[position] << (8 * bit)
                    position += 1
            size = size or 0x10000
            if offset + size > len(source):
                raise CorruptObject("delta copy outside its base")
            piece = source[offset:offset + size]
        elif opcode:
            if position + opcode > len(delta):
                raise CorruptObject("delta insert truncated")
            piece = delta[position:position + opcode]
            position += opcode
        else:
            raise CorruptObject("delta opcode 0 is reserved")
        if filled + len(piece) > target_size:
            raise CorruptObject("delta result larger than declared")
        out[filled:filled + len(piece)] = piece
        filled += len(piece)
    return filled


__all__ = [
    "CorruptObject",
    "MissingObject",
    "ObjectStore",
    "StoreError",
    "UnsupportedLayout",
    "apply_delta",
    "character_width",
    "config_bool",
    "config_int",
    "config_maybe_bool",
    "packed_references",
    "parse_config",
    "resolve_head",
    "resolve_reference",
    "symbolic_target",
    "valid_reference_name",
]
