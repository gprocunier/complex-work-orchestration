"""Final-bytes outbound screening.

``screen_outbound`` inspects the exact bytes about to leave the machine (a
manual prompt or a local HTTP request) immediately before the effect, and
binds its result to their SHA-256; ``screen_request`` does the same for an
HTTP request's method, URL, non-authentication headers and body together.
Every finding maps back to offsets in the raw text. Views read:

- the raw text, and a normalized copy (confusable letters folded, compatibility
  forms decomposed, combining marks and format characters such as zero-width
  spaces removed, then NFKC);
- the text with backslash escapes decoded (``\\u0070``, ``\\"`` and the other
  JSON escapes), repeatedly for doubly escaped text, so JSON fragments inside
  prose or code are read as they would be decoded;
- for a payload that is JSON, and for JSON written anywhere inside text (each
  ``{`` or ``[`` where a JSON value decodes), every key and every string value,
  each member of an object including repeated keys, and JSON nested inside
  strings, read by a parser that keeps raw offsets; each JSON value is read
  once, whichever entry point reaches it first, under one JSON budget for the
  whole payload, and a string or subtree another reading reaches unchanged
  (the same raw text) is not read again;
- the decoded text of ``data:`` URIs, read in their declared charset (UTF-8 or
  US-ASCII, quoted or not; any other charset, parameters that cannot be read,
  or content that does not decode to text, is reported as opaque), metadata
  written with whitespace around the media type and parameters included, and
  decoded JSON read structurally. A base64 payload runs over whitespace and
  line breaks to every further base64 run before the first ordinary word; every
  run in it must decode completely to text, both segment by segment and as a
  decoder that skips padding inside the stream reads it (a reading that fails
  is a failure, not the same reading), or the whole URI is opaque. A payload
  run, or a word joined after it, that ends at a character outside the alphabet
  is followed as a lenient decoder follows it, through words and delimiters,
  each counting toward the run budget; with more base64 text after it before
  the first ordinary word it is opaque too, and what that decoder reads through
  it is read;
- under a credential name or header, every value in a nested list, tuple or
  mapping written in text, and every string and number under a credential key
  in JSON; a literal that cannot be read whole is reported.

No part of a name exempts it: a name holding a credential word is a credential
name whatever else it holds, except a quantity the product itself generates
(``credential_source_count``, ``max_tokens``, ``max_output_tokens``) with a
non-negative integer value. A name is read twice, and is a credential name when
either reading holds a credential word: case-folded and split only at
punctuation (``PaSsWoRd``), and split at case changes, acronym boundaries
(``DBPassword``) and digits as well. Every credential word, every word of a
credential pair and every word of a phrase name also counts as a plural
(``api_keys``, ``seed_phrases``), and a credential word or pair as the end of a
compound (``dbpassword``, ``dbaccess_key``); every policy phrase name
(``mnemonic``, ``seed phrase``) is a credential name. No value is exempt for
being ordinary words: a credential name, a separator and a value is a finding.
A placeholder, a code reference, a generated count or a structure whose values
are all exempt exempts only a whole value: an unquoted value runs to the end of
its line unless the next member, a closing bracket or the literal it is in ends
it, and a more indented next line continues it (YAML and HTTP fold such lines);
anything after a closing bracket continues a structure; string literals Python
joins (adjacent, across lines too, f-strings included) and quoted words a shell
joins are one value, and a header's checks apply to the joined value.
The only labels recognized are exact product-generated text. Every inspection
limit fails closed: an encoded payload that is empty, quoted, split or not
fully decodable, a base64 continuation longer than the run budget, embedded
JSON too deep (counting the JSON around it), beyond the JSON budget or holding
a value the decoder cannot convert, a decoded view beyond the view allowance,
and a literal longer than the structure limit are reported as unreadable or
opaque, never skipped. JSON already read is never decoded or charged again.

The detectors and their data (``policy/outbound-screening.yaml``) are kept
apart from the packet redaction rules in ``cwo_core.packets``: this module does
not import them, so a gap in one is not automatically a gap in the other. That
is separation, not statistical independence, and no detector here promises to
find every secret. Findings are ``certain`` (structure that is a credential, a
key block or declared prohibited data) or ``uncertain`` (entropy, prose such as
"the secret is ...", contact data, opaque encoded content). Both refuse the
disclosure; this slice has no exception mechanism. A refusal never repeats
input: rule names are fixed, and the value appears only as a SHA-256 prefix.
"""

from __future__ import annotations

import argparse
import binascii
import bisect
import hashlib
import itertools
import json
import math
import re
import sys
import traceback
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Iterator, NoReturn

from .policy import load_policy

SCREEN_VERSION = 2

# These labels can only narrow formats; no label exempts content from inspection.
_TEXT_FORMATS = frozenset({"text/plain", "application/json"})
_SURFACE_FORMATS = {
    "manual export": _TEXT_FORMATS,
    "ChatGPT browser Send": frozenset({"text/plain"}),
    "local HTTP request": frozenset({"application/json"}),
    "local HTTP model preflight": frozenset({"application/json"}),
}
_CONTENT_TYPE = re.compile(
    r'(text/plain|application/json)(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?',
    re.IGNORECASE,
)
_ATTACHMENT_FIELDS = frozenset({"attachments", "files", "uploads"})


class OutboundRefused(SystemExit):
    """The payload must not leave the machine. The message never contains input text."""


def _utf8_payload(payload: bytes | str, *, surface: str) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if not isinstance(payload, str):
        raise OutboundRefused(f"outbound screening refused {surface}: unsupported payload representation")
    try:
        return payload.encode("utf-8")
    except UnicodeEncodeError:
        raise OutboundRefused(f"outbound screening refused {surface}: payload cannot be represented as UTF-8") from None


def require_text_disclosure(payload: str, *, surface: str) -> str:
    """Renderers accept text, never implicit stringification of files or rich content."""
    if not isinstance(payload, str):
        raise OutboundRefused(f"outbound screening refused {surface}: renderer requires text; attachments are unsupported")
    _utf8_payload(payload, surface=surface)
    return payload


def refuse_attachments(document: dict[str, Any], *, surface: str) -> None:
    """There is no file/upload adapter: reject attachment declarations instead of ignoring them."""
    if isinstance(document, dict) and _ATTACHMENT_FIELDS.intersection(document):
        raise OutboundRefused(f"outbound screening refused {surface}: attachments are unsupported")


def _supported_content_type(content_type: str, *, surface: str) -> str:
    """Only plain text and JSON, unencoded or explicitly UTF-8, have complete readers."""
    match = _CONTENT_TYPE.fullmatch(content_type.strip(" \t")) if isinstance(content_type, str) else None
    if match is None:
        raise OutboundRefused(f"outbound screening refused {surface}: unsupported content type or charset")
    media = match[1].lower()
    if media not in _SURFACE_FORMATS.get(surface, _TEXT_FORMATS):
        raise OutboundRefused(f"outbound screening refused {surface}: unsupported renderer format")
    return media


def _request_content_type(headers: tuple[tuple[str, str], ...], content_type: str, *, surface: str) -> str:
    declared = _supported_content_type(content_type, surface=surface)
    media_types = []
    for name, value in headers:
        if name == "content-type":
            media_types.append(_supported_content_type(value, surface=surface))
        elif name in {"content-encoding", "transfer-encoding"} and value.strip().lower() != "identity":
            raise OutboundRefused(f"outbound screening refused {surface}: unsupported HTTP encoding")
    if len(media_types) > 1 or any(media != declared for media in media_types):
        raise OutboundRefused(f"outbound screening refused {surface}: ambiguous or contradictory HTTP content type")
    if surface in {"local HTTP request", "local HTTP model preflight"} and not media_types:
        raise OutboundRefused(f"outbound screening refused {surface}: HTTP content type is missing")
    return declared


@dataclass(frozen=True)
class Finding:
    rule: str
    certainty: str
    view: str
    start: int
    end: int
    fingerprint: str

    def describe(self) -> str:
        return f"{self.rule} ({self.certainty}, {self.view} view, offsets {self.start}-{self.end})"


@dataclass(frozen=True)
class ScreenedPayload:
    """Bytes that passed screening, bound to their digest."""

    data: bytes = field(repr=False)
    sha256: str
    surface: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return not self.findings

    def text(self) -> str:
        return self.data.decode("utf-8")

    def require_unchanged(self, data: bytes | str) -> bytes:
        """Return the captured immutable bytes for a supported unchanged candidate."""
        raw = _utf8_payload(data, surface=self.surface)
        if (self.findings or type(self.data) is not bytes or raw != self.data
                or hashlib.sha256(self.data).hexdigest() != self.sha256):
            raise OutboundRefused(f"outbound screening refused {self.surface}: the payload changed after it was screened")
        return self.data


# Header names never screened or bound: the request's own authentication,
# which CWO adds from its configured credential.
_AUTHENTICATION_HEADERS = frozenset({"authorization", "proxy-authorization"})


def _request_headers(headers: dict[str, str] | list[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    items = headers.items() if isinstance(headers, dict) else headers
    return tuple(sorted((str(name).lower(), str(value)) for name, value in items if str(name).lower() not in _AUTHENTICATION_HEADERS))


def _authentication_digest(headers: dict[str, str] | list[tuple[str, str]]) -> str:
    """A digest of the authentication headers, so they are bound without being kept."""
    items = headers.items() if isinstance(headers, dict) else headers
    chosen = sorted((str(name).lower(), str(value)) for name, value in items if str(name).lower() in _AUTHENTICATION_HEADERS)
    return hashlib.sha256(repr(chosen).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScreenedRequest:
    """An HTTP request whose method, URL, non-authentication headers and body passed screening.

    Authentication headers are bound too, by digest, but never screened.
    """

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    authentication: str
    body: ScreenedPayload
    descriptor: ScreenedPayload
    surface: str

    def require_unchanged(self, method: str, url: str, headers: dict[str, str] | list[tuple[str, str]], body: bytes | None) -> None:
        """Refuse unless the request about to be sent is exactly the screened one."""
        if (method.upper() != self.method or url != self.url or _request_headers(headers) != self.headers
                or _authentication_digest(headers) != self.authentication):
            raise OutboundRefused(f"outbound screening refused {self.surface}: the request changed after it was screened")
        descriptor = f"{self.method} {self.url}\n" + "".join(f"{name}: {value}\n" for name, value in self.headers)
        self.descriptor.require_unchanged(descriptor)
        self.body.require_unchanged(body or b"")


@lru_cache(maxsize=1)
def _rules() -> dict[str, Any]:
    return load_policy("outbound-screening")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


# Views ------------------------------------------------------------------


class _View:
    """A string to scan and, for derived views, the raw range each of its characters came from."""

    def __init__(self, name: str, text: str, ranges: list[tuple[int, int]] | None = None) -> None:
        self.name = name
        self.text = text
        self.ranges = ranges
        # Indices of characters that came from an encoding that did not decode (a lone surrogate
        # escape, %XX bytes that are not UTF-8); the screen reports them as opaque.
        self.undecodable: list[int] = []

    def raw_range(self, index: int) -> tuple[int, int]:
        if self.ranges is None:
            return (index, index + 1)
        if not self.ranges:
            return (0, 0)
        return self.ranges[min(max(index, 0), len(self.ranges) - 1)]

    def raw_span(self, start: int, end: int) -> tuple[int, int]:
        if self.ranges is None:
            return (start, end)
        if not self.ranges:
            return (0, 0)
        return (self.raw_range(start)[0], self.raw_range(max(end - 1, start))[1])


def _derived(name: str, parent: _View, characters: list[str], spans: list[tuple[int, int]]) -> _View:
    """A view whose characters came from ``spans`` (start, end) of ``parent``."""
    ranges = [(parent.raw_range(start)[0], parent.raw_range(max(end - 1, start))[1]) for start, end in spans]
    return _View(name, "".join(characters), ranges)


def _skeleton(character: str, confusables: dict[str, str]) -> str:
    """One character's comparison form: confusables folded, decomposed, marks and format characters dropped."""
    # Unmapped single ASCII characters survive both Unicode normalizations and
    # cannot be marks/format characters. Mapped ASCII still needs both lookups.
    if len(character) == 1 and character.isascii() and character not in confusables:
        return character
    pieces = []
    for piece in unicodedata.normalize("NFKD", confusables.get(character, character)):
        if unicodedata.category(piece) in ("Mn", "Me", "Cf"):
            continue
        pieces.append(confusables.get(piece, piece))
    return unicodedata.normalize("NFKC", "".join(pieces))


def _normalized_view(parent: _View, confusables: dict[str, str]) -> _View:
    characters: list[str] = []
    positions: list[tuple[int, int]] = []
    for index, character in enumerate(parent.text):
        for piece in _skeleton(character, confusables):
            characters.append(piece)
            positions.append((index, index + 1))
    return _derived("normalized" if parent.name == "raw" else f"{parent.name}+normalized", parent, characters, positions)


_ESCAPE = re.compile(r'\\(u[0-9a-fA-F]{4}|["\\/bfnrt])')
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _decode_escape(text: str, match: re.Match[str]) -> tuple[str, int]:
    """The character an escape encodes and where it ends, joining a UTF-16 surrogate pair."""
    code = match.group(1)
    if code[0] != "u":
        return _SIMPLE_ESCAPES[code], match.end()
    value = int(code[1:], 16)
    if 0xD800 <= value <= 0xDBFF:
        following = _ESCAPE.match(text, match.end())
        if following and following.group(1)[0] == "u":
            low = int(following.group(1)[1:], 16)
            if 0xDC00 <= low <= 0xDFFF:
                return chr(0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00)), following.end()
    return chr(value), match.end()


def _unescaped_view(parent: _View, name: str) -> _View | None:
    """``parent`` with JSON-style backslash escapes decoded; None when it has none."""
    text = parent.text
    if not _ESCAPE.search(text):
        return None
    characters: list[str] = []
    positions: list[tuple[int, int]] = []
    undecodable: list[int] = []
    index = 0
    while index < len(text):
        match = _ESCAPE.match(text, index) if text[index] == "\\" else None
        if match is None:
            characters.append(text[index])
            positions.append((index, index + 1))
            index += 1
            continue
        character, index_after = _decode_escape(text, match)
        if 0xD800 <= ord(character) <= 0xDFFF:
            undecodable.append(len(characters))  # a surrogate escape without its pair
        characters.append(character)
        positions.append((index, index_after))
        index = index_after
    view = _derived(name, parent, characters, positions)
    view.undecodable = undecodable
    return view


_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")


def _percent_view(parent: _View, name: str) -> _View | None:
    """``parent`` with %XX sequences decoded as UTF-8; None when it has none."""
    import codecs

    text = parent.text
    if not _PERCENT.search(text):
        return None
    characters: list[str] = []
    positions: list[tuple[int, int]] = []
    undecodable: list[int] = []
    index = 0
    while index < len(text):
        if not _PERCENT.match(text, index):
            characters.append(text[index])
            positions.append((index, index + 1))
            index += 1
            continue
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        run_start = first = index
        first_character = len(characters)
        while _PERCENT.match(text, index):
            produced = decoder.decode(bytes([int(text[index + 1:index + 3], 16)]))
            index += 3
            for character in produced:
                characters.append(character)
                positions.append((run_start, index))
                run_start = index
        for character in decoder.decode(b"", final=True):
            characters.append(character)
            positions.append((run_start, index))
        try:
            bytes.fromhex(text[first:index].replace("%", "")).decode("utf-8")
        except UnicodeDecodeError:
            undecodable.extend(range(first_character, len(characters)))  # bytes that are not UTF-8 text
    view = _derived(name, parent, characters, positions)
    view.undecodable = undecodable
    return view


# A parameter is a name with an optional value, which may be quoted ("UTF-8" or 'UTF-8').
# In JSON-encoded text the quotes are escaped (charset=\"UTF-8\").
_DATA_URI_VALUE = r"""(?:"[^"\n]*"|'[^'\n]*'|\\"[^"\\\n]*\\"|\\'[^'\\\n]*\\'|[^,;\s"'<>]*)"""
_DATA_URI_PARAMETER = r"""(?:;[^,;\s"'<>=]*(?:=""" + _DATA_URI_VALUE + r""")?)"""
_DATA_URI = re.compile(r"(?i)data:[^,;\s\"'<>]*(" + _DATA_URI_PARAMETER + r"*),([^\s\"'<>)]*)")
# Where a data URI written without whitespace starts: "data:", a media type if any, then ";" or ",".
# A start that _DATA_URI cannot read to its payload is reported as opaque rather than skipped.
_DATA_URI_START = re.compile(r"(?i)data:[^,;\s\"'<>]*[;,]")
# Parameters, with optional whitespace around each name, "=" and value, as Python's data-URI handler
# accepts them. For metadata written without whitespace this reads exactly the strict parameters.
_DATA_URI_PARAMETERS = re.compile(r"""(?i);\s*([^,;\s"'<>=]*)\s*(?:=\s*(""" + _DATA_URI_VALUE + r"""))?""")
_DATA_SCHEME = re.compile(r"(?i)data:")
# A character that would make "data:" the end of a longer URI scheme.
_SCHEME_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-")
# Metadata written with whitespace that declares base64 or a charset, whether or not it can be read.
_DECLARES_ENCODING = re.compile(r"(?i);\s*(?:base64\s*$|charset\s*=)")
_ANY_ENCODING = re.compile(r"(?i);\s*(?:base64|charset)")
_PAYLOAD = re.compile(r"[^\s\"'<>)]*")
# Python's data-URI handler decodes base64 leniently: it skips whitespace and joins
# what follows. A base64 payload therefore runs on over any whitespace, line breaks
# included, to further base64 text, and an empty one to the text after it.
# Continuation runs joined at most; a URI with more is not inspected whole, so it is opaque. Every run is
# matched, so the refusal covers them all, but none is decoded once the budget is exceeded.
MAX_CONTINUATION_RUNS = 64
_BASE64_CONTINUED = re.compile(r"(?:\s+[A-Za-z0-9+/=]+)+")
_BASE64_AFTER_EMPTY = re.compile(r"\s*([A-Za-z0-9+/=]+)((?:\s+[A-Za-z0-9+/=]+)*)")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]+")
_BASE64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
# An ordinary word (letters, an optional capital first, at least two): the payload ends before a run
# that is one, so prose after a URI is not decoded as payload.
_PROSE_WORD = re.compile(r"[A-Za-z][a-z]+")
# A whitespace-separated token, and the rest of one. A lenient decoder skips every character outside
# the base64 alphabet, so a payload run that ends at such a character (a bracket, a quote, a full stop)
# continues, for that decoder, through the rest of its token and over whitespace to further tokens.
_TOKEN = re.compile(r"\s+(\S+)")
_TOKEN_TAIL = re.compile(r"\S*")
# The characters outside the base64 alphabet around a token, so an ordinary word in brackets or quotes,
# or followed by punctuation ("(see", "next.") is still an ordinary word.
_AROUND_TOKEN = re.compile(r"^[^A-Za-z0-9+/=]+|[^A-Za-z0-9+/=]+$")
# A payload that ends at a quote or bracket with payload text right after it is split, not ended.
_SPLIT_PAYLOAD = re.compile(r"""(?:\\?["']|[<>)])[A-Za-z0-9+/=%]""")
# The rest of a token, for the span of a payload that cannot be read.
_TOKEN_REST = re.compile(r"[^\s<>]*")
# Charsets a data URI may declare and still be read; any other declared charset
# (UTF-7, UTF-16, legacy code pages) makes the content opaque, so it refuses.
_DATA_URI_CHARSETS = {"utf-8": "utf-8", "utf8": "utf-8", "us-ascii": "ascii", "ascii": "ascii"}


def _data_uri_parameters(parameters: str) -> list[tuple[str, str | None]]:
    """``(name, value)`` pairs, names lower-cased and values unquoted."""
    return [(match.group(1).lower(), None if match.group(2) is None else match.group(2).strip("\\\"'"))
            for match in _DATA_URI_PARAMETERS.finditer(parameters)]


def _is_base64(parameters: str) -> bool:
    return ("base64", None) in _data_uri_parameters(parameters)


def _data_uri_charset(parameters: str) -> str | None:
    """The codec for the declared charset (UTF-8 when none is declared), or None when it is not supported."""
    declared = [(value or "").strip().lower() for name, value in _data_uri_parameters(parameters) if name == "charset"]
    if len(declared) > 1:
        return None
    return _DATA_URI_CHARSETS.get(declared[0]) if declared else "utf-8"


def _spaced_parameters(metadata: str) -> str | None:
    """The parameters of metadata written with whitespace, or None when they cannot be read: the
    media type runs to the first ";", and the rest must be parameters with only whitespace between."""
    _media_type, separator, rest = metadata.partition(";")
    rest = separator + rest
    index = 0
    for match in _DATA_URI_PARAMETERS.finditer(rest):
        if rest[index:match.start()].strip():
            return None
        index = match.end()
    return rest if not rest[index:].strip() else None


def _data_uri_candidates(text: str, consumed: list[int]) -> Iterator[tuple[int, str | None, int, int]]:
    """Each data URI in ``text``: where it starts, its parameters, and its payload's start and end; or
    None for the parameters and the span to report when it cannot be read.

    A URI written without whitespace in its metadata is read by the strict pattern. Otherwise, at a
    "data:" where a URI scheme can start, the metadata runs to the first comma, as Python's handler
    reads it, with optional whitespace around the media type and around each parameter, its "=" and
    its value. Such metadata is a URI when it declares base64 or a charset; when it declares either
    but cannot be read, it is reported. When a later "data:" that is read the same way comes before
    that comma, the later one reads the same metadata tail and payload; the text skipped between them
    must not declare base64 or a charset, or the URI is reported. A start before ``consumed[0]`` (the
    end of what the caller has read) is not read again, so the scan is linear."""
    commas = [index for index, character in enumerate(text) if character == ","]
    strict_end = 0
    tried: list[tuple[int, bool]] = []  # (start, strict) for each "data:" read as a URI start
    for match in _DATA_SCHEME.finditer(text):
        start = match.start()
        if start < strict_end:
            continue  # inside the media type of a strict start, as a non-overlapping scan reads it
        strict = _DATA_URI_START.match(text, start)
        if strict:
            strict_end = strict.end()
            tried.append((start, True))
        elif start == 0 or text[start - 1] not in _SCHEME_CHARACTERS:
            tried.append((start, False))
    for number, (start, strict) in enumerate(tried):
        if start < consumed[0]:
            continue
        if strict:
            match = _DATA_URI.match(text, start)
            if match is None:
                yield start, None, start, _TOKEN_REST.match(text, start).end()
            else:
                yield start, match.group(1), match.start(2), match.end(2)
            continue
        position = bisect.bisect_left(commas, start)
        if position == len(commas):
            continue
        comma = commas[position]
        if number + 1 < len(tried) and tried[number + 1][0] < comma:
            if _ANY_ENCODING.search(text, start + 5, tried[number + 1][0]):
                yield start, None, start, _TOKEN_REST.match(text, comma + 1).end()
            continue
        metadata = text[start + 5:comma]
        parameters = _spaced_parameters(metadata)
        if parameters is None:
            if _DECLARES_ENCODING.search(metadata):
                yield start, None, start, _TOKEN_REST.match(text, comma + 1).end()
            continue
        if not {"base64", "charset"} & {name for name, _value in _data_uri_parameters(parameters)}:
            continue  # nothing to decode: a percent-encoded payload is read by the percent view
        yield start, parameters, comma + 1, _PAYLOAD.match(text, comma + 1).end()


def _lenient_continuation(text: str, position: int, runs: int, budget: int = MAX_CONTINUATION_RUNS) -> tuple[int, bool, int] | None:
    """Where a lenient decoder's reading continues from a base64 run that ended at ``position``, at a
    character outside the alphabet, whether that continuation holds any base64 character, and the runs
    counted so far, its tokens included.

    The continuation is the rest of that run's token, then every further whitespace-separated token up
    to the first ordinary word (with the punctuation around it). None when the runs read so far and
    these tokens together exceed ``MAX_CONTINUATION_RUNS``: the payload cannot be read whole."""
    tail = _TOKEN_TAIL.match(text, position)
    end, holds_base64 = tail.end(), any(character in _BASE64_ALPHABET for character in tail.group(0))
    while token := _TOKEN.match(text, end):
        if _PROSE_WORD.fullmatch(_AROUND_TOKEN.sub("", token.group(1))):
            break
        runs += 1
        if runs > budget:
            return None
        end, holds_base64 = token.end(), holds_base64 or any(character in _BASE64_ALPHABET for character in token.group(1))
    return end, holds_base64, runs


def _lenient_join_end(text: str, position: int) -> int:
    """Where a lenient decoder's join from ``position`` ends: through every delimiter and the tokens and
    words after it, until the join ends at whitespace. Found without decoding anything, so a refusal
    for the run budget covers every run the decoder would join."""
    while position < len(text) and not text[position].isspace():
        end = _lenient_continuation(text, position, 0, len(text))[0]  # type: ignore[index]
        words = _BASE64_CONTINUED.match(text, end)
        if not words:
            return end
        position = words.end()
    return position


def _data_uri_spans(text: str) -> Iterator[tuple[str | None, int, int, int, int | None]]:
    """Each data URI in ``text``: its parameters, payload start, payload end, the end of any base64
    continuation a lenient decoder would join (equal to the payload end when there is none), and None;
    or None and the span of a URI that cannot be read whole, with, as the last item, the end of a
    lenient decoder's continuation past a delimiter when that is why (so its reading is still read).

    A URI cannot be read whole when its parameters or payload cannot be read, when its payload is
    empty (a quoted payload, or nothing after the comma), when its payload is split by a quote or
    bracket with payload text right after it, when a base64 payload continues over more than
    ``MAX_CONTINUATION_RUNS`` runs, or when a base64 payload ends at a character outside the alphabet
    and a lenient decoder, which skips that character, reads further base64 text after it, before the
    first ordinary word, whitespace between included. Such a URI is reported as opaque, never skipped."""
    consumed = [0]
    for start, parameters, payload_start, payload_end in _data_uri_candidates(text, consumed):
        if parameters is None:
            consumed[0] = payload_end
            yield None, start, payload_end, payload_end, None
            continue
        capture_end = joined_end = payload_end
        base64_payload = _is_base64(parameters)
        if base64_payload:
            if payload_start == payload_end:
                # An empty capture followed by base64 text: its first run is the payload, the rest continues it.
                if continued := _BASE64_AFTER_EMPTY.match(text, payload_end):
                    payload_end, joined_end = continued.end(1), continued.end()
            elif continued := _BASE64_CONTINUED.match(text, payload_end):
                joined_end = continued.end()
        empty = payload_start == payload_end
        split = _SPLIT_PAYLOAD.match(text, joined_end) is not None
        runs = _BASE64_RUN.findall(text, payload_end, joined_end)
        over_budget = base64_payload and len(runs) > MAX_CONTINUATION_RUNS
        if empty or split or over_budget:
            end = max(capture_end, joined_end)
            end = _TOKEN_REST.match(text, end).end() if empty or split else end
            consumed[0] = end
            yield None, start, end, end, None
            continue
        # The join (the payload's last run, or the last word joined after it) ends at a character outside
        # the alphabet, not at whitespace: a lenient decoder skips that character and reads on, through
        # words and delimiters alike. Each delimiter is followed until the join ends at whitespace or the
        # end of the text, every token and word on the way counting toward the run budget.
        spent, refused = len(runs), False
        while base64_payload and joined_end < len(text) and not text[joined_end].isspace():
            continuation = _lenient_continuation(text, joined_end, spent)
            if continuation is None or continuation[1]:
                end = continuation[0] if continuation else _lenient_join_end(text, joined_end)
                consumed[0] = end
                yield None, payload_start, end, end, end if continuation else None
                refused = True
                break
            # Only punctuation before the first ordinary word: the payload ends here, and, as for a payload
            # that ends at whitespace, the join through the words after it is read when it is text.
            continuation_end, _holds_base64, spent = continuation
            words = _BASE64_CONTINUED.match(text, continuation_end)
            if not words:
                break
            spent += len(_BASE64_RUN.findall(text, continuation_end, words.end()))
            joined_end = words.end()
            if spent > MAX_CONTINUATION_RUNS or _SPLIT_PAYLOAD.match(text, joined_end):
                end = _lenient_join_end(text, joined_end) if spent > MAX_CONTINUATION_RUNS else _TOKEN_REST.match(text, joined_end).end()
                consumed[0] = end
                yield None, payload_start, end, end, None
                refused = True
                break
        if refused:
            continue
        consumed[0] = max(capture_end, joined_end)
        yield parameters, payload_start, payload_end, joined_end, None


def _data_uri_text(parameters: str, payload: str) -> str | None:
    """A percent-encoded payload decoded in its declared charset, or None when it is not text."""
    from urllib.parse import unquote_to_bytes

    return _text_of(unquote_to_bytes(payload), _data_uri_charset(parameters))


def _text_of(data: bytes | None, codec: str | None) -> str | None:
    """``data`` decoded completely in ``codec``, or None when it is not text (it does not decode, or
    holds a control character other than a line break or tab)."""
    if data is None or codec is None:
        return None
    try:
        text = data.decode(codec)
    except UnicodeDecodeError:
        return None
    if any(unicodedata.category(character) == "Cc" and character not in "\n\r\t" for character in text):
        return None
    return text


def _base64_stream(text: str, runs: list[tuple[int, int]]) -> tuple[str, list[int]] | None:
    """The base64 characters of ``runs`` joined, whitespace aside, with the raw index of each; None
    when a run holds any other character."""
    characters: list[str] = []
    positions: list[int] = []
    for run_start, run_end in runs:
        for index in range(run_start, run_end):
            character = text[index]
            if character.isspace():
                continue
            if character not in _BASE64_ALPHABET:
                return None
            characters.append(character)
            positions.append(index)
    return "".join(characters), positions


_SEGMENT = re.compile(r"[A-Za-z0-9+/]+=*|=+")


def _segment_bytes(segment: str) -> bytes | None:
    """One pad-delimited segment decoded, or None unless it is whole base64: data in groups of four,
    or a last group of two or three closed by its padding."""
    data = segment.rstrip("=")
    if not data or (len(data) % 4, len(segment) - len(data)) not in {(0, 0), (2, 2), (3, 1)}:
        return None
    return binascii.a2b_base64(segment)


def _segment_reading(stream: str) -> tuple[bytes | None, list[tuple[int, int, bytes | None]]]:
    """The stream decoded segment by segment (each segment is base64 data and the padding that closes
    it), and each segment's span and bytes. The bytes are None when any segment does not decode whole.
    A decoder that stops at the first padding yields a prefix of these bytes."""
    segments = [(match.start(), match.end(), _segment_bytes(match.group(0))) for match in _SEGMENT.finditer(stream)]
    if not segments or any(data is None for _start, _end, data in segments):
        return None, segments
    return b"".join(data for _start, _end, data in segments if data is not None), segments


def _flat_reading(stream: str) -> bytes | None:
    """The stream decoded as Python 3.14's lenient decoder decodes it: padding inside the stream is skipped and
    the data runs on. None when that decoder refuses the stream, or reads it the same as segments do
    (padding only at the end)."""
    if "=" not in stream.rstrip("="):
        return None
    data = stream.replace("=", "")
    remainder = len(data) % 4
    if remainder == 1 or (remainder and len(stream) - len(stream.rstrip("=")) < 4 - remainder):
        return None
    return binascii.a2b_base64(data + "=" * (-len(data) % 4))


def _always() -> bool:
    return True


def _data_uri_views(parent: _View, allow: Callable[[], bool] = _always) -> Iterator[tuple[_View | None, int, int]]:
    """For each data URI: a view of its decoded text, or None when it is not text.

    Percent-encoded payloads are read with %XX decoded, base64 payloads by ``_base64_views``. The bytes
    are read in the declared charset, which must be UTF-8 or US-ASCII. Every decoded character maps to
    the whole encoded run. ``allow`` is asked before each view is created; when it refuses, the URI is
    reported (None) instead.
    """
    text = parent.text
    for parameters, start, end, joined_end, continued_end in _data_uri_spans(text):
        if parameters is None:
            yield None, start, end
            if continued_end is not None:
                # What a lenient decoder reads past the delimiter is read too, so the refusal names it.
                yield from _legible_readings(parent, start, continued_end, allow, None)
        elif _is_base64(parameters):
            yield from _base64_views(parent, parameters, start, end, joined_end, allow)
        elif (decoded := _data_uri_text(parameters, text[start:end])) is None:
            yield None, start, max(end, _TOKEN_REST.match(text, end).end())
        elif not allow():
            yield None, start, end
        else:
            yield _derived("data-uri", parent, list(decoded), [(start, end)] * len(decoded)), start, end


def _legible_readings(parent: _View, start: int, end: int, allow: Callable[[], bool], skip: str | None,
                      codec: str | None = "utf-8") -> Iterator[tuple[_View | None, int, int]]:
    """Every base64 character in ``parent.text[start:end]`` joined, as a lenient decoder joins them, and
    read both ways (segments, and padding skipped); each reading that is text, other than ``skip``, is
    a view of the whole span."""
    stream = "".join(character for character in parent.text[start:end] if character in _BASE64_ALPHABET)
    seen = {skip}
    for reading in (_segment_reading(stream)[0], _flat_reading(stream)):
        if (legible := _text_of(reading, codec)) is not None and legible not in seen:
            seen.add(legible)
            if not allow():
                yield None, start, end
                return
            yield _derived("data-uri", parent, list(legible), [(start, end)] * len(legible)), start, end


def _base64_views(parent: _View, parameters: str, start: int, end: int, joined_end: int,
                  allow: Callable[[], bool] = _always) -> Iterator[tuple[_View | None, int, int]]:
    """A base64 payload's decoded text, or None when it cannot be read whole.

    The payload is the URI's own run and every whitespace-separated base64 run after it, line breaks
    included, up to the first ordinary word. Each of those runs is payload and must decode: read as
    pad-delimited segments, and as a decoder that skips padding inside the stream reads it, the bytes
    must decode completely to text. Otherwise the whole URI is opaque, and each segment that is text on
    its own is also read, so the refusal names legible content too. Nothing is replaced or dropped. The
    longer join through the words is read as well when it decodes to text, as a lenient decoder would
    join it."""
    text = parent.text
    runs = [(start, end)] + [match.span() for match in _BASE64_RUN.finditer(text, end, joined_end)]
    payload = runs[:1]
    for run in runs[1:]:
        if _PROSE_WORD.fullmatch(text, *run):
            break
        payload.append(run)
    payload_end = payload[-1][1]
    codec = _data_uri_charset(parameters)

    def view(characters: str, span_start: int, span_end: int) -> tuple[_View | None, int, int]:
        """A view of ``characters``, or None (reported) once the view allowance is spent."""
        if not allow():
            return None, span_start, span_end
        return _derived("data-uri", parent, list(characters), [(span_start, span_end)] * len(characters)), span_start, span_end

    stream = _base64_stream(text, payload)
    whole, segments = _segment_reading(stream[0]) if stream else (None, [])
    decoded = _text_of(whole, codec)
    flat = _flat_reading(stream[0]) if stream else None
    # Padding inside the stream means the padding-skipping decoder reads it differently; when that
    # decoder refuses the stream, the payload cannot be read whole. Only a stream with no inner padding
    # reads the same both ways.
    flat_differs = stream is not None and "=" in stream[0].rstrip("=")
    flat_text = _text_of(flat, codec) if flat is not None else None
    if decoded is not None and (not flat_differs or flat_text is not None):
        yield view(decoded, start, payload_end)
        if flat_text is not None and flat_text != decoded:
            yield view(flat_text, start, payload_end)
    else:
        yield None, start, joined_end if len(runs) > 1 else max(end, _TOKEN_REST.match(text, end).end())
        for segment_start, segment_end, data in segments:
            if (legible := _text_of(data, codec)) and stream:
                span_start, span_end = stream[1][segment_start], stream[1][segment_end - 1] + 1
                yield view(legible, span_start, span_end)
    if len(payload) < len(runs) and _base64_stream(text, runs):
        yield from _legible_readings(parent, start, joined_end, allow, decoded, codec)


# JSON reading with raw offsets ------------------------------------------


class _JsonError(ValueError):
    pass


class _TooDeep(Exception):
    pass


class _OverBudget(Exception):
    """The screen's JSON budget would be exceeded: the JSON cannot be read whole, so it refuses."""


@dataclass
class _JsonString:
    view: _View  # the decoded value, with each character's raw offset

    @property
    def value(self) -> str:
        return self.view.text


@dataclass
class _JsonNumber:
    view: _View  # the number as written, with its raw offsets

    @property
    def value(self) -> str:
        return self.view.text


@dataclass
class _JsonObject:
    members: list[tuple[_JsonString, Any]]  # every member in order, repeated keys included
    span: tuple[int, int, str] | None = None  # raw start, raw end and the text read


class _JsonArray(list):  # type: ignore[type-arg]
    """A JSON array, with the raw start, raw end and text it was read from."""

    span: tuple[int, int, str] | None = None


class _JsonReader:
    """Strict JSON read by hand so that every string keeps its raw offsets and every
    object member is kept, repeated keys included."""

    _NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

    def __init__(self, parent: _View, limit: int) -> None:
        self.parent = parent
        self.text = parent.text
        self.index = 0
        self.limit = limit

    def parse(self) -> Any:
        value = self._value(0)
        self._skip()
        if self.index != len(self.text):
            raise _JsonError("trailing content")
        return value

    def _skip(self) -> None:
        while self.index < len(self.text) and self.text[self.index] in " \t\n\r":
            self.index += 1

    def _value(self, depth: int) -> Any:
        if depth > self.limit:
            raise _TooDeep
        self._skip()
        if self.index >= len(self.text):
            raise _JsonError("unexpected end")
        character = self.text[self.index]
        if character == "{":
            return self._object(depth)
        if character == "[":
            return self._array(depth)
        if character == '"':
            return self._string()
        for literal, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(literal, self.index):
                self.index += len(literal)
                return value
        match = self._NUMBER.match(self.text, self.index)
        if match:
            self.index = match.end()
            return _JsonNumber(_derived("json", self.parent, list(match.group(0)),
                                        [(position, position + 1) for position in range(match.start(), match.end())]))
        raise _JsonError("unexpected character")

    def _expect(self, character: str) -> bool:
        self._skip()
        if self.text.startswith(character, self.index):
            self.index += 1
            return True
        return False

    def _span(self, begin: int) -> tuple[int, int, str]:
        """The raw span and text of what was read from ``begin`` to here."""
        return (*self.parent.raw_span(begin, self.index), self.text[begin:self.index])

    def _object(self, depth: int) -> _JsonObject:
        members: list[tuple[_JsonString, Any]] = []
        begin = self.index
        self.index += 1
        if self._expect("}"):
            return _JsonObject(members, self._span(begin))
        while True:
            self._skip()
            if not self.text.startswith('"', self.index):
                raise _JsonError("expected a key")
            key = self._string()
            if not self._expect(":"):
                raise _JsonError("expected ':'")
            members.append((key, self._value(depth + 1)))
            if self._expect(","):
                continue
            if self._expect("}"):
                return _JsonObject(members, self._span(begin))
            raise _JsonError("expected ',' or '}'")

    def _array(self, depth: int) -> _JsonArray:
        items = _JsonArray()
        begin = self.index
        self.index += 1
        if self._expect("]"):
            items.span = self._span(begin)
            return items
        while True:
            items.append(self._value(depth + 1))
            if self._expect(","):
                continue
            if self._expect("]"):
                items.span = self._span(begin)
                return items
            raise _JsonError("expected ',' or ']'")

    def _string(self) -> _JsonString:
        self.index += 1
        characters: list[str] = []
        positions: list[tuple[int, int]] = []
        text = self.text
        while True:
            if self.index >= len(text):
                raise _JsonError("unterminated string")
            character = text[self.index]
            if character == '"':
                self.index += 1
                return _JsonString(_derived("json", self.parent, characters, positions))
            if character == "\\":
                match = _ESCAPE.match(text, self.index)
                if match is None:
                    raise _JsonError("invalid escape")
                decoded, end = _decode_escape(text, match)
                characters.append(decoded)
                positions.append((self.index, end))
                self.index = end
                continue
            if ord(character) < 0x20:
                raise _JsonError("control character in string")
            characters.append(character)
            positions.append((self.index, self.index + 1))
            self.index += 1


def _parse_json(view: _View, limit: int) -> Any:
    return _JsonReader(view, limit).parse()


# Detectors --------------------------------------------------------------


_OPENERS = {"(": ")", "[": "]", "{": "}"}


# Code that refers to a secret held elsewhere, recognized by shape: an
# environment lookup by an upper-case name, a call whose arguments are only
# names, a subscript by a name-like key, or an attribute chain. A string
# literal anywhere else (as in str('...') or a default value) is not a
# reference. Accepted only for unquoted values in code-like assignments.
_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_CHAIN = rf"{_NAME}(?:\.{_NAME})*"
_CODE_REFERENCE = re.compile(
    rf"""^(?:
        (?:os\.getenv|os\.environ\.get|getenv|System\.getenv|ENV\.fetch)\(\s*["'][A-Z_][A-Z0-9_]*["']\s*\)
      | (?:os\.environ|process\.env|ENV)\s*\[\s*["'][A-Z_][A-Z0-9_]*["']\s*\]
      | {_CHAIN}\(\s*(?:{_CHAIN}(?:\s*,\s*{_CHAIN})*)?\s*\)
      | {_CHAIN}\[\s*(?:"{_NAME}"|'{_NAME}'|{_NAME})\s*\]
      | {_NAME}(?:\.{_NAME})+
    )$""",
    re.X,
)


class _Detector:
    def __init__(self, rules: dict[str, Any]) -> None:
        self.rules = rules
        self.confusables = rules.get("confusables", {})
        self.placeholder_values = {value.lower() for value in rules.get("placeholder_values", [])}
        self.placeholder_patterns = [re.compile(pattern) for pattern in rules.get("placeholder_patterns", [])]
        self.segments = {value.lower() for value in rules.get("secret_name_segments", [])}
        self.pairs = [tuple(pair) for pair in rules.get("secret_name_pairs", [])]
        # Every credential word, every word of a credential pair and every word of a phrase name is read
        # with its plural, in both readings of a name: api_keys, ApiKeys, apikeys and seed_phrases alike.
        self.segment_forms = {form for segment in self.segments for form in self.word_forms(segment)}
        self.pair_forms = [(self.word_forms(first), self.word_forms(second)) for first, second in self.pairs]
        self.suffixes = ({form for segment in self.segments if segment not in self.WHOLE_PART_ONLY for form in self.word_forms(segment)}
                         | {first + second for first_forms, second_forms in self.pair_forms for first in first_forms for second in second_forms})
        self.phrases = [phrase.lower() for phrase in rules.get("phrase_names", [])]
        self.phrase_forms = {" ".join(combination) for phrase in self.phrases
                             for combination in itertools.product(*(sorted(self.word_forms(word)) for word in phrase.split()))}
        self.secret_headers = {header.lower() for header in rules.get("secret_headers", [])}
        headers = "|".join(re.escape(header) for header in rules.get("secret_headers", []))
        # A header at the start of a line (after optional quoting or list
        # marks) or inside a -H/--header argument; not a word in prose.
        self.header_re = re.compile(
            r"(?im)(?:^[ \t>*\-\"']*|(?:-H|--header)\s*[\"']?)(" + headers + r")\s*:\s*(?:(bearer|basic|token|digest)\s+)?([^\s\"',;]+)"
        )
        # The same headers written as quoted members, as in JSON or a dict
        # literal anywhere in text. The value is read by member_header_values:
        # a string, or every string in a list, tuple or mapping, nested or not.
        self.member_header_re = re.compile(r"(?i)([\"'])(" + headers + r")\1\s*:\s*")
        # Each flag with its last word plural as well (--api-keys, --passwords); the finding names the flag.
        flags = "|".join(re.escape(flag) for flag in rules.get("secret_cli_flags", []))
        self.flag_re = re.compile(r"(?i)(?<![A-Za-z0-9-])--(" + flags + r")(?:(?<=[sxz])es|(?<=ch)es|(?<=sh)es|s)?(?:=|\s+)([^\s\"']+|\"[^\"]*\"|'[^']*')")
        self.prefixes = [
            re.compile(r"(?<![A-Za-z0-9_])" + re.escape(item["prefix"]) + r"[A-Za-z0-9_\-./+=]{" + str(int(item["min_tail"])) + r",}")
            for item in rules.get("token_prefixes", [])
        ]
        self.role_locals = {value.lower() for value in rules.get("role_email_local_parts", [])}
        self.entropy = rules.get("entropy", {})
        self.pii = rules.get("pii", {})
        self._lines: tuple[str, list[int], list[int]] | None = None

    # Value helpers ------------------------------------------------------

    def placeholder(self, value: str) -> bool:
        stripped = value.strip().strip("\"'`")
        if not stripped:
            return True
        if stripped.lower() in self.placeholder_values:
            return True
        return any(pattern.match(stripped) for pattern in self.placeholder_patterns)

    @staticmethod
    def code_reference(value: str) -> bool:
        return bool(_CODE_REFERENCE.match(value.strip()))

    # The only fields read as a quantity although their name holds a credential word: names the product
    # itself generates, exactly as written, with a non-negative integer value. content_free_route writes
    # credential_source_count in place of credential references (an access profile's credential_sources,
    # a transport's api_key_env); max_tokens and max_output_tokens are the token limits a route's
    # transport and request options carry and a local request body sends. No other part of a name
    # (count, env, source or anything else) takes a name out of the credential names.
    GENERATED_QUANTITY_FIELDS = frozenset({"credential_source_count", "max_tokens", "max_output_tokens"})
    # A non-negative integer; in text a trailing backtick or full stop closes inline code or a sentence.
    _QUANTITY = re.compile(r"(?:0|[1-9][0-9]*)[`.]*")

    def normalized_name(self, name: str) -> str:
        """``name`` in the same comparison form as the normalized view."""
        return "".join(_skeleton(character, self.confusables) for character in name)

    def generated_quantity(self, name: str, value: str) -> bool:
        """Whether ``name`` is exactly a field the product generates as a count and ``value`` a non-negative integer."""
        return name in self.GENERATED_QUANTITY_FIELDS and self._QUANTITY.fullmatch(value) is not None

    # Where a name splits into parts: lower case or a digit before upper case (dbPassword), the last
    # capital of an upper-case run before a capitalized word (DBPassword, HTTPToken), and letters
    # next to digits (pass2), as well as at every character that is not a letter or digit.
    _NAME_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")
    # Credential words matched only as a whole part, never as the end of a longer part: each also ends
    # common words (bypass, compass, spin). Every other credential word, and each credential pair
    # written as one word (accesskey), is also matched at the end of a part (dbpassword, authtoken).
    WHOLE_PART_ONLY = frozenset({"pass", "pin"})

    def name_components(self, name: str) -> list[str]:
        """``name`` in comparison form, case-folded, split only at characters that are not letters or
        digits (``_``, ``-``, ``.``, spaces): case never splits it, so ``PaSsWoRd`` is ``password``."""
        return self._components_from_normalized(self.normalized_name(name))

    @staticmethod
    def _components_from_normalized(normalized: str) -> list[str]:
        return [part for part in re.split(r"[^a-z0-9]+", normalized.casefold()) if part]

    def name_parts(self, name: str) -> list[str]:
        """``name`` in comparison form, split at case changes, acronyms and digits as well, case-folded."""
        return self._parts_from_normalized(self.normalized_name(name))

    def _parts_from_normalized(self, normalized: str) -> list[str]:
        spaced = self._NAME_BOUNDARY.sub(" ", normalized)
        return [part.casefold() for part in re.split(r"[^A-Za-z0-9]+", spaced) if part]

    def name_readings(self, name: str) -> tuple[list[str], list[str]]:
        """Both readings of ``name``: its unsplit components, and its parts split at case changes."""
        normalized = self.normalized_name(name)
        return self._components_from_normalized(normalized), self._parts_from_normalized(normalized)

    @staticmethod
    def word_forms(word: str) -> set[str]:
        """``word`` and its plural: with ``s``, or ``es`` after s, x, z, ch or sh (``key``, ``keys``;
        ``pass``, ``passes``)."""
        forms = {word, word + "s"}
        if word.endswith(("s", "x", "z", "ch", "sh")):
            forms.add(word + "es")
        return forms

    def credential_part(self, part: str) -> bool:
        """Whether one name part is a credential word or its plural, or ends with one, or with a
        credential pair written as one word (``apikeys``, ``dbaccesskey``) with either word plural."""
        return part in self.segment_forms or any(part.endswith(suffix) for suffix in self.suffixes)

    def credential_reading(self, parts: list[str]) -> bool:
        """Whether one reading of a name holds a credential word or a credential pair. Each word of a
        pair is read with its plural (``api_keys``, ``access_keys``, ``private_keys``), and the first
        word, like a credential word, also as the end of a compound (``dbaccess_key``)."""
        if any(self.credential_part(part) for part in parts):
            return True
        return any(second in second_forms and any(first.endswith(form) for form in first_forms)
                   for first, second in zip(parts, parts[1:]) for first_forms, second_forms in self.pair_forms)

    def secret_name(self, name: str) -> bool:
        """Whether ``name`` is a credential name: either reading holds a credential word or pair, or it
        names a recovery phrase (``phrase_name``). Splitting at case changes adds a reading; it never
        replaces the unsplit one."""
        readings = self.name_readings(name)
        return any(self.credential_reading(parts) for parts in readings) or self._phrase_readings(readings)

    def header_name(self, name: str) -> str | None:
        """The policy header ``name`` denotes (normalized, case-insensitive), or None."""
        normalized = self.normalized_name(name).strip().lower()
        return normalized if normalized in self.secret_headers else None

    def header_value_secret(self, header: str, value: str) -> bool:
        """Whether a credential header's value is a credential rather than a placeholder. The placeholder
        test reads everything after the scheme: a placeholder first word never exempts what follows it."""
        match = re.match(r"(?i)\s*(bearer|basic|token|digest)\s+(\S)", value)
        credential = value[match.start(2):].strip() if match else value.strip()
        if not credential or self.placeholder(credential):
            return False
        return bool(match) or header in {"cookie", "set-cookie"} or (len(credential) >= 8 and bool(re.search(r"\d", credential)))

    def phrase_name(self, name: str) -> bool:
        """Whether ``name`` names a policy phrase (``mnemonic``, ``seed phrase``): in either reading, with
        its words apart (``seed_phrase``, ``SeedPhrase``) or joined (``seedphrase``), each word read with
        its plural (``seed_phrases``, ``seedsphrase``)."""
        return self._phrase_readings(self.name_readings(name))

    def _phrase_readings(self, parts: tuple[list[str], list[str]]) -> bool:
        readings = [" ".join(reading) for reading in parts]
        joined = [reading.replace(" ", "") for reading in readings]
        return any(phrase in reading for phrase in self.phrase_forms for reading in readings) or any(
            phrase.replace(" ", "") in reading for phrase in self.phrase_forms for reading in joined)

    # Detectors ------------------------------------------------------------

    def scan(self, view: _View) -> Iterator[tuple[str, str, int, int]]:
        text = view.text
        yield from self.key_blocks(text)
        yield from self.url_userinfo(text)
        for pattern in self.prefixes:
            for match in pattern.finditer(text):
                yield ("token-prefix", "certain", match.start(), match.end())
        for match in re.finditer(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}", text):
            yield ("jwt", "certain", match.start(), match.end())
        for match in self.header_re.finditer(text):
            value = match.group(3)
            credential_like = bool(match.group(2)) or match.group(1).lower() in {"cookie", "set-cookie"} or (
                len(value) >= 8 and bool(re.search(r"\d", value))
            )
            if credential_like and not self.placeholder(value):
                # The header name comes from the policy list, never from input.
                yield (f"header:{match.group(1).lower()}", "certain", match.start(3), match.end(3))
            elif (rest_end := self.continued(text, match.end(3), start=match.start(3))) is not None and (
                    credential_like or self.header_value_secret(match.group(1).lower(), text[match.start(2) if match.group(2) else match.start(3):rest_end])):
                # A placeholder, or a first word that is not credential-shaped, exempts the value only when
                # it is the whole value: with what continues it on its line, it is tested whole.
                yield (f"header:{match.group(1).lower()}", "certain", match.start(3), rest_end)
        for match in self.member_header_re.finditer(text):
            header = match.group(2).lower()
            read = self.member_header_values(text, match.end())
            if read is None:
                line_end = text.find("\n", match.end())
                yield ("header-unreadable", "uncertain", match.end(), len(text) if line_end == -1 else line_end)
                continue
            values, rest_end = read
            for start, end, value in values:
                if self.header_value_secret(header, value):
                    yield (f"header:{header}", "certain", start, end)
            if rest_end is not None:
                # Nothing after the value is exempt: what continues it is part of the header's value.
                yield (f"header:{header}", "certain", match.end(), rest_end)
        for match in self.flag_re.finditer(text):
            value = match.group(2)
            if not self.placeholder(value) and not self.code_reference(value):
                yield (f"cli-flag:{match.group(1).lower()}", "certain", match.start(2), match.end(2))
            elif not self.literal_closed(text, match.end(2)):
                # A shell joins what follows the value at once ("example""hunter2", 'example'hunter2) into
                # the same word: a placeholder exempts only the whole word.
                yield (f"cli-flag:{match.group(1).lower()}", "certain", match.start(2), _TOKEN_TAIL.match(text, match.end(2)).end())
        for match in re.finditer(r"(?i)\b(?:mysql|mysqldump|mysqladmin)\b[^\n]*?\s-p(\S+)", text):
            if not self.placeholder(match.group(1)):
                yield ("cli-flag:mysql-p", "certain", match.start(1), match.end(1))
        for match in re.finditer(r"(?i)(?<!\S)-u\s+[^\s:@]+:(\S+)", text):
            if not self.placeholder(match.group(1)):
                yield ("cli-flag:user-password", "certain", match.start(1), match.end(1))
        yield from self.assignments(text)
        yield from self.prose(text)
        yield from self.contact(text)
        yield from self.entropic(text)

    def key_blocks(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        for match in re.finditer(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----", text):
            end = text.find("-----END", match.end())
            close = text.find("-----", end + 8) + 5 if end != -1 else len(text)
            yield ("key-block", "certain", match.start(), max(close, match.end()))

    def url_userinfo(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        for match in re.finditer(r"\b[A-Za-z][A-Za-z0-9+.\-]*://([^\s/@:\"'<>]+)(?::([^\s/@\"'<>]*))?@[^\s/@\"'<>]", text):
            user, password = match.group(1), match.group(2)
            if password and not self.placeholder(password):
                yield ("url-userinfo", "certain", match.start(2), match.end(2))
            elif password is None and len(user) >= 16 and re.search(r"\d", user) and re.search(r"[A-Za-z]", user):
                yield ("url-userinfo", "certain", match.start(1), match.end(1))

    # Whitespace after a separator, including the escapes that stand for it in
    # JSON-encoded text (a JSON-quoted prompt writes a line break as \n).
    _GAP = re.compile(r"(?:\s|\\[nrt]|\\u000[9aAdD])+")
    # An unquoted value ends at whitespace, a comma or semicolon, an escaped line
    # break or tab, or a bracket that closes an enclosing structure.
    _UNQUOTED_VALUE = re.compile(r"(?:(?!\\[nrt]|\\u000[9aAdD])[^\s,;])+")

    @staticmethod
    def unquoted_end(text: str, start: int, end: int) -> int:
        """Where an unquoted value in ``text[start:end]`` ends: before a closing bracket it did not open."""
        depth = 0
        for index in range(start, end):
            if text[index] in _OPENERS:
                depth += 1
            elif text[index] in ")]}":
                if depth == 0:
                    return index
                depth -= 1
        return end
    _TEMPLATE = re.compile(r"<[^<>\n]*>|\{\{[^{}\n]*\}\}|\$\{[^{}\n]*\}")

    # The end of a line: a line break, or its escape in JSON-encoded text.
    _LINE_END = re.compile(r"[\r\n]|\\[nr]|\\u000[aAdD]")
    # Spaces and tabs after a value, escaped tabs included.
    _SPACES = re.compile(r"(?:[ \t]|\\t)*")
    # The next member after a comma or semicolon: a quoted or bare name and its own separator.
    _NEXT_MEMBER = re.compile(r"""(?:"[^"\n]*"|'[^'\n]*'|[A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*[:=]""")

    def continued(self, text: str, end: int, *, start: int | None = None, literal: bool = False) -> int | None:
        """None when the value ending at ``end`` is complete; otherwise where the content that continues
        it ends. An exemption (a placeholder, a code reference, a generated count, a structure whose
        values are all exempt) applies only to a complete value: what follows it is never exempt.

        A value is complete when, after spaces, its line ends, a closing bracket follows, or a comma or
        semicolon follows and then the line ends, a closing bracket, or the next member (a name and its
        separator). A value that starts at ``start`` (unquoted, or a structure) is also complete when it
        ends with, or is followed at once by, a quote or backtick that closes a literal opened before
        it on its line (`password=changeme` in prose, -H "Authorization: Bearer $TOKEN"), unless more
        text is joined to that quote (shell joins 'a''b' and 'a'b). A string ``literal`` whose line
        ends is continued by a string literal on a later line that is not a key, since Python joins
        adjacent literals across lines inside brackets. Anything else on the line continues the value:
        another literal (adjacent literals join, f-strings included), more words, or code
        (``or "hunter2"``, ``+ "hunter2"``)."""
        line_end = self.line_bounds(text, end)[1]
        index = self._SPACES.match(text, end, line_end).end()
        if index == line_end:
            return self.adjacent_literal(text, index) if literal else self.folded_line(text, end, line_end)
        if text[index] in ")]}":
            return None
        if text[index] in ",;":
            after = self._SPACES.match(text, index + 1, line_end).end()
            if after == line_end or text[after] in ")]}" or self._NEXT_MEMBER.match(text, after, line_end):
                return None
        elif start is not None and (quote := self.closing_quote(text, start, end)):
            line_start = self.line_bounds(text, start)[0]
            after_quote = end if end > start and text[end - 1] == quote else end + 1
            if (start - line_start <= self.LITERAL_REACH and text.count(quote, line_start, start) % 2 == 1
                    and self.literal_closed(text, after_quote)):
                return None
        # The finding covers what continues the value, up to LITERAL_REACH characters of it.
        return max(index + 1, end + len(text[end:min(line_end, index + self.LITERAL_REACH)].rstrip()))

    # One line end, a CRLF pair or its escapes included.
    _ONE_LINE_END = re.compile(r"\r\n|\\r\\n|[\r\n]|\\[nr]|\\u000[aAdD]")

    def folded_line(self, text: str, end: int, line_end: int) -> int | None:
        """Where the next line ends when it continues the value that ends its line at ``end``; else None.
        YAML folds the more indented lines after a plain scalar into it, and HTTP folds a header the
        same way. The next line continues the value when it is indented deeper than the line holding the
        value and is not blank, a member (a name and its separator), a list item, a comment, a closing
        bracket or a comma."""
        line_start = self.line_bounds(text, end)[0]
        indent = self._SPACES.match(text, line_start, line_end).end() - line_start
        if (step := self._ONE_LINE_END.match(text, line_end)) is None:
            return None
        next_start = step.end()
        next_end = self.line_bounds(text, next_start)[1]
        first = self._SPACES.match(text, next_start, next_end).end()
        if first == next_end or first - next_start <= indent or text[first] in "-#)]},":
            return None
        return None if self._NEXT_MEMBER.match(text, first, next_end) else next_end

    # A string literal's opening: an optional Python prefix (f, r, b, u and their pairs) and a quote, or
    # an escaped quote in JSON-encoded text. The match ends at the quote.
    _LITERAL_OPENING = re.compile(r"""(?i)(?:rb|br|fr|rf|[rbuf])?(?=\\?["'])""")

    def literal_closed(self, text: str, index: int) -> bool:
        """Whether the quote before ``index`` ends the literal: nothing is joined to it (whitespace, a line
        end, the end of the text or punctuation follows), as a shell would join 'a''b' or 'a'b."""
        return index >= len(text) or self._GAP.match(text, index) is not None or text[index] in ".,;:!?)]}>"

    def literal_after(self, text: str, index: int) -> tuple[tuple[int, int] | None, int] | None:
        """The string literal that follows ``index`` over whitespace and line breaks: its content span
        (None when it does not close on its line) and where it ends. None when no literal follows, or
        when it is a key (a ``:`` or ``=`` follows it)."""
        gap = self._GAP.match(text, index)
        following = gap.end() if gap else index
        opening = self._LITERAL_OPENING.match(text, following)
        if opening is None:
            return None
        quote_at = opening.end()
        span = self.quoted(text, quote_at, len(text))
        if span is None:
            return None, self.line_bounds(text, quote_at)[1]
        after = span[1] + (2 if text[quote_at] == "\\" else 1)
        gap = self._GAP.match(text, after)
        key_at = gap.end() if gap else after
        if key_at < len(text) and text[key_at] in ":=" and not text.startswith("==", key_at):
            return None
        return span, after

    def adjacent_literal(self, text: str, index: int) -> int | None:
        """Where a string literal Python would join to the one ending before ``index`` ends, or None."""
        following = self.literal_after(text, index)
        return None if following is None else max(following[1], index + 1)

    def literal_group(self, text: str, start: int) -> tuple[list[tuple[int, int]], int] | None:
        """The string literal opening at ``start`` (a prefix allowed) and every literal Python joins to it
        (adjacent, across lines too, keys excluded): their content spans and where the last ends. None
        when one does not close on its line."""
        opening = self._LITERAL_OPENING.match(text, start)
        quote_at = opening.end() if opening else start
        span = self.quoted(text, quote_at, len(text))
        if span is None:
            return None
        pieces = [span]
        end = span[1] + (2 if text[quote_at] == "\\" else 1)
        while (following := self.literal_after(text, end)) is not None:
            if following[0] is None:
                return None
            pieces.append(following[0])
            end = following[1]
        return pieces, end

    @staticmethod
    def closing_quote(text: str, start: int, end: int) -> str | None:
        """The quote or backtick an unquoted value ends with, or that follows it at once; else None."""
        if end > start and text[end - 1] in "`\"'":
            return text[end - 1]
        return text[end] if end < len(text) and text[end] in "`\"'" else None

    # An unquoted value is matched to a literal opened before it only within this many characters of
    # its line; on a longer line it is not taken as closed, so no exemption applies.
    LITERAL_REACH = 4096

    def line_bounds(self, text: str, index: int) -> tuple[int, int]:
        """Where the line holding ``index`` starts and ends (at a line break or its escape)."""
        if self._lines is None or self._lines[0] is not text:
            spans = [match.span() for match in self._LINE_END.finditer(text)]
            self._lines = (text, [start for start, _end in spans], [end for _start, end in spans])
        _text, starts, ends = self._lines
        before = bisect.bisect_right(ends, index) - 1
        after = bisect.bisect_left(starts, index)
        return (ends[before] if before >= 0 else 0), (starts[after] if after < len(starts) else len(text))

    _TRIPLE = re.compile(r'"""|\'\'\'')
    _SEPARATOR = re.compile(r"[:=]")

    @staticmethod
    def escaped(text: str, index: int) -> bool:
        """Whether the character at ``index`` follows an odd number of backslashes."""
        backslashes = 0
        while index - backslashes > 0 and text[index - backslashes - 1] == "\\":
            backslashes += 1
        return backslashes % 2 == 1

    def assignment_names(self, text: str) -> Iterator[tuple[str, int]]:
        """Each name written before a ``:`` or ``=``, and where that separator ends.

        Names are read back from the separator, with no length limit. A name that ends in a quote
        is a quoted key (JSON, a dict literal, YAML): it is read whole back to its opening quote on
        the same line, whatever characters it holds (other quotes, punctuation, separators). Any
        other name is the run of letters, digits, underscores, dots, hyphens and spaces before the
        separator. Each separator reads back over its own stretch of text, so the scan is linear."""
        for separator in self._SEPARATOR.finditer(text):
            index = separator.start()
            while index > 0 and text[index - 1].isspace():
                index -= 1
            if index > 0 and text[index - 1] in "\"'" and not self.escaped(text, index - 1):
                quote, opening = text[index - 1], index - 2
                while opening >= 0 and text[opening] != "\n" and (text[opening] != quote or self.escaped(text, opening)):
                    opening -= 1
                if opening >= 0 and text[opening] == quote:
                    yield text[opening + 1:index - 1], separator.end()
                continue
            begin = index
            while begin > 0 and (text[begin - 1].isalnum() or text[begin - 1] in "_.- "):
                begin -= 1
            yield text[begin:index], separator.end()

    # Product-generated text recognized exactly, never by the shape of a value. The contractor return
    # template (RETURN_TEMPLATE_SECTIONS in generate_manual_dispatch_prompt) writes each section as an
    # empty "Section:" line; its only section with a credential word is always followed by the next
    # section. Written with a line break or, in JSON-encoded text, its escape, at the start of a line
    # or of a JSON string.
    _GENERATED_LABEL = re.compile(r"(?:^|(?<=\n)|(?<=\\n)|(?<=\"))(Secret or personal-data spill):(?:\n|\\n)Scope compliance:")

    def assignments(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        generated = {match.end(1) + 1 for match in self._GENERATED_LABEL.finditer(text)}
        for raw_name, separator_end in self.assignment_names(text):
            name = raw_name.strip()
            if not name or not self.secret_name(name) or separator_end in generated:
                continue
            gap = self._GAP.match(text, separator_end)
            start = gap.end() if gap else separator_end
            if start >= len(text):
                continue
            if self.phrase_name(name) and text[start] not in "\"'":
                end = text.find("\n", start)
                end = len(text) if end == -1 else end
                if not self.placeholder(text[start:end]):
                    yield ("assignment", "certain", start, end)
                continue
            if bracketed := self._TEMPLATE.match(text, start):
                # A bracketed template such as <your password> or {{ token }} is one value; a placeholder
                # template exempts it only when nothing continues the value on its line.
                if not self.placeholder(bracketed.group(0)):
                    yield ("assignment", "certain", start, bracketed.end())
                elif (rest_end := self.continued(text, bracketed.end())) is not None:
                    yield ("assignment", "certain", start, rest_end)
                continue
            if text[start] in _OPENERS:
                yield from self.structure_findings(text, start)
                continue
            if triple := self._TRIPLE.match(text, start):
                # A triple-quoted string may span lines; one that does not close cannot be read whole.
                close = text.find(triple.group(0), triple.end())
                if close == -1:
                    yield ("assignment-unreadable", "uncertain", start, len(text))
                elif not self.placeholder(text[triple.end():close]):
                    yield ("assignment", "certain", triple.end(), close)
                elif (rest_end := self.continued(text, close + 3, literal=True)) is not None:
                    yield ("assignment", "certain", triple.end(), rest_end)
                continue
            if text[start] in "\"'" or text.startswith(("\\\"", "\\'"), start):
                span = self.quoted(text, start, len(text))
                if span is None:
                    # A quoted value that does not close on its line (truncated, or continued on the next).
                    line_end = text.find("\n", start)
                    yield ("assignment-unreadable", "uncertain", start, len(text) if line_end == -1 else line_end)
                elif not self.placeholder(text[span[0]:span[1]]):
                    yield ("assignment", "certain", span[0], span[1])
                elif (rest_end := self.continued(text, span[1] + (2 if text[start] == "\\" else 1), literal=True)) is not None:
                    yield ("assignment", "certain", span[0], rest_end)
                continue
            end_match = self._UNQUOTED_VALUE.match(text, start)
            if not end_match:
                continue
            value_start, value_end = start, self.unquoted_end(text, start, end_match.end())
            if value_end == value_start:
                continue
            value = text[value_start:value_end]
            # No value is taken for prose because it is a word followed by more words: a credential
            # name, a separator and a value is a credential, whatever the value looks like.
            words = name.split()
            # A placeholder, code naming where the secret comes from, or the product's own count (such as
            # credential_source_count: 2 after prose with no credential word) is exempt only as the whole
            # value: an unquoted value runs to the end of its line, so anything after it there continues it.
            if self.placeholder(value) or self.code_reference(value) or (
                    self.generated_quantity(words[-1], value) and not self.secret_name(" ".join(words[:-1]))):
                if (rest_end := self.continued(text, value_end, start=value_start)) is not None:
                    yield ("assignment", "certain", value_start, rest_end)
                continue
            yield ("assignment", "certain", value_start, value_end)

    # Structures ------------------------------------------------------------

    # A bracketed literal is read at most this far; one still open there cannot
    # be inspected completely, so it refuses.
    STRUCTURE_LIMIT = 8192
    _BARE = re.compile(r"(?:[^\s,:=;()\[\]{}\"'\\]|\\(?![\"'])|(?<=[A-Za-z0-9])'(?=[A-Za-z0-9]))+")
    _LITERALS = frozenset({"true", "false", "null", "none", "nil", "undefined"})

    def quoted(self, text: str, start: int, limit: int) -> tuple[int, int] | None:
        """The content span of the string literal opening at ``start`` (a quote, or an escaped quote
        in JSON-encoded text), or None when it does not close on its line."""
        escaped = text[start] == "\\"
        quote = text[start + 1] if escaped else text[start]
        index = start + (2 if escaped else 1)
        while index < limit:
            character = text[index]
            if character == "\n":
                return None
            if escaped and text.startswith("\\" + quote, index):
                return (start + 2, index)
            if character == "\\":
                index += 2
                continue
            if not escaped and character == quote:
                return (start + 1, index)
            index += 1
        return None

    def structure(self, text: str, start: int) -> tuple[list[tuple[int, int, bool, str]], int | None]:
        """Read the bracketed literal opening at ``start`` (JSON, a Python or JavaScript literal, a
        flow-style mapping or list) and return its value leaves ``(start, end, quoted, text)`` and its end.

        A credential field gives every value inside it its credential context, nested lists and
        mappings included, whatever the nested keys are called. Not values: mapping keys; call
        names, subscripts and the names passed to a call; and JSON and Python literals. Plain words
        are values like any other. String literals Python joins (adjacent, a prefix such as ``f``
        allowed, across lines too) are also one leaf with their joined text, besides each piece. The
        end is None when the literal does not close within ``STRUCTURE_LIMIT`` characters or closes
        with the wrong bracket."""
        limit = min(len(text), start + self.STRUCTURE_LIMIT)
        # Each frame: [closer, names are code (call or subscript), subscript]
        frames: list[list[Any]] = [[_OPENERS[text[start]], False, False]]
        leaves: list[tuple[int, int, bool, str]] = []
        words: list[tuple[int, int]] = []
        group: list[tuple[int, int]] = []  # adjacent string literals read so far, which Python joins

        def flush() -> None:
            # Every bare word is a value: a run of ordinary words inside a credential field is not prose.
            leaves.extend((s, e, False, text[s:e]) for s, e in words)
            words.clear()

        def close_group() -> None:
            if len(group) > 1:
                leaves.append((group[0][0], group[-1][1], True, "".join(text[s:e] for s, e in group)))
            group.clear()

        index = start + 1
        while index < limit:
            character = text[index]
            frame = frames[-1]
            if character.isspace():
                index += 1
                continue
            prefix = self._LITERAL_OPENING.match(text, index, limit)
            if prefix is None:
                close_group()  # anything but another literal ends a run of adjacent literals
            elif prefix.end() > index:
                # A string prefix (f, r, b, u): kept as a word, as before, but it does not end the run.
                words.append((index, prefix.end()))
                index = prefix.end()
                continue
            if character in _OPENERS:
                flush()
                frames.append([_OPENERS[character], False, False])
                index += 1
                continue
            if character in ")]}":
                flush()
                if character != frame[0]:
                    return leaves, None
                frames.pop()
                index += 1
                if not frames:
                    return leaves, index
                continue
            if character in ",;":
                flush()
                index += 1
                continue
            if character in ":=":
                flush()
                index += 1
                continue
            if character in "\"'" or text.startswith(("\\\"", "\\'"), index):
                flush()
                span = self.quoted(text, index, limit)
                if span is None:
                    return leaves, None
                after = span[1] + (2 if character == "\\" else 1)
                follow = self._GAP.match(text, after)
                following = follow.end() if follow else after
                key = following < limit and text[following] in ":=" and not text.startswith("==", following)
                if not key and not (frame[2] and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text[span[0]:span[1]])):
                    leaves.append((span[0], span[1], True, text[span[0]:span[1]]))  # a subscript's name-like key is code, not a value
                    group.append(span)
                else:
                    close_group()
                index = after
                continue
            match = self._BARE.match(text, index)
            if match is None:
                index += 1
                continue
            end = match.end()
            token = match.group(0)
            follow = self._GAP.match(text, end)
            following = follow.end() if follow else end
            if end < limit and text[end] in "([":
                flush()  # a call or subscript: the name and the names inside are code
                frames.append([_OPENERS[text[end]], True, text[end] == "["])
                index = end + 1
                continue
            if following < limit and text[following] in ":=" and not text.startswith("==", following):
                flush()  # a key
            elif not (frame[1] or token.lower() in self._LITERALS or self.code_reference(token)):
                words.append((index, end))
            index = end
        return leaves, None

    def structure_findings(self, text: str, start: int) -> Iterator[tuple[str, str, int, int]]:
        """Credential values inside the literal opening at ``start``; one that cannot be read whole refuses.
        The structure exempts nothing after it: anything that continues the value past its closing
        bracket (``[REDACTED] + "hunter2"``, ``("example") + "hunter2"``) is a finding."""
        leaves, end = self.structure(text, start)
        if end is None:
            line_end = text.find("\n", start)
            yield ("assignment-unreadable", "uncertain", start, min(len(text), start + self.STRUCTURE_LIMIT) if line_end == -1 else line_end)
            return
        for value_start, value_end, _quoted, value in leaves:
            if not self.placeholder(value):
                yield ("assignment", "certain", value_start, value_end)
        if (rest_end := self.continued(text, end, start=start)) is not None:
            yield ("assignment", "certain", start, rest_end)

    def member_header_values(self, text: str, start: int) -> tuple[list[tuple[int, int, str]], int | None] | None:
        """Values of a credential header written as a quoted member, each as (start, end, text): a string
        literal (a prefix allowed) joined with every literal Python joins to it, its pieces too, or the
        strings inside a structure at any depth, adjacent ones joined as well; and, when anything
        continues the value after it, where that ends (else None). None when the value cannot be read
        whole."""
        if start >= len(text):
            return [], None
        if self._LITERAL_OPENING.match(text, start):
            group = self.literal_group(text, start)
            if group is None:
                return None
            pieces, end = group
            values = [(piece_start, piece_end, text[piece_start:piece_end]) for piece_start, piece_end in pieces]
            if len(pieces) > 1:
                values.append((pieces[0][0], pieces[-1][1], "".join(value for _start, _end, value in values)))
            return values, self.continued(text, end)
        if text[start] in _OPENERS:
            leaves, end = self.structure(text, start)
            if end is None:
                return None
            return [(value_start, value_end, value) for value_start, value_end, quoted, value in leaves if quoted], self.continued(text, end)
        return [], None

    def prose(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        common = {"in", "on", "at", "a", "an", "the", "not", "set", "required", "missing", "empty", "stored", "kept", "never", "always", "optional", "unknown", "valid", "invalid", "redacted"}
        for match in re.finditer(r"(?i)\b(password|passphrase|secret|token|pin|api key|key)\s+(?:is|was)\s+[\"'`]?([^\s\"'`.,;]+)", text):
            value = match.group(2)
            if value.lower() in common or self.placeholder(value):
                continue
            if re.fullmatch(r"[a-z]+", value) or len(value) < 5:
                continue  # an ordinary word, as in "no other argument key is tolerated"
            # The label is one of the fixed alternatives above, never free input.
            yield (f"prose:{match.group(1).lower()}", "uncertain", match.start(2), match.end(2))

    def contact(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        if self.pii.get("email"):
            for match in re.finditer(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
                if match.group(1).lower() not in self.role_locals:
                    yield ("pii:email", str(self.pii["email"]), match.start(), match.end())
        if self.pii.get("phone"):
            for match in re.finditer(r"(?<![\w.+-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?![\w.-])", text):
                yield ("pii:phone", str(self.pii["phone"]), match.start(), match.end())
        if self.pii.get("ssn"):
            for match in re.finditer(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", text):
                yield ("pii:ssn", str(self.pii["ssn"]), match.start(), match.end())

    @staticmethod
    def word_like(token: str) -> bool:
        """Identifiers built from short words and version tags (model names, paths, env names)."""
        segments = [segment for segment in re.split(r"[-_/.]+", token) if segment]
        return len(segments) > 1 and all(
            len(segment) <= 12 and (segment.isalpha() or re.fullmatch(r"[A-Za-z]*\d+[A-Za-z]*", segment)) for segment in segments
        )

    def entropic(self, text: str) -> Iterator[tuple[str, str, int, int]]:
        for match in re.finditer(r"[A-Za-z0-9+/_\-]{24,}={0,2}", text):
            # Judge the token without base64 padding, so NAME= in an assignment
            # is still recognised as a name.
            token = match.group(0).rstrip("=")
            if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", token):
                continue  # digests and commit identifiers
            if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", token):
                continue
            if self.word_like(token) or self.placeholder(token):
                continue
            bits = _entropy(token)
            mixed = bool(re.search(r"[a-z]", token) and re.search(r"[A-Z]", token) and re.search(r"\d", token))
            if (
                mixed
                and not re.search(r"[-_]", token)
                and len(token) >= int(self.entropy.get("mixed_min_length", 24))
                and bits >= float(self.entropy.get("mixed_min_bits", 3.8))
            ) or (
                len(token) >= int(self.entropy.get("long_min_length", 40))
                and bits >= float(self.entropy.get("long_min_bits", 4.3))
                and re.search(r"\d", token)
                and re.search(r"[A-Za-z]", token)
            ):
                yield ("entropy", "uncertain", match.start(), match.end())


def _entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for character in token:
        counts[character] = counts.get(character, 0) + 1
    return -sum(count / len(token) * math.log2(count / len(token)) for count in counts.values())


# Screening --------------------------------------------------------------


class _Screen:
    def __init__(self, rules: dict[str, Any], length: int = 0) -> None:
        self.detector = _Detector(rules)
        self.confusables = rules.get("confusables", {})
        self.findings: dict[tuple[str, int, int], Finding] = {}
        self.views = 0
        self.json_depth = int(rules.get("limits", {}).get("max_json_depth", 64))
        # JSON already read structurally, by any entry point: (raw start, raw end, text); and the
        # payload's own JSON. Each is read once, so a second reading cannot spend the budgets again.
        self.structured: set[tuple[int, int, str]] = set()
        self.payload_json: tuple[int, int, str] | None = None
        # Every JSON value any reading has decoded, by raw start: (raw end, text). A reading checks this
        # before it decodes or charges anything, so JSON already read is never decoded or charged again.
        self.decoded_at: dict[int, set[tuple[int, str]]] = {}
        # One JSON budget for the whole payload, shared by every entry point: the characters the
        # embedded-JSON decoder examines and the characters each structural reading parses.
        self.json_budget = self.JSON_EXAMINED_PER_CHARACTER * length + self.JSON_EXAMINED_ALLOWANCE
        self.json_examined = 0
        # Every JSON string and subtree read structurally to the end, by raw start, raw end and text, with
        # the deepest level it was read at. Another structural reading (the normalized view of the same
        # JSON, say) reaches the same raw text unchanged: it is read once, at that level or any shallower.
        self.traversed: dict[tuple[str, int, int, str], int] = {}

    def charge(self, cost: int) -> None:
        """Spend ``cost`` characters of the JSON budget, or raise _OverBudget without spending them."""
        if self.json_examined + cost > self.json_budget:
            raise _OverBudget
        self.json_examined += cost

    @staticmethod
    def json_bounds(text: str) -> tuple[int, int]:
        """``text`` without the JSON whitespace around it, as (start, end)."""
        return len(text) - len(text.lstrip(" \t\n\r")), len(text.rstrip(" \t\n\r"))

    @staticmethod
    def claim_key(view: _View, begin: int, end: int) -> tuple[int, int, str]:
        return (*view.raw_span(begin, end), view.text[begin:end])

    def already_read(self, key: tuple[int, int, str]) -> bool:
        """Whether the JSON with this raw span and text was read structurally already."""
        return key in self.structured or self.inside_payload_json(*key)

    def claim(self, view: _View, begin: int, end: int) -> bool:
        """Mark ``view.text[begin:end]`` as read structurally; False when it already was."""
        key = self.claim_key(view, begin, end)
        self.decoded_at.setdefault(key[0], set()).add(key[1:])
        if self.already_read(key):
            return False
        self.structured.add(key)
        return True

    def decoded_end(self, view: _View, begin: int) -> int | None:
        """Where JSON that an earlier reading decoded and claimed (or found already read) ends, when the
        same raw text starts at ``begin`` in ``view``; None otherwise. In the raw view, every value that
        starts inside the payload's own JSON lies inside it and was read with it, so the scan skips to
        its end."""
        if view.ranges is None and self.payload_json is not None and self.payload_json[0] <= begin < self.payload_json[1]:
            return self.payload_json[1]
        raw_start = view.raw_range(begin)[0]
        for raw_end, text in self.decoded_at.get(raw_start, ()):
            end = begin + len(text)
            if view.text.startswith(text, begin) and view.raw_span(begin, end) == (raw_start, raw_end):
                return end
        return None

    def scan_decoded_json(self, view: _View, nesting: int = 0) -> None:
        """A decoded view that is JSON gets the structural checks too (credential keys, nested values),
        with its raw offsets and the same depth limit, counted from the ``nesting`` of the JSON around
        it; JSON nested too deep is opaque. JSON already read is skipped before it is decoded or charged."""
        stripped = view.text.strip()
        if stripped[:1] not in ("{", "[") or stripped[-1:] not in ("}", "]"):
            return
        if self.already_read(self.claim_key(view, *self.json_bounds(view.text))):
            return
        try:
            self.charge(len(view.text))
            parsed = _parse_json(view, max(0, self.json_depth - nesting))
            if not self.claim(view, *self.json_bounds(view.text)):
                return
            self.scan_json(parsed, nesting, self.json_depth)
        except (_TooDeep, RecursionError):
            self.record(view, "encoded-content", "uncertain", 0, len(view.text))
        except _OverBudget:
            self.record(view, "json-unreadable", "uncertain", 0, len(view.text))
        except _JsonError:
            return

    # Embedded JSON is decoded in windows that grow from this size. The JSON budget is this many
    # characters per character of the payload, plus a fixed allowance; JSON that needs more is not
    # inspected whole, so it refuses.
    JSON_WINDOW = 256
    JSON_EXAMINED_PER_CHARACTER = 64
    JSON_EXAMINED_ALLOWANCE = 1 << 20
    # Where a JSON value can start: { before a key or }, [ before a value or ].
    _JSON_START = re.compile(r"""\{(?=[ \t\n\r]*["}])|\[(?=[ \t\n\r]*[\]\[{"0-9tfnNI-])""")
    _DECODER = json.JSONDecoder()

    def _json_end(self, text: str, begin: int) -> int | None:
        """Where the JSON value starting at ``begin`` ends, or None when none does. Each window is charged
        to the JSON budget before it is decoded, so the budget is never exceeded (_OverBudget). A window
        cut short of the text that fails where the cut could be the cause (near its end, or in a string
        still open there) is retried four times as large. A value the decoder starts but cannot finish
        for any reason other than a syntax error (such as an integer too long to convert) raises
        _JsonError: it cannot be read, so it refuses."""
        window = self.JSON_WINDOW
        while True:
            document = text[begin:begin + window]
            self.charge(len(document))
            try:
                return begin + self._DECODER.raw_decode(document)[1]
            except json.JSONDecodeError as error:
                cut = begin + window < len(text)
                if cut and (error.pos >= len(document) - 16 or error.msg.startswith("Unterminated string")):
                    window *= 4
                    continue
                return None
            except ValueError:
                raise _JsonError("a value the decoder cannot convert") from None

    def scan_embedded_json(self, view: _View, nesting: int = 0) -> None:
        """Read JSON written inside text structurally: at each { or [ that can start a JSON value, a value
        that decodes is read by the structural JSON checks, with its raw offsets, and the scan resumes
        after it. Keys are read whole, whatever they hold and however long. JSON an earlier reading
        decoded at the same raw text is skipped before it is decoded or charged. Depth counts from the
        ``nesting`` of the JSON the text is in. A value that is too deep or cannot be read with offsets,
        a value the decoder cannot finish, or JSON that would exceed the budget, refuses."""
        text = view.text
        index = 0
        while start := self._JSON_START.search(text, index):
            begin = start.start()
            if (skip := self.decoded_end(view, begin)) is not None:
                index = max(skip, begin + 1)
                continue
            try:
                end = self._json_end(text, begin)
            except (RecursionError, _OverBudget, _JsonError):
                self.record(view, "json-unreadable", "uncertain", begin, len(text))
                return
            if end is None:
                index = begin + 1
                continue
            index = end
            if not self.claim(view, begin, end):
                continue
            embedded = _derived("json", view, list(text[begin:end]), [(position, position + 1) for position in range(begin, end)])
            try:
                self.charge(end - begin)
                self.scan_json(_parse_json(embedded, max(0, self.json_depth - nesting)), nesting, self.json_depth)
            except (_TooDeep, RecursionError, _JsonError, _OverBudget):
                self.record(view, "json-unreadable", "uncertain", begin, end)

    def inside_payload_json(self, raw_start: int, raw_end: int, text: str) -> bool:
        """Whether ``text`` is exactly the raw text at these offsets inside the payload's own JSON, which
        was read structurally already, so it is not read twice. Such text is a value read there, or
        starts inside one of the payload's strings: then, since a payload string ends at its first
        unescaped quote, its strings and keys are only the punctuation, numbers and literals between
        the payload's strings, and everything else in it is numbers, literals and brackets."""
        if self.payload_json is None:
            return False
        begin, end, payload = self.payload_json
        return begin <= raw_start and raw_end <= end and payload[raw_start - begin:raw_end - begin] == text

    def record_undecodable(self, view: _View) -> None:
        """Characters of a decoded view that came from an encoding that did not decode are opaque."""
        for index in view.undecodable:
            self.record(view, "encoded-content", "uncertain", index, index + 1)

    def record(self, view: _View, rule: str, certainty: str, start: int, end: int) -> None:
        raw_start, raw_end = view.raw_span(start, end)
        key = (rule, raw_start, raw_end)
        if key not in self.findings:
            self.findings[key] = Finding(rule, certainty, view.name, raw_start, raw_end, _fingerprint(view.text[start:end]))

    DECODING_DEPTH = 3
    # Decoded views per payload; more is refused as opaque rather than scanned slowly.
    MAX_VIEWS = 64

    def allow_view(self) -> bool:
        """Spend one decoded view of the allowance, or False when it is spent: asked before each view is
        created, so the allowance is never exceeded, and what would need another view is reported."""
        if self.views >= self.MAX_VIEWS:
            return False
        self.views += 1
        return True

    def scan_text(self, view: _View, *, depth: int = 0, nesting: int = 0) -> None:
        """Scan ``view`` and its normalized copy, then decode data URIs, escapes and %XX
        sequences, up to three levels, and scan what they reveal the same way.

        Decoding works on the normalized copy, so a fullwidth or confusable ``\\``, ``%``
        or ``data:`` decodes like its ASCII form, and each decoded level is normalized
        again before the next. Any of the three encodings still present after the last
        level, or beyond the view budget, is reported as opaque content rather than
        passed. Each derived view is created only within the view allowance. ``nesting`` is the depth
        of the JSON the text is in, so JSON inside it counts the levels around it."""
        normalized = _normalized_view(view, self.confusables)
        source = view if normalized.text == view.text else normalized
        for current in (view,) if source is view else (view, normalized):
            for rule, certainty, start, end in self.detector.scan(current):
                self.record(current, rule, certainty, start, end)
            self.scan_embedded_json(current, nesting)
        if depth >= self.DECODING_DEPTH or self.views >= self.MAX_VIEWS:
            for pattern in (_ESCAPE, _PERCENT):
                for match in pattern.finditer(source.text):
                    self.record(source, "encoded-content", "uncertain", match.start(), match.end())
                    break
            for _match, start, _end, joined_end, _continued in _data_uri_spans(source.text):
                self.record(source, "encoded-content", "uncertain", start, joined_end)
                break
            return
        for decoded, start, end in _data_uri_views(source, self.allow_view):
            if decoded is None:
                self.record(source, "encoded-content", "uncertain", start, end)
            else:
                self.scan_decoded_json(decoded, nesting)
                self.scan_text(decoded, depth=depth + 1, nesting=nesting)
        prefix = "" if source.name == "raw" else f"{source.name}+"
        for pattern, make in ((_ESCAPE, lambda: _unescaped_view(source, f"{prefix}unescaped")),
                              (_PERCENT, lambda: _percent_view(source, f"{prefix}percent-decoded"))):
            if not (match := pattern.search(source.text)):
                continue
            if not self.allow_view():
                self.record(source, "encoded-content", "uncertain", match.start(), match.end())
                continue
            derived = make()
            if derived is not None:
                self.record_undecodable(derived)
                self.scan_decoded_json(derived, nesting)
                self.scan_text(derived, depth=depth + 1, nesting=nesting)

    def read_before(self, kind: str, span: tuple[int, int, str] | None, depth: int) -> bool:
        """Whether this string or subtree, the same raw text, was read to the end at ``depth`` or deeper:
        reading it again finds nothing new, so another structural reading skips it."""
        return span is not None and self.traversed.get((kind, *span), -1) >= depth

    def mark_read(self, kind: str, span: tuple[int, int, str] | None, depth: int) -> None:
        if span is not None:
            key = (kind, *span)
            self.traversed[key] = max(depth, self.traversed.get(key, -1))

    def scan_json(self, value: Any, depth: int, limit: int) -> None:
        """Every object member (repeated keys included), every string, and JSON inside strings. A subtree
        read already, unchanged, is not read again."""
        if depth > limit:
            raise _TooDeep
        span = value.span if isinstance(value, (_JsonObject, _JsonArray)) else None
        if self.read_before("tree", span, depth):
            return
        self._scan_json(value, depth, limit)
        self.mark_read("tree", span, depth)

    def _scan_json(self, value: Any, depth: int, limit: int) -> None:
        if isinstance(value, _JsonObject):
            for key, item in value.members:
                self.scan_string(key, depth, limit)
                # A field the product generates as a count is a quantity only with a non-negative integer.
                quantity = isinstance(item, _JsonNumber) and self.detector.generated_quantity(key.value, item.value)
                secret = self.detector.secret_name(key.value) and not quantity
                header = self.detector.header_name(key.value)
                # Every string and number under the member, through lists and objects
                # at any depth: nesting a value does not take it out of the field.
                for leaf in self._values(item, depth, limit) if secret or header else ():
                    if secret and not self.detector.placeholder(leaf.value):
                        # A JSON value is data: no code-reference exemption applies.
                        self.record(leaf.view, "json-pair", "certain", 0, len(leaf.value))
                    if header and self.detector.header_value_secret(header, leaf.value):
                        # A credential header written as a JSON member, as it would be sent.
                        self.record(leaf.view, f"header:{header}", "certain", 0, len(leaf.value))
                self.scan_json(item, depth + 1, limit)
        elif isinstance(value, list):
            for item in value:
                self.scan_json(item, depth + 1, limit)
        elif isinstance(value, _JsonString):
            self.scan_string(value, depth, limit)

    def _values(self, item: Any, depth: int, limit: int) -> Iterator[_JsonString | _JsonNumber]:
        """Every string and number under a credential member, whatever the nested keys are called:
        a nested key cannot take a value out of the field."""
        if depth > limit:
            raise _TooDeep
        if isinstance(item, (_JsonString, _JsonNumber)):
            yield item
        elif isinstance(item, list):
            for element in item:
                yield from self._values(element, depth + 1, limit)
        elif isinstance(item, _JsonObject):
            for _key, element in item.members:
                yield from self._values(element, depth + 1, limit)

    def scan_string(self, string: _JsonString, depth: int, limit: int) -> None:
        """A JSON string's text, and JSON written as the whole string, read once.

        Nested JSON is read here, with the depth of the string it is in, and claimed before the text is
        scanned, so the embedded-JSON scan of the same text does not read it again. A string another
        structural reading read already, the same raw text, unchanged, is not read again."""
        span = (*string.view.raw_span(0, len(string.value)), string.value) if string.value else None
        if self.read_before("string", span, depth):
            return
        self._scan_string(string, depth, limit)
        self.mark_read("string", span, depth)

    def _scan_string(self, string: _JsonString, depth: int, limit: int) -> None:
        nested: Any = None
        stripped = string.value.strip()
        if (stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]")
                and not self.already_read(self.claim_key(string.view, *self.json_bounds(string.value)))):
            try:
                self.charge(len(string.value))
                parsed = _parse_json(string.view, max(0, limit - depth))
                if self.claim(string.view, *self.json_bounds(string.value)):
                    nested = (parsed,)
            except _JsonError:
                pass
            except _OverBudget:
                self.record(string.view, "json-unreadable", "uncertain", 0, len(string.value))
        self.scan_text(string.view, nesting=depth)
        if nested is not None:
            self.scan_json(nested[0], depth + 1, limit)


def screen_outbound(payload: bytes | str, *, surface: str, content_type: str = "text/plain") -> ScreenedPayload:
    """Screen exactly these bytes for ``surface`` and bind the result to their digest.

    Unsupported encodings, oversize payloads, unparsable declared JSON and JSON
    nested beyond the screening depth refuse: an incomplete scan never passes.
    """
    content_type = _supported_content_type(content_type, surface=surface)
    rules = _rules()
    data = _utf8_payload(payload, surface=surface)
    digest = hashlib.sha256(data).hexdigest()
    limits = rules.get("limits", {})
    limit = int(limits.get("max_input_bytes", 8 * 1024 * 1024))
    if len(data) > limit:
        raise OutboundRefused(f"outbound screening refused {surface}: payload exceeds the {limit}-byte screening limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutboundRefused(f"outbound screening refused {surface}: payload is not UTF-8 text") from exc
    screen = _Screen(rules, len(text))
    raw = _View("raw", text)
    depth = int(limits.get("max_json_depth", 64))
    if content_type == "application/json" or text.lstrip()[:1] in ("{", "["):
        try:
            screen.charge(len(text))
            parsed = _parse_json(raw, depth)
            begin, end = _Screen.json_bounds(text)
            screen.structured.add((begin, end, text[begin:end]))
            screen.scan_json(parsed, 0, depth)
            screen.payload_json = (begin, end, text[begin:end])
        except (_TooDeep, RecursionError):
            raise OutboundRefused(f"outbound screening refused {surface}: JSON nesting exceeds the screening depth of {depth}") from None
        except _OverBudget:
            raise OutboundRefused(f"outbound screening refused {surface}: JSON exceeds the screening budget") from None
        except _JsonError:
            if content_type == "application/json":
                raise OutboundRefused(f"outbound screening refused {surface}: declared JSON payload does not parse") from None
    screen.scan_text(raw)
    findings = tuple(sorted(screen.findings.values(), key=lambda f: (f.start, f.rule)))
    return ScreenedPayload(data=data, sha256=digest, surface=surface, findings=findings)


def _refusal(screened: ScreenedPayload) -> OutboundRefused:
    details = "; ".join(finding.describe() for finding in screened.findings[:10])
    more = f" and {len(screened.findings) - 10} more" if len(screened.findings) > 10 else ""
    return OutboundRefused(
        f"outbound screening refused {screened.surface}: {len(screened.findings)} finding(s): {details}{more}. "
        "Remove or redact the flagged content; nothing was sent."
    )


def require_clean(payload: bytes | str, *, surface: str, content_type: str = "text/plain") -> ScreenedPayload:
    """Screen and refuse on any finding; return the bound payload to send unchanged."""
    screened = screen_outbound(payload, surface=surface, content_type=content_type)
    if screened.findings:
        raise _refusal(screened)
    return screened


@contextmanager
def withheld_diagnostics(command: str) -> Iterator[None]:
    """Run a command whose own diagnostics can repeat input before anything screens it.

    A ``SystemExit`` message that the outbound screen would refuse is replaced by a
    fixed one naming only the rules it tripped and a digest; the exit status stays
    an error. An exit value that is neither an integer, None nor a plain string is
    withheld whole, like an unexpected exception. Any other exception, and any
    other BaseException except KeyboardInterrupt (a BaseExceptionGroup, whatever
    its members), is replaced by a diagnostic naming only its class and a digest
    of its full rendered traceback, which is not printed. Refusals from
    the screen itself pass through unchanged. Messages are still best written
    without caller input: this is the backstop, not the fix.
    """
    try:
        yield
    except OutboundRefused:
        raise
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        if not (exc.code is None or isinstance(exc.code, int) or type(exc.code) is str):
            # Python prints any other exit value (a mapping, a list, a str subclass) as text the screen
            # has not read: it is withheld whole, reported only by its class and a digest.
            raise _unexpected(command, exc) from None
        if isinstance(exc.code, str) and exc.code:
            try:
                _withhold(command, exc.code)
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as failure:
                # Screening the diagnostic failed: the failure's traceback holds the diagnostic as its
                # context, so it is withheld the same way, and the original is suppressed.
                raise _unexpected(command, failure) from None
        raise
    except BaseException as exc:
        # Any other exception, and any BaseException that is not an exit (a BaseExceptionGroup, which
        # Python prints whole, members, notes and exit values included), is withheld whole.
        raise _unexpected(command, exc) from None


def _unexpected(command: str, exc: BaseException) -> SystemExit:
    """The diagnostic for an unexpected error. Its traceback can repeat input anywhere: its message, a
    chained cause or context, a note, an exception-group member. None of it is printed; the diagnostic
    names the exception class and a digest of the whole rendered traceback. Raise it ``from None``."""
    rendered = "".join(traceback.format_exception(exc))
    digest = hashlib.sha256(rendered.encode("utf-8", errors="surrogatepass")).hexdigest()
    return SystemExit(
        f"{command} stopped on an unexpected {type(exc).__name__}; its details are withheld "
        f"(traceback sha256:{digest[:16]})"
    )


def _withhold(command: str, message: str) -> None:
    """Raise a fixed SystemExit in place of ``message`` if the outbound screen would refuse it."""
    screened = screen_outbound(message, surface=f"{command} diagnostic")
    if screened.findings:
        rules = ", ".join(sorted({finding.rule for finding in screened.findings}))
        raise SystemExit(
            f"{command} stopped; its diagnostic is withheld because it repeats content the outbound screen "
            f"refuses ({rules}; message sha256:{screened.sha256[:16]})"
        ) from None


def screen_request(
    method: str,
    url: str,
    headers: dict[str, str] | list[tuple[str, str]],
    body: bytes,
    *,
    surface: str,
    content_type: str = "application/json",
) -> ScreenedRequest:
    """Screen an HTTP request's method, URL, non-authentication headers and body; refuse on any finding.

    The ``Authorization`` and ``Proxy-Authorization`` headers carry CWO's own
    configured credential: they are bound by digest but not screened.
    """
    bound_headers = _request_headers(headers)
    content_type = _request_content_type(bound_headers, content_type, surface=surface)
    descriptor_text = f"{method.upper()} {url}\n" + "".join(f"{name}: {value}\n" for name, value in bound_headers)
    descriptor = require_clean(descriptor_text, surface=f"{surface} line and headers")
    screened_body = (require_clean(body, surface=surface, content_type=content_type) if body
                     else require_clean(b"", surface=f"{surface} empty body"))
    return ScreenedRequest(method.upper(), url, bound_headers, _authentication_digest(headers), screened_body, descriptor, surface)


# Argparse's own count messages. They are generated from the parser definition, never from input.
_ARGPARSE_COUNT_MESSAGES = ("expected one argument", "expected at most one argument", "expected at least one argument")
_ARGPARSE_EXPECTED_COUNT = re.compile(r"expected [0-9]+ arguments?")


def _argparse_action_name(action: argparse.Action) -> str | None:
    """The name argparse gives an action in its diagnostics, computed from the parser definition."""
    if action.option_strings:
        return "/".join(action.option_strings)
    if action.metavar not in (None, argparse.SUPPRESS):
        return action.metavar if isinstance(action.metavar, str) else " ".join(action.metavar)
    if action.dest not in (None, argparse.SUPPRESS):
        return action.dest
    return None


class ScreeningArgumentParser(argparse.ArgumentParser):
    """An argument parser whose diagnostics never repeat a value the caller supplied.

    Argparse writes its diagnostic to stderr before it raises SystemExit(2), so
    ``withheld_diagnostics`` cannot intercept it, and screening the formatted text
    is not enough: formatting quotes a value out of the context the detectors read
    it in. ``error()`` therefore never prints argparse's message. It writes the
    usage line and a fixed message built only from the parser's own definition:
    the option name, the kind of problem and, for an option with choices, the
    allowed choices, for example ``argument --data-sensitivity: invalid value
    (value withheld)`` or ``unrecognized arguments (values withheld)``. Nothing is
    screened, so a clean mistake is reported as plainly as a credential-shaped one.
    The exit status is 2. A screening refusal raised while parsing (a type
    function that screens) and any failure while building the message are
    reported by a fixed message with exit status 2. ``--help`` is unchanged.
    """

    def __init__(self, command_name: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, prog=command_name, **kwargs)
        self.command_name = command_name

    def parse_known_args(self, args: Any = None, namespace: Any = None) -> Any:
        try:
            return super().parse_known_args(args, namespace)
        except OutboundRefused:
            # The refusal's own text names no input, but the parser reports it by a fixed message
            # all the same, and with argparse's exit status.
            self._stop("an argument was refused by the outbound screen (details withheld)")

    def error(self, message: str) -> NoReturn:
        try:
            withheld = self._withheld_message(message)
        except KeyboardInterrupt:
            raise
        except BaseException:
            # OutboundRefused included: whatever went wrong, nothing from the message is written.
            withheld = "invalid arguments (details withheld)"
        self._stop(withheld)

    def _stop(self, withheld: str) -> NoReturn:
        try:
            self.print_usage(sys.stderr)
        except KeyboardInterrupt:
            raise
        except BaseException:
            pass
        self.exit(2, f"{self.prog}: error: {withheld}\n")

    def _withheld_message(self, message: str) -> str:
        """The message for ``message``, built only from fixed text and the parser's definition.

        ``message`` is read only to recognize which of argparse's templates produced it; no
        part of it is copied into the result except a name the parser itself defines.
        """
        actions: dict[str, argparse.Action] = {}
        for action in self._actions:
            name = _argparse_action_name(action)
            if name is not None:
                actions.setdefault(name, action)
        # Longest first, so "--local" never claims a message about "--local-ok".
        for name in sorted(actions, key=len, reverse=True):
            prefix = f"argument {name}: "
            if message.startswith(prefix):
                return f"argument {name}: {self._problem(message[len(prefix):], actions[name], actions)}"
        if message.startswith("unrecognized arguments:"):
            return "unrecognized arguments (values withheld)"
        if message.startswith("ambiguous option:"):
            return "ambiguous option (value withheld)"
        required = "the following arguments are required: "
        if message.startswith(required):
            names = message[len(required):].split(", ")
            if names and all(name in actions for name in names):
                return required + ", ".join(names)
            return "required arguments are missing"
        if message.startswith("one of the arguments ") and message.endswith(" is required"):
            return "a required argument is missing"
        return "invalid arguments (values withheld)"

    @staticmethod
    def _problem(rest: str, action: argparse.Action, actions: dict[str, argparse.Action]) -> str:
        """The kind of problem argparse reported for ``action``, without the value."""
        for count in _ARGPARSE_COUNT_MESSAGES:
            if rest == count:
                return count
        if _ARGPARSE_EXPECTED_COUNT.fullmatch(rest):
            return f"expected {action.nargs} arguments" if isinstance(action.nargs, int) else "wrong number of values"
        conflict = "not allowed with argument "
        if rest.startswith(conflict):
            other = rest[len(conflict):]
            return conflict + other if other in actions else "not allowed with another argument"
        if rest.startswith("ignored explicit argument"):
            return "unexpected value (value withheld)"
        problem = "invalid value (value withheld)"
        if action.choices is not None and not isinstance(action.choices, (str, bytes)):
            try:
                choices = ", ".join(str(choice) for choice in action.choices)
            except Exception:
                return problem
            problem += f"; choose from {choices}"
        return problem


__all__ = [
    "Finding",
    "OutboundRefused",
    "SCREEN_VERSION",
    "ScreenedPayload",
    "ScreenedRequest",
    "ScreeningArgumentParser",
    "refuse_attachments",
    "require_clean",
    "require_text_disclosure",
    "screen_outbound",
    "screen_request",
    "withheld_diagnostics",
]
