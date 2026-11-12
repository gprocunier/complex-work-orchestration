#!/usr/bin/env python3
from __future__ import annotations

from html.parser import HTMLParser
import html
import re
import sys
import unicodedata
from typing import Callable

from cwo_core.paths import REPO_ROOT
from cwo_core.public_copy import validate_markdown_public_copy
from validate_repository import (
    iter_public_copy_markdown_docs,
    public_copy_allows_internal_labels,
)
from validate_site import validate_html


class _VisibleText(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.parts: list[str] = []
        self.feed(source)

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


RETIRED_BROWSER_GUIDANCE = re.compile(
    r"\b(?:ChatGPT\s+Pro\s+5\.5|GPT[-\s]?5\.5\s+Pro|Extended\s+Reasoning)\b"
    r"|\b(?:chatgpt_browser_review\.py|launch_chatgpt_cdp_chrome\.sh|"
    r"chatgpt_pro_browser_master_reviewer)\b"
    r"|\b(?:set|export|configure)\s+CWO_CHATGPT_BROWSER_CONFIG\b",
    re.IGNORECASE,
)


def retired_browser_guidance_errors(source: str, *, source_name: str) -> list[str]:
    """Reject withdrawn setup in maintained copy, including highlighted code.

    Legacy runtime policy, tests and historical records are not altered by this
    documentation rule. A version-neutral deferral notice is allowed.
    """
    error = _gate(source)
    if error:
        return [f"{source_name}: {error}"]
    try:
        visible = " ".join("".join(_VisibleText(source).parts).split())
        return [f"{source_name}: withdrawn browser guidance: {m.group(0)}"
                for m in RETIRED_BROWSER_GUIDANCE.finditer(visible)]
    except (ValueError, RecursionError, OverflowError):
        return [f"{source_name}: rewording required (processing failure)"]


# Wordings that overstated a mechanism. See references/claims-register.md.
def _phrase(words: str) -> re.Pattern[str]:
    """Match the words in order, separated by any run of non-alphanumerics.

    Visible punctuation such as literal asterisks or brackets between words does
    not hide a phrase; nothing is ever removed from inside a word.
    """
    return re.compile(r"\b" + r"[\W_]+".join(re.escape(word) for word in words.split()) + r"\b", re.IGNORECASE)


RETIRED_CLAIMS = (
    (
        _phrase("hashes make tampering detectable"),
        "the audit hash chain detects altered retained events and broken links only",
    ),
    (
        re.compile(r"\bprovides?[\W_]+tamper-evident[\W_]+detection\b", re.IGNORECASE),
        "the audit hash chain detects altered retained events and broken links only",
    ),
    (
        _phrase("native productive work uses the admitted version-2 pool launcher"),
        "the pool launcher refuses ordinary plans without a trusted controller",
    ),
)


# Claim matching is a heuristic. It reads maintained copy roughly as a reader
# sees it, in a supported subset: CommonMark-style Markdown (block quotes,
# nested list items, fenced and indented code, raw HTML blocks, ATX and setext
# headings, thematic breaks, link reference definitions, code spans, autolinks,
# links, images, emphasis) plus HTML judged by each element's default display
# and a single inline ``display`` declaration. Stylesheets, scripts, fonts and
# text drawn inside images are not evaluated, so maintained copy must not rely
# on them to hide text or to split words. Each source gets these readings, and
# a phrase found in any of them is reported: the rendered text, with hidden
# subtrees removed; the body text with hidden subtrees kept (they keep their
# layout boundaries), which also stands for a renderer that strips hiding
# attributes; and the attribute values, comments and image descriptions, each
# read on its own. Hidden copy is still maintained copy, and markup quoted
# inside code must not hide a claim.
#
# ``details`` elements and images with alt text are state-dependent regions: a
# closed details element shows only its summary, and a broken image shows its
# alt text in its place. Regions with at most ``_NEAR_WORDS`` always-visible
# words between them form a cluster, since the longest retired phrase has ten
# words and a region on either side can join two fragments into one word. The
# rendered and hidden-kept readings are taken in every combination of states
# within each cluster, and no phrase can reach regions of two clusters.
#
# Markup outside the subset that the check recognizes is refused for
# rewording rather than modeled: a hidden element holding anything but plain
# text in one block or not ending with its own end tag, a head holding more
# than metadata elements, elements, attributes and inline styles the readings
# do not model, repeated attributes, ``hidden`` combined with an inline style,
# a hidden image with alt text, inline scripts and stylesheets or scripts given
# as data URLs, a details element not starting with its summary, text or
# elements outside table cells, text in svg, an end tag closing an open details
# element, link reference definitions the block pass cannot parse, footnotes,
# link text joined to an adjacent word, a cluster too large to read in every
# combination, and characters that render invisibly or imitate ASCII letters.
_BLOCK_TAGS = frozenset(
    "address article aside blockquote body br caption center col colgroup dd details dialog dir div dl dt "
    "fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 header hgroup hr html legend "
    "li listing main menu nav ol optgroup option p plaintext pre search section summary table tbody td "
    "tfoot th thead tr ul xmp".split()
)
_DEFAULT_HIDDEN_TAGS = frozenset("area base datalist head link meta param rp script source style template title track".split())
_VOID_TAGS = frozenset("area base br col embed hr img input keygen link meta param source track wbr".split())
# Inline display values the readings interpret: hidden, inline-level (its text
# joins its neighbors) or block-level (separated from them).
_INNER_DISPLAYS = ("flow", "flow-root", "flex", "grid", "table")
_DISPLAY_VALUES = {
    "none": "none",
    **dict.fromkeys(("contents", "inline", "inline-block", "inline-flex", "inline-grid", "inline-table"), "join"),
    **dict.fromkeys(("block", "flow-root", "flex", "grid", "table", "list-item"), "separate"),
    **{
        f"{first} {second}": kind
        for outer, kind in (("inline", "join"), ("block", "separate"))
        for inner in _INNER_DISPLAYS
        for first, second in ((outer, inner), (inner, outer))
    },
}
_CSS_SPACE = "[ \t\n\r\f]"
_DISPLAY_DECLARATION = re.compile(
    rf"{_CSS_SPACE}*display{_CSS_SPACE}*:{_CSS_SPACE}*([a-z-]+(?:{_CSS_SPACE}+[a-z-]+)?){_CSS_SPACE}*;?{_CSS_SPACE}*",
    re.ASCII | re.IGNORECASE,
)
# Elements the readings model. Others need rewording, including elements
# whose content browsers show or hide by state, scripting or media support
# (dialog, noscript, select, canvas, video, object, ruby annotations),
# template, whose shadow-root form hides its host's text, style, which can
# define hiding rules in the copy itself, and bdo, which reorders letters.
_SUPPORTED_TAGS = frozenset(
    "a abbr address article aside b base bdi blockquote body br caption circle cite code col colgroup data dd "
    "del details dfn div dl dt ellipse em fieldset figcaption figure footer form g h1 h2 h3 h4 h5 h6 head header "
    "hgroup hr html i img input ins kbd label legend li line link main mark meta nav ol p path picture polygon "
    "polyline pre q rect s samp script search section small source span strong sub summary sup svg table tbody "
    "td tfoot th thead time title tr u ul var wbr".split()
)
# Attributes the readings model; aria-* and data-* attributes do not change
# what is shown. Others need rewording, such as event handlers, dir, popover
# and presentational colors or sizes.
_SUPPORTED_ATTRIBUTES = frozenset(
    "abbr alt async charset checked cite class colspan content crossorigin cx cy d datetime decoding defer fill "
    "focusable for headers height hidden href hreflang id integrity lang loading media name nonce open points r "
    "referrerpolicy rel reversed role rowspan rx ry scope sizes span src srcset start stroke stroke-linecap "
    "stroke-linejoin stroke-width style tabindex target title type value viewbox width x x1 x2 xmlns y y1 y2".split()
)
_ATTRIBUTE_PREFIXES = ("aria-", "data-")
_TEXTLESS_INPUTS = frozenset({"checkbox", "radio", "hidden"})
_HEAD_CONTENT = frozenset("base link meta script title".split())
_TABLE_CONTEXT = frozenset("table thead tbody tfoot tr colgroup".split())
_TABLE_CHILDREN = frozenset("caption colgroup col thead tbody tfoot tr td th script style template".split())
# Clusters of state-dependent regions: see the comment above.
_NEAR_WORDS = 12
_MAX_CLUSTER = 6
# Why a construct needs rewording.
_UNREADABLE_HIDDEN = "a hidden element may hold only plain text and must end with its own end tag"
_UNREADABLE_HEAD = "a head may hold only base, link, meta, script and title elements and must end with </head>"
_UNREADABLE_ELEMENT = "the check does not model this element"
_UNREADABLE_ATTRIBUTE = "the check does not model this attribute"
_UNREADABLE_REPEATED = "a repeated attribute, of which browsers keep the first"
_UNREADABLE_INPUT = "the check reads input elements only of type checkbox, radio or hidden"
_UNREADABLE_STYLE = "an inline style must be empty or one display declaration with a value the check reads"
_UNREADABLE_HIDDEN_STYLE = "hidden combined with an inline style"
_UNREADABLE_HIDDEN_IMAGE = "a hidden image with alt text"
_UNREADABLE_SCRIPT = "the check does not run scripts"
_UNREADABLE_EMBEDDED = "a stylesheet or script written into the copy as a data URL"
_UNREADABLE_SUMMARY = "a details element must start with its summary"
_UNREADABLE_TABLE = "browsers move text and elements found outside table cells"
_UNREADABLE_SVG = "the check does not read text in svg"
_UNREADABLE_DETAILS = "an end tag closes an open details element"
_UNREADABLE_DEFINITION = "a link reference definition the check cannot parse; keep each definition on one line"
_UNREADABLE_FOOTNOTE = "the check does not read footnotes"
_UNREADABLE_LINK = "link text joined to an adjacent word"
_UNREADABLE_CLUSTER = (
    "more details elements and images with alt text near one another than the check reads in every combination"
)
_UNREADABLE_CHARACTER = "a character that renders invisibly or imitates an ASCII letter"
_UNREADABLE_REFERENCE = "character reference (only &amp;, &lt;, &gt;, and &quot; are allowed)"
# Private-use characters: protected text, the boundary between Markdown blocks,
# the start of a raw HTML block (literal for Markdown inline syntax), a
# Markdown image followed by its protected description, and the bounds of a
# state-dependent region in a measuring reading.
_PROTECT_BASE = 0xF0000
_BLOCK_BREAK = "\ue000"
_RAW_HTML = "\ue001"
_REGION_START = "\ue002"
_REGION_END = "\ue003"
_IMAGE = "\ue004"
_STRUCTURE = frozenset({_BLOCK_BREAK, _RAW_HTML})
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")


def _check_unreadable_characters(text: str) -> str | None:
    """Check for literal characters that require rewording.

    Refuses all private-use code points, noncharacters, surrogates, and code points
    in the internal token namespace. Returns an error message if found, None otherwise.

    Internal working markers (U+E000..U+E004) are only valid in internally generated
    text, not in raw input at public entry points.
    """
    for char in text:
        code_point = ord(char)
        category = unicodedata.category(char)
        # Private use (Co): refuse all, including internal markers at raw boundary
        if category == "Co":
            return f"rewording required (unreadable private-use character U+{code_point:04X})"
        # Surrogates (Cs)
        if category == "Cs":
            return f"rewording required (unreadable surrogate character U+{code_point:04X})"
        # Noncharacters: U+FDD0..U+FDEF
        if 0xFDD0 <= code_point <= 0xFDEF:
            return f"rewording required (unreadable noncharacter U+{code_point:04X})"
        # Noncharacters: U+nFFFE and U+nFFFF in all 17 planes
        if (code_point & 0xFFFE) == 0xFFFE:
            return f"rewording required (unreadable noncharacter U+{code_point:04X})"
        # Internal token namespace
        if _PROTECT_BASE <= code_point <= 0xFFFFD:
            return f"rewording required (unreadable character in internal namespace U+{code_point:04X})"
    return None


# Character reference pattern: named (&name;), decimal (&#123;), or hex (&#xAB; or &#XAB;)
_CHAR_REFERENCE = re.compile(r"&(?:[a-zA-Z][a-zA-Z0-9]*|#[0-9]+|#[xX][0-9a-fA-F]+);")
# The four allowed named references
_ALLOWED_REFERENCES = frozenset(("&amp;", "&lt;", "&gt;", "&quot;"))


def _raw_character_reference_scan(text: str) -> str | None:
    """Raw context-free character reference check on original source text.

    Refuses any & followed by # or ASCII letter unless it is exactly one of
    the four allowed entities (&amp;, &lt;, &gt;, &quot;), case-sensitive with
    semicolon. Also refuses &amp; immediately followed by # or ASCII letter
    (encoded reference). Returns an error string if refused, None if accepted.
    """
    index = 0
    while index < len(text):
        if text[index] == "&":
            # Check if followed by # or ASCII letter
            if index + 1 < len(text):
                next_char = text[index + 1]
                if next_char == "#" or next_char.isascii() and next_char.isalpha():
                    # Check if it's one of the four allowed references
                    for allowed in _ALLOWED_REFERENCES:
                        if text[index:index + len(allowed)] == allowed:
                            # Found an allowed reference; check for encoded reference pattern
                            end_index = index + len(allowed)
                            if allowed == "&amp;" and end_index < len(text):
                                follow = text[end_index]
                                if follow == "#" or follow.isascii() and follow.isalpha():
                                    excerpt = text[max(0, index - 20):index + 40]
                                    return f"rewording required (encoded character reference): {excerpt}"
                            index = end_index - 1
                            break
                    else:
                        # Not an allowed reference
                        excerpt = text[max(0, index - 20):index + 40]
                        return f"rewording required (character reference): {excerpt}"
        index += 1
    return None


def _gate(source: str) -> str | None:
    """Gate for all public text entry points: refuses unreadable input on untouched source.

    This runs before any normalization, zero-width removal, or other preprocessing.
    Refuses format characters (Cf), literal unreadable code points, and character
    references. Returns an error diagnostic string if refused, None if accepted.
    """
    # Refuse format characters (Unicode category Cf) anywhere in public copy.
    # The repository's public copy contains no Cf characters, so any occurrence
    # is unreadable and requires rewording.
    for char in source:
        if unicodedata.category(char) == "Cf":
            code_point = ord(char)
            return f"rewording required (unreadable format character U+{code_point:04X})"
    # Refuse literal unreadable code points
    error = _check_unreadable_characters(source)
    if error:
        return error
    # Run raw character reference scan
    error = _raw_character_reference_scan(source)
    if error:
        return error
    return None


def _check_character_references(text: str, protected: _Protected, *, is_html: bool = False) -> list[tuple[str, str]]:
    """Check for character references that require rewording.

    Refuses all character references except &amp;, &lt;, &gt;, and &quot;.
    For Markdown, this is called after code spans and backslash escapes are protected.
    For HTML, all references are checked (no element exemptions).
    Returns list of (reason, excerpt) tuples for any refused references.
    """
    unreadable: list[tuple[str, str]] = []
    # Check all references; protected regions (code spans, escapes) are already replaced with
    # private-use characters for Markdown, so they won't match the reference pattern
    for match in _CHAR_REFERENCE.finditer(text):
        reference = match.group(0)
        if reference not in _ALLOWED_REFERENCES:
            unreadable.append((_UNREADABLE_REFERENCE, reference))
    return unreadable


class _Protected:
    """Literal text (code, escapes, entities) kept out of markup processing."""

    def __init__(self) -> None:
        self.values: list[str] = []

    def hold(self, text: str) -> str:
        # Check token capacity before allocation to avoid overflow beyond U+FFFFD
        # Maximum index is 65,533 (0xFFFD), giving final token U+FFFFD
        # Index 65,534 would produce U+FFFFE (noncharacter, never restored)
        if len(self.values) >= 65534:
            raise ValueError("rewording required (token capacity exceeded)")
        self.values.append(text)
        return chr(_PROTECT_BASE + len(self.values) - 1)

    def restore(self, text: str) -> str:
        def value(match: re.Match[str]) -> str:
            index = ord(match.group(0)) - _PROTECT_BASE
            return self.values[index] if index < len(self.values) else match.group(0)

        # Iterative restoration to prevent stack overflow; bounded by number of tokens
        # to detect expansion cycles from malformed source
        max_iterations = len(self.values) + 1 if self.values else 2
        iterations = 0
        previous = None
        while previous != text:
            iterations += 1
            if iterations > max_iterations:
                raise ValueError(
                    "rewording required (restoration cycle detected; "
                    "text contains literal protected-range characters or self-expanding markup)"
                )
            previous = text
            text = re.sub("[\U000f0000-\U000ffffd]", value, text)
        return text


def _inline_display(style: str) -> str | None:
    """How an inline style displays its element: 'none', 'join', 'separate', None (no style) or 'unreadable'.

    Only an empty style or one ``display`` declaration with a value in
    ``_DISPLAY_VALUES`` is read. Comments, escapes, ``!important``, repeated
    or other declarations and unknown values are unreadable.
    """
    if not style.strip(" \t\n\r\f"):
        return None
    match = _DISPLAY_DECLARATION.fullmatch(style)
    if match is None:
        return "unreadable"
    return _DISPLAY_VALUES.get(" ".join(match.group(1).lower().split()), "unreadable")


def _excerpt(text: str) -> str:
    return " ".join(text.split())[:60]


class _ClaimText(HTMLParser):
    """One reading of HTML: ``rendered``, ``hidden`` (hidden body text kept) or ``metadata``.

    State-dependent regions, each ``details`` element and each image with alt
    text (HTML or Markdown), are numbered in document order. The rendered and
    hidden-kept readings show region ``n`` when ``shown(n)``: the details
    element is open, or the image is broken and its alt text is in place.
    Without ``shown``, details elements are open and images loaded.
    ``measure`` marks each region for ``_clusters``. Markup the readings cannot
    interpret is collected in ``unreadable`` as (reason, excerpt) pairs.
    """

    def __init__(
        self,
        source: str,
        protected: _Protected,
        *,
        mode: str,
        shown: Callable[[int], bool] | None = None,
        measure: bool = False,
    ) -> None:
        super().__init__(convert_charrefs=False)
        self.protected = protected
        self.mode = mode
        self.shown = shown
        self.measure = measure
        self.regions = 0
        self.parts: list[str] = []
        self.stack: list[tuple[str, bool, bool, bool]] = []  # (tag, hidden, separates, folded in a closed details)
        self.details: list[list[bool]] = []  # per open details: [closed, summary started]
        self.unreadable: list[tuple[str, str]] = []
        self.feed(source)
        self.close()
        guard = self._guard()
        if guard is not None:
            self._refuse_inside(guard, "end of source")

    def _region(self, default: bool) -> bool:
        index = self.regions
        self.regions += 1
        return default if self.shown is None else self.shown(index)

    def _closed_details(self) -> bool:
        return bool(self.stack) and self.stack[-1][0] == "details" and self.details[-1][0]

    def _hidden(self) -> bool:
        if self.mode == "metadata":
            return False
        if self._closed_details() or any(folded for _, _, _, folded in self.stack):
            return True
        return self.mode == "rendered" and any(hidden for _, hidden, _, _ in self.stack)

    def _guard(self) -> str | None:
        """The innermost open element that the rendered reading hides by itself."""
        return next((tag for tag, hidden, _, _ in reversed(self.stack) if hidden), None)

    def _classify(self, tag: str, values: dict[str, str]) -> tuple[bool, bool]:
        display = _inline_display(values.get("style", ""))
        if display == "unreadable":
            display = None  # refused; read with the element's default display
        hidden = "hidden" in values or display == "none" or (display is None and tag in _DEFAULT_HIDDEN_TAGS)
        separates = display == "separate" or (display in {None, "none"} and tag in _BLOCK_TAGS)
        return hidden, separates

    def _folds(self, tag: str) -> bool:
        """Whether a closed details element hides this child: anything but its first summary, which must come first."""
        if not (self.stack and self.stack[-1][0] == "details"):
            return False
        state = self.details[-1]
        if tag == "summary" and not state[1]:
            state[1] = True
            return False
        if not state[1]:
            self.unreadable.append((_UNREADABLE_SUMMARY, f"<{tag}>"))
        return state[0]

    def _refuse_inside(self, guard: str, what: str) -> None:
        reason = _UNREADABLE_HEAD if guard == "head" else _UNREADABLE_HIDDEN
        self.unreadable.append((reason, f"{what} inside <{guard}>"))

    def _check_start(self, tag: str, attrs: list[tuple[str, str | None]], values: dict[str, str]) -> None:
        excerpt = f"<{tag}>"
        if tag not in _SUPPORTED_TAGS:
            self.unreadable.append((_UNREADABLE_ELEMENT, excerpt))
        names = [name for name, _ in attrs]
        if len(set(names)) < len(names):
            self.unreadable.append((_UNREADABLE_REPEATED, excerpt))
        for name in names:
            if name not in _SUPPORTED_ATTRIBUTES and not name.startswith(_ATTRIBUTE_PREFIXES):
                self.unreadable.append((_UNREADABLE_ATTRIBUTE, f"{name} on <{tag}>"))
        if tag == "input" and values.get("type", "text").strip().lower() not in _TEXTLESS_INPUTS:
            self.unreadable.append((_UNREADABLE_INPUT, excerpt))
        if _inline_display(values.get("style", "")) == "unreadable":
            self.unreadable.append((_UNREADABLE_STYLE, excerpt))
        if "hidden" in values and values.get("style", "").strip(" \t\n\r\f"):
            self.unreadable.append((_UNREADABLE_HIDDEN_STYLE, excerpt))
        stylesheet = tag == "link" and "stylesheet" in values.get("rel", "").lower().split()
        address = values.get("href" if stylesheet else "src", "") if stylesheet or tag == "script" else ""
        if address.strip().lower().startswith("data:"):
            self.unreadable.append((_UNREADABLE_EMBEDDED, excerpt))
        guard = self._guard()
        if guard is not None and (guard != "head" or tag not in _HEAD_CONTENT):
            self._refuse_inside(guard, excerpt)
        if self.stack and self.stack[-1][0] in _TABLE_CONTEXT and tag not in _TABLE_CHILDREN:
            self.unreadable.append((_UNREADABLE_TABLE, excerpt))

    def _check_text(self, text: str) -> None:
        guard = self._guard()
        if guard == "head" and text.strip():
            self._refuse_inside(guard, "text")
        elif guard == "script" and text.strip():
            self.unreadable.append((_UNREADABLE_SCRIPT, _excerpt(text)))
        elif guard is not None and guard != "head" and any(character in _STRUCTURE for character in text):
            self._refuse_inside(guard, "a block boundary")
        if text.strip() and self.stack:
            top = self.stack[-1][0]
            if top in _TABLE_CONTEXT:
                self.unreadable.append((_UNREADABLE_TABLE, _excerpt(text)))
            content = "".join(character for character in text if character not in _STRUCTURE).strip()
            if top == "details" and not self.details[-1][1] and content:
                self.unreadable.append((_UNREADABLE_SUMMARY, _excerpt(text)))
            if guard is None and any(tag == "svg" for tag, _, _, _ in self.stack):
                self.unreadable.append((_UNREADABLE_SVG, _excerpt(text)))

    def _check_markup(self) -> None:
        guard = self._guard()
        if guard is not None and guard != "head":
            self._refuse_inside(guard, "a comment or declaration")

    def _foreign(self, tag: str) -> bool:
        return tag == "svg" or any(open_tag == "svg" for open_tag, _, _, _ in self.stack)

    def _boundary(self, hidden: bool, separates: bool) -> None:
        if separates and self.mode != "metadata" and not self._hidden() and (self.mode == "hidden" or not hidden):
            self.parts.append(" ")

    def _attributes(self, attrs: list[tuple[str, str | None]]) -> None:
        if self.mode == "metadata":
            for _, value in attrs:
                if value:
                    self.parts.append(f" {value} ")

    def _image(self, description: str, hidden: bool, folded: bool, *, markdown: bool = False) -> None:
        """An image with alt text is a region; when broken, it shows the text in its place.

        The metadata reading gets a Markdown image's description here and an
        HTML image's alt attribute with its other attributes.
        """
        if hidden and self.protected.restore(description).strip():
            self.unreadable.append((_UNREADABLE_HIDDEN_IMAGE, _excerpt(self.protected.restore(description))))
        broken = self._region(False)
        if self.measure:
            self.parts.append(_REGION_START + _REGION_END)
        if self.mode == "metadata":
            if markdown:
                self.parts.append(f" {description} ")
        elif broken and not folded and not (hidden and self.mode == "rendered") and not self._hidden():
            self.parts.append(self.protected.hold(description))

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], *, opens: bool) -> None:
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name, value or "")  # browsers keep the first of repeated attributes
        self._check_start(tag, attrs, values)
        hidden, separates = self._classify(tag, values)
        folded = self._folds(tag)
        self._boundary(hidden or folded, separates)
        self._attributes(attrs)
        if tag == "img" and values.get("alt"):
            self._image(values["alt"], hidden, folded)
        if opens:
            self.stack.append((tag, hidden, separates, folded))
            if tag == "details":
                self.details.append([not self._region(True), False])
                if self.measure:
                    self.parts.append(_REGION_START)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, opens=tag not in _VOID_TAGS)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # HTML ignores the slash on other elements, which stay open; svg content honors it.
        self._start(tag, attrs, opens=tag not in _VOID_TAGS and not self._foreign(tag))

    def handle_endtag(self, tag: str) -> None:
        guard = self._guard()
        if guard is not None and guard != tag:
            self._refuse_inside(guard, f"</{tag}>")
        if not any(open_tag == tag for open_tag, _, _, _ in self.stack):
            return
        while self.stack:
            open_tag, hidden, separates, folded = self.stack.pop()
            if open_tag == "details":
                self.details.pop()
                if self.measure:
                    self.parts.append(_REGION_END)
            self._boundary(hidden or folded, separates)
            if open_tag == tag:
                break
            if open_tag == "details":
                self.unreadable.append((_UNREADABLE_DETAILS, f"</{tag}>"))

    def handle_data(self, data: str) -> None:
        text, *images = data.split(_IMAGE)
        self._text(text)
        for image in images:
            # A Markdown image: its protected description, then the text after it.
            self._image(image[:1], self._guard() is not None, False, markdown=True)
            self._text(image[1:])

    def _text(self, data: str) -> None:
        self._check_text(data)
        if self.mode == "metadata" or self._hidden():
            # Block structure always survives, so later stages stay aligned.
            self.parts.append("".join(character for character in data if character in _STRUCTURE))
        else:
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        self._check_markup()
        if self.mode == "metadata":
            self.parts.append(f" {data} ")

    def handle_decl(self, decl: str) -> None:
        self._check_markup()

    def handle_pi(self, data: str) -> None:
        self._check_markup()

    def unknown_decl(self, data: str) -> None:
        self._check_markup()

    def handle_entityref(self, name: str) -> None:
        reference = f"&{name};"
        # Only the four basic XML entities are allowed
        if reference in ("&amp;", "&lt;", "&gt;", "&quot;"):
            self._literal(html.unescape(reference))
        else:
            self.unreadable.append((_UNREADABLE_REFERENCE, reference))

    def handle_charref(self, name: str) -> None:
        reference = f"&#{name};"
        self.unreadable.append((_UNREADABLE_REFERENCE, reference))

    def _literal(self, text: str) -> None:
        self._check_text(text)
        if self.mode != "metadata" and not self._hidden():
            self.parts.append(self.protected.hold(text))


_BLOCKQUOTE = re.compile(r"^ {0,3}>[ \t]?")
_LIST_MARKER = re.compile(r"^( {0,3})([-*+]|\d{1,9}[.)])([ \t]+|$)")
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,})[^`]*$|^ {0,3}(~{3,}).*$")
_ATX = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)")
_SETEXT_OR_BREAK = re.compile(r"^ {0,3}(?:=+|-+|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})[ \t]*$")
_DEFINITION_LABEL = re.compile(r"^ {0,3}\[((?:[^\]\\]|\\.)+)\]:")
_HTML_LITERAL_START = re.compile(r"^ {0,3}<(pre|script|style|textarea)(?:\s|>|$)", re.IGNORECASE)
_HTML_LITERAL_END = re.compile(r"</(?:pre|script|style|textarea)>", re.IGNORECASE)
_HTML_SPECIAL_START = (("<!--", "-->"), ("<?", "?>"), ("<![CDATA[", "]]>"))
_HTML_BLOCK_NAMES = (
    "address article aside base basefont blockquote body caption center col colgroup dd details dialog dir div dl "
    "dt fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend "
    "li link main menu menuitem nav noframes ol optgroup option p param search section summary table tbody td tfoot "
    "th thead title tr track ul"
).split()
_HTML_BLOCK_START = re.compile(r"^ {0,3}</?(?:" + "|".join(_HTML_BLOCK_NAMES) + r")(?:\s|/?>|$)", re.IGNORECASE)
_HTML_TAG_ALONE = re.compile(r"^ {0,3}(?:<[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*)?/?>|</[A-Za-z][A-Za-z0-9-]*\s*>)\s*$")


def _label(text: str) -> str:
    return " ".join(re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", text).split()).casefold()


def _definition_tail(text: str) -> bool:
    """True when ``text`` is exactly a link destination and an optional title.

    Follows CommonMark: an angle destination, or a non-empty run of
    non-space characters with balanced unescaped parentheses; then optional
    whitespace (at most one line break) and a quoted or parenthesized title;
    then nothing but whitespace.
    """
    index = 0
    length = len(text)

    def skip(position: int, *, newline: bool) -> int:
        seen = False
        while position < length and text[position] in " \t\n":
            if text[position] == "\n":
                if seen or not newline:
                    break
                seen = True
            position += 1
        return position

    index = skip(index, newline=True)
    if index >= length:
        return False
    if text[index] == "<":
        index += 1
        while index < length and text[index] != ">":
            if text[index] in "<\n":
                return False
            index += 2 if text[index] == "\\" else 1
        if index >= length:
            return False
        index += 1
    else:
        start, depth = index, 0
        while index < length and not text[index].isspace():
            character = text[index]
            if character == "\\" and index + 1 < length:
                index += 2
                continue
            if ord(character) < 0x20:
                return False
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    return False
            index += 1
        if depth or index == start:
            return False
    after_destination = index
    index = skip(index, newline=True)
    if index >= length:
        return True
    if text[index] not in "\"'(" or index == after_destination:
        return False
    closing = ")" if text[index] == "(" else text[index]
    index += 1
    while index < length and text[index] != closing:
        if text[index] == "\\":
            index += 1
        elif closing == ")" and text[index] == "(":
            return False
        elif text.startswith("\n\n", index):
            return False
        index += 1
    if index >= length:
        return False
    return not text[index + 1:].strip(" \t\n")


def _definition_start(text: str) -> bool:
    """True when a paragraph starts with a link label, on one line or more, and a colon.

    Definitions the block pass accepts never reach a paragraph, so this is one
    it could not parse, or text that only looks like one.
    """
    if not re.match(r" {0,3}\[", text):
        return False
    index = text.index("[") + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "[":
            return False
        if text[index] == "]":
            return text.startswith(":", index + 1)
        index += 1
    return False


def _code_spans(text: str, protected: _Protected) -> str:
    """Replace CommonMark code spans (which may span lines) by protected literal content."""
    out: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            out.append(text[index:index + 2])
            index += 2
            continue
        if text[index] != "`":
            out.append(text[index])
            index += 1
            continue
        run_end = index
        while run_end < len(text) and text[run_end] == "`":
            run_end += 1
        run = text[index:run_end]
        close = text.find(run, run_end)
        while close != -1 and (text[close - 1] == "`" or text[close + len(run):close + len(run) + 1] == "`"):
            close = text.find(run, close + 1)
        if close == -1:
            out.append(run)  # unmatched backticks are literal
            index = run_end
            continue
        content = text[run_end:close].replace("\n", " ")
        if len(content) > 1 and content.startswith(" ") and content.endswith(" ") and content.strip():
            content = content[1:-1]
        out.append(protected.hold(content))
        index = close + len(run)
    return "".join(out)


def _open_tag_state(line: str, in_tag: bool, quote: str | None) -> tuple[bool, str | None]:
    """Track whether an HTML tag (with quoted attributes) continues past this line."""
    for index, character in enumerate(line):
        if in_tag:
            if quote:
                if character == quote:
                    quote = None
            elif character in "\"'":
                quote = character
            elif character == ">":
                in_tag = False
        elif character == "<" and (line[index + 1:index + 2].isalpha() or line[index + 1:index + 2] in {"/", "!"}):
            in_tag = True
    return in_tag, quote


class _Blocks:
    """A line-oriented CommonMark block pass over the supported subset."""

    def __init__(self, protected: _Protected) -> None:
        self.protected = protected
        self.blocks: list[str] = []
        self.paragraph: list[str] = []
        self.definitions: set[str] = set()
        self.lists: list[int] = []  # content columns of open list items
        self.fence: tuple[str, int] | None = None
        self.html_end: str | re.Pattern[str] | None = None
        self.html: list[str] = []
        self.in_tag = False
        self.quote: str | None = None
        self.previous_blank = True
        self.pending_definition: tuple[str, str] | None = None
        self.quotes = 0  # block-quote markers on the current line
        self.owner: tuple[int, int | None] = (0, None)  # containers of the open code or HTML block
        self.unparsed: list[str] = []  # first lines of paragraphs that start like a definition
        self.footnotes: list[str] = []  # GitHub footnote definitions, whose text shows at the end

    def flush(self) -> None:
        if self.paragraph:
            text = "\n".join(self.paragraph)
            if _definition_start(text):
                self.unparsed.append(_excerpt(self.paragraph[0]))
            self.blocks.append(_code_spans(text, self.protected))
            self.paragraph.clear()

    def flush_html(self) -> None:
        if self.html:
            self.blocks.append(_RAW_HTML + "\n".join(self.html))
            self.html.clear()
        self.html_end = None

    def close_open_block(self) -> None:
        self.fence = None
        self.flush_html()

    def continuation(self, raw: str) -> str | None:
        """The line inside the open code or HTML block, or None once its container has ended."""
        quotes, list_column = self.owner
        line = raw
        for _ in range(quotes):
            quoted = _BLOCKQUOTE.match(line)
            if not quoted:
                return None if raw.strip() else ""
            line = line[quoted.end():]
        if list_column is not None:
            if not line.strip():
                return ""
            if len(line) - len(line.lstrip(" ")) < list_column:
                return None
            line = line[list_column:]
        return line

    def containers(self, line: str) -> tuple[str, bool]:
        self.quotes = 0
        while True:
            quoted = _BLOCKQUOTE.match(line)
            if not quoted:
                break
            line = line[quoted.end():]
            self.quotes += 1
        indent = len(line) - len(line.lstrip(" "))
        if line.strip():
            while self.lists and indent < self.lists[-1]:
                if not (self.previous_blank or _LIST_MARKER.match(line)):
                    break  # lazy continuation keeps the item open
                self.lists.pop()
        base = self.lists[-1] if self.lists else 0
        if line.strip() and indent >= base:
            marker = _LIST_MARKER.match(line[base:])
            if marker:
                column = base + len(marker.group(0))
                self.lists.append(column)
                return line[column:], True
        if self.lists and indent >= base:
            return line[base:], False
        return line, False

    def line(self, raw: str) -> None:
        if self.in_tag:
            self.paragraph.append(raw)
            self.in_tag, self.quote = _open_tag_state(raw, self.in_tag, self.quote)
            return
        if self.html_end is not None or self.fence is not None:
            inner = self.continuation(raw)
            if inner is None:
                self.close_open_block()  # the container ended; read the line afresh
            elif self.html_end is not None:
                self.html.append(inner)
                end = self.html_end
                if (end == "blank" and not inner.strip()) or (isinstance(end, str) and end != "blank" and end in inner) or (
                    isinstance(end, re.Pattern) and end.search(inner)
                ):
                    self.flush_html()
                return
            else:
                stripped = inner.strip()
                if stripped.startswith(self.fence[0] * self.fence[1]) and set(stripped) == {self.fence[0]}:
                    self.fence = None
                else:
                    self.blocks.append(self.protected.hold(inner))
                return
        line, opened_item = self.containers(raw)
        if self.pending_definition is not None:
            label, label_line = self.pending_definition
            self.pending_definition = None
            if line.strip() and _definition_tail(line):
                self.definitions.add(label)
                self.previous_blank = False
                return
            self.paragraph.append(label_line)  # not a definition: ordinary text
        if not line.strip():
            self.flush()
            self.previous_blank = True
            return
        if self.previous_blank and not self.paragraph and not opened_item and (line.startswith("    ") or line.startswith("\t")):
            self.blocks.append(self.protected.hold(line))  # indented code, relative to any list content
            return
        opened = _FENCE_OPEN.match(line)
        if opened:
            self.flush()
            marker = opened.group(1) or opened.group(2)
            self.fence = (marker[0], len(marker))
            self.owner = (self.quotes, self.lists[-1] if self.lists else None)
            self.previous_blank = False
            return
        if (not self.paragraph or _HTML_BLOCK_START.match(line)) and self.start_html(line):
            self.previous_blank = False
            return
        label = _DEFINITION_LABEL.match(line) if not self.paragraph else None
        if label and label.group(1).startswith("^"):
            self.footnotes.append(_excerpt(line))
        if label:
            tail = line[label.end():]
            if tail.strip() and _definition_tail(tail):
                self.definitions.add(_label(label.group(1)))
                self.previous_blank = False
                return
            if not tail.strip():
                self.pending_definition = (_label(label.group(1)), line)
                self.previous_blank = False
                return
        if _SETEXT_OR_BREAK.match(line):
            self.flush()  # a setext underline ends its heading; a break ends the block
            self.previous_blank = False
            return
        if _ATX.match(line):
            self.flush()
            self.blocks.append(_code_spans(_ATX.sub("", line, count=1), self.protected))
            self.previous_blank = False
            return
        if line.endswith("\\") and not line.endswith("\\\\"):
            line = line[:-1]  # hard line break
        self.paragraph.append(line)
        self.in_tag, self.quote = _open_tag_state(line, False, None)
        self.previous_blank = False

    def start_html(self, line: str) -> bool:
        if self.paragraph:
            self.flush()
        self.owner = (self.quotes, self.lists[-1] if self.lists else None)
        stripped = line.lstrip(" ")
        if _HTML_LITERAL_START.match(line):
            self.html, self.html_end = [line], _HTML_LITERAL_END
            if _HTML_LITERAL_END.search(line):
                self.flush_html()
            return True
        for start, end in _HTML_SPECIAL_START:
            if stripped.startswith(start):
                self.html, self.html_end = [line], end
                if end in stripped[len(start):]:
                    self.flush_html()
                return True
        if re.match(r"^ {0,3}<![A-Za-z]", line):
            self.html, self.html_end = [line], ">"
            if ">" in stripped[2:]:
                self.flush_html()
            return True
        if _HTML_BLOCK_START.match(line) or _HTML_TAG_ALONE.match(line):
            self.html, self.html_end = [line], "blank"
            return True
        return False

    def run(self, source: str) -> tuple[list[str], set[str]]:
        for raw in source.splitlines():
            self.line(raw)
        return self.result()

    def result(self) -> tuple[list[str], set[str]]:
        if self.pending_definition is not None:
            self.paragraph.append(self.pending_definition[1])
            self.pending_definition = None
        self.flush()
        self.flush_html()
        return self.blocks, self.definitions


def _escapes(text: str, protected: _Protected) -> str:
    return re.sub(r"\\([!-/:-@\[-`{-~])", lambda match: protected.hold(match.group(1)), text)


def _matching_bracket(text: str, start: int) -> int | None:
    depth = 1
    index = start
    while index < len(text):
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _inline_link_end(text: str, start: int) -> int | None:
    """End index of ``(destination "title")`` starting at ``text[start] == "("``."""
    length = len(text)

    def skip_space(position: int) -> int:
        while position < length and text[position] in " \t\n":
            position += 1
        return position

    index = skip_space(start + 1)
    if index < length and text[index] == "<":
        close = text.find(">", index + 1)
        if close == -1 or "\n" in text[index:close]:
            return None
        index = close + 1
    elif index < length and text[index] not in "\"'()":
        depth = 0
        while index < length and text[index] not in " \t\n":
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                if depth == 0:
                    break
                depth -= 1
            index += 1
        if depth:
            return None
    index = skip_space(index)
    if index < length and text[index] in "\"'(":
        closing = ")" if text[index] == "(" else text[index]
        close = text.find(closing, index + 1)
        if close == -1:
            return None
        index = skip_space(close + 1)
    return index if index < length and text[index] == ")" else None


def _markdown_links(text: str, definitions: set[str], protected: _Protected, *, alt: bool = False) -> str:
    """Replace links by their text, and images by an image region; references need a definition.

    An image with a description becomes ``_IMAGE`` followed by the protected
    description, which ``_ClaimText`` reads as loaded or broken. Inside a
    description (``alt``), nested images contribute their text, as in the alt
    attribute.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        image = text[index] == "!" and text.startswith("[", index + 1)
        if text[index] == "[" or image:
            label_start = index + (2 if image else 1)
            label_end = _matching_bracket(text, label_start)
            if label_end is not None:
                label = text[label_start:label_end]
                after = label_end + 1
                end = None
                if text.startswith("(", after):
                    end = _inline_link_end(text, after)
                elif text.startswith("[", after):
                    reference_end = _matching_bracket(text, after + 1)
                    if reference_end is not None:
                        reference = text[after + 1:reference_end] or label
                        if _label(protected.restore(reference)) in definitions:
                            end = reference_end
                elif _label(protected.restore(label)) in definitions:
                    end = label_end
                if end is not None:
                    inner = _markdown_links(label, definitions, protected, alt=alt or image)
                    if image and not alt:
                        description = _emphasis(inner)
                        inner = _IMAGE + protected.hold(description) if protected.restore(description).strip() else ""
                    out.append(inner)
                    index = end + 1
                    continue
        out.append(text[index])
        index += 1
    return "".join(out)


_ENTITY_BEFORE = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});$")
_ENTITY_AFTER = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")


def _edge(text: str, index: int, step: int, protected: _Protected) -> str:
    """The character a reader sees at ``index``, looking in direction ``step`` (1 or -1).

    Protected text (escapes, code spans) and character references are read as
    what they show; protected text that shows nothing is passed over.
    """
    while 0 <= index < len(text):
        character = text[index]
        if _PROTECT_BASE <= ord(character) <= 0xFFFFD:
            shown = protected.restore(character)
            if shown:
                return shown[0] if step > 0 else shown[-1]
            index += step
            continue
        entity = _ENTITY_AFTER.match(text, index) if step > 0 else _ENTITY_BEFORE.search(text, 0, index + 1)
        if entity and html.unescape(entity.group(0)) != entity.group(0):
            shown = html.unescape(entity.group(0))
            return shown[0] if step > 0 else shown[-1]
        return character
    return ""


def _joined_links(text: str, definitions: set[str], protected: _Protected) -> list[str]:
    """Link and image syntax whose text is joined to an adjacent word, as in ``Hash[es](u)``.

    Attempts count even when the destination or reference does not resolve.
    """
    found: list[str] = []
    for block in text.split(_BLOCK_BREAK):
        if block.startswith(_RAW_HTML):
            continue
        for start in (match.start() for match in re.finditer(r"\[", block)):
            label_end = _matching_bracket(block, start + 1)
            if label_end is None:
                continue
            after = label_end + 1
            if block.startswith("(", after):
                end = _inline_link_end(block, after)
            elif block.startswith("[", after):
                end = _matching_bracket(block, after + 1)
            elif _label(protected.restore(block[start + 1:label_end])) in definitions:
                end = label_end
            else:
                continue
            opening = start - 1 if start and block[start - 1] == "!" else start
            before = _edge(block, opening - 1, -1, protected)
            after_link = _edge(block, end + 1, 1, protected) if end is not None else ""
            if re.match(r"\w", before) or re.match(r"\w", after_link):
                found.append(_excerpt(protected.restore(block[max(0, opening - 20):(end or label_end) + 21])))
    return found


_EMPHASIS = re.compile(r"(\*{1,3}|_{1,3}|~{1,2})(?=\S)(.+?)(?<=\S)\1", re.DOTALL)


def _emphasis(text: str) -> str:
    """Drop paired emphasis and strikethrough delimiters; unpaired ones stay literal.

    Underscore pairs must not be intraword, as in CommonMark.
    """
    def replace(match: re.Match[str]) -> str:
        if match.group(1)[0] == "_":
            before = match.string[match.start() - 1:match.start()] if match.start() else ""
            after = match.string[match.end():match.end() + 1]
            if before.isalnum() or after.isalnum():
                return match.group(0)
        return match.group(2)

    previous = None
    while previous != text:
        previous = text
        text = _EMPHASIS.sub(replace, text)
    return text


def _per_markdown_block(text: str, transform: Callable[[str], str]) -> str:
    """Apply a Markdown inline transform within each block, never inside raw HTML blocks."""
    return _BLOCK_BREAK.join(
        block if block.startswith(_RAW_HTML) else transform(block) for block in text.split(_BLOCK_BREAK)
    )


# CommonMark autolinks, which show their text.
_AUTOLINK = re.compile(
    r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\x00-\x20<>]*"
    r"|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)>"
)


def _footnote_references(text: str, protected: _Protected) -> list[str]:
    """GitHub footnote references (``[^label]``) outside raw HTML blocks."""
    return [
        _excerpt(protected.restore(block[max(0, match.start() - 20):match.end() + 20]))
        for block in text.split(_BLOCK_BREAK)
        if not block.startswith(_RAW_HTML)
        for match in re.finditer(r"\[\^", block)
    ]


def _reading(
    source: str,
    *,
    markdown: bool,
    mode: str = "rendered",
    shown: Callable[[int], bool] | None = None,
    measure: bool = False,
) -> tuple[str, list[tuple[str, str]]]:
    """One reading, and the markup it could not interpret as (reason, excerpt) pairs."""
    protected = _Protected()
    text = _ZERO_WIDTH.sub("", source)
    unreadable: list[tuple[str, str]] = []
    # Gate checks (Cf characters, unreadable characters, raw references) are now
    # done at public entry points before calling this function
    # Wrap remaining processing to catch restoration or decoding failures
    try:
        if markdown:
            blocks_pass = _Blocks(protected)
            blocks, definitions = blocks_pass.run(text)
            unreadable.extend((_UNREADABLE_DEFINITION, line) for line in blocks_pass.unparsed)
            unreadable.extend((_UNREADABLE_FOOTNOTE, line) for line in blocks_pass.footnotes)
            text = _per_markdown_block(
                _BLOCK_BREAK.join(blocks),
                lambda block: _AUTOLINK.sub(lambda match: protected.hold(match.group(1)), _escapes(block, protected)),
            )
            unreadable.extend((_UNREADABLE_FOOTNOTE, excerpt) for excerpt in _footnote_references(text, protected))
            unreadable.extend((_UNREADABLE_LINK, excerpt) for excerpt in _joined_links(text, definitions, protected))
            text = _per_markdown_block(text, lambda block: _markdown_links(block, definitions, protected))
        reader = _ClaimText(text, protected, mode=mode, shown=shown, measure=measure)
        unreadable.extend(reader.unreadable)
        text = "".join(reader.parts)
        if markdown and mode != "metadata":
            text = _per_markdown_block(text, _emphasis)
        text = text.replace(_BLOCK_BREAK, "\n").replace(_RAW_HTML, "")
        return " ".join(protected.restore(text).split()), list(dict.fromkeys(unreadable))
    except (ValueError, RecursionError, OverflowError) as exc:
        return "", [("rewording required (processing failure)", _excerpt(str(exc)))]


def claim_text(
    source: str, *, markdown: bool = True, mode: str = "rendered", shown: Callable[[int], bool] | None = None
) -> str:
    """One reading of maintained copy for phrase matching: rendered, hidden or metadata.

    See the comment above for the supported subset and the readings, and
    ``_ClaimText`` for ``shown``.
    """
    error = _gate(source)
    if error:
        return ""
    try:
        return _reading(source, markdown=markdown, mode=mode, shown=shown)[0]
    except (ValueError, RecursionError, OverflowError):
        return ""


_WORD_RUN = re.compile(r"[^\W_]+(?:[*_~]+[^\W_]+)*")


def _clusters(measured: str) -> list[int]:
    """Sizes of the clusters of state-dependent regions in a measuring reading, in document order.

    A region joins the cluster before it when it lies inside an open region,
    or when at most ``_NEAR_WORDS`` words outside every region come between
    them. Emphasis delimiters do not split words here, so a join is never
    missed.
    """
    sizes: list[int] = []
    depth = words = 0
    for piece in re.split(f"([{_REGION_START}{_REGION_END}])", measured):
        if piece == _REGION_START:
            if sizes and (depth or words <= _NEAR_WORDS):
                sizes[-1] += 1
            else:
                sizes.append(1)
            depth += 1
            words = 0
        elif piece == _REGION_END:
            depth = max(0, depth - 1)
        elif not depth:
            words += len(_WORD_RUN.findall(piece))
    return sizes


def _states(sizes: list[int]) -> list[Callable[[int], bool]]:
    """Every combination of shown regions within each cluster; clusters vary independently."""
    if not sizes:
        return []
    bits = min(max(sizes), _MAX_CLUSTER)
    offsets = [offset % bits for size in sizes for offset in range(size)]
    return [lambda index, n=n: index < len(offsets) and bool(n >> offsets[index] & 1) for n in range(2 ** bits)]


def _characters(source: str) -> list[str]:
    """Characters that render invisibly or imitate ASCII letters, after entity decoding.

    Format characters, combining marks left after composition, private-use
    characters (which the readings use internally) and letters or digits
    outside ASCII and Latin-1. The zero-width characters removed above are
    exempt when written literally.
    """
    text = unicodedata.normalize("NFC", html.unescape(_ZERO_WIDTH.sub("", source)))
    found = [
        f"U+{ord(character):04X}"
        for character in text
        if unicodedata.category(character) in {"Cf", "Mn", "Me", "Co"} or (character.isalnum() and ord(character) > 0xFF)
    ]
    return list(dict.fromkeys(found))


# The source readings below are deliberately conservative and need no Markdown
# or HTML model: markup is replaced by a space, never removed so that fragments
# join, and no word is dropped except text directly after a hidden-marked tag.
# They catch a phrase that markup outside the supported subset (invalid or
# multiline link definitions, attribute values quoting Markdown, implicitly
# closed elements) hides from the readings above. A phrase found in any
# reading is reported, including across attribute values or across a link label
# that a reader would not see; such a false positive is resolved by rewording.
# Full CommonMark and HTML fidelity is outside the supported subset, not a
# property of this check.
_SOURCE_TAG = re.compile(r"<!--|-->|<[^<>]*>")
_ATTRIBUTE_VALUE = re.compile(r"""=\s*(?:"([^"]*)"|'([^']*)')""")
_HIDDEN_RUN = re.compile(r"""<[A-Za-z][^<>]*?(?:\shidden\b|aria-hidden\s*=\s*["']?true|display\s*:\s*none)[^<>]*>[^<]*""", re.IGNORECASE)
_LINK_TAIL = re.compile(r"\]\(\s*<?[^\s()<>]*>?|\]\[[^\]\n]*\]")


def source_readings(source: str) -> list[str]:
    """The conservative source-level readings: plain, attribute values, link labels unlinked, hidden runs dropped."""
    error = _gate(source)
    if error:
        return []
    try:
        text = _ZERO_WIDTH.sub("", source)
        attributes = "\n".join(
            html.unescape(match.group(1) if match.group(1) is not None else match.group(2))
            for tag in re.finditer(r"<[^<>]*>", text)
            for match in _ATTRIBUTE_VALUE.finditer(tag.group(0))
        )
        return [
            html.unescape(_SOURCE_TAG.sub(" ", text)),
            attributes,
            html.unescape(_SOURCE_TAG.sub(" ", _LINK_TAIL.sub("] ", text))),
            html.unescape(_SOURCE_TAG.sub(" ", _HIDDEN_RUN.sub(" ", text))),
        ]
    except (ValueError, RecursionError, OverflowError):
        return []


def retired_claim_errors(source: str, *, source_name: str) -> list[str]:
    """Reject wordings retired by the claims register, through markup and line breaks.

    Sources named ``*.html`` are read as HTML only; anything else as Markdown,
    which may contain inline HTML. Conservative: see the comment above
    ``source_readings``. Markup the readings cannot interpret is reported as
    needing rewording; see the comment above ``_BLOCK_TAGS``.
    """
    error = _gate(source)
    if error:
        return [f"{source_name}: {error}"]
    try:
        markdown = not source_name.endswith(".html")
        rendered, unreadable = _reading(source, markdown=markdown)
        # Collect diagnostics from measuring reading
        measured_text, measured_unreadable = _reading(source, markdown=markdown, measure=True)
        unreadable.extend(measured_unreadable)
        sizes = _clusters(measured_text)
        if sizes and max(sizes) > _MAX_CLUSTER:
            unreadable.append((_UNREADABLE_CLUSTER, f"{max(sizes)} together"))
        readings = [rendered]
        # Collect diagnostics from all alternate readings (state-dependent, hidden, metadata)
        # Any processing failure in any reading causes public rejection
        for shown in _states(sizes):
            for mode in ("rendered", "hidden"):
                reading_text, reading_unreadable = _reading(source, markdown=markdown, mode=mode, shown=shown)
                readings.append(reading_text)
                unreadable.extend(reading_unreadable)
        for mode in ("hidden", "metadata"):
            reading_text, reading_unreadable = _reading(source, markdown=markdown, mode=mode)
            readings.append(reading_text)
            unreadable.extend(reading_unreadable)
        readings.extend(source_readings(source))
        errors: list[str] = []
        for pattern, reason in RETIRED_CLAIMS:
            # Matches differing only in punctuation or spacing are one finding.
            found = {" ".join(re.findall(r"[^\W_]+", match.group(0))) for reading in readings
                     for match in pattern.finditer(reading)}
            errors.extend(f"{source_name}: retired claim ({reason}): {text}" for text in sorted(found))
        unreadable.extend((_UNREADABLE_CHARACTER, code) for code in _characters(source))
        errors.extend(f"{source_name}: rewording required ({reason}): {excerpt}" for reason, excerpt in unreadable)
        return errors
    except (ValueError, RecursionError, OverflowError):
        return [f"{source_name}: rewording required (processing failure)"]


def main() -> int:
    errors: list[str] = []
    for path in iter_public_copy_markdown_docs(REPO_ROOT):
        relative = path.relative_to(REPO_ROOT).as_posix()
        errors.extend(
            validate_markdown_public_copy(
                path,
                source_name=relative,
                allow_internal_labels=public_copy_allows_internal_labels(relative),
            )
        )
    for path in sorted((REPO_ROOT / "docs").glob("*.html")):
        errors.extend(validate_html(path))
    maintained = [*iter_public_copy_markdown_docs(REPO_ROOT),
                  *sorted((REPO_ROOT / "experts").glob("*.md")),
                  *sorted((REPO_ROOT / "docs").glob("*.html"))]
    for path in maintained:
        source = path.read_text(encoding="utf-8")
        name = path.relative_to(REPO_ROOT).as_posix()
        errors.extend(retired_browser_guidance_errors(source, source_name=name))
        if name != "references/claims-register.md":
            errors.extend(retired_claim_errors(source, source_name=name))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Public-copy validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
