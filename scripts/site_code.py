"""Stdlib-only inspection of committed, build-time-highlighted site code."""
from __future__ import annotations

from html.parser import HTMLParser
import re


def without_token_spans(source: str) -> str:
    """Keep HTML/ordering intact while checking literal code across token spans."""
    return re.sub(
        r"<pre\b[^>]*>.*?</pre>",
        lambda block: re.sub(r"</?span\b[^>]*>", "", block[0]),
        source,
        flags=re.DOTALL,
    )


class CodeBlocks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.blocks: list[tuple[dict[str, str | None], str]] = []
        self._attrs: dict[str, str | None] | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self._attrs = dict(attrs)
            self._text = []

    def handle_data(self, data):
        if self._attrs is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self._attrs is not None:
            self.blocks.append((self._attrs, "".join(self._text)))
            self._attrs = None
