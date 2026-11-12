from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_public_copy import claim_text, retired_claim_errors  # noqa: E402


class ClaimsRegisterTests(unittest.TestCase):
    def test_retired_claim_detection_text_variants(self) -> None:
        variants = (
            ('test_retired_wordings_are_rejected_even_across_line_breaks',
             'Local evidence: hashes make\ntampering detectable when checked.',
             '| Audit | Hashes provide tamper-evident detection |',
             '- Native productive work uses the admitted\n  version-2 pool launcher and the transaction.',
             '<p>Native productive work uses the <code>admitted</code> version-2 pool launcher.</p>',
             'fixture'),
            # Reported by a source reading although no reader sees the phrase;
            # resolved by rewording. No reading joins fragments into a word.
            ('test_the_check_is_conservative_where_a_reader_would_not_see_the_claim',
             '<custom-note>hashes make</custom-note><custom-note>tampering detectable</custom-note>',
             'Hashes [make][undefined] tampering detectable',
             '[bad]: two words\n\nHashes [make][bad] tampering detectable',
             '<span data-a="hashes make" data-b="tampering detectable">safe</span>',
             'fixture.md'),
        )
        for original, text_one, text_two, text_three, text_four, source_name in variants:
            with self.subTest(original=original):
                for text in (
                    text_one,
                    text_two,
                    text_three,
                    text_four,
                ):
                    with self.subTest(text=text):
                        self.assertTrue(retired_claim_errors(text, source_name=source_name))

    def test_retired_wordings_are_rejected_through_markup(self) -> None:
        for text in (
            "Hashes **make** tampering detectable.",
            "Hashes _make_ tampering ~~detectable~~.",
            "`hashes make tampering detectable`",
            "[Hashes make](audit.md) tampering detectable.",
            "Hashes make [tampering][ref] detectable.\n\n[ref]: audit.md",
            "Hashes *make* tampering detectable, written with literal asterisks.".replace("*", "\\*"),
            "Hashes \\*make\\* tampering detectable.",
            "<p>hashes make<br>tampering detectable</p>",
            "<p>hashes make</p><p>tampering detectable</p>",
            "<li>Native productive work uses the admitted</li><li>version-2 pool launcher</li>",
            "<b>hash</b>es make <em>tamper</em>ing detectable",
            "hashes\u200b make tampering detectable",
            "Hashes [make](audit_(draft).md) tampering detectable.",
            "Hashes [make](<audit file.md>) tampering detectable.",
            "Hashes [make] tampering detectable.\n\n[make]: audit.md",
            "Hashes [make][] tampering detectable.",
            "Hashes make\\\ntampering detectable.",
            "> Hashes make\n> tampering detectable.",
            "> > Hashes make\n> > tampering detectable.",
            "- Hashes make\n  tampering detectable.",
            "1. Hashes make\n   tampering detectable.",
            "## Hashes make tampering detectable",
            "<form>hashes make</form><form>tampering detectable</form>",
            "<fieldset>hashes make</fieldset>tampering detectable",
            "```hashes make tampering detectable```",
            "Hashes make\n===========\ntampering detectable",
            "Hashes make\n---\ntampering detectable",
            'Hashes [make](audit.md "a draft)") tampering detectable.',
            "Hashes [make](audit.md 'title') tampering detectable.",
            "Hashes [make](audit.md (paren title)) tampering detectable.",
            "Hashes [make][ref] tampering detectable.\n\n[REF]: audit.md",
            "~~~\nhashes make tampering detectable\n~~~",
            "hash*es* make tampering detectable",
            "&#104;ashes make tampering detectable",
            "<p>hashes <span hidden>do not </span>make tampering detectable</p>",
            '<p>hashes <span style="display:none">do not </span>make tampering detectable</p>',
            "hash<script>x</script>es make tampering detectable",
            '<p class="note"\n>Hashes make <a href="x">tampering</a> detectable.</p>',
            "\\<span hidden>hashes make tampering detectable",
            "use `<span hidden>` then hashes make tampering detectable",
            "<custom-note>hash</custom-note>es make tampering detectable",
            "Intro.\n\n    <span hidden>hashes make tampering detectable\n",
            "A span `<span hidden>\nhashes make` tampering detectable across lines.",
            "> ```\n> <span hidden>hashes make tampering detectable\n> ```",
            '- item\n\n  ```\n  hashes make tampering detectable\n  ```',
            'Hashes [make](<audit.md> "the title") tampering detectable.',
            'Hashes [make]( "a title with words") tampering detectable.',
            "Hashes [make][ref] tampering detectable.\n\n[ref]:\n  audit.md",
            "Hashes [make][a\\]b] tampering detectable.\n\n[a\\]b]: audit.md",
            '<span style="display:none;display:inline">hashes make tampering detectable</span>',
            # Hidden text is still maintained copy, so it is checked too.
            '<span style="display:inline;display:none">hashes make tampering detectable</span>',
            "<span hidden>hashes make tampering detectable</span>",
            "<script>hashes make tampering detectable</script>",
            "[note]: hashes make tampering detectable",
            "[note]:\nhashes make tampering detectable",
            "- item\n\n      <!-- hashes make tampering detectable -->",
            "1. a\n   - b\n\n         hashes make tampering detectable",
            "> - item\n>\n>   ```\n>   <span hidden>hashes make tampering detectable\n>   ```",
            "<div hidden>hashes make</div>tampering detectable",
            '<span style="display:inline ! important">hash</span>es make tampering detectable',
            '<span style="display:initial">hash</span>es make tampering detectable',
            '<div style="display: inline flow-root">hash</div>es make tampering detectable',
            "[ok]:\n  /audit.md 'T'\n\nHashes [make][ok] tampering detectable",
            '<img alt="hashes make tampering detectable" src="x.png">',
            "<!-- hashes make tampering detectable -->",
            '[note]: x "title" hashes make tampering detectable "tail"',
            "Hashes [make][r] tampering detectable\n\n[r]: foo\\(bar",
            "> ```\n> harmless\nhash*es* make tampering detectable",
            "- item\n\n  ```\n  harmless\nhash*es* make tampering detectable",
            '<span style="display:flex inline">hash</span>es make tampering detectable',
            '<div hidden>hashes <span class="note">make</span> tampering detectable</div>',
            "<div hidden>hashes <!-- c --> make tampering detectable</div>",
        ):
            with self.subTest(text=text):
                self.assertTrue(retired_claim_errors(text, source_name="fixture.md"))

    def test_block_boundaries_do_not_join_word_fragments(self) -> None:
        for text in (
            "<form>hash</form><form>es make tampering detectable</form>",
            "<fieldset>hash</fieldset>es make tampering detectable",
            "<p>hash</p><p>es make tampering detectable</p>",
            "<div>hash<br>es make tampering detectable</div>",
            '<span style="display:block">hash</span><span style="display:block">es make tampering detectable</span>',
            "<div hidden>hash</div>es make tampering detectable",
            '<span style="display:block flex">hash</span>es make tampering detectable',
            '<span style="display:flow block">hash</span>es make tampering detectable',
        ):
            with self.subTest(text=text):
                self.assertEqual(retired_claim_errors(text, source_name="fixture.md"), [])

    def test_literal_punctuation_never_manufactures_a_claim(self) -> None:
        for text in (
            "hash_es make tampering detectable",
            "hash\\_es make tampering detectable",
            "hash[es] make tampering detectable",
            "hash`es make tampering detectable",
            "hash*es make tampering detectable",
            "hash~es make tampering detectable",
            "    indented code keeps hash*es* literal: make tampering detectable",
            "<pre>hash*es* make tampering detectable</pre>",
            "    - hash*es* make tampering detectable",
            "hash*es make tampering detectable\n\nx*",
        ):
            with self.subTest(text=text):
                self.assertEqual(retired_claim_errors(text, source_name="fixture.md"), [])

    def test_claims_hidden_from_the_supported_subset_are_still_found(self) -> None:
        # Round-7 counterexamples: each hides the claim from the rendered,
        # hidden and metadata readings, but not from the source readings.
        for text in (
            "[note]: hashes\\ make\\ tampering\\ detectable",
            'Hashes [make][r] tampering detectable\n\n[r]: u "a\nb"',
            """<span title='[note](x "hashes make tampering detectable")'>safe</span>""",
            "<span title=\"[note](x 'hashes make tampering detectable')\">safe</span>",
            "text <!-- [note](x \"hashes make tampering detectable\") --> more",
            "<p hidden>notes<p>hashes <span hidden>do not </span>make tampering detectable</p>",
        ):
            with self.subTest(text=text):
                self.assertTrue(retired_claim_errors(text, source_name="fixture.md"))
                self.assertTrue(retired_claim_errors(text, source_name="fixture.html"))


    def test_markup_the_check_cannot_read_needs_rewording(self) -> None:
        # Round-8 counterexamples and close variants. Markup whose rendering the
        # readings do not model is refused whether or not a retired phrase is
        # present, so a claim cannot hide in it.
        both = (
            "<p hidden>notes<p>hashes <span hidden><b>do not </b></span>make tampering detectable</p>",
            "<p hidden>notes<p>hashes make tampering detectable</p>",
            "<span hidden><b>do not</b></span>",
            "<span hidden>notes <!-- c --> more</span>",
            "<p>notes <span hidden>do not</p>",
            "notes <span hidden>do not",
            "hashes <span hidden/><b>do not</b></span> make tampering detectable",
            "<template><p>notes</p></template>",
            '<span><template shadowrootmode="open"></template>do not</span>',
            '<style>.x { display: none }</style><span class="x">do not</span>',
            "<head><p>notes</p></head>",
            "<head>notes</head>",
            "<ruby>notes<rp>(<rt>more</rt></ruby>",
            "<noscript>do not</noscript>",
            "<dialog>do not</dialog>",
            "<select><option>a</option><option>do not</option></select>",
            "<bdo dir=\"rtl\">ton od</bdo>",
            "<custom-note>notes</custom-note>",
            '<input type="submit" value="do not">',
            '<span style="visibility:hidden">do not</span>',
            '<span style="display:inline;font-size:0">do not</span>',
            "<span popover>do not</span>",
            "<table><tr><td>a</td></tr>notes</table>",
            "<table><span>notes</span><tr><td>a</td></tr></table>",
            "<svg><text>do not</text></svg>",
            "<svg>do not</svg>",
            "<b><details><summary>a</summary></b>notes</details>",
            "notes\u00admore",
            "notes&shy;more",
            "notes \u202edon\u202c more",
            "notes &#8203; more",
            "h\u0430shes",
            "\uff48ashes",
            "notes\u0338 more",
            "notes \U000f0000 more",
            # Round-9 findings: inline styles the check cannot interpret, and duplicate attributes.
            'hash<span style="display:/**/none">x</span>es make tampering detectable',
            'hash<span style="display:none;display:garbage">x</span>es make tampering detectable',
            'hash<span style="display:none" style="display:inline">x</span>es make tampering detectable',
            '<span style="display:none !important">x</span>',
            '<span style="display:none;;">x</span>',
            '<span style="display:n\\one">x</span>',
            '<span style="display:inline block">x</span>',
            '<span style="display:\u00a0none">x</span>',
            '<span style="display:none/">x</span>',
            '<span title="a" TITLE="b">x</span>',
            # Attributes the readings do not model, and hidden with an inline style.
            '<span onclick="this.remove()">x</span>',
            '<span dir="rtl">x</span>',
            '<body text="white" bgcolor="white">x</body>',
            '<span hidden style="display:inline">x</span>',
            # Scripts, and details content before its summary.
            "<script>document.body.hidden = true</script>",
            '<script src="data:text/javascript,document.body.remove()"></script>',
            '<link rel="stylesheet" href="data:text/css,span{display:none}">',
            "<details>notes<summary>a</summary></details>",
            "<details><p>notes</p><summary>a</summary></details>",
            # Round-9 sampling finding: a hidden image with alt text, and more nearby regions than are read in combination.
            'hashes <img src="a.png" alt="do not">' + '<img hidden src="h.png" alt="x">' * 15
            + ' make <img src="b.png" alt="tampering"> detectable',
            'hashes <img src="a.png" alt="do not">' + '<img src="m.png" alt=".">' * 15
            + ' make <img src="b.png" alt="tampering"> detectable',
        )
        markdown_only = (
            'Hash[es][r] make tampering detectable\n\n[r]: u "a\nb"',
            '[r]: u "a\nb"',
            "[a\nb]: u",
            '- [r]: u "a\n  b"',
            '> [r]: u "a\n> b"',
            '[r]:\n  u "a\n  b"',
            "[r]: two words",
            "Hash[es](u) make",
            "Hash![es](u.png) make",
            "[Hash](u)es make",
            "Hash[es][r] make\n\n[r]: u",
            "[Hash][r]es make\n\n[r]: u",
            "Hash[es] make\n\n[es]: u",
            "Hash[es][] make\n\n[es]: u",
            "Hash[es][undefined] make",
            "<p hidden>notes\n\nhashes make tampering detectable\n\n</p>",
            "<div hidden>\n\nhashes <span hidden>do not </span>make tampering detectable\n\n</div>",
            "Text [^1] here.\n\n[^1]: note",
            "See [^note].",
            "[^1]: note",
            "<span hidden>![do not](dot.png)</span>",
        )
        cases = [(text, name) for text in both for name in ("fixture.md", "fixture.html")]
        cases.extend((text, "fixture.md") for text in markdown_only)
        for text, name in cases:
            with self.subTest(text=text, source=name):
                errors = retired_claim_errors(text, source_name=name)
                self.assertTrue(any(": rewording required (" in error for error in errors), errors)

    def test_supported_markup_needs_no_rewording(self) -> None:
        page = (
            '<!doctype html>\n<html lang="en">\n  <head>\n    <meta charset="utf-8">\n    <title>Guide | CWO</title>\n'
            '    <link rel="icon" href="data:image/svg+xml,%3Csvg%3E%3C/svg%3E">\n'
            '    <link rel="stylesheet" href="./styles.css">\n    <script src="./site.js" defer></script>\n  </head>\n'
            '  <body><main><p>Text.</p></main></body>\n</html>\n'
        )
        both = (
            page,
            "<p>notes <span hidden>more</span> text</p>",
            "<p hidden>notes</p><p>text</p>",
            '<span style="display:none">a</span> <span style="display: inline flow-root">b</span>',
            "<details open><summary>More</summary><p>text</p><ul><li>a</li></ul></details>",
            '<svg viewBox="0 0 2 2" aria-hidden="true"><path d="M0 0"/> <circle cx="1" cy="1" r="1"/></svg>',
            "<table><caption>c</caption><thead><tr><th>A</th></tr></thead><tbody>\n<tr><td>B</td></tr></tbody></table>",
            '<input class="sr-only" type="radio" name="theme" value="dark"><label for="x">Dark</label>',
            '<picture><source srcset="a.webp"><img src="a.png" alt="A diagram of the flow"></picture>',
            "A caf\u00e9 r\u00e9sum\u00e9 \u201cquoted\u201d \u2192 next.",
            '<span style="DISPLAY: NONE;">a</span> <span style=" display:block flow ">b</span>',
        )
        markdown_only = (
            'See [the audit](audit.md), then [the guide][g] and [g].\n\n[g]: guide.md "Guide"',
            "Use hash[es] literally, or escape it: hash\\[es\\](x).",
            "- item [link](u)\n\n  > quote [ref]\n\n[ref]:\n  /ref.md",
            "Code `a[b](c)d` and\n\n```\nx[y](z)w\n[r]: u \"a\n```",
            # Round-9 minor: escaped punctuation next to a link is not a word.
            "See [guide](u)\\.",
            "Call it [guide](u)\\) now, or see \\([the guide](u)\\).",
            "Visit <https://example.com/guide> or <team@example.com>.",
            "[![A diagram of the flow](docs/flow.svg)](https://example.com/#flow)",
            "![A diagram](docs/a.svg)\n\nSome text.\n\n![](docs/b.svg)",
            "<details>\n\n<summary>More</summary>\n\nText.\n\n</details>",
        )
        cases = [(text, name) for text in both for name in ("fixture.md", "fixture.html")]
        cases.extend((text, "fixture.md") for text in markdown_only)
        for text, name in cases:
            with self.subTest(text=text, source=name):
                self.assertEqual(retired_claim_errors(text, source_name=name), [])

    def test_claims_shown_by_closed_details_or_broken_images_are_found(self) -> None:
        for text in (
            "<details><summary>hashes make</summary>do not</details>tampering detectable",
            'hashes <img src="x.png" alt="make"> tampering detectable',
            'hashes <img src="x.png" alt="make"> <details><summary>tampering</summary>do not</details> detectable',
            # Mixed states: one details element closed and the next open; one image loaded and the next broken.
            "<details><summary>hashes</summary>do not</details><details><summary>make</summary>tampering detectable</details>",
            'hashes <img src="a.png" alt="do not"> make <img src="b.png" alt="tampering"> detectable',
            # Beyond four such elements, any four consecutive ones still take every combination.
            "<details><summary>a</summary>b</details>" * 5
            + "<details><summary>hashes</summary>do not</details><details><summary>make</summary>tampering detectable</details>",
            # Regions far apart in document order but near in the text, read in every combination.
            '<details><summary>hashes</summary>' + '<img src="m.png" alt=".">' * 4
            + '</details><img src="b.png" alt="make"> tampering detectable',
            # Hidden copy that a renderer stripping hiding attributes would show, with a closed details element.
            "<details><summary>hashes</summary>do not</details><span hidden>make</span> tampering detectable",
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    self.assertTrue(any(": retired claim (" in error for error in errors), errors)
        # Round-9 finding: Markdown images are loaded or broken like HTML images.
        for text in (
            "hashes ![do not](dot.png) make tampering detectable",
            "hashes ![do not][img] make tampering detectable\n\n[img]: dot.png",
            "hashes [![do not](dot.png)](u) make tampering detectable",
            "hashes ![make](a.png) tampering detectable",
            "hashes ![ma*ke*](a.png) tampering detectable",
        ):
            with self.subTest(text=text, source="fixture.md"):
                errors = retired_claim_errors(text, source_name="fixture.md")
                self.assertTrue(any(": retired claim (" in error for error in errors), errors)

    def test_regions_within_reach_of_one_phrase_form_clusters(self) -> None:
        from validate_public_copy import _NEAR_WORDS, RETIRED_CLAIMS, _clusters

        start, end = "\ue002", "\ue003"
        words = " ".join(["w"] * _NEAR_WORDS)
        self.assertEqual(_clusters(f"{start}{end} {words} {start}{end}"), [2])
        self.assertEqual(_clusters(f"{start}{end} {words} w {start}{end}"), [1, 1])
        self.assertEqual(_clusters(f"{start}{start} {words} w {end}{end} {start}{end}"), [3])
        self.assertEqual(_clusters(f"{start} {words} w w {end} x {start}{end}"), [2])
        self.assertEqual(_clusters("no regions"), [])
        for phrase in ("hashes make tampering detectable", "provides tamper-evident detection",
                       "Native productive work uses the admitted version-2 pool launcher"):
            with self.subTest(phrase=phrase):
                self.assertTrue(any(pattern.search(phrase) for pattern, _ in RETIRED_CLAIMS))
                self.assertLessEqual(len(phrase.replace("-", " ").split()) + 2, _NEAR_WORDS)

    def test_html_sources_are_not_read_as_markdown(self) -> None:
        page = '<p class="note"\n>Hashes make <a href="x">tampering</a> detectable.</p>'
        self.assertTrue(retired_claim_errors(page, source_name="page.html"))
        self.assertTrue(retired_claim_errors(page, source_name="page.md"))
        self.assertEqual(claim_text("<p>see <code>a_b</code> and [x] *y*</p>", markdown=False), "see a_b and [x] *y*")

    def test_accurate_wordings_are_allowed(self) -> None:
        for text in (
            "The audit hash chain detects accidental or partial edits when it is later checked.",
            "Native pool work is designed around the admitted version-2 pool launcher, but needs a trusted controller.",
            "Records are tamper-evident only against edits that do not recompute the chain.",
        ):
            with self.subTest(text=text):
                self.assertEqual(retired_claim_errors(text, source_name="fixture"), [])

    def test_maintained_copy_contains_no_retired_wording(self) -> None:
        maintained = [ROOT / "README.md", ROOT / "SKILL.md", *sorted((ROOT / "references").glob("*.md")), *sorted((ROOT / "docs").glob("*.html"))]
        errors: list[str] = []
        for path in maintained:
            if path.name == "claims-register.md":
                continue
            errors.extend(retired_claim_errors(path.read_text(encoding="utf-8"), source_name=path.name))
        self.assertEqual(errors, [])

    def test_register_covers_each_claim_area(self) -> None:
        register = (ROOT / "references" / "claims-register.md").read_text(encoding="utf-8")
        for area in (
            "Helper gates",
            "Native supervision checks",
            "Execution boundary",
            "Content digests",
            "Audit hash chain",
            "Signed activation-preview approvals",
            "Signed maintenance approvals",
            "Concurrent native pool contract",
            "Stale-agent cleanup",
            "Operator prompt qualification",
        ):
            with self.subTest(area=area):
                self.assertIn(area, register)

    def test_character_references_are_refused_except_basic_entities(self) -> None:
        # All character references except &amp;, &lt;, &gt;, &quot; are refused.
        for text in (
            # Numeric references (decimal and hex)
            "See &#107; here.",
            "See &#x6b; here.",
            # Markdown image description
            'See ![&#xF0000;](u "title") here.',
            'hashes ![ma&#107;e](u "title") tampering detectable',
            'hashes ![ma&#107;e](u) tampering detectable',
            # Before a link
            "See [guide](u)&#xF0000;",
            # Noncharacters
            "See &#xFDD0; here.",
            "See &#64976; here.",
            "See &#xFDEF; here.",
            # HTML attribute
            '<img src="u" alt="&#xFFFE;">',
            # Named references (not the four basic ones)
            "See &copymake; here.",
            'hashes ![&copymake;](u "title") tampering detectable',
            'hashes ![&copymake;](u) tampering detectable',
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    self.assertTrue(any("rewording required (character reference" in error for error in errors), errors)

    def test_emphasis_does_not_assemble_character_references(self) -> None:
        # Emphasis around part of a reference should not falsely report it as a retired claim.
        # Uses complete retired sentences including the titled-image form.
        # The emphasis markers break the reference pattern, so these are not valid references
        # and won't be decoded, thus won't match the retired claim "hashes make tampering detectable".
        for text in (
            "hashes ma&**#107**;e tampering detectable",
            'hashes ![ma&**#107**;e](u "title") tampering detectable',
            "hashes ma&*#107*;e tampering detectable",
            'hashes ![ma&*#107*;e](u "title") tampering detectable',
            "hashes ma&_#107_;e tampering detectable",
            'hashes ![ma&_#107_;e](u "title") tampering detectable',
        ):
            with self.subTest(text=text):
                errors = retired_claim_errors(text, source_name="fixture.md")
                # Should not be reported as containing a retired claim
                self.assertFalse(any("retired claim" in error for error in errors), errors)

    def test_basic_xml_entities_are_allowed(self) -> None:
        # Only &amp;, &lt;, &gt;, &quot; are allowed
        for text in (
            "See &amp; here.",
            "See &lt; here.",
            "See &gt; here.",
            "See &quot; here.",
            "a &lt; b &amp; c &gt; d",
            '<span title="&lt;&gt;&amp;&quot;">text</span>',
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    # Should not be refused for character references
                    self.assertFalse(any("rewording required (character reference" in error for error in errors), errors)


    def test_unreadable_literal_characters_are_refused(self) -> None:
        # Private use, noncharacters, surrogates, internal namespace
        for text, char_name in (
            # Noncharacters
            ("﷐ text", "U+FDD0"),
            ("﷯ text", "U+FDEF"),
            ("￾ text", "U+FFFE"),
            ("￿ text", "U+FFFF"),
            # Private use (not in validator's working set)
            (" text", "U+E005"),
            # Internal token namespace
            ("\U000f0000 x text", "U+F0000"),
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, char=char_name, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    self.assertTrue(any("rewording required (unreadable" in error for error in errors), errors)

    def test_literal_unreadable_in_image_description_does_not_loop(self) -> None:
        # Regression: literal U+F0000 followed by " x" in image description caused infinite loop
        # This should return immediately with rewording error, not hang
        errors = retired_claim_errors("See ![\U000f0000 x](u) here.", source_name="fixture.md")
        self.assertTrue(any("rewording required (unreadable" in error for error in errors), errors)
        errors = retired_claim_errors('See ![\U000f0000 x](u "title") here.', source_name="fixture.md")
        self.assertTrue(any("rewording required (unreadable" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
