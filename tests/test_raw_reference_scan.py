from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_public_copy import (  # noqa: E402
    _Protected,
    _reading,
    claim_text,
    retired_claim_errors,
    retired_browser_guidance_errors,
    source_readings,
)


class RawReferenceScanTests(unittest.TestCase):
    """Tests for raw character reference scanning without context exemptions."""

    def test_backtick_in_attribute_does_not_protect_reference(self) -> None:
        # Round 14 regression: backticks inside attributes incorrectly protected intervening markup
        text = 'hashes <span title="`" style="display:&#110;one" data-x="`">do not </span>make tampering detectable'
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused for character reference (&#110; = n, decodes to display:none)
        self.assertTrue(any("rewording required (character reference)" in error or
                           "rewording required (encoded character reference)" in error
                           for error in errors), errors)

    def test_reference_in_image_alt_does_not_raise_valueerror(self) -> None:
        # Round 14 regression: reference in alt raised uncaught ValueError
        for text in (
            'See <img src="u" alt="&#xF0000; x"> here.',
            'See <img src="u" alt="&#xF0000; x"> here.',
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    # Should return rewording diagnostic, not raise
                    self.assertTrue(any("rewording required" in error for error in errors), errors)

    def test_semicolonless_references_are_refused(self) -> None:
        # Round 14 regression: scanner required semicolons but HTML accepts without them
        for text in (
            '<img alt="&#xFFFE">',
            '<img alt="&copy">',
        ):
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=text, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    self.assertTrue(any("rewording required (character reference)" in error or
                                       "rewording required (encoded character reference)" in error
                                       for error in errors), errors)

    def test_references_in_code_spans_are_refused(self) -> None:
        # Round 14 regression: code span exemption contradicted by unconditional unescape
        for text in (
            'Use `&#xF0000;` literally.',
            '```\n&#xF0000;\n```',
        ):
            with self.subTest(text=text):
                errors = retired_claim_errors(text, source_name="fixture.md")
                # Should have character reference error AND unreadable character error
                # (reference is detected first in raw scan, then after decoding would show unreadable)
                self.assertTrue(any("rewording required (character reference)" in error or
                                   "rewording required (encoded character reference)" in error
                                   for error in errors), errors)

    def test_encoded_references_are_refused(self) -> None:
        # Encoded references: &amp; followed by # or ASCII letter
        for text in (
            "Use &amp;#107; for k.",
            "See &amp;copy; notice.",
        ):
            with self.subTest(text=text):
                errors = retired_claim_errors(text, source_name="fixture.md")
                self.assertTrue(any("rewording required (encoded character reference)" in error
                                   for error in errors), errors)

    def test_allowed_entities_pass(self) -> None:
        # The four allowed entities should pass in both prose and code
        for text in (
            "Use &amp; for ampersand.",
            "See &lt; and &gt; brackets.",
            'Use &quot; for quotes.',
            "All four: &amp; &lt; &gt; &quot; work.",
            "In code: `&amp;` and `&lt;` and `&gt;` and `&quot;`.",
        ):
            with self.subTest(text=text):
                errors = retired_claim_errors(text, source_name="fixture.md")
                # Should not have character reference errors
                self.assertFalse(any("rewording required (character reference)" in error or
                                    "rewording required (encoded character reference)" in error
                                    for error in errors), errors)

    def test_bare_ampersand_with_space_passes(self) -> None:
        # Bare & followed by space or other non-# non-ASCII-letter
        for text in (
            "R & D department.",
            "Johnson & Johnson",
            "A & B & C",
        ):
            with self.subTest(text=text):
                errors = retired_claim_errors(text, source_name="fixture.md")
                self.assertFalse(any("rewording required (character reference)" in error or
                                    "rewording required (encoded character reference)" in error
                                    for error in errors), errors)

    def test_expansion_bomb_with_encoded_reference_returns_diagnostic_quickly(self) -> None:
        # Round 14 regression: 212-char input with doubled self-reference and 30 &amp; exceeded 196k chars
        # Now with encoded references (&amp;#...) to trigger raw scan refusal
        style_attr = 'style="' + '&amp;#97;' * 30 + '"'
        text = f'<span {style_attr}>text</span>'
        # This should be refused quickly for encoded character reference (first &amp;#97;), not hang or explode
        errors = retired_claim_errors(text, source_name="fixture.md")
        # The raw scan should catch the first encoded reference
        self.assertTrue(any("rewording required (encoded character reference)" in error
                           for error in errors), errors)


class GateEntryPointTests(unittest.TestCase):
    """Round 16 regressions: gate at every public entry point."""

    def test_zero_width_inside_entity_names_refused(self) -> None:
        # Round 15 regression: zero-width removal before raw scan allowed repair
        # U+200B (zero-width space) is a Cf character
        zero_width_texts = [
            ("Use &l​t; here.", "lt with U+200B"),
            ("Use &am​p; here.", "amp with U+200B"),
            ("Use &g​t; here.", "gt with U+200B"),
            ("Use &quo​t; here.", "quot with U+200B"),
        ]
        for text, desc in zero_width_texts:
            for name in ("fixture.md", "fixture.html"):
                with self.subTest(text=desc, source=name):
                    errors = retired_claim_errors(text, source_name=name)
                    # Should be refused for format character before any repair
                    self.assertTrue(any("rewording required (unreadable format character" in error
                                       for error in errors), f"{desc} in {name}: {errors}")

    def test_other_cf_characters_inside_entity_names_refused(self) -> None:
        # Test other Cf characters: U+200C (zero-width non-joiner), U+200D (zero-width joiner),
        # U+2060 (word joiner), U+FEFF (zero-width no-break space)
        cf_chars = [
            ("‌", "U+200C"),
            ("‍", "U+200D"),
            ("⁠", "U+2060"),
            ("﻿", "U+FEFF"),
        ]
        for cf_char, desc in cf_chars:
            for entity in ("&lt;", "&amp;", "&gt;", "&quot;"):
                # Insert Cf character in the middle of entity name
                pos = len(entity) // 2
                text = f"Use {entity[:pos]}{cf_char}{entity[pos:]} here."
                for name in ("fixture.md", "fixture.html"):
                    with self.subTest(cf=desc, entity=entity, source=name):
                        errors = retired_claim_errors(text, source_name=name)
                        self.assertTrue(any("rewording required (unreadable format character" in error
                                           for error in errors), f"{desc} in {entity} in {name}: {errors}")

    def test_oversized_decimal_reference_returns_diagnostic(self) -> None:
        # Round 15 regression: 4301-digit decimal reference raised uncaught ValueError
        oversized_ref = "&#" + "1" * 4301 + ";"
        test_cases = [
            (f"Use {oversized_ref} here.", "fixture.md", "prose Markdown"),
            (f"Use {oversized_ref} here.", "fixture.html", "prose HTML"),
            (f"Use `{oversized_ref}` here.", "fixture.md", "code span Markdown"),
            (f'<img src="u" alt="{oversized_ref}">', "fixture.md", "image alt Markdown"),
            (f'<img src="u" alt="{oversized_ref}">', "fixture.html", "image alt HTML"),
        ]
        for text, name, desc in test_cases:
            with self.subTest(context=desc):
                errors = retired_claim_errors(text, source_name=name)
                # Should return diagnostic, not raise ValueError
                self.assertTrue(any("rewording required" in error for error in errors),
                              f"{desc}: {errors}")
                # Should specifically be refused for character reference
                self.assertTrue(any("rewording required (character reference)" in error
                                   for error in errors), f"{desc}: {errors}")

    def test_gate_rejection_stops_processing(self) -> None:
        # After gate rejection, downstream helpers should not be called
        # Use a Cf character to trigger gate rejection
        bad_text = "Use ​ here."

        # Test retired_claim_errors: _reading should not be called
        with mock.patch("validate_public_copy._reading") as mock_reading:
            errors = retired_claim_errors(bad_text, source_name="fixture.md")
            self.assertTrue(any("rewording required (unreadable format character" in error
                               for error in errors), errors)
            mock_reading.assert_not_called()

        # Test claim_text: _reading should not be called
        with mock.patch("validate_public_copy._reading") as mock_reading:
            result = claim_text(bad_text, markdown=True)
            self.assertEqual(result, "")
            mock_reading.assert_not_called()

        # Test source_readings: html.unescape should not be called
        with mock.patch("html.unescape") as mock_unescape:
            result = source_readings(bad_text)
            self.assertEqual(result, [])
            mock_unescape.assert_not_called()

        # Test retired_browser_guidance_errors: _VisibleText should not be called
        with mock.patch("validate_public_copy._VisibleText") as mock_visible:
            errors = retired_browser_guidance_errors(bad_text, source_name="fixture.md")
            self.assertTrue(any("rewording required (unreadable format character" in error
                               for error in errors), errors)
            mock_visible.assert_not_called()

    def test_oversized_decimal_reference_stops_processing(self) -> None:
        # Oversized reference should be caught by gate and stop processing
        oversized_ref = "&#" + "1" * 4301 + ";"
        bad_text = f"Use {oversized_ref} here."

        # html.unescape should not be called (would raise ValueError)
        with mock.patch("html.unescape") as mock_unescape:
            # Make unescape raise ValueError to verify it's not called
            mock_unescape.side_effect = ValueError("decimal string too long")

            # Should return diagnostic without calling unescape
            errors = retired_claim_errors(bad_text, source_name="fixture.md")
            self.assertTrue(any("rewording required (character reference)" in error
                               for error in errors), errors)
            mock_unescape.assert_not_called()


class TokenCapacityTests(unittest.TestCase):
    """Token capacity overflow beyond U+FFFFD."""

    def test_max_safe_token_count_works(self) -> None:
        # 65,533 base spans plus the claim's `k` span fill all 65,534 tokens.
        # The split word requires restoration; source-level matching cannot find it.
        text = "`x` " * 65533 + "hashes ma`k`e tampering detectable"
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should find the retired claim
        self.assertTrue(any("retired claim" in error for error in errors), errors)
        # Should not have processing failure
        self.assertFalse(any("rewording required" in error for error in errors), errors)

    def test_oversized_token_count_refused(self) -> None:
        # 65,535 protected spans should be refused (would overflow to U+FFFFE)
        # The verdict example: 65,534 "`x` " + claim with backticks around k = 65,535 total
        text = "`x` " * 65534 + "hashes ma`k`e tampering detectable"
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused with rewording diagnostic, not silently return []
        self.assertTrue(len(errors) > 0, "Expected rewording diagnostic, got empty list")
        self.assertTrue(any("rewording required" in error for error in errors), errors)
        # This fixture's split claim is absent from the successful readings.
        self.assertFalse(any("retired claim" in error for error in errors), errors)

    def test_complete_claim_with_oversized_tokens(self) -> None:
        # Complete claim text with oversized token count (65,535 total spans)
        # This tests that even when the claim is complete and correct, token overflow refuses it
        text = "`x` " * 65534 + "the audit hash chain detects altered retained events and bro`k`en links only"
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused for token capacity
        self.assertTrue(len(errors) > 0, errors)
        self.assertTrue(any("rewording required" in error for error in errors), errors)

    def test_next_allocation_after_max_fails(self) -> None:
        # Verify that allocation 65,535 (index 65,534) fails and doesn't change stored values
        # This is the boundary: 65,534 tokens work, token 65,535 would be U+FFFFE (noncharacter)
        protected = _Protected()
        tokens = [protected.hold(f"value-{index}") for index in range(65534)]
        self.assertEqual(len(protected.values), 65534)
        self.assertEqual(tokens[0], "\U000f0000")
        self.assertEqual(tokens[-1], "\U000ffffd")
        self.assertEqual(protected.restore(tokens[-1]), "value-65533")
        self.assertEqual(
            protected.restore(" ".join(tokens)),
            " ".join(f"value-{index}" for index in range(65534)),
        )
        stored_values = tuple(protected.values)
        with self.assertRaisesRegex(ValueError, "token capacity exceeded"):
            protected.hold("overflow")
        self.assertEqual(tuple(protected.values), stored_values)
        self.assertEqual(protected.restore(tokens[-1]), "value-65533")

        text = "`x` " * 65534 + " next allocation: `y`"
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused for token capacity (the `y` span would be token 65,535)
        self.assertTrue(len(errors) > 0, errors)
        self.assertTrue(any("rewording required" in error for error in errors), errors)


class AlternateReadingOverflowTests(unittest.TestCase):
    """Collect diagnostics from every reading including alternate readings."""

    def test_broken_image_alt_overflow_markdown(self) -> None:
        # Verdict counterexample: overflow in broken image alt text (Markdown)
        # "`x` " * 65534 + 'hashes <img src="u" alt="make"> tampering detectable'
        # Reading the broken image's alt text allocates the overflowing token
        text = "`x` " * 65534 + 'hashes <img src="u" alt="make"> tampering detectable'
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused with rewording diagnostic, not return [] silently
        self.assertTrue(len(errors) > 0, f"Expected rewording diagnostic, got empty list: {errors}")
        self.assertTrue(any("rewording required" in error for error in errors), errors)
        # This fixture's claim is absent from the successful readings.
        self.assertFalse(any("retired claim" in error for error in errors), errors)

    def test_markdown_image_alt_overflow(self) -> None:
        # Code spans and the image description use exactly 65,534 tokens.
        # Showing the broken image's alt text requires allocation 65,535.
        text = "`x` " * 65532 + 'hashes ![ma`k`e](broken.png) tampering detectable'
        initial_text, initial_unreadable = _reading(text, markdown=True)
        self.assertEqual(initial_unreadable, [])
        self.assertTrue(initial_text.endswith("hashes tampering detectable"), initial_text[-80:])
        measured_text, measured_unreadable = _reading(text, markdown=True, measure=True)
        self.assertEqual(measured_unreadable, [])
        self.assertTrue(measured_text, "The measuring reading must succeed to enumerate image states")
        alternate_text, alternate_unreadable = _reading(
            text, markdown=True, shown=lambda _index: True
        )
        self.assertEqual(alternate_text, "")
        self.assertEqual(
            alternate_unreadable,
            [("rewording required (processing failure)", "rewording required (token capacity exceeded)")],
        )
        errors = retired_claim_errors(text, source_name="fixture.md")
        # Should be refused with rewording diagnostic
        self.assertTrue(len(errors) > 0, f"Expected rewording diagnostic, got empty list: {errors}")
        self.assertTrue(any("rewording required" in error for error in errors), errors)
        self.assertTrue(any("processing failure" in error and "token capacity exceeded" in error
                            for error in errors), errors)
        # This fixture's split claim is absent from the successful readings.
        self.assertFalse(any("retired claim" in error for error in errors), errors)


class PrivateUseGateTests(unittest.TestCase):
    """Refuse literal private-use characters at gate, including U+E000..U+E004."""

    def _test_private_use_refused_at_entry_point(self, entry_point: str, char: str, char_name: str) -> None:
        """Test that a private-use character is refused at the given entry point."""
        text = f"See {char} here."

        if entry_point == "retired_claim_errors":
            with mock.patch("validate_public_copy._reading") as mock_reading:
                errors = retired_claim_errors(text, source_name="fixture.md")
                self.assertTrue(any(f"rewording required (unreadable private-use character {char_name})" in error
                                   for error in errors), f"{char_name} at {entry_point}: {errors}")
                mock_reading.assert_not_called()

        elif entry_point == "claim_text":
            with mock.patch("validate_public_copy._reading") as mock_reading:
                result = claim_text(text, markdown=True)
                self.assertEqual(result, "")
                mock_reading.assert_not_called()

        elif entry_point == "source_readings":
            with mock.patch("html.unescape") as mock_unescape:
                result = source_readings(text)
                self.assertEqual(result, [])
                mock_unescape.assert_not_called()

        elif entry_point == "retired_browser_guidance_errors":
            with mock.patch("validate_public_copy._VisibleText") as mock_visible:
                errors = retired_browser_guidance_errors(text, source_name="fixture.md")
                self.assertTrue(any(f"rewording required (unreadable private-use character {char_name})" in error
                                   for error in errors), f"{char_name} at {entry_point}: {errors}")
                mock_visible.assert_not_called()

    def test_internal_markers_refused_at_all_entry_points(self) -> None:
        # U+E000..U+E004 are internal markers, but should be refused in raw input
        markers = [
            ("", "U+E000"),
            ("", "U+E001"),
            ("", "U+E002"),
            ("", "U+E003"),
            ("", "U+E004"),
        ]
        entry_points = [
            "retired_claim_errors",
            "claim_text",
            "source_readings",
            "retired_browser_guidance_errors",
        ]

        for char, char_name in markers:
            for entry_point in entry_points:
                with self.subTest(char=char_name, entry_point=entry_point):
                    self._test_private_use_refused_at_entry_point(entry_point, char, char_name)


class DownstreamCallSpyTests(unittest.TestCase):
    """Parameterized spy assertions for all rejection classes."""

    def test_all_rejection_classes_stop_processing(self) -> None:
        """Test that all rejection classes prevent downstream processing at all entry points."""

        # Rejection classes with test inputs
        rejection_cases = [
            ("format_character", "Use ​ here.", "Cf character U+200B"),
            ("private_use", "Use  here.", "private-use U+E005"),
            ("character_reference", "Use &#110; here.", "character reference"),
            ("oversized_reference", "&#" + "1" * 4301 + ";", "oversized reference"),
        ]

        entry_points = [
            ("retired_claim_errors", "validate_public_copy._reading"),
            ("claim_text", "validate_public_copy._reading"),
            ("source_readings", "html.unescape"),
            ("retired_browser_guidance_errors", "validate_public_copy._VisibleText"),
        ]

        for rejection_class, bad_text, desc in rejection_cases:
            for entry_name, mock_target in entry_points:
                with self.subTest(rejection=desc, entry_point=entry_name):
                    with mock.patch(mock_target) as mock_downstream:
                        if mock_target == "html.unescape":
                            mock_downstream.side_effect = ValueError("should not be called")

                        if entry_name == "retired_claim_errors":
                            errors = retired_claim_errors(bad_text, source_name="fixture.md")
                            self.assertTrue(len(errors) > 0, f"{desc}: expected errors")
                        elif entry_name == "claim_text":
                            result = claim_text(bad_text, markdown=True)
                            self.assertEqual(result, "", f"{desc}: expected empty string")
                        elif entry_name == "source_readings":
                            result = source_readings(bad_text)
                            self.assertEqual(result, [], f"{desc}: expected empty list")
                        elif entry_name == "retired_browser_guidance_errors":
                            errors = retired_browser_guidance_errors(bad_text, source_name="fixture.md")
                            self.assertTrue(len(errors) > 0, f"{desc}: expected errors")

                        mock_downstream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
