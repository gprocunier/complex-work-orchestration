"""Unicode comparison forms retain mapped ASCII and both credential-name readings."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core import outbound_screen as screen  # noqa: E402


class OutboundNormalizationTests(unittest.TestCase):
    def test_unmapped_ascii_is_unchanged_including_controls(self):
        for code in range(128):
            with self.subTest(code=code):
                self.assertEqual(screen._skeleton(chr(code), {}), chr(code))

    def test_mapped_ascii_and_unicode_keep_both_confusable_stages(self):
        cases = [('a', {'a': 'b', 'b': 'c'}, 'c'),
                 ('x', {'x': 'ﬃ', 'f': 'F', 'i': 'I'}, 'FFI'),
                 ('A', {'A': 'a\u0301', 'a': 'b'}, 'b'),
                 ('x', {'x': '\u200bA', 'A': 'Z'}, 'Z'),
                 ('ﬃ', {'f': 'F', 'i': 'I'}, 'FFI'), ('K', {}, 'K'), ('é', {}, 'e'),
                 ('ab', {'a': 'x'}, 'xb'), ('', {'': 'x'}, 'x')]
        for value, mapping, expected in cases:
            with self.subTest(value=value, mapping=mapping):
                self.assertEqual(screen._skeleton(value, mapping), expected)

    def test_unsplit_split_and_phrase_readings_preserve_their_contracts(self):
        detector = screen._Detector(screen._rules())
        name = 'ＤＢPassword2_SeedPhrases'
        self.assertEqual(detector.name_components(name), ['dbpassword2', 'seedphrases'])
        self.assertEqual(detector.name_parts(name), ['db', 'password', '2', 'seed', 'phrases'])
        self.assertEqual(detector.name_readings(name), (['dbpassword2', 'seedphrases'], ['db', 'password', '2', 'seed', 'phrases']))
        self.assertTrue(detector.secret_name(name))
        self.assertTrue(detector.phrase_name(name))
        self.assertTrue(detector.secret_name('RecoveryPhrase'))
        self.assertTrue(detector.phrase_name('RecoveryPhrase'))
        self.assertEqual(detector.name_readings('compass_spin'), (['compass', 'spin'], ['compass', 'spin']))
        self.assertFalse(detector.secret_name('compass_spin'))
        self.assertFalse(detector.phrase_name('compass_spin'))
