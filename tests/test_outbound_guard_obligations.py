"""Parser/privacy witnesses: each guard is load-bearing at its own boundary."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cwo_core import outbound_screen as screen  # noqa: E402


class OutboundGuardObligationTests(unittest.TestCase):
    def send(self, payload, opener, *, content_type='text/plain'):
        body = payload.encode() if isinstance(payload, str) else payload
        request = screen.screen_request('POST', 'https://example.invalid/v1/models', [], body,
                                        surface='fake send', content_type=content_type)
        return opener.open(request)

    def test_F9_0553201f82f7983c_direct_json_depth_and_zero_send_boundary(self):
        for limit in (0, 1, 3):
            with self.subTest(limit=limit):
                allowed = '[' * limit + 'true' + ']' * limit
                expected = True
                for _ in range(limit):
                    expected = [expected]
                self.assertEqual(screen._JsonReader(screen._View('raw', allowed), limit).parse(), expected)
                deep = '[' + allowed + ']'
                with self.assertRaises(screen._TooDeep):
                    screen._JsonReader(screen._View('raw', deep), limit).parse()
                opener = Mock()
                with patch.dict(screen._rules()['limits'], {'max_json_depth': limit}):
                    with self.assertRaises(screen.OutboundRefused):
                        self.send(deep, opener, content_type='application/json')
                    opener.open.assert_not_called()
                    self.assertIs(self.send(allowed, opener, content_type='application/json'), opener.open.return_value)
                    opener.open.assert_called_once()

    def test_F9_9063adaede9ed45e_only_identifier_subscript_is_code(self):
        detector = screen._Detector(screen._rules())
        code, data = '[lookup["api_key"]]', '[lookup["hunter2!"]]'
        self.assertEqual(detector.structure(code, 0), ([], len(code)))
        leaves, end = detector.structure(data, 0)
        self.assertEqual(end, len(data))
        self.assertEqual(leaves, [(data.index('hunter2!'), data.index('hunter2!') + len('hunter2!'), True, 'hunter2!')])
        opener = Mock()
        payload = 'password=' + data
        finding = screen.screen_outbound(payload, surface='subscript scan').findings
        self.assertIn(('assignment', payload.index('hunter2!'), payload.index('hunter2!') + len('hunter2!')),
                      [(row.rule, row.start, row.end) for row in finding])
        with self.assertRaises(screen.OutboundRefused):
            self.send(payload, opener)
        opener.open.assert_not_called()
        self.assertIs(self.send('password=' + code, opener), opener.open.return_value)
        opener.open.assert_called_once()

    def test_F9_e0010d27f46fffdd_punctuation_is_not_a_word_like_entropy_exemption(self):
        token = 'Ab3+De4/Gh5+Jk6/Mn7+Pq8/Rs9+Tu0'
        benign = 'bounded-model-version2-document'
        self.assertFalse(screen._Detector.word_like(token))
        self.assertTrue(screen._Detector.word_like(benign))
        self.assertIn('entropy', {row.rule for row in screen.screen_outbound(token, surface='entropy scan').findings})
        opener = Mock()
        with self.assertRaises(screen.OutboundRefused):
            self.send(token, opener)
        opener.open.assert_not_called()
        self.assertIs(self.send(benign, opener), opener.open.return_value)
        opener.open.assert_called_once()

    def test_F9_c830a071fd42e5b9_json_window_charge_precedes_decoder(self):
        document = '{"a":1}'
        for budget, permitted in ((len(document) - 1, False), (len(document), True)):
            with self.subTest(budget=budget):
                state = screen._Screen(screen._rules(), len(document))
                state.json_budget, state.json_examined = budget, 0
                decoder = Mock(wraps=json.JSONDecoder())
                state._DECODER = decoder
                if permitted:
                    self.assertEqual(state._json_end(document, 0), len(document))
                    decoder.raw_decode.assert_called_once_with(document)
                    self.assertEqual(state.json_examined, len(document))
                else:
                    with self.assertRaises(screen._OverBudget):
                        state._json_end(document, 0)
                    decoder.raw_decode.assert_not_called()
                    self.assertEqual(state.json_examined, 0)
        opener = Mock()
        with patch.multiple(screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=0):
            with self.assertRaises(screen.OutboundRefused):
                self.send('Config: ' + document, opener)
        opener.open.assert_not_called()
        self.assertIs(self.send('Config: ' + document, opener), opener.open.return_value)
        opener.open.assert_called_once()

    def test_F9_d0f2b653efc18d01_nested_string_charge_precedes_structural_parse(self):
        document = '{"a":1}'
        for budget, permitted in ((len(document) - 1, False), (len(document), True)):
            with self.subTest(budget=budget):
                state = screen._Screen(screen._rules(), len(document))
                state.json_budget, state.json_examined = budget, 0
                string = screen._JsonString(screen._View('raw', document))
                with patch.object(screen, '_parse_json', wraps=screen._parse_json) as parse:
                    state._scan_string(string, 0, 64)
                if permitted:
                    parse.assert_called_once()
                    self.assertEqual(state.json_examined, len(document))
                    self.assertEqual(state.findings, {})
                else:
                    parse.assert_not_called()
                    self.assertEqual(state.json_examined, 0)
                    self.assertIn('json-unreadable', {row.rule for row in state.findings.values()})
        opener = Mock()
        nested = json.dumps(document)
        with patch.multiple(screen._Screen, JSON_EXAMINED_PER_CHARACTER=0, JSON_EXAMINED_ALLOWANCE=0):
            with self.assertRaises(screen.OutboundRefused):
                self.send(nested, opener, content_type='application/json')
        opener.open.assert_not_called()
        self.assertIs(self.send(nested, opener, content_type='application/json'), opener.open.return_value)
        opener.open.assert_called_once()
