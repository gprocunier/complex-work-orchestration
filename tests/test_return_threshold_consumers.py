"""Real current-policy files, direct language consumer and conservative decisions."""
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from cwo_core.return_language import analyze_return_language
from cwo_core.return_risk import sabotage_thresholds, malpractice_thresholds
from cwo_core.errors import CWOPolicyError
from cwo_core.policy_schema import PolicySchemaError
from tests.test_policy_current_effects import current_policy


class ThresholdConsumerTests(unittest.TestCase):
    def test_language_consumer_refuses_out_of_order_current_policy(self):
        def mutate(document):
            document['sabotage_policy']['thresholds']['architect_escalation'] = 10
        with current_policy('contracting-controls', mutate):
            with self.assertRaises(CWOPolicyError):
                analyze_return_language('ordinary prose', expected_language='en')

    def test_shipped_policy_positive_and_values_unchanged(self):
        with current_policy():
            self.assertEqual(sabotage_thresholds(), {'review':20,'architect_escalation':35,'quarantine':50})
            self.assertEqual(malpractice_thresholds(), {'review':25,'reject':60})
            result = analyze_return_language('ordinary English prose', expected_language='en')
            self.assertEqual(result['return_language_status'], 'clear')


class CurrentPolicyMatrixTests(unittest.TestCase):
    def assert_policy_refusal(self, consumer, family, case):
        # Capture the legacy CLI exception family, then require its precise
        # policy class: an unrelated SystemExit must never satisfy this test.
        with self.assertRaises((CWOPolicyError, SystemExit)) as caught:
            consumer()
        expected_type = CWOPolicyError if case == 'wrong-order' else PolicySchemaError
        self.assertIs(type(caught.exception), expected_type)
        message = str(caught.exception)
        self.assertIn('policy/contracting-controls.yaml', message)
        diagnostic = {
            'missing-family': f"missing required field '{family}'",
            'missing-thresholds': f"$.{family}: missing required field 'thresholds'",
            'missing-value': f"$.{family}.thresholds: missing required field 'peer_review'",
            'string': f"$.{family}.thresholds.peer_review: expected integer, found string",
            'bool': f"$.{family}.thresholds.peer_review: expected integer, found boolean",
            'out-of-range': f"$.{family}.thresholds.peer_review: must be at least 1",
            'wrong-order': f"{family}.thresholds must increase in the order peer_review",
        }[case]
        self.assertIn(diagnostic, message)

    def test_real_policy_invalid_thresholds_refuse_at_each_family_consumer(self):
        for family, consumer in (('sabotage_policy', sabotage_thresholds),
                                 ('malpractice_policy', malpractice_thresholds)):
            for case in ('missing-family', 'missing-thresholds', 'missing-value',
                         'string', 'bool', 'out-of-range', 'wrong-order'):
                def mutate(document):
                    if case == 'missing-family':
                        del document[family]
                    elif case == 'missing-thresholds':
                        del document[family]['thresholds']
                    elif case == 'missing-value':
                        del document[family]['thresholds']['peer_review']
                    else:
                        document[family]['thresholds']['peer_review'] = {
                            'string':'20', 'bool':True, 'out-of-range':0, 'wrong-order':99,
                        }[case]
                consumers = [('family-helper', consumer)]
                if family == 'sabotage_policy':
                    consumers.append(('language', lambda: analyze_return_language(
                        'ordinary prose', expected_language='en')))
                # Separate subtests keep each direct consumer observable even
                # when another consumer has the wrong exception/diagnostic.
                for label, current in consumers:
                    with self.subTest(family=family, case=case, consumer=label):
                        with current_policy('contracting-controls', mutate):
                            self.assert_policy_refusal(current, family, case)
