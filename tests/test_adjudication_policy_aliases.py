import dataclasses
import json,sys,unittest
from unittest.mock import patch
sys.path.insert(0,'scripts')
from tests.test_adjudication_binding import FixtureProducer
from tests.test_policy_current_effects import current_policy
from cwo_core import adjudication_binding as b,policy
from cwo_core import adjudication_source as source
from cwo_core.policy_schema import policy_document_errors
from tests.test_adjudication_source import SourceFixture
import tests.test_source_hold_clearance as evidence_cases
class PolicyAndAlias(unittest.TestCase):
 def test_cache_cleared_policy_refusals_return_unresolved_at_every_boundary(self):
  for kind in ['schema','top-level']:
   for boundary in ['prepare','synthesis','status']:
    with self.subTest(kind=kind,boundary=boundary),current_policy() as home:
     f=FixtureProducer(home);prepared=f.prepare();p=home/'policy/synthesis-policy.yaml';value=json.loads(p.read_bytes());value['default_pattern']=False
     p.write_text(json.dumps(value) if kind=='schema' else '[]');policy.clear_policy_cache()
     try:
      result=f.prepare() if boundary=='prepare' else (b.synthesis_preparation if boundary=='synthesis' else b.status_preparation)(prepared,f.context)
     except SystemExit as exc:result=exc
     self.assertNotIsInstance(result,BaseException,'expected loader refusal escaped unresolved interface')
     out=b.status_preparation(result,f.context) if boundary=='prepare' else result
     self.assertFalse(out['inert_valid']);self.assertIsNone(out['decision']);self.assertEqual(out['resolved_findings'],[]);self.assertEqual(set(out['remaining_holds']),set(f.result['hold_reasons']))
 def test_equivalent_duplicate_support_paths_refuse_before_support_io(self):
  for names in [('support.json','./support.json'),('sub/support.json','sub//support.json')]:
   with self.subTest(names=names),current_policy() as home:
    f=FixtureProducer(home);raw=f.support[0].raw
    if names[0].startswith('sub/'):(home/'sub').mkdir();(home/'sub/support.json').write_bytes(raw)
    item=f.record['supporting_evidence'][0];f.record['supporting_evidence']=[dict(item,artifact=name) for name in names];f.support=tuple(b.SupportObservation(name,f.finding,raw) for name in names)
    with patch.object(b,'read_support',wraps=b.read_support) as reader:prepared=f.prepare()
    self.assertFalse(prepared.inert_valid,'two spellings of the same support were accepted');self.assertEqual(reader.call_count,0)
 def test_single_equivalent_path_remains_a_valid_fixture_positive(self):
  with current_policy() as home:
   f=FixtureProducer(home);f.record['supporting_evidence'][0]['artifact']='./support.json';f.support=(b.SupportObservation('./support.json',f.finding,f.support[0].raw),)
   prepared=f.prepare();self.assertTrue(prepared.inert_valid,prepared.errors);self.assertIn(f.finding,prepared.resolved_findings)

class PolicyIdentity(unittest.TestCase):
    def mutate_policy(self, name, field):
        path = policy.POLICY_DIR / (name + '.yaml')
        original = path.read_bytes()
        document = json.loads(original)
        if field == 'version':
            document['version'] = True
        elif field == 'provider':
            document['providers']['internal_codex']['may_primary'] = 1
        else:
            document['boundaries']['redacted-packet']['allows_external'] = 1
        self.assertTrue(policy_document_errors(name + '.yaml', document))
        path.write_bytes(b._json(document))
        return path, original

    def current_policy_snapshot(self):
        documents = {}
        for name in b.POLICIES:
            raw = (policy.POLICY_DIR / (name + '.yaml')).read_bytes()
            documents[name] = {'raw_sha256': b._sha(raw), 'value': json.loads(raw)}
        return b._json(documents)

    def test_numeric_policy_alias_cannot_supply_current_source_observation(self):
        for field in ('version', 'provider'):
            with self.subTest(field=field), current_policy() as home:
                fixture = SourceFixture(home)
                valid = source.prepare_source(fixture.source, fixture.context, fixture.record,
                    home, observed_support=fixture.support)
                self.assertTrue(source.consume_source(valid, fixture.context, home)['source_valid'])
                self.mutate_policy('provider-registry', field)
                with self.assertRaisesRegex(ValueError, 'policy cache/bytes mismatch'):
                    source.observe_source(home, fixture.path, fixture.raw_return, fixture.context)

    def test_numeric_policy_alias_cannot_supply_qualified_evidence_use(self):
        for name, field in (('provider-registry', 'version'), ('provider-registry', 'provider'),
                            ('share-boundaries', 'boundary')):
            with self.subTest(policy=name, field=field):
                case = evidence_cases.QualifiedEvidenceUseTests()
                try:
                    case.setUp()
                    valid = case.use(case.issue()).projection()
                    self.assertTrue(valid['affected_accepted_for_use'])
                    path, _ = self.mutate_policy(name, field)
                    observed = case.control.observation
                    # The fake pinned control declares the exact current bytes.
                    # Refusal must come from current policy validation, not an
                    # unrelated stale digest or a duplicate permit identity.
                    observed = dataclasses.replace(observed,
                        policy_bytes=self.current_policy_snapshot(),
                        boundary_policy_bytes=(path.read_bytes() if field == 'boundary'
                            else observed.boundary_policy_bytes))
                    control = evidence_cases.FixedExampleAdjudicationControl(observed)
                    broker = evidence_cases.qualified.QualifiedAdjudicationBroker(case.home, control)
                    with self.assertRaisesRegex(ValueError, 'policy cache/bytes mismatch'):
                        broker.issue('EXAMPLE_CONTROL_NUMERIC_ALIAS')
                    self.assertEqual(broker._issued, {})
                    self.assertEqual(observed.evaluation_bytes, case.control.observation.evaluation_bytes)
                finally:
                    case.doCleanups()


if __name__ == "__main__":
    unittest.main()
