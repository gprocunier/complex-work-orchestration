"""Zero mutation classification is shared; eligibility is not dispatch authority."""
import copy
import unittest
from tests.test_native_work_sizing import _literal_command_payload
from cwo_core.work_sizing import evaluate_work_estimate,is_read_only_work_estimate
from prepare_native_worker import _read_only_work_plan


def semantic_review():
    raw=_literal_command_payload()
    raw['task_profile'].update(task_class='diagnosis',command_count=0,commands=[],read_context_count=9)
    raw['task_profile'].pop('execution_contract',None)
    raw['context_manifest']=[{'path':f'context/{i}.py','selector':'file','purpose':'review',
        'bytes':20,'sha256':'a'*64} for i in range(9)]
    raw['semantic_estimate'].update(expected_context_reads=9,expected_mutations=0,
        read_to_mutation_ratio=9,estimated_diff_p50=0,estimated_diff_p90=0,
        behavioral_changes=0,state_machine_changes=0,schema_changes=0)
    return raw


class SemanticReadonlyContractTests(unittest.TestCase):
    def test_nine_context_review_is_semantic_and_readonly_without_mutations(self):
        result=evaluate_work_estimate(semantic_review())
        self.assertEqual(result['fit_mode'],'semantic')
        self.assertNotIn('semantic-read-mutation-split-trigger',result['hard_gate_reasons'])
        self.assertTrue(is_read_only_work_estimate(result))
        self.assertTrue(_read_only_work_plan(result))

    def test_ratio_consistent_contradictory_mutation_is_rejected_at_intended_check(self):
        raw=semantic_review();raw['semantic_estimate']['expected_mutations']=1
        # nine reads / one mutation remains ratio-consistent; this is NOT a malformed ratio fixture.
        result=evaluate_work_estimate(raw)
        self.assertEqual(result['route'],'architect')
        self.assertIn('source_mutation_count must equal semantic_estimate.expected_mutations',
            result['fit_evidence']['contradictions'])
        self.assertFalse(is_read_only_work_estimate(result))

    def test_write_capable_commands_do_not_obtain_readonly_permission(self):
        for argv in (["git","diff","--output","x"],["python","-m","unittest","arbitrary_module"],
                     ["git","status","--short",";","touch","x"],[],None,["git",{}]):
            with self.subTest(argv=argv):
                raw=semantic_review();raw['task_profile'].update(command_count=1,commands=[{'argv':argv}])
                try:result=evaluate_work_estimate(raw)
                except ValueError:continue
                self.assertFalse(is_read_only_work_estimate(result))
                self.assertFalse(_read_only_work_plan(result))

    def test_post_evaluation_tampering_is_not_a_readonly_contract(self):
        result=evaluate_work_estimate(semantic_review())
        for key,value in [('write_paths',['x']),('task_profile',None),('semantic_estimate',[]),
                          ('aggregate_allowance',{'runtime_seconds_hard':False})]:
            changed=copy.deepcopy(result);changed[key]=value
            self.assertFalse(is_read_only_work_estimate(changed))
