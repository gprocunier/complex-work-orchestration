"""Independent stage consumer fixtures; synthetic transaction authority only.

The validation subprocess is real. Synthetic transaction/closure records here
exercise consumer decisions, not live qualification or historical containment.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from threading import RLock
from types import SimpleNamespace
import unittest

from tests.test_checked_command import ROOT,spec
from cwo_core.checked_command import execute_checked_command
from cwo_core.native_pool_transaction import execution_authoritative_bead_sha256
from cwo_core.stage_completion import consume,CompletionError,canonical
from cwo_core.stage_evidence import StageEvidenceBinding,pinned,read,StageEvidenceError
import cwo_core.checked_command as checked
import cwo_core.native_pool_transaction as transaction


class StageConsumerTests(unittest.TestCase):
    def setUp(self):
        audit_directory = ROOT / '.orchestration-audit'
        audit_directory.mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(prefix='cwo-stage-fixture-',dir=audit_directory)
        self.addCleanup(self.tmp.cleanup);self.directory=Path(self.tmp.name)
        self.files={}
        self.issue={'id':'synthetic-stage','title':'Toy consumer proof','status':'closed',
            'assignee':None,'labels':[],'dependencies':[],'metadata':{}}
        self.baseline=self.directory/'source.txt';self.baseline.write_text('unchanged')
        self.pin(self.baseline)
        for p in (Path(checked.__file__),Path(transaction.__file__),Path(__file__).resolve()):self.pin(p)
        self.guard_action=lambda:None
        self.guard_calls=0
        self.show_calls=0
        def guard():
            self.guard_calls+=1;self.guard_action()
        def show(root,database,bead):
            self.show_calls+=1;return copy.deepcopy(self.issue)
        self.registry=SimpleNamespace(completion_reader_key=lambda *a:'independent-native-stage-proof:v1',
            consumed={('toy','primary')},guard=guard)
        self.boundary=SimpleNamespace(__file__=str(Path(__file__).resolve()),show=show)
        command=spec(str(self.directory),command_id='real-toy-check',mode='python-source',argv=[],
            source="assert 'unchanged' == open('source.txt').read()\n")
        result=execute_checked_command(command)
        self.assertEqual(result['execution_status'],'passed')
        command_path=self.write('check-spec.json',command)
        receipt_path=self.write('check-receipt.json',result)
        txn_path=self.write('transaction.json',{'accepted':True,'state':'ACCEPTED',
            'transaction_id':'synthetic-transaction','plan_sha256':'a'*64})
        physical_path=self.write('physical.json',{'all_contained':True,'transaction_id':'synthetic-transaction'})
        closure_path=self.write('closure.json',{'kind':'controller-observed-native-stage-closure:v1',
            'transaction_id':'synthetic-transaction','bead_id':'synthetic-stage','all_contained':True,
            'supervisor_closed':True,'diagnostic_pending':0,'original_physical_proof_paths':[physical_path]})
        self.row={'owner':'toy','slot':'primary','role':'product','obligations':['check-content'],
            'proof_path':str(self.directory/'proof.json'),'proof_sha256':''}
        recipe=dict(self.row,unit='toy-stage',bead_id='synthetic-stage',segment_id='synthetic-segment',
            write_paths=['source.txt'],validation_specs={'content':command_path},
            baseline_files={str(self.baseline):self.files[str(self.baseline)]},
            transaction_id='synthetic-transaction',plan_sha256='a'*64,
            closed_bead_projection_sha256=execution_authoritative_bead_sha256(self.issue))
        recipe.pop('proof_sha256')
        adjudication={
            'kind':'controller-sol-private-stage-adjudication:v1','unit':'toy-stage','owner':'toy',
            'slot':'primary','role':'product','decision':'accepted-private-stage-only',
            'full_route_accepted':False,'transaction_result_sha256':self.files[txn_path],
            'containment_sha256':self.files[closure_path],
            'physical_proof_pins':{physical_path:self.files[physical_path]},
            'obligations':['check-content'],'scope_verified':True,'validation_verified':True,
            'closure_verified':True,'baseline_verified':True}
        adj_path=self.write('adjudication.json',adjudication)
        proof={'kind':'controller-private-native-stage-proof:v1','unit':'toy-stage','owner':'toy',
            'slot':'primary','role':'product','decision':'accepted-private-stage-only',
            'full_route_accepted':False,'transaction_result_path':txn_path,'containment_path':closure_path,
            'adjudication_path':adj_path,'validation_receipts':{'content':receipt_path},
            'postimage':{},'bead_id':'synthetic-stage'}
        self.write('proof.json',proof)
        self.row['proof_sha256']=self.files[self.row['proof_path']]
        recipes=self.write('recipes.json',{'kind':'controller-closed-family-completion-recipes:v1',
            'recipes':{'toy-stage':recipe}})
        self.binding=StageEvidenceBinding(ROOT,{'files':self.files,
            'economic_completion_recipe_path':recipes,'database':str(self.directory/'toy-db')},
            self.boundary,RLock())

    def pin(self,path):
        self.files[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    def write(self,name,value):
        p=self.directory/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');self.pin(p);return str(p)
    def run_consumer(self):
        return consume(self.binding,self.registry,'toy-stage',self.row)

    def test_positive_through_actual_shared_consumer_and_checked_child(self):
        self.assertTrue(self.run_consumer())
        self.assertEqual(self.guard_calls,1);self.assertEqual(self.show_calls,1)

    def test_guard_reentrant_bead_scope_drift_is_not_accepted(self):
        self.guard_action=lambda:self.issue.update(acceptance_criteria='changed')
        with self.assertRaisesRegex(CompletionError,'final-bead-scope-drift'):
            self.run_consumer()

    def test_guard_reentrant_source_drift_is_not_accepted(self):
        self.guard_action=lambda:self.baseline.write_text('drift')
        with self.assertRaises(CompletionError):self.run_consumer()

    def test_late_reader_changed_pin_rejected(self):
        def show(*args):
            self.baseline.write_text('drift-after-registry-check')
            return copy.deepcopy(self.issue)
        self.boundary.show=show
        with self.assertRaises(CompletionError):self.run_consumer()

    def test_completed_transport_is_not_sufficient(self):
        self.write('transaction.json',{'accepted':False,'state':'CONTAINED',
            'transaction_id':'synthetic-transaction','plan_sha256':'a'*64})
        with self.assertRaises(CompletionError):self.run_consumer()

    def test_owned_bead_must_be_closed_and_unassigned(self):
        for changes in ({'status':'open'},{'assignee':'somebody'}):
            with self.subTest(changes=changes):
                original=copy.deepcopy(self.issue);self.issue.update(changes)
                with self.assertRaisesRegex(CompletionError,'owned-bead-not-closed'):self.run_consumer()
                self.issue=original

    def test_receipt_boolean_number_confusion_rejected(self):
        data=json.loads((self.directory/'check-receipt.json').read_text());data['exit_code']=False
        self.write('check-receipt.json',data)
        with self.assertRaisesRegex(CompletionError,'checked-validation'):self.run_consumer()

    def test_missing_or_unknown_containment_rejected(self):
        data=json.loads((self.directory/'closure.json').read_text());data['all_contained']=None
        self.write('closure.json',data)
        with self.assertRaisesRegex(CompletionError,'owned-closure'):self.run_consumer()

    def test_symlink_and_outside_inventory_are_denied(self):
        alias=self.directory/'alias';alias.symlink_to(self.baseline)
        with self.assertRaises(StageEvidenceError):pinned(self.binding,str(alias))
        with self.assertRaises(StageEvidenceError):read(self.binding,str(self.directory/'not-pinned'))

    def test_valid_second_consumer_has_no_extra_effectful_observer(self):
        self.assertTrue(self.run_consumer());self.assertTrue(self.run_consumer())
        self.assertEqual(self.guard_calls,2);self.assertEqual(self.show_calls,2)
