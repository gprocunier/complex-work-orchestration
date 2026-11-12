"""M3: real environment overrides cannot replace default host quota/history."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

PROBE = r'''
from contextlib import redirect_stdout,redirect_stderr
from dataclasses import replace
from io import StringIO
import json,os,sys,tempfile
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'scripts')]
from cwo_core import audit,host_records,execution_status_report
import import_execution_telemetry as telemetry
import render_execution_status_report as status
legacy=Path(os.environ['CWO_AUDIT_FILE'])
store=host_records.HostRecordStore.for_tests(legacy.parent/'host',limits=replace(host_records.RecordLimits(),max_events=2))
with host_records.using_test_store(store):
 limit=audit.load_contracting_controls()['quota_policy']['external_manual_dispatches_per_epic']
 for i in range(limit):
  store.record_audit_event(dict(event_type='manual_dispatch',dispatch_id='EXAMPLE-'+str(i),quota_event_type='external_manual_dispatch',epic_id='EXAMPLE-scope',executor_external=True))
 before={str(p.relative_to(store.state_root)):p.read_bytes().hex() for p in store.state_root.rglob('*') if p.is_file()}
 refused=False
 try:audit.enforce_contracting_quota('EXAMPLE-scope','external_reasoner','external-contract')
 except SystemExit:refused=True
 after={str(p.relative_to(store.state_root)):p.read_bytes().hex() for p in store.state_root.rglob('*') if p.is_file()}
 result=dict(limit=limit,quota_refused=refused,quota_refusal_zero_write=before==after,
  count=audit.count_audit_events('external_manual_dispatch','EXAMPLE-scope',True),
  iter_count=len(audit.iter_audit_events()),matching_count=len(audit.matching_audit_events(event_type='manual_dispatch')),
  verify_count=audit.verify_audit_log()['event_count'],status_count=len(execution_status_report.load_audit_events()))
 audit.record_audit_event({'event_type':'EXAMPLE-default-write'})
 sidecar=legacy.parent/'usage.json';sidecar.write_text(json.dumps({'dispatch_id':'EXAMPLE-0','input_tokens':3,'output_tokens':2}))
 with redirect_stdout(StringIO()),redirect_stderr(StringIO()):
  result['telemetry_exit']=telemetry.main(['--file',str(sidecar),'--json'])
 result['private_events_after_default_writes']=len(store.audit_events())
 result['legacy_created_by_defaults']=legacy.exists()
 with redirect_stdout(StringIO()) as rendered:
  result['render_exit']=status.main(['--format','json'])
 report=json.loads(rendered.getvalue())
 result['render_count']=report['source_counts']['audit_events']
 result['render_sources']=report['source_files']['audit_logs']
 result['configured_audit_file']=str(store.audit_file)
 private_before=store.audit_events()
 audit.record_audit_event({'event_type':'EXAMPLE-explicit-diagnostic'},legacy)
 result['explicit_diagnostic_count']=len(audit.iter_audit_events(legacy))
 result['explicit_diagnostic_kept_private_history']=store.audit_events()==private_before
 result['quota_after_diagnostic']=audit.count_audit_events('external_manual_dispatch','EXAMPLE-scope',True)
 print(json.dumps(result))
'''


class DefaultAuditAuthorityTests(unittest.TestCase):
    def test_fresh_process_env_cannot_reset_quota_or_default_reader_writer_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = dict(os.environ, CWO_AUDIT_FILE=str(Path(temporary)/'caller-legacy.jsonl'))
            completed = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE, str(ROOT)],
                                       env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result['quota_refused'], 'Configured quota history must guard real dispatch admission.')
        self.assertTrue(result['quota_refusal_zero_write'])
        for name in ('count','iter_count','matching_count','verify_count','status_count','quota_after_diagnostic'):
            with self.subTest(reader=name):
                self.assertEqual(result[name], result['limit'])
        self.assertEqual(result['telemetry_exit'], 0)
        self.assertEqual(result['render_exit'], 0)
        self.assertEqual(result['private_events_after_default_writes'], result['limit']+2)
        self.assertEqual(result['render_count'], result['limit']+2)
        self.assertEqual(result['render_sources'], [result['configured_audit_file']])
        self.assertFalse(result['legacy_created_by_defaults'])
        self.assertEqual(result['explicit_diagnostic_count'], 1)
        self.assertTrue(result['explicit_diagnostic_kept_private_history'])
