"""Test-only private-cursor applicability; fixtures grant no kernel or execution credit."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import selected_native_containment as selected

FIXTURE = Path(__file__).parent / 'fixtures/private-pid-cursor-write-eperm.json'


_MEASURED_PID_ENTRY = r'''
import sys,json
sys.path.insert(0,sys.argv[1])
import selected_native_containment as s
def observe(stage):
 try:
  record={'stage':stage,**s._pid_reuse_security_state()}
  print('Private PID security '+json.dumps(record,sort_keys=True),file=sys.stderr,flush=True)
 except BaseException:
  pass
original=s._drop_reuse_inheritance
def measured_clear(namespaces):
 observe('PRE_CLEAR')
 original(namespaces)
 observe('POST_CLEAR')
s._drop_reuse_inheritance=measured_clear
observe('ENTRY')
s._pid_reuse_entry(sys.argv[2:])
'''

_PRIVATE_CURSOR_SOURCE_SHA256 = '71bcfc1ec3d03e89bad7208b5bc30f428d901f30d416bdefe53ef28f39bd8e5b'
_PRIVATE_CURSOR_LOCATIONS = [
    {'file': 'selected_native_containment.py', 'function': '_pid_reuse_entry', 'line': 1092},
    {'file': 'selected_native_containment.py', 'function': '_reuse_case', 'line': 986},
    {'file': 'selected_native_containment.py', 'function': '_reuse_sentinel', 'line': 955},
    {'file': 'selected_native_containment.py', 'function': '_write_private_pid_cursor', 'line': 841},
]
_PRIVATE_CURSOR_CAPS = {'CapEff': '000001ffffffffff', 'CapPrm': '000001ffffffffff',
                        'CapInh': '0000000000000000', 'CapAmb': '0000000000000000'}


def _original_cursor_refusal(report, failure):
    if type(report) is not dict or set(report) != {'error', 'locations', 'driver_context'}:
        return False
    return (type(failure) is selected.SelectedProbeError
            and str(failure) == 'Private PID reuse refused: ' + json.dumps(report, sort_keys=True)
            and report['error'] == 'PermissionError: [Errno 1] Operation not permitted'
            and type(report['locations']) is list
            and all(type(row) is dict and type(row.get('line')) is int for row in report['locations'])
            and report['locations'] == _PRIVATE_CURSOR_LOCATIONS
            and hashlib.sha256(Path(selected.__file__).read_bytes()).hexdigest() == _PRIVATE_CURSOR_SOURCE_SHA256)


def _original_cursor_security(failure):
    # Read only the already captured stderr note; never run another cursor probe.
    notes = getattr(failure, '__notes__', ())
    prefix = 'Ownership cleanup: Diagnostic child stderr: '
    if len(notes) != 1 or not notes[0].startswith(prefix):
        return False
    lines = notes[0][len(prefix):].splitlines()
    if len(lines) != 3 or any(not line.startswith('Private PID security ') for line in lines):
        return False
    try:
        records = [json.loads(line[len('Private PID security '):]) for line in lines]
    except json.JSONDecodeError:
        return False
    inherited = {name: '000001ffffffffff' for name in _PRIVATE_CURSOR_CAPS}
    expected = [
        {'stage': 'ENTRY', 'capabilities': inherited, 'parent_death_signal': 0, 'securebits': 0},
        {'stage': 'PRE_CLEAR', 'capabilities': inherited, 'parent_death_signal': 9, 'securebits': 0},
        {'stage': 'POST_CLEAR', 'capabilities': _PRIVATE_CURSOR_CAPS, 'parent_death_signal': 9, 'securebits': 0},
    ]
    return json.dumps(records, sort_keys=True) == json.dumps(expected, sort_keys=True)


def _original_cursor_namespaces(owner, context, boundary):
    facts, user = context['namespaces'], boundary.get('pid_owner_user_namespace')
    if type(facts) is not dict or set(facts) != {'pid', 'user', 'mnt', 'net'}:
        return False
    if type(user) is not tuple or len(user) != 2 or any(type(value) is not int or value <= 0 for value in user):
        return False
    reported_owner = context['pid_owner_user_namespace']
    if (type(reported_owner) is not list or any(type(value) is not int for value in reported_owner)
            or reported_owner != list(user) or facts['user'] != 'user:[' + str(user[1]) + ']'):
        return False
    host = owner.host_namespaces
    return (set(host) == set(facts) and all(
        type(value) is str and value.startswith(kind + ':[') and value.endswith(']')
        and value[len(kind) + 2:-1].isdigit() and value != host[kind] for kind, value in facts.items()))


def _original_cursor_parent(boundary, parent):
    pids = [boundary.get(name) for name in ('namespace_init', 'bwrap_pid', 'watchdog_pid')]
    if any(type(pid) is not int or pid <= 1 for pid in pids) or len(set(pids)) != 3:
        return False
    if type(parent) is not tuple or len(parent) != 2 or type(parent[0]) is not int:
        return False
    identity = parent[1]
    if (type(identity) is not tuple or len(identity) != 4
            or any(type(identity[index]) is not int for index in (0, 2, 3))):
        return False
    return (identity[0] == boundary['bwrap_pid'] and identity[2] == boundary['watchdog_pid']
            and type(identity[1]) is str and bool(identity[1])
            and type(boundary.get('bwrap_start_ticks')) is int and boundary['bwrap_start_ticks'] > 0
            and identity[3] == boundary['bwrap_start_ticks'])


def _original_cursor_boundary(owner, report, proof):
    boundary, context = proof.get('boundary'), report['driver_context']
    keys = {'namespaces', 'namespace_init', 'watchdog_pid', 'private_proc',
            'bwrap_pid', 'bwrap_start_ticks', 'pid_owner_user_namespace'}
    if type(boundary) is not dict or set(boundary) != keys or type(context) is not dict:
        return False
    expected = {'uid': os.getuid(), 'gid': os.getgid(), 'capabilities': _PRIVATE_CURSOR_CAPS,
                'parent_death_signal': 9, 'securebits': 0, 'namespaces': boundary.get('namespaces'),
                'pid_owner_user_namespace': context.get('pid_owner_user_namespace')}
    if (json.dumps(context, sort_keys=True) != json.dumps(expected, sort_keys=True)
            or boundary.get('private_proc') is not True or type(owner.boundary) is not dict
            or type(owner.boundary.get('pid_owner_user_namespace')) is not tuple
            or json.dumps(owner.boundary, sort_keys=True) != json.dumps(boundary, sort_keys=True)):
        return False
    return (_original_cursor_namespaces(owner, context, boundary)
            and _original_cursor_parent(boundary, proof.get('parent')))


def _original_cursor_helpers(owner, metadata):
    versions = {'bwrap': ['bubblewrap 0.11.1'], 'python': ['Python 3.14.4'],
                'timeout': ['timeout (uutils coreutils) 0.10.0']}
    expected = {name: {'path': getattr(owner, name)[0], 'mode': '0o755', 'uid': 0, 'gid': 0,
                       'file_caps': {'errno': 61}, 'version': version} for name, version in versions.items()}
    if type(metadata) is not dict or set(metadata) != set(expected):
        return False
    if not all(type(row) is dict and type(row.get('version')) is list for row in metadata.values()):
        return False
    return json.dumps(metadata, sort_keys=True) == json.dumps(expected, sort_keys=True)


def _exited_cursor_watchdog(report, boundary):
    # An original wait-handle cleanup can confirm/reap a zombie whose exe link
    # disappeared before identity observation. This never grants signal authority.
    return (report.get('outcome') == 'identity-unavailable' and report.get('signals') == []
            and report.get('reason')
            == f"[Errno 2] No such file or directory: '/proc/{boundary['watchdog_pid']}/exe'")


def _original_cursor_cleanup(proof, boundary):
    for name, outcomes in (('owner_termination', {'already-exited', 'exited-before-signal', 'terminated', 'killed'}),
                           ('owner_close', {'closed'})):
        reports = proof.get(name)
        if type(reports) is not list or len(reports) != 1 or type(reports[0]) is not dict:
            return False
        report = reports[0]
        if (type(report.get('outcome')) is not str
                or (report['outcome'] not in outcomes
                    and not (name == 'owner_termination' and _exited_cursor_watchdog(report, boundary)))
                or type(report.get('child_pid')) is not int or report['child_pid'] != boundary['watchdog_pid']
                or report.get('registration_committed') is not True or report.get('child_exit_confirmed') is not True
                or report.get('child_reaped') is not True or report.get('receipt_available') is not False):
            return False
        if ((name == 'owner_close' and report.get('close_errors') != [])
                or report.get('close_errors', []) != []
                or {'close_error', 'cleanup_errors', 'retained_cleanup_errors'} & set(report)):
            return False
    return True


def _close_measured_pid_owner(owner, proof, close):
    """Observe only the original cleanup calls and return their reports unchanged."""
    controller = owner.controller
    if controller is None:
        close()
        proof['closed'] = True
        return
    terminate, finish = controller.terminate, controller.close
    proof['owner_termination'], proof['owner_close'] = [], []
    def measured_terminate(receipt, *args, **kwargs):
        report = terminate(receipt, *args, **kwargs)
        if receipt is proof.get('receipt'):
            proof['owner_termination'].append(copy.deepcopy(report))
        return report
    def measured_finish():
        report = finish()
        proof['owner_close'].append(copy.deepcopy(report))
        return report
    with patch.object(controller, 'terminate', measured_terminate), patch.object(controller, 'close', measured_finish):
        close()
    proof['closed'] = True


def _private_cursor_unsupported(owner, proof, metadata, failure):
    """A test applicability exception, after all original bounded cleanup finished."""
    reports = proof.get('reports')
    if (owner.package or set(proof) != {'reports', 'boundary', 'parent', 'promoted', 'closed',
                                               'controller', 'receipt', 'owner_termination', 'owner_close'}
            or type(reports) is not list or len(reports) != 1
            or not _original_cursor_refusal(reports[0], failure)):
        return None
    if not _original_cursor_security(failure) or not _original_cursor_boundary(owner, reports[0], proof):
        return None
    if not _original_cursor_helpers(owner, metadata) or not _original_cursor_cleanup(proof, proof['boundary']):
        return None
    if (set(owner.cleanup) - {'namespace_exited', 'accepted_output', 'namespace_kill', 'namespace_signal_exit_race'}
            or any(type(value) is not bool for value in owner.cleanup.values())
            or proof.get('promoted') is not True or proof.get('closed') is not True
            or owner.cleanup.get('namespace_exited') is not True or owner.cleanup.get('accepted_output') is not False
            or any(getattr(owner, name) is not None for name in
                   ('namespace_handle', '_quarantined_handle', '_parent_observation', 'controller', 'process'))):
        return None
    return ('Measured unsupported: os.write(/proc/sys/kernel/ns_last_pid) EPERM; actual host permission denial '
            '(individual policy rule unknown). Primitive PID-reuse positive assertions remain unperformed; '
            'no selected scope or qualification credit. ' + json.dumps({
                'report': reports[0], 'boundary': proof['boundary'], 'cleanup': owner.cleanup,
                'helpers': metadata, 'owner_termination': proof['owner_termination'][0],
                'owner_close': proof['owner_close'][0]}, sort_keys=True))


def _run_measured_pid_owner(owner):
    """Bounded observation only; retain every original refusal and cleanup path."""
    metadata = {}
    for name in ('timeout', 'bwrap', 'python'):
        executable = getattr(owner, name)[0]
        info = Path(executable).stat()
        try:
            capabilities = os.getxattr(executable, 'security.capability').hex()[:128]
        except OSError as failure:
            capabilities = {'errno': failure.errno}
        version = subprocess.run([executable, '--version'], capture_output=True, timeout=2, check=False)
        metadata[name] = {'path': executable, 'mode': oct(info.st_mode & 0o7777),
                          'uid': info.st_uid, 'gid': info.st_gid, 'file_caps': capabilities,
                          'version': version.stdout[:256].decode('utf-8', errors='replace').splitlines()[:1]}
    print('Private PID helpers: ' + json.dumps(metadata, sort_keys=True), flush=True)
    verify, namespace, close = owner._verify_result, owner._verify_namespace, owner.close
    proof = {'reports': []}
    def measured_namespace(payload, descriptor):
        namespace(payload, descriptor)
        proof['boundary'] = copy.deepcopy(owner.boundary)
        proof['parent'] = owner._parent_observation
        proof['controller'], proof['receipt'] = owner.controller, owner.receipt
    def measured_close():
        proof['promoted'] = (type(owner.namespace_handle) is int and owner.namespace_handle >= 0
                             and owner._quarantined_handle is None
                             and type(owner.boundary) is dict
                             and _original_cursor_parent(owner.boundary, owner._parent_observation)
                             and owner._parent_observation == proof.get('parent')
                             and json.dumps(owner.boundary, sort_keys=True)
                             == json.dumps(proof.get('boundary'), sort_keys=True)
                             and owner.controller is proof.get('controller') and owner.receipt is proof.get('receipt'))
        _close_measured_pid_owner(owner, proof, close)
    def measured_result(report):
        proof['reports'].append(report)
        verify(report)
        observation = selected.SelectedProbeError('Private PID transition observations')
        selected._note_child_stderr(owner.process, observation)
        print('\n'.join(getattr(observation, '__notes__', ())), flush=True)
    try:
        with patch.object(selected, '_PID_REUSE_ENTRY', _MEASURED_PID_ENTRY), \
                patch.object(owner, '_verify_result', measured_result), \
                patch.object(owner, '_verify_namespace', measured_namespace), \
                patch.object(owner, 'close', measured_close):
            return owner.run()
    except BaseException as failure:
        # owner.run has completed its finally, including every cleanup action.
        unsupported = _private_cursor_unsupported(owner, proof, metadata, failure)
        selected.owned._note(failure, 'Private PID helpers: ' + json.dumps(metadata, sort_keys=True))
        print('\n'.join(getattr(failure, '__notes__', ())), flush=True)
        if unsupported is not None:
            raise unittest.SkipTest(unsupported) from failure
        raise


class PrivatePidCIApplicabilityTests(unittest.TestCase):
    def fixture(self):
        data = json.loads(FIXTURE.read_text())
        report = data['report']
        # Unit replay rebases coordinates only; the fixture retains measured locations.
        report['locations'] = copy.deepcopy(_PRIVATE_CURSOR_LOCATIONS)
        boundary = {'namespaces': copy.deepcopy(report['driver_context']['namespaces']),
                    'pid_owner_user_namespace': tuple(report['driver_context']['pid_owner_user_namespace']),
                    'namespace_init': 6003, 'bwrap_pid': 6002, 'watchdog_pid': 6001,
                    'bwrap_start_ticks': 789, 'private_proc': True}
        owner = object.__new__(selected._PrivatePidReuseOwner)
        owner.package = ''
        owner.boundary = boundary
        owner.host_namespaces = {name: name + ':[EXAMPLE-host]' for name in boundary['namespaces']}
        owner.cleanup = {'namespace_exited': True, 'accepted_output': False}
        for name, metadata in data['helpers'].items():
            setattr(owner, name, (metadata['path'], (1, 2)))
        for name in ('namespace_handle', '_quarantined_handle', '_parent_observation', 'controller', 'process'):
            setattr(owner, name, None)
        failure = selected.SelectedProbeError('Private PID reuse refused: ' + json.dumps(report, sort_keys=True))
        stderr = ''.join('Private PID security ' + json.dumps(row, sort_keys=True) + '\n'
                         for row in data['security_records'])
        selected.owned._note(failure, 'Diagnostic child stderr: ' + stderr)
        child_facts = {'child_pid': 6001, 'registration_committed': True, 'child_exit_confirmed': True,
                       'child_reaped': True, 'receipt_available': False}
        proof = {'reports': [report], 'boundary': copy.deepcopy(boundary),
                 'parent': (37, (6002, 'EXAMPLE-bwrap', 6001, 789)), 'promoted': True, 'closed': True,
                 'controller': object(), 'receipt': object(),
                 'owner_termination': [{'outcome': 'already-exited', **child_facts}],
                 'owner_close': [{'outcome': 'closed', 'close_errors': [], **child_facts}]}
        return owner, proof, data['helpers'], failure

    def classify(self, owner, proof, metadata, failure):
        with patch.object(os, 'getuid', return_value=1001), \
                patch.object(os, 'getgid', return_value=1001):
            return _private_cursor_unsupported(owner, proof, metadata, failure)

    def refresh_failure(self, proof, failure):
        updated = selected.SelectedProbeError('Private PID reuse refused: ' + json.dumps(proof['reports'][0], sort_keys=True))
        updated.__notes__ = failure.__notes__[:]
        return updated

    def test_original_hosted_data_requires_independent_proof_and_reports_unperformed_scope(self):
        owner, proof, metadata, failure = self.fixture()
        reason = self.classify(owner, proof, metadata, failure)
        self.assertIn('os.write(/proc/sys/kernel/ns_last_pid) EPERM', reason)
        self.assertIn('actual host permission denial', reason)
        self.assertIn('positive assertions remain unperformed', reason)
        self.assertIn('no selected scope or qualification credit', reason)
        self.assertIn('"namespace_exited": true', reason)
        self.assertIn(json.dumps(proof['reports'][0], sort_keys=True), reason)
        for missing in ('reports', 'boundary', 'parent', 'promoted', 'closed', 'controller', 'receipt',
                        'owner_termination', 'owner_close'):
            with self.subTest(missing=missing):
                incomplete = {key: value for key, value in proof.items() if key != missing}
                self.assertIsNone(self.classify(owner, incomplete, metadata, failure))

    def test_wrong_error_syscall_errno_source_and_unknown_report_stay_failures(self):
        variants = [
            ('os.open', lambda report: report['locations'][-1].update(line=report['locations'][-1]['line'] - 4)),
            ('float-line', lambda report: report['locations'][-1].update(line=float(report['locations'][-1]['line']))),
            ('bool-line', lambda report: report['locations'][-1].update(line=True)),
            ('string-line', lambda report: report['locations'][-1].update(line=str(report['locations'][-1]['line']))),
            ('non-list-locations', lambda report: report.update(locations=tuple(report['locations']))),
            ('other-function', lambda report: report['locations'][-1].update(function='_drop_reuse_inheritance')),
            ('other-file', lambda report: report['locations'][-1].update(file='other.py')),
            ('other-caller', lambda report: report['locations'][1].update(function='_other_case')),
            ('missing-location', lambda report: report['locations'].pop()),
            ('wrong-errno', lambda report: report.update(error='PermissionError: [Errno 13] Permission denied')),
            ('other-operation', lambda report: report.update(error='OSError: [Errno 1] Operation not permitted')),
            ('child-cleanup-note', lambda report: report.update(error=report['error'] + 'Private PID-reuse cleanup: refused')),
            ('unknown-field', lambda report: report.update(diagnostic_error='Unknown')),
            ('missing-context', lambda report: report.pop('driver_context')),
            ('missing-error', lambda report: report.pop('error')),
            ('missing-locations', lambda report: report.pop('locations')),
            ('malformed-context', lambda report: report.update(driver_context=[])),
            ('unknown-locations', lambda report: report.update(locations='unknown')),
        ]
        for name, mutate in variants:
            with self.subTest(case=name):
                owner, proof, metadata, failure = self.fixture()
                mutate(proof['reports'][0])
                self.assertIsNone(self.classify(owner, proof, metadata, self.refresh_failure(proof, failure)))
        owner, proof, metadata, failure = self.fixture()
        with patch(__name__ + '._PRIVATE_CURSOR_SOURCE_SHA256', '0' * 64):
            self.assertIsNone(self.classify(owner, proof, metadata, failure))
        self.assertIsNone(self.classify(owner, proof, metadata, ValueError(str(failure))))
        proof['reports'] = []
        self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_old_capability_clearing_and_death_binding_defects_cannot_classify(self):
        for mutation in ('old-E-P-zero', 'post-clear-zero', 'pre-clear-death-zero', 'report-death-zero'):
            with self.subTest(regression=mutation):
                owner, proof, metadata, failure = self.fixture()
                if mutation == 'old-E-P-zero':
                    proof['reports'][0]['driver_context']['capabilities'].update(
                        CapEff='0000000000000000', CapPrm='0000000000000000')
                    failure = self.refresh_failure(proof, failure)
                elif mutation == 'report-death-zero':
                    proof['reports'][0]['driver_context']['parent_death_signal'] = 0
                    failure = self.refresh_failure(proof, failure)
                else:
                    records = json.loads(FIXTURE.read_text())['security_records']
                    if mutation == 'post-clear-zero':
                        records[2]['capabilities'].update(CapEff='0000000000000000', CapPrm='0000000000000000')
                    else:
                        records[1]['parent_death_signal'] = 0
                    failure.__notes__ = ['Ownership cleanup: Diagnostic child stderr: ' + ''.join(
                        'Private PID security ' + json.dumps(row) + '\n' for row in records)]
                self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_missing_malformed_unknown_security_and_helper_receipts_stay_failures(self):
        notes = [[], ['unknown'], ['Ownership cleanup: Diagnostic child stderr: Private PID security {bad}\n' * 3]]
        for malformed in notes:
            with self.subTest(notes=malformed):
                owner, proof, metadata, failure = self.fixture()
                failure.__notes__ = malformed
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        for field in ('capabilities', 'namespaces', 'pid_owner_user_namespace', 'uid', 'gid', 'securebits'):
            with self.subTest(missing=field):
                owner, proof, metadata, failure = self.fixture()
                proof['reports'][0]['driver_context'].pop(field)
                self.assertIsNone(self.classify(owner, proof, metadata, self.refresh_failure(proof, failure)))
        for name, value in (('mode', '0o4755'), ('file_caps', 'EXAMPLE-capability'),
                ('uid', 0.0), ('uid', False), ('gid', 0.0), ('gid', False),
                ('file_caps', {'errno': 61.0}), ('file_caps', {'errno': True}),
                ('path', '/EXAMPLE/python'), ('version', ['unknown']), ('version', ('Python 3.14.4',))):
            with self.subTest(helper_field=name):
                owner, proof, metadata, failure = self.fixture()
                metadata['python'][name] = value
                self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_uid_namespace_private_owner_and_original_parent_must_match(self):
        for field, value in (('uid', 9999), ('gid', 9999), ('securebits', False),
                ('uid', 1001.0), ('gid', 1001.0), ('parent_death_signal', 9.0), ('securebits', 0.0),
                ('uid', True), ('parent_death_signal', '9'),
                ('pid_owner_user_namespace', [5.0, 4026532261.0]),
                ('pid_owner_user_namespace', [5.0, 4026532261]),
                ('pid_owner_user_namespace', [5, 4026532261.0]),
                ('pid_owner_user_namespace', [True, 4026532261]),
                ('pid_owner_user_namespace', (5, 4026532261)),
                ('pid_owner_user_namespace', [5, 9999]), ('namespaces', [])):
            with self.subTest(context=field):
                owner, proof, metadata, failure = self.fixture()
                proof['reports'][0]['driver_context'][field] = value
                self.assertIsNone(self.classify(owner, proof, metadata, self.refresh_failure(proof, failure)))
        for field, value in (('unknown', True), ('private_proc', False), ('pid_owner_user_namespace', None),
                             ('pid_owner_user_namespace', 'unknown'), ('bwrap_start_ticks', 9999),
                             ('namespace_init', 6001), ('watchdog_pid', None)):
            with self.subTest(boundary=field, value=value):
                owner, proof, metadata, failure = self.fixture()
                proof['boundary'][field] = value
                owner.boundary = copy.deepcopy(proof['boundary'])
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        for index, value in ((0, 6002.0), (2, 6001.0), (3, 789.0), (0, True), (3, '789')):
            with self.subTest(parent_field=index, value=value):
                owner, proof, metadata, failure = self.fixture()
                identity = list(proof['parent'][1])
                identity[index] = value
                proof['parent'] = (37, tuple(identity))
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        for field, value in (('namespace_init', 6003.0), ('watchdog_pid', 6001.0),
                             ('bwrap_start_ticks', 789.0), ('private_proc', 1)):
            with self.subTest(current_boundary=field):
                owner, proof, metadata, failure = self.fixture()
                owner.boundary[field] = value
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        owner, proof, metadata, failure = self.fixture()
        owner.host_namespaces['pid'] = proof['boundary']['namespaces']['pid']
        self.assertIsNone(self.classify(owner, proof, metadata, failure))
        proof['parent'] = (37, (6002, 'EXAMPLE-bwrap', 9999, 789))
        self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_unconfirmed_or_failed_cleanup_never_becomes_a_skip(self):
        for field, value in (('namespace_exited', False), ('accepted_output', True), ('unknown', True),
                ('namespace_exited', 1), ('accepted_output', 0.0), ('namespace_kill', 1.0),
                ('namespace_signal_exit_race', 1), ('namespace_kill', 'true')):
            with self.subTest(cleanup=field):
                owner, proof, metadata, failure = self.fixture()
                owner.cleanup[field] = value
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        for name in ('namespace_handle', '_quarantined_handle', '_parent_observation', 'controller', 'process'):
            with self.subTest(retained=name):
                owner, proof, metadata, failure = self.fixture()
                setattr(owner, name, object())
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        for note in ('Private PID-reuse cleanup: secondary failure', 'Private PID-reuse cleanup: KeyboardInterrupt',
                     'Diagnostic stderr observation: unknown'):
            with self.subTest(secondary=note):
                owner, proof, metadata, failure = self.fixture()
                selected.owned._note(failure, note)
                self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_original_watchdog_exit_reap_and_error_free_close_reports_are_required(self):
        for name in ('owner_termination', 'owner_close'):
            for field, value in (('outcome', 'unknown'), ('outcome', []), ('child_pid', 9999),
                    ('child_pid', 6001.0), ('child_pid', True), ('child_pid', '6001'),
                    ('registration_committed', 1), ('child_exit_confirmed', 1.0), ('child_reaped', 1),
                    ('receipt_available', 0),
                    ('registration_committed', False), ('child_exit_confirmed', False), ('child_reaped', False),
                    ('receipt_available', True), ('close_errors', ['EXAMPLE failure']),
                    ('close_error', 'EXAMPLE failure'), ('cleanup_errors', ['EXAMPLE failure']),
                    ('retained_cleanup_errors', ['EXAMPLE failure'])):
                with self.subTest(report=name, field=field):
                    owner, proof, metadata, failure = self.fixture()
                    proof[name][0][field] = value
                    self.assertIsNone(self.classify(owner, proof, metadata, failure))
            required = {'outcome', 'child_pid', 'registration_committed', 'child_exit_confirmed',
                        'child_reaped', 'receipt_available'}
            if name == 'owner_close':
                required.add('close_errors')
            for missing in required:
                with self.subTest(report=name, missing=missing):
                    owner, proof, metadata, failure = self.fixture()
                    proof[name][0].pop(missing)
                    self.assertIsNone(self.classify(owner, proof, metadata, failure))
            for malformed in (None, [], [{}], ['unknown']):
                with self.subTest(report=name, malformed=malformed):
                    owner, proof, metadata, failure = self.fixture()
                    proof[name] = malformed
                    self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def test_historical_cleanup_states_do_not_acquire_skip_credit(self):
        for reason, exited, reaped in (
                ('The observed process has no valid live start identity.', True, True),
                ("[Errno 2] No such file or directory: '/proc/6001/exe'", False, False)):
            with self.subTest(reason=reason, exited=exited, reaped=reaped):
                owner, proof, metadata, failure = self.fixture()
                proof['owner_termination'][0].update(
                    outcome='identity-unavailable', signals=[], reason=reason)
                for name in ('owner_termination', 'owner_close'):
                    proof[name][0].update(child_exit_confirmed=exited, child_reaped=reaped,
                                          receipt_available=False)
                self.assertIsNone(self.classify(owner, proof, metadata, failure))
        owner, proof, metadata, failure = self.fixture()
        proof['owner_termination'][0].update(outcome='identity-unavailable', signals=[],
            reason="[Errno 2] No such file or directory: '/proc/6001/exe'")
        self.assertIsNotNone(self.classify(owner, proof, metadata, failure))

    def test_selected_package_scope_cannot_inherit_primitive_applicability(self):
        owner, proof, metadata, failure = self.fixture()
        owner.package = '/EXAMPLE/exact-selected-package'
        self.assertIsNone(self.classify(owner, proof, metadata, failure))

    def exercise_run(self, *, broken_cleanup=False, cleanup_report_error=False, regression=None, success=False):
        """Exercise original owner.run/finally with explicit unit-only fake IO."""
        owner, proof, metadata, failure = self.fixture()
        report = proof['reports'][0]
        if regression == 'old-E-P-zero':
            report['driver_context']['capabilities'].update(CapEff='0000000000000000', CapPrm='0000000000000000')
        if regression == 'old-death-zero':
            report['driver_context']['parent_death_signal'] = 0
        if regression == 'uid-float':
            report['driver_context']['uid'] = 1001.0
        if regression == 'death-float':
            report['driver_context']['parent_death_signal'] = 9.0
        if regression == 'line-float':
            report['locations'][-1]['line'] = float(report['locations'][-1]['line'])
        if regression == 'pid-owner-floats':
            report['driver_context']['pid_owner_user_namespace'] = [5.0, 4026532261.0]
        events = []
        owner._quarantined_handle = 38
        owner.namespace_handle = None
        owner._parent_observation = proof['parent']
        owner.cleanup = {'namespace_exited': False, 'accepted_output': False}
        owner.receipt = proof['receipt']
        controller = types.SimpleNamespace(terminate=Mock(return_value=proof['owner_termination'][0]),
                                           close=Mock(return_value=proof['owner_close'][0]))
        if cleanup_report_error:
            controller.close.return_value['close_errors'] = ['EXAMPLE returned close failure']
        owner.controller = controller
        owner._spawn = Mock()
        owner._receive_namespace = Mock(return_value=b'EXAMPLE-handoff')
        owner._verify_namespace = Mock(side_effect=lambda *_args: events.append('namespace-verified'))
        def close():
            events.append('cleanup')
            owner.namespace_handle = owner._parent_observation = None
            owner.cleanup['namespace_exited'] = True
            controller.terminate(owner.receipt, .1, allow_kill=True)
            controller.close()
            owner.controller = None
            if broken_cleanup:
                raise OSError('EXAMPLE cleanup secondary failure')
        owner.close = Mock(side_effect=close)
        if success:
            report = {'scope': 'primitive-controller-pid-reuse', 'accepted_output': False,
                      'execution_authorized': False, 'profile_status': 'selected-unqualified', 'confidential': 'unsupported'}
        parent, child = MagicMock(), MagicMock()
        parent.recv.return_value = json.dumps(report).encode()
        def stderr(_process, primary):
            primary.__notes__ = failure.__notes__[:]
        info = types.SimpleNamespace(st_mode=0o755, st_uid=0, st_gid=0)
        def version(command, **_kwargs):
            return types.SimpleNamespace(stdout=(metadata[next(name for name in metadata
                if metadata[name]['path'] == command[0])]['version'][0] + '\n').encode())
        with contextlib.ExitStack() as stack:
            for target, name, value in ((os, 'getuid', Mock(return_value=1001)),
                    (os, 'getgid', Mock(return_value=1001)),
                    (Path, 'stat', Mock(return_value=info)),
                    (os, 'getxattr', Mock(side_effect=OSError(61, 'No data'))),
                    (subprocess, 'run', Mock(side_effect=version)),
                    (selected.socket, 'socketpair', Mock(return_value=(parent, child))),
                    (selected, '_note_child_stderr', stderr),
                    (selected.select, 'select', Mock(return_value=([38], [], [])))):
                stack.enter_context(patch.object(target, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            try:
                result = _run_measured_pid_owner(owner)
            except BaseException as error:
                return error, owner, events
        return result, owner, events

    def test_skip_waits_for_original_run_cleanup_and_preserves_original_refusal(self):
        result, owner, events = self.exercise_run()
        self.assertIs(type(result), unittest.SkipTest)
        self.assertEqual(events, ['namespace-verified', 'cleanup'])
        self.assertTrue(owner.cleanup['namespace_exited'])
        self.assertIs(type(result.__cause__), selected.SelectedProbeError)
        self.assertIn('PermissionError: [Errno 1] Operation not permitted', str(result.__cause__))
        self.assertIn('namespace_exited', str(result))

    def test_original_cleanup_secondary_remains_failure_even_after_confirmed_exit(self):
        result, owner, events = self.exercise_run(broken_cleanup=True)
        self.assertIs(type(result), selected.SelectedProbeError)
        self.assertEqual(events, ['namespace-verified', 'cleanup'])
        self.assertTrue(owner.cleanup['namespace_exited'])
        self.assertIn('EXAMPLE cleanup secondary failure', str(result.__notes__))

    def test_cleanup_error_return_cannot_hide_behind_a_skip(self):
        result, owner, events = self.exercise_run(cleanup_report_error=True)
        self.assertIs(type(result), selected.SelectedProbeError)
        self.assertEqual(events, ['namespace-verified', 'cleanup'])
        self.assertTrue(owner.cleanup['namespace_exited'])

    def test_counterfactual_product_regressions_remain_errors_without_skips(self):
        for regression in ('old-E-P-zero', 'old-death-zero', 'uid-float', 'death-float',
                           'line-float', 'pid-owner-floats'):
            with self.subTest(regression=regression):
                failure, _owner, events = self.exercise_run(regression=regression)
                self.assertIs(type(failure), selected.SelectedProbeError)
                self.assertEqual(events, ['namespace-verified', 'cleanup'])

    def test_successful_original_run_returns_positive_report_without_classification(self):
        with patch(__name__ + '._private_cursor_unsupported', side_effect=AssertionError('must not classify success')):
            result, owner, events = self.exercise_run(success=True)
        self.assertIs(type(result), dict)
        self.assertEqual(result['scope'], 'primitive-controller-pid-reuse')
        self.assertTrue(result['cleanup']['namespace_exited'])
        self.assertTrue(owner.cleanup['namespace_exited'])
        self.assertEqual(events, ['namespace-verified', 'cleanup'])
