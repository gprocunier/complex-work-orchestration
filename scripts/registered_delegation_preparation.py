"""Compile an ordinary request into one unsigned known-output delegation offer."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from tempfile import mkdtemp

import registered_delegation_approval as approval
import registered_delegation_entry as entry
from cwo_core import host_records, manual_delivery, outbound_screen, requirement_baseline, workspace_capture
from cwo_core.model_identities import resolve_model
from cwo_core.paths import BLOCKED_OUTPUT_PATH_PARTS, _reject_secret_like_path

workflow, runtime, authority = approval.workflow, approval.runtime, approval.authority
admission = approval.admission
planner = admission.planner
_need = workflow._need
_PROFILE = 'cwo_standing_delegation'
_PROFILE_SECTION = f'permissions.{_PROFILE}'
_NODE = 'implementation'
MAX_TEXT_BYTES = 2048
_DURATION_SECONDS = 600


def _known_output(path, text):
    path = runtime.native._relative(path)
    _need(not (set(path.lower().split('/')) & BLOCKED_OUTPUT_PATH_PARTS), 'Protected project paths cannot be delegation outputs.')
    try:
        _reject_secret_like_path(Path(path))
    except SystemExit as exc:
        raise ValueError(str(exc)) from exc
    data = _text(text)
    command = f'/usr/bin/printf %s {shlex.quote(text)} > {shlex.quote(path)}'
    _need(len(command) <= 4096, 'The proposed output does not fit the finite command bound.')
    policy = {'version': 1, 'outputs': [{'path': path, 'validator': 'bytes', 'size': len(data),
                                        'sha256': sha256(data).hexdigest()}]}
    return command, policy, data


def _text(value):
    _need(type(value) is str and '\x00' not in value, 'A bounded UTF-8 text value is required.')
    data = value.encode('utf-8')
    _need(0 < len(data) <= MAX_TEXT_BYTES, 'Delegation text must have 1 to 2,048 UTF-8 bytes.')
    return data


def _screen(task, text):
    try:
        for value in (task, text):
            outbound_screen.require_clean(value, surface='registered delegation')
    except outbound_screen.OutboundRefused as exc:
        raise ValueError(str(exc)) from exc


def _project(project, database, chain):
    project = runtime.native._path(project)
    _need(workspace_capture.worktree_top_level(project) == str(project), 'Run delegation from the original project checkout.')
    observed, run_bd = manual_delivery.project_beads(project)
    _need(observed == database, 'The original project Beads database is required.')
    delivery = manual_delivery.Delivery(chain['bead_id'], project, chain, {})
    bead = delivery.task(run_bd)
    _need(bead.get('status') in manual_delivery._OPEN, 'An open Bead is required for registered worker delivery.')
    errors = requirement_baseline.bead_reference_errors(bead, chain)
    if errors:
        raise requirement_baseline.RequirementBaselineError(errors)
    return project


def _worker_home():
    home = workflow.login_config.read_worker_login_home()
    _need(home is not None, workflow.delegation_setup_message())
    login = runtime.qualification.WorkerLoginMount(home, runtime.qualification.worker_login_state())
    return login.protected_roots()


def _clone(project, worker):
    git = workspace_capture.trusted_git()
    _need(git is not None, workspace_capture.NO_TRUSTED_GIT)
    environment = {**workspace_capture._environment(), 'GIT_ALLOW_PROTOCOL': 'file'}
    command = [git.path, *workspace_capture.INERT_GIT_CONFIG, 'clone', '--quiet', '--no-local',
               '--no-hardlinks', '--no-tags', '--no-recurse-submodules', '--template=', '--', str(project), str(worker)]
    try:
        result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('The independent worker checkout did not complete within its time bound.') from exc
    _need(result.returncode == 0, 'The independent worker checkout could not be created.')
    worker.chmod(0o700)


def _existing_output(worker, path):
    relative = Path(path)
    with runtime.native._directory(worker / relative.parent) as directory:
        try:
            info = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return b''
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'The proposed output must be a single regular file.')
    original = runtime.native._read(worker, path, runtime.native.MAX_TASK_BYTES)
    _need('\x00' not in original.decode('utf-8'), 'The proposed output must replace a UTF-8 text file.')
    return original


def _custody(store, protected_login, project, stack):
    sibling = store.state_root.with_name(store.state_root.name + '-delegation')
    runtime._disjoint((store.state_root, sibling, project, *protected_login))
    scripts = Path(runtime.__file__).resolve().parent
    runtime.require_private_roots((sibling, *protected_login), visible_paths=(scripts, scripts.parent / 'policy', scripts.parent / 'schemas'))
    os.close(host_records._directory(sibling, create=True, private=True))
    runtime_root = Path(mkdtemp(prefix='offer-', dir=sibling))
    stack.callback(shutil.rmtree, runtime_root, ignore_errors=True)
    worker = runtime_root / 'worker'
    _clone(project, worker)
    host, control = runtime_root / 'host', runtime_root / 'control'
    for path in (host, host / 'records', host / 'fake-server', host / 'fake-server' / 'codex-home', control,
                 control / 'controller', control / 'publication', control / 'authority'):
        path.mkdir(mode=0o700)
    return runtime.native.OfflineN1Host(host, project, worker), control


def _project_key(store, project, database):
    name = entry._key_name(project, database)
    with entry._key_directory(store, create=True) as directory:
        try:
            return host_records._read_at(directory, name, entry._MAX_KEY_BYTES)
        except FileNotFoundError:
            key = secrets.token_bytes(32)
        try:
            host_records._write_at(directory, name, key, atomic_create=True)
        except FileExistsError:
            return host_records._read_at(directory, name, entry._MAX_KEY_BYTES)
    return key


def _configuration(worker, model, effort):
    features = runtime.qualification.configuration_features()
    code_mode = features.pop('code_mode')
    flags = ''.join(f'{name} = false\n' for name in features)
    namespaces = json.dumps(code_mode['direct_only_tool_namespaces'])
    login = json.dumps(str(runtime.qualification.LOGIN_MOUNT), ensure_ascii=False)
    worker_path = json.dumps(str(worker), ensure_ascii=False)
    return {'rules/default.rules': '', 'config.toml': (
        'cli_auth_credentials_store = "file"\n'
        f'default_permissions = "{_PROFILE}"\napproval_policy = "never"\napprovals_reviewer = "user"\n'
        f'model = {json.dumps(model)}\nmodel_reasoning_effort = {json.dumps(effort)}\nservice_tier = "default"\n'
        f'[{_PROFILE_SECTION}.filesystem]\n"/" = "deny"\n{login} = "deny"\n{worker_path} = "read"\n'
        f'[{_PROFILE_SECTION}.network]\nenabled = false\n[features]\n{flags}'
        f'[features.code_mode]\nenabled = true\ndirect_only_tool_namespaces = {namespaces}\n')}


def _specification(host, ledger, command, policy, policy_sha256):
    codex = shutil.which('codex')
    _need(codex is not None, 'The installed Codex CLI is required for delegation.')
    model, effort = resolve_model('luna'), 'high'
    approval_policy = runtime.qualification.APPROVAL_POLICY
    spec = {'model': model, 'provider': runtime.qualification.PROVIDER, 'effort': effort,
            'command': command, 'validation_policy': policy, 'expected_token': 'CWO_DELEGATION_COMPLETE',
            'production_live': True, 'finite_tool_mode': runtime.finite_calls.LIVE_CAPTURE_MODE,
            'thread_start': {'permissions': _PROFILE, 'approvalPolicy': approval_policy,
                             'approvalsReviewer': 'user', 'ephemeral': False},
            'profile_readback': {'activePermissionProfile': {'id': _PROFILE, 'extends': None},
                                 'approvalPolicy': approval_policy, 'approvalsReviewer': 'user'},
            'pre_effect': {'profile': _PROFILE, 'policy_id': policy_sha256, 'rules': [], 'hooks': [],
                           'grants': [], 'network': False, 'input_capability': 'finite'},
            'configuration_files': _configuration(host.worker, model, effort),
            'custody': {'state': str(host.state), 'worker': str(host.worker), 'target': str(host.target),
                        'ledger': str(ledger.root), 'initial': host._initial, 'state_identity': host._state_identity},
            'max_steps': 64, 'purpose': 'local-engineering', 'implementation_sha256': runtime.implementation_sha256()}
    for name, path in (('executable', codex), ('launcher', '/usr/bin/bwrap'), ('validator', sys.executable)):
        spec[name], spec[name + '_sha256'], _ = runtime._file(Path(path).resolve(strict=True))
    spec['configuration_pins'] = {'w14': spec['executable_sha256'], 'w15': policy_sha256}
    return spec


def _estimate(task, bead, path, spec, diff_lines):
    estimates = {'tool_calls_p50': 2, 'tool_calls_p90': 6, 'runtime_seconds_p50': 45, 'runtime_seconds_p90': 180}
    semantic = dict.fromkeys(planner.work_sizing.SEMANTIC_ESTIMATE_KEYS, 0)
    semantic.update(estimated_diff_p50=diff_lines, estimated_diff_p90=diff_lines, behavioral_changes=1,
                    command_complexity=1, expected_mutations=1)
    return {'estimate_type': 'cwo-native-work-estimate', 'version': 1, 'estimate_contract_version': 2,
            'work_unit_id': _NODE, 'bead_id': bead, 'requested_model': spec['model'], 'primary_outcome': task,
            'expected_artifacts': [path], 'expert_profiles': ['executor'], 'context_manifest': [],
            'frozen_decisions': ['one exact UTF-8 output and fixed bytes validator'], 'unresolved_decisions': [],
            'subsystems': ['registered-delegation'], 'write_paths': [path],
            'acceptance_checks': ['The registered output matches the approved size and SHA-256 digest.'],
            'estimates': {**estimates, 'context_tokens_p90': 8000}, 'semantic_estimate': semantic,
            'scores': dict.fromkeys(planner.work_sizing.DIMENSIONS, 0),
            'pm_estimate': estimates, 'domain_expert_estimate': estimates,
            'task_profile': {'task_class': 'narrow-mechanical', 'declared_outcome_count': 1, 'command_count': 1,
                             'check_count': 1, 'focused_test_count': 0, 'full_suite_count': 0,
                             'read_context_count': 0, 'source_mutation_count': 1,
                             'commands': [{'argv': ['/usr/bin/sh', '-c', spec['command']]}], 'source_mutation_paths': [path]}}


def _route(task, bead, path, identity, spec, policy, diff_lines):
    source = _estimate(task, bead, path, spec, diff_lines)
    sizing = planner.work_sizing
    unit = sizing.evaluate_work_estimate(source, policy=policy)
    _need(unit['route'] == 'spark' and unit['fit_mode'] == 'deterministic',
          'The proposed replacement exceeds the bounded single-worker route.')
    required = {'id': _NODE, 'role': 'product', 'depends_on': []}
    execution = {**{field: spec[field] for field in ('model', 'provider', 'effort')},
                 'options': {'registered_n1': spec}, 'executor': 'internal_worker_luna',
                 'tool_surface': ['cwo_finite.finite_command', 'cwo_finite.finite_poll'], 'output_tokens_upper': 8192}
    node = {**required, 'kind': 'primary', 'lineage_parent': None, 'execution': execution, 'prompt': task,
            'wrappers': [], 'attachments': [], 'sources': [], 'estimate_source': source, 'unit_estimate': unit,
            'source_sha256': sizing.canonical_work_estimate_sha256(source),
            'unit_sha256': sizing.canonical_work_estimate_sha256(unit),
            'sizing_rationale': 'Bound one invocation of the fixed writer and bytes validator.',
            'uncertainty': {'status': 'bounded', 'detail': 'Provider latency and billing remain unknown.'},
            'additional_input_tokens_upper': 0}
    node['rendered_request'] = planner.render_request(node)
    projection = {'mode': 'declared-conservative', 'tokens_per_utf8_byte_upper': 1, 'input_overhead_tokens': 4096,
                  'rationale': 'Bound the encoded request plus control overhead.',
                  'uncertainty': 'Provider tokenization and billing are unobserved.',
                  'billing': {'currency': 'delegation-planning-unit', 'input_microunits_per_token_upper': 1,
                              'output_microunits_per_token_upper': 1, 'fixed_microunits_per_attempt_upper': 1,
                              'rationale': 'Finite internal accounting units, independent of provider billing.'}}
    route = {'parent_id': bead, 'run_id': identity, 'aggregate_id': identity, 'purpose': task, 'output': path,
             'acceptance': source['acceptance_checks'], 'nodes': [node], 'projection_policy': projection,
             'policy': policy, 'policy_sha256': planner.canonical_authority_sha256(policy),
             'estimator_version': planner.ESTIMATOR_VERSION,
             'task_contract': {'contract_id': 'known-output-delegation', 'root_id': _NODE, 'required_roles': [required]},
             'limits': {'tool_calls': 10, 'runtime_seconds': 300, 'tokens': 65536, 'cost_microunits': 65537}}
    route['bound_input_sha256'] = planner.input_sha256(route)
    return route


def _capability_evidence():
    """No current trusted quota or capacity observation is supplied by guided login."""
    return {}


def _standing(route, chain, database, now):
    unit = route['nodes'][0]['unit_estimate']
    cache = {'source': 'deterministic-context-plan', 'observed_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
             'total_context_tokens_p90': unit['estimates']['context_tokens_p90'], 'stable_context_tokens_p90': 0,
             'expected_reuse_opportunities': 0, 'repeatable_unit_count': 0, 'repeat_template_sha256': None,
             'observed_input_tokens': 0, 'observed_cached_input_tokens': 0, 'same_work_lineage': False,
             'context_plan_sha256': workflow.digest(unit['context_manifest']), 'telemetry_lineage_id': None}
    cache['evidence_sha256'] = workflow.digest(cache)
    return workflow.D.StandingDelegation(baseline_sha256=chain['digest'], database_sha256=database,
                                        capability_evidence=_capability_evidence(), cache_profile=cache)


def _mission(host, directory, identity, route, chain, model, key):
    registry = {}
    for name, filename in (('registered-native', runtime.__file__), ('registered-publication', workflow.G.__file__)):
        path = Path(filename).resolve(strict=True)
        registry[name] = {'adapter_path': str(path), 'adapter_sha256': sha256(path.read_bytes()).hexdigest()}
    mission = {'mission_type': 'cwo-maintenance-mission', 'version': 1, 'mission_id': identity,
               'objective': 'Prepare one finite registered assignment for independent hand review.',
               'provenance': {'adoption_id': identity, 'user_request_sha256': workflow.digest(
                   {'route': route['bound_input_sha256'], 'baseline': chain['digest']})},
               'scope': {'effect_scope': 'cwo-maintenance', 'workspace_roots': [str(host.worker), str(host.target)],
                         'models': [model], 'roles': ['product'], 'factory_ids': list(registry)},
               'budget': {'mode': 'unbounded'}, 'lifetime': {'mode': 'until-revoked'}}
    mission_hash = authority.mission_sha256(mission)
    actor, source = f'uid:{os.getuid()}', 'cwo-protected-project-controller'
    directive = authority.sign_controller_directive(verification_key=key, actor_id=actor, identity_source=source,
                                                    action_sha256=mission_hash, directive_id=identity)
    store = authority.MaintenanceStateStore(directory, mission_id=identity, mission_sha256=mission_hash)
    store.initialize()
    verifier = authority.MaintenanceAuthorityVerifier(mission=mission, operator_directive=directive,
        verification_key=key, expected_actor_id=actor, expected_identity_source=source,
        factory_registry=registry, state_reader=store.read_state, claim_operation=store.claim_operation)
    return verifier, directive


def prepare(*, project, database, task, chain, output_path, output_text) -> approval.PendingDelegationApproval:
    """Offer one literal replacement. A verified foreground decision redeems it separately."""
    _text(task)
    _need(bool(task.strip()), 'The original lead task is required.')
    command, validation, data = _known_output(output_path, output_text)
    _screen(task, output_text)
    protected_login = _worker_home()
    project = _project(project, database, chain)
    store = entry._protected_store(project, *protected_login)
    with ExitStack() as stack:
        host, control = _custody(store, protected_login, project, stack)
        original = _existing_output(host.worker, output_path)
        _need(original != data, 'The proposed exact output already matches the worker base.')
        diff_lines = len(original.splitlines()) + len(data.splitlines())
        ledger = admission.ledger_api.InvocationLedger(control / 'ledger')
        policy_bytes = admission._read_policy_bytes()
        spec = _specification(host, ledger, command, validation, sha256(policy_bytes).hexdigest())
        identity = 'delegation-' + secrets.token_hex(16)
        route = _route(task, chain['bead_id'], output_path, identity, spec, json.loads(policy_bytes), diff_lines)
        workflow.D._route(route['nodes'][0], None)
        key = _project_key(store, project, database)
        verifier, mission = _mission(host, control / 'authority', identity, route, chain, spec['model'], key)
        now = ledger.current_time()
        pending = approval.prepare_assignment(verifier=verifier, mission_directive=mission, host=host, ledger=ledger,
            controller_state=control / 'controller', publication_state=control / 'publication', registered_specification=spec,
            standing=_standing(route, chain, database, now), route=route, node_id=_NODE, native_operation_id=identity + '-native',
            publication_operation_id=identity + '-publication', cleanup_seconds=15, expires_at=now + _DURATION_SECONDS)
        stack.pop_all()
    return pending
