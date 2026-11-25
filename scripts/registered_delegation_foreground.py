"""Carry a Codex foreground decision to an original registered assignment."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4

import everyday_delegation as everyday
import registered_delegation_approval as approval
import registered_delegation_entry as entry
from cwo_core import manual_delivery, workspace_capture


_TOOL = {
    'name': 'authorize_assignment',
    'description': 'Ask the user to approve the original prepared CWO assignment. Reuse its standing approval if already retained.',
    'inputSchema': {
        'type': 'object',
        'properties': {
            'task': {'type': 'string', 'description': 'Exact original lead assignment.'},
            'baseline': {'type': 'string', 'description': 'Original requirement baseline JSON.'},
            'amendments': {'type': 'array', 'items': {'type': 'string'}},
            'output_path': {'type': 'string', 'description': 'One project-relative output path.'},
            'output_text': {'type': 'string', 'description': 'Exact UTF-8 text the worker should deliver.'},
        },
        'required': ['task', 'baseline', 'output_path', 'output_text'],
        'additionalProperties': False,
    },
}
_MAX_MESSAGE = 1_048_576
_VERSION = '2025-11-25'
_VERSIONS = {'2025-03-26', '2025-06-18', _VERSION}
_RETAINED = ('Standing approval is retained. Run cwo delegate with the same task and requirement baseline. '
             'Dispatch still requires current routing and admission.')
_QUESTION = {'type': 'object', 'properties': {
    'approve': {'type': 'boolean', 'title': 'Authorize this assignment', 'default': False}},
    'required': ['approve']}


@dataclass(frozen=True)
class Proposal:
    task: str
    baseline: str
    amendments: tuple[str, ...]
    output_path: str
    output_text: str


def _read(stream):
    line = stream.readline(_MAX_MESSAGE + 1)
    if not line:
        return None
    if len(line) > _MAX_MESSAGE or not line.endswith('\n'):
        raise ValueError('CWO foreground message exceeds its bound.')
    frame = entry._RECONCILIATION._decode(line.encode('utf-8'))
    if type(frame) is not dict or frame.get('jsonrpc') != '2.0':
        raise ValueError('Invalid CWO foreground message.')
    return frame


def _write(stream, **body):
    stream.write(json.dumps({'jsonrpc': '2.0', **body}) + '\n')
    stream.flush()


def _text(message, *, error=False):
    return {'content': [{'type': 'text', 'text': message}], 'isError': error}


def _arguments(params):
    if type(params) is not dict or params.get('name') != _TOOL['name']:
        raise ValueError('Unknown CWO approval tool.')
    args = params.get('arguments')
    properties = _TOOL['inputSchema']['properties']
    if type(args) is not dict or not args.keys() <= properties.keys():
        raise ValueError('Supply the original assignment and requirement baseline.')
    amendments = args.get('amendments', [])
    if type(amendments) is not list or not all(type(path) is str for path in amendments):
        raise ValueError('Supply the applied requirement amendments in order.')
    task, baseline, path, text = (args.get(key) for key in ('task', 'baseline', 'output_path', 'output_text'))
    if type(text) is not str or not all(type(value) is str and value.strip() for value in (task, baseline, path)):
        raise ValueError('Supply the assignment, requirement baseline and exact UTF-8 output.')
    return Proposal(task, baseline, tuple(amendments), path, text)


def _require_output(policy, proposal):
    raw = proposal.output_text.encode('utf-8')
    outputs = [(item['path'], item['size'], item['sha256']) for item in policy['outputs']]
    if outputs != [(proposal.output_path, len(raw), sha256(raw).hexdigest())]:
        raise ValueError('The proposed output differs from the original registered assignment.')


def _pending_assignment(project, proposal):
    if project is None:
        raise ValueError('Open cwo-codex in the original project checkout.')
    _, _, chain = everyday._baseline(project / proposal.baseline, [project / path for path in proposal.amendments])
    database, run_bd = manual_delivery.project_beads(project)
    everyday._open_task(manual_delivery.Delivery(chain['bead_id'], project, chain, {}), run_bd)
    try:
        existing = entry.open_project_assignment(project, database, proposal.task, chain)
    except entry.StandingApprovalMissing:
        from registered_delegation_preparation import prepare
        return prepare(project=project, database=database, task=proposal.task, chain=chain,
                       output_path=proposal.output_path, output_text=proposal.output_text)
    _require_output(existing.config.policy.report, proposal)
    return None


def _prompt(pending, proposal):
    scope = pending.approval_scope
    node = json.loads(pending._receipt.selected_node_bytes)
    plan, native = json.loads(pending._plans)[0]
    _require_output(plan['registered_n1']['validation_policy'], proposal)
    reservation = native['reservation']
    return '\n'.join((
        'Approve this CWO assignment for one registered Codex worker?',
        f'Project {json.dumps(scope.get("project", scope["target"]))}',
        f'Bead {json.dumps(scope["bead_id"])}',
        f'Task {json.dumps(node["prompt"])}',
        f'Output path {json.dumps(proposal.output_path)}',
        f'Exact output text {json.dumps(proposal.output_text)}',
        f'Model {native["model"]} through OpenAI',
        f'Budget {reservation["tool_calls"]} tool calls, {reservation["runtime_seconds"]} seconds',
        'Delivery requires independent review.',
    ))


def _decision_frame(source, tool_call):
    while (frame := _read(source)) is not None:
        method = frame.get('method')
        if 'id' in frame or type(method) is not str or not method.startswith('notifications/'):
            return frame
        if method == 'notifications/cancelled' and _cancelled(frame.get('params'), tool_call):
            return None
    return None


def _cancelled(params, tool_call):
    return type(params) is dict and params.get('requestId') == tool_call


def _ask(source, sink, pending, proposal, tool_call):
    request_id = 'cwo-standing-' + uuid4().hex
    params = {'message': _prompt(pending, proposal), 'requestedSchema': _QUESTION,
              '_meta': {'codex_requires_user_input': True}}
    _write(sink, id=request_id, method='elicitation/create', params=params)
    response = _decision_frame(source, tool_call)
    if _accepted(response, request_id):
        return request_id
    raise ValueError('The foreground did not approve this assignment.')


def _accepted(response, request_id):
    if response is None or response.keys() != {'jsonrpc', 'id', 'result'} or response['id'] != request_id:
        return False
    result = response['result']
    if type(result) is not dict or result.get('action') != 'accept':
        return False
    content = result.get('content')
    return type(content) is dict and content.keys() == {'approve'} and content['approve'] is True


def _retain(pending, request_id):
    verifier = pending._verifier
    directive = approval.authority.sign_controller_directive(verification_key=verifier._key,
        actor_id=verifier._actor, identity_source=verifier._identity,
        action_sha256=approval.workflow.digest(pending.approval_scope), directive_id=request_id,
        parent_receipt_sha256=verifier._directive_hash)
    entry.retain_approved_assignment(pending.create_workflow(directive))


def _authorize(source, sink, project, message, elicitation):
    try:
        if not elicitation:
            raise ValueError('Open the assignment in the local cwo-codex foreground to approve it.')
        proposal = _arguments(message.get('params'))
        pending = _pending_assignment(project, proposal)
        if pending is not None:
            if type(pending) is not approval.PendingDelegationApproval:
                raise ValueError('The original protected preparation is required.')
            from registered_delegation_preparation import discard_unretained
            try:
                _retain(pending, _ask(source, sink, pending, proposal, message['id']))
            finally:
                discard_unretained(pending)
        return _text(_RETAINED)
    except (OSError, ValueError, SystemExit) as failure:
        return _text(str(failure), error=True)


def _initialize(params):
    version = params.get('protocolVersion')
    capabilities = params.get('capabilities', {})
    elicitation = capabilities.get('elicitation') if type(capabilities) is dict else None
    form = type(elicitation) is dict and (not elicitation or type(elicitation.get('form')) is dict)
    negotiated = version if type(version) is str and version in _VERSIONS else _VERSION
    return {'protocolVersion': negotiated, 'capabilities': {'tools': {}},
            'serverInfo': {'name': 'cwo-delegation', 'version': '1'}}, form


def _request(source, sink, project, message, elicitation):
    request_id, method = message['id'], message.get('method')
    if method == 'tools/list':
        _write(sink, id=request_id, result={'tools': [_TOOL]})
    elif method == 'tools/call':
        _write(sink, id=request_id, result=_authorize(source, sink, project, message, elicitation))
    elif method == 'ping':
        _write(sink, id=request_id, result={})
    else:
        _write(sink, id=request_id, error={'code': -32601, 'message': 'Unknown CWO foreground method.'})


def serve(source, sink, project):
    """Run on the private provider-independent MCP connection opened by Codex."""
    first = _read(source)
    if first is not None and first.get('method') == 'server/discover' and 'id' in first:
        _write(sink, id=first['id'], error={'code': -32601, 'message': 'Use the MCP initialize handshake.'})
        first = _read(source)
    if first is None or 'id' not in first or first.get('method') != 'initialize' or type(first.get('params')) is not dict:
        return
    result, elicitation = _initialize(first['params'])
    _write(sink, id=first['id'], result=result)
    initialized = _read(source)
    if initialized is None or initialized.get('method') != 'notifications/initialized':
        return
    while (message := _read(source)) is not None:
        if 'id' in message and 'method' in message:
            _request(source, sink, project, message, elicitation)


def _owns_pipes(parent):
    streams = [os.fstat(stream.fileno()) for stream in (sys.stdin, sys.stdout)]
    if not all(stat.S_ISFIFO(info.st_mode) for info in streams):
        return False
    expected = {f'pipe:[{info.st_ino}]' for info in streams}
    for descriptor in (parent / 'fd').iterdir():
        try:
            expected.discard(os.readlink(descriptor))
        except FileNotFoundError:
            continue
    return not expected


def _foreground_parent(argv):
    if len(argv) != 3 or argv[1] != str(os.getppid()):
        return False
    parent = Path('/proc') / argv[1]
    codex = Path(argv[2])
    registration = 'mcp_servers.cwo-delegation.args=' + json.dumps(['-B', '-E', '-s', *argv])
    try:
        if codex.name != 'codex' or not (parent / 'exe').samefile(codex):
            return False
        with (parent / 'cmdline').open('rb') as command:
            arguments = command.read(_MAX_MESSAGE).split(b'\x00')
        return b'--no-daemon' in arguments and registration.encode() in arguments and _owns_pipes(parent)
    except OSError:
        return False


def main():
    if not _foreground_parent(sys.argv):
        raise SystemExit('Open the delegation approval from the local cwo-codex foreground.')
    try:
        checkout = workspace_capture.worktree_top_level(Path.cwd())
    except workspace_capture.WorkspaceDiscoveryError:
        checkout = None
    serve(sys.stdin, sys.stdout, None if checkout is None else Path(checkout))


if __name__ == '__main__':
    main()
