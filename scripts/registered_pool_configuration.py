"""Pinned stock Codex settings for a contained pool qualification worker."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tomllib

from cwo_core.native_tool_isolation import CONTAINED_POOL_WRITER_NAME as WRITER_TOOL
from cwo_core.policy_schema import strict_json_loads
from cwo_core.worker_patch import MAX_WORKER_DIFF_BYTES
from registered_n1_qualification import (
    APPROVAL_POLICY, EFFORT, FINITE_TOOL_NAMESPACE, HISTORY_MODE, LOGIN_MOUNT, MODEL, PROVIDER, TIER,
)

PROFILE = 'cwo-pool-contained'
CATALOG_NAME = 'model-catalog.json'
MAX_CATALOG_BYTES = 2_000_000
# Codex uses fast_mode to expose the default tier too. The config and RPC selectors pin the tier.
_DISABLED_FEATURES = (
    'shell_tool', 'unified_exec', 'unified_exec_tty', 'code_mode_only', 'code_mode_only_strict_3p_tools',
    'view_image', 'image_generation', 'standalone_web_search', 'request_permissions_tool',
    'deferred_executor', 'default_mode_request_user_input', 'apps', 'plugins', 'tool_suggest',
    'skill_search', 'multi_agent', 'multi_agent_v2', 'agent_message_board', 'agent_message_board_mcp',
    'current_time_reminder', 'sleep_tool', 'token_budget', 'context_management', 'goals',
    'multi_env_copy_file', 'memories', 'memory_tool', 'browser_use', 'browser_use_external',
    'browser_use_full_cdp_access', 'computer_use', 'js_repl', 'js_repl_tools_only', 'hooks',
    'codex_hooks', 'plugin_hooks', 'undo', 'send_message_to_user_async',
    'executor_capability_discovery', 'executor_capability_discovery_v2',
)
_CATALOG_OPTIONALS = frozenset({'apply_patch_tool_type', 'multi_agent_version'})
_TURN_REQUIRED = {'threadId', 'model', 'effort', 'serviceTier', 'input'}
_TURN_METADATA = {'clientUserMessageId', 'responsesapiClientMetadata'}


class PoolContainmentError(ValueError):
    """A contained pool worker rejected configuration or lost original custody."""


def require(condition, message):
    if not condition:
        raise PoolContainmentError(message)


def _selected_model(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CATALOG_BYTES, 'Bounded model catalog required.')
    try:
        catalog = strict_json_loads(raw.decode('utf-8'))
    except (ValueError, RecursionError) as error:
        raise PoolContainmentError('Invalid model catalog.') from error
    require(type(catalog) is dict and type(catalog.get('models')) is list, 'Invalid model catalog shape.')
    selected = [model for model in catalog['models'] if type(model) is dict and model.get('slug') == MODEL]
    require(len(selected) == 1, 'The catalog must contain the original qualification model once.')
    return selected[0]


def _trimmed(model):
    return {**{name: value for name, value in model.items() if name not in _CATALOG_OPTIONALS},
            'tool_mode': 'direct', 'supports_search_tool': False, 'experimental_supported_tools': []}


def trim_model_catalog(source, *, source_sha256):
    """Derive the optional direct-only catalog from one independently pinned export."""
    model = _selected_model(source)
    require(sha256(source).hexdigest() == source_sha256, 'The source model catalog pin differs.')
    return _catalog_bytes(_trimmed(model))


def _catalog_bytes(model):
    return json.dumps({'models': [model]}, sort_keys=True, allow_nan=False,
                      separators=(',', ':')).encode('utf-8') + b'\n'


def require_trimmed_model_catalog(catalog, sha256_pin):
    model = _selected_model(catalog)
    require(catalog == _catalog_bytes(_trimmed(model)) and sha256(catalog).hexdigest() == sha256_pin,
            'The selected trimmed model catalog differs from its pin or projection.')


def configuration_files(worktree: Path, spool: Path, *, catalog=None):
    """Return the complete operation-owned configuration to stage read-only."""
    strings = {'default_permissions': PROFILE, 'approval_policy': APPROVAL_POLICY,
               'approvals_reviewer': 'user', 'model': MODEL, 'model_provider': PROVIDER,
               'model_reasoning_effort': EFFORT, 'service_tier': TIER,
               'cli_auth_credentials_store': 'file', 'web_search': 'disabled'}
    if catalog is not None:
        strings['model_catalog_json'] = str(spool / CATALOG_NAME)
    lines = [f'{key} = {json.dumps(value, ensure_ascii=False)}' for key, value in strings.items()]
    lines.extend(('', '[features]'))
    lines.extend(f'{name} = false' for name in _DISABLED_FEATURES)
    # The stock model's Code Mode routing needs this table to expose the writer directly.
    lines.extend((
        '', '[features.code_mode]', f'enabled = {str(catalog is None).lower()}',
        f'direct_only_tool_namespaces = ["{FINITE_TOOL_NAMESPACE}"]',
        '', '[tools.update_plan]', 'enabled = false',
        '', '[tools.experimental_request_user_input]', 'enabled = false',
        '', '[skills]', 'include_instructions = false',
        '', '[skills.bundled]', 'enabled = false',
        '', '[cloud.skills]', 'enabled = false',
        '', '[agents]', 'enabled = false',
        '', '[mcp_servers]',
        '', f'[permissions.{PROFILE}.filesystem]',
        '"/" = "deny"', f'{json.dumps(str(worktree), ensure_ascii=False)} = "read"',
        f'"{LOGIN_MOUNT}" = "deny"',
        '', f'[permissions.{PROFILE}.network]', 'enabled = false', '',
    ))
    files = {'config.toml': '\n'.join(lines).encode('utf-8'), 'rules/default.rules': b''}
    if catalog is not None:
        files[CATALOG_NAME] = catalog
    return files


def require_named_deny_policy(worktree: Path, content: bytes):
    """Verify the complete policy for the named, read-only worker profile."""
    try:
        settings = tomllib.loads(content.decode('utf-8'))
    except ValueError as error:
        raise PoolContainmentError('Invalid named login deny policy.') from error
    expected = {'filesystem': {'/': 'deny', str(worktree): 'read', str(LOGIN_MOUNT): 'deny'},
                'network': {'enabled': False}}
    require(settings.get('default_permissions') == PROFILE and settings.get('permissions') == {PROFILE: expected},
            'The named login deny policy or its worker scope differs.')


def _writer_registration(*, patch_mode: bool):
    tool = {'type': 'function', 'name': WRITER_TOOL,
            'description': 'The controller writes the signed fixture already selected for this worker. '
                           'The worker shell and checkout stay read-only.',
            'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}}
    description = 'Registered qualification writer.'
    if patch_mode:
        description = 'Registered one-file patch writer.'
        tool['description'] = ('Submit a unified text diff for the signed file already selected for this worker. '
                               'The worker shell and checkout stay read-only.')
        tool['inputSchema'].update({
            'properties': {'diff': {'type': 'string', 'minLength': 1, 'maxLength': MAX_WORKER_DIFF_BYTES}},
            'required': ['diff'],
        })
    return [{'type': 'namespace', 'name': FINITE_TOOL_NAMESPACE, 'description': description, 'tools': [tool]}]


def thread_start_selectors(worktree, *, patch_mode: bool = False):
    require(type(patch_mode) is bool, 'The original writer mode is required.')
    return {'cwd': str(worktree), 'runtimeWorkspaceRoots': [str(worktree)], 'permissions': PROFILE,
            'approvalPolicy': APPROVAL_POLICY, 'approvalsReviewer': 'user', 'ephemeral': False,
            'model': MODEL, 'modelProvider': PROVIDER, 'serviceTier': TIER, 'historyMode': HISTORY_MODE,
            'allowProviderModelFallback': False, 'dynamicTools': _writer_registration(patch_mode=patch_mode)}


def require_thread_readback(worktree, response):
    require(type(response) is dict, 'The actual contained qualification thread is required.')
    expected = {'cwd': str(worktree), 'runtimeWorkspaceRoots': [str(worktree)],
                'activePermissionProfile': {'id': PROFILE, 'extends': None}, 'model': MODEL,
                'approvalPolicy': APPROVAL_POLICY, 'approvalsReviewer': 'user',
                'modelProvider': PROVIDER, 'reasoningEffort': EFFORT, 'serviceTier': TIER}
    require(all(response.get(key) == value for key, value in expected.items()),
            'The actual contained qualification thread settings differ.')
    thread = response.get('thread')
    require(type(thread) is dict and type(thread.get('id')) is str and thread['id']
            and thread.get('turns') == [] and thread.get('ephemeral') is False
            and thread.get('historyMode') == HISTORY_MODE,
            'A fresh, persistent qualification thread is required.')


def require_turn_selectors(params, *, thread_id):
    require(type(params) is dict and _TURN_REQUIRED <= params.keys() <= _TURN_REQUIRED | _TURN_METADATA,
            'Unexpected qualification turn selectors.')
    expected = {'threadId': thread_id, 'model': MODEL, 'effort': EFFORT, 'serviceTier': TIER}
    require(type(thread_id) is str and thread_id and all(params.get(key) == value for key, value in expected.items()),
            'The original qualification thread and model must remain selected.')
