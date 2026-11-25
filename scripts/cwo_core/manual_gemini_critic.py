"""Record one original Antigravity completion observed by the embedding host.

The host selects the fresh conversation and obtains the stdout and full
transcript in its protected custody. This adapter has no file or dispatch entry
point. Caller-supplied captures do not belong at this boundary.
"""
from __future__ import annotations

from hashlib import sha256
import re

from .errors import CWOPolicyError
from .host_records import HostRecordStore
from .host_return_intake import MAX_RETURN_BYTES, record_received_return
from .peer_review_identity import registered_review_model
from .policy import GEMINI_CRITIC_EXECUTOR, executor_config, provider_profile
from .policy_schema import strict_json_loads


_CONVERSATION_ID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')
_REQUEST_OPEN = '<USER_REQUEST>\n'
_REQUEST_CLOSE = '</USER_REQUEST>'
_METADATA_TAG = re.compile(r'</?[A-Z][A-Z_0-9]*(?=[\s/>])[^<>]*>')


def _require(condition, message):
    if not condition:
        raise CWOPolicyError(message)


def _utf8(raw: bytes) -> str:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RETURN_BYTES,
             'Gemini observation requires bounded original bytes')
    try:
        return raw.decode('utf-8')
    except UnicodeError:
        raise CWOPolicyError('Gemini observation is not UTF-8') from None


def _object(raw: bytes) -> dict:
    text = _utf8(raw)
    try:
        value = strict_json_loads(text)
    except (ValueError, RecursionError):
        raise CWOPolicyError('Gemini observation has invalid JSON') from None
    _require(type(value) is dict, 'Gemini observation requires a JSON object')
    return value


def _step(row, index, kind, source):
    return (type(row.get('step_index')) is int and row['step_index'] == index
            and (row.get('type'), row.get('source'), row.get('status')) == (kind, source, 'DONE')
            and 'truncated_fields' not in row and type(row.get('content')) is str)


def _transcript_steps(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_RETURN_BYTES,
             'Gemini observation requires bounded original bytes')
    lines = raw.split(b'\n', 2)
    _require(len(lines) == 3 and lines[2] == b'', 'Gemini transcript requires two complete steps')
    request, response = (_object(line) for line in lines[:2])
    _require(_step(request, 0, 'USER_INPUT', 'USER_EXPLICIT')
             and _step(response, 1, 'PLANNER_RESPONSE', 'MODEL'),
             'Gemini transcript requires one untruncated request and one completed model response')
    return request, response


def _metadata_only(suffix: str) -> bool:
    for name in ('ADDITIONAL_METADATA', 'USER_SETTINGS_CHANGE'):
        opening = f'\n<{name}>\n'
        if not suffix.startswith(opening):
            continue
        body, end, suffix = suffix[len(opening):].partition(f'\n</{name}>')
        if not body or not end:
            return False
        nested = _METADATA_TAG.findall(body)
        if nested and (name != 'ADDITIONAL_METADATA' or nested != ['<PLAN>', '</PLAN>']):
            return False
    return not suffix


def _matches_request(content: str, prompt: str) -> bool:
    # Plan mode may prepend its command and reuse the prompt's final LF as
    # the separator. Always locate the close from the exact prompt length.
    for command in ('', '/plan '):
        prefix = _REQUEST_OPEN + command + prompt
        if not content.startswith(prefix):
            continue
        tail = content[len(prefix):]
        if tail.startswith('\n'):
            tail = tail[1:]
        elif not prompt.endswith('\n'):
            continue
        if tail.startswith(_REQUEST_CLOSE) and _metadata_only(tail[len(_REQUEST_CLOSE):]):
            return True
    return False


def _completed_return(prompt, stdout, transcript, conversation_id, expected_model):
    completion = _object(stdout)
    _require(type(conversation_id) is str and _CONVERSATION_ID.fullmatch(conversation_id)
             and completion.get('conversation_id') == conversation_id,
             'Gemini completion does not match the host-selected conversation')
    _require(completion.get('status') == 'SUCCESS' and type(completion.get('num_turns')) is int
             and completion['num_turns'] == 1, 'Gemini CLI must report one successful turn')
    request, response = _transcript_steps(transcript)
    _require(_matches_request(request['content'], _utf8(prompt)),
             'Gemini transcript request differs from the exact screened prompt')
    model = response.get('model')
    _require(type(model) is str and model == expected_model,
             'Gemini transcript does not observe the selected critic model')
    final = response['content']
    _require(bool(final.strip()) and completion.get('response') == final + '\n',
             'Gemini stdout differs from the completed transcript response')
    try:
        return model, completion['response'].encode('utf-8')
    except UnicodeError:
        raise CWOPolicyError('Gemini response is not UTF-8') from None


def _require_prepared_dispatch(dispatch, provider_key, provider, screened_prompt):
    _require(dispatch.get('dispatch_role') == 'executor' and dispatch.get('executor') == GEMINI_CRITIC_EXECUTOR
             and dispatch.get('provider_key') == provider_key and dispatch.get('provider') == provider
             and dispatch.get('packet_sha256') is not None
             and dispatch['evaluation_metadata'].get('dispatch_mode') == 'manual_ui',
             'Gemini completion requires an original prepared manual critic dispatch')
    _require(dispatch.get('request_sha256') == sha256(screened_prompt).hexdigest(),
             'Gemini completion prompt differs from the prepared dispatch')


def record_gemini_critic_completion(store: HostRecordStore, dispatch_id: str, *, screened_prompt: bytes,
                                    stdout: bytes, full_transcript: bytes, conversation_id: str) -> str:
    """Bind trusted completion evidence to an existing screened Gemini dispatch."""
    executor = executor_config(GEMINI_CRITIC_EXECUTOR)
    provider_key = executor['provider_key']
    provider = provider_profile(provider_key).get('family')
    transport = executor['transport']
    model, raw_return = _completed_return(screened_prompt, stdout, full_transcript, conversation_id, transport['model'])
    registered = registered_review_model(provider, model)
    effort = transport['effort']
    _require(provider == 'google' and registered is not None and model.endswith('-' + effort),
             'Gemini observed model variant has no registered critic effort')
    dispatch = store.require_dispatch(dispatch_id)
    _require_prepared_dispatch(dispatch, provider_key, provider, screened_prompt)
    observation = sha256(b'cwo:agy-completion-v1\0' + sha256(stdout).digest() + sha256(full_transcript).digest())
    fields = dict(observation_sha256=observation.hexdigest(), provider=provider,
                  model_family=registered['model_family'], model_id=model,
                  reasoning_effort=effort, session_id=conversation_id)
    if dispatch.get('stage') == 'observed':
        _require(all(dispatch.get(key) == value for key, value in fields.items()),
                 'Gemini completion differs from the original observation')
    else:
        store.write_observed_dispatch(dispatch_id, prepared_record_sha256=dispatch['_record_sha256'], **fields)
    return record_received_return(store, dispatch_id, raw_return)
