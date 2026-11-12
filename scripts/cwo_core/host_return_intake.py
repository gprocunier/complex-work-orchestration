"""Host intake binds received bytes; a receipt does not accept their claims."""
from __future__ import annotations

import hashlib
import json

from .errors import CWOPolicyError
from .peer_review import validate_peer_review_request
from .policy_schema import strict_json_loads

MAX_RETURN_BYTES = 4 * 1024 * 1024


def record_manual_return(store, dispatch_id: str, raw: bytes) -> str:
    """Public intake is restricted to recorded manual executor dispatches."""
    dispatch = store.require_dispatch(dispatch_id)
    if (dispatch['dispatch_role'] != 'executor'
            or dispatch.get('evaluation_metadata', {}).get('dispatch_mode') != 'manual_ui'):
        raise CWOPolicyError("manual intake requires a recorded manual executor dispatch")
    return _record_capture(store, dispatch_id, raw, 'manual-intake-v1')


def _record_capture(store, dispatch_id, raw, provenance, canonical=None):
    if type(raw) is not bytes or len(raw) > MAX_RETURN_BYTES:
        raise CWOPolicyError("host return intake requires bounded exact bytes")
    digest = hashlib.sha256(raw).hexdigest()
    canonical_digest = hashlib.sha256(canonical).hexdigest() if canonical is not None else None
    dispatch = store.require_dispatch(dispatch_id)
    prior = store.find('return-received', dispatch_id=dispatch_id,
                       dispatch_record_sha256=dispatch['_record_sha256'])
    exact = [record for record in prior if record.get('return_sha256') == digest
             and record.get('capture_provenance') == provenance
             and record.get('canonical_return_sha256') == canonical_digest]
    if exact:
        return store.require_return(dispatch_id, digest)['_record_sha256']
    return store.write_return_received(dispatch_id, digest, capture_provenance=provenance,
                                       canonical_return_sha256=canonical_digest)


def record_received_return(store, dispatch_id: str, raw: bytes) -> str:
    """Internal host capture after the original host observed its completion.

    The actual bytes remain in the host's immutable completion/artifact custody.
    One receipt binds their digest and, for peers, the canonical decision digest.
    No public command routes caller bytes through this function.
    """
    if type(raw) is not bytes or len(raw) > MAX_RETURN_BYTES:
        raise CWOPolicyError("host return intake requires bounded exact bytes")
    dispatch = store.require_dispatch(dispatch_id)
    canonical = None
    if dispatch['dispatch_role'] == 'peer-review':
        try:
            value = strict_json_loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError) as failure:
            raise CWOPolicyError("peer-review return must be structured JSON") from failure
        reviewer = value.get('reviewer_identity') if type(value) is dict else None
        value = validate_peer_review_request('passed', reviewer, value)
        expected = {name: dispatch[name] for name in (
            'provider', 'model_family', 'model_id', 'reasoning_effort', 'dispatch_id')}
        if reviewer != expected:
            raise CWOPolicyError("peer-review return identity differs from the actual host dispatch")
        target = dispatch['review_target']
        if any(value[name] != target[name] for name in ('return_sha256', 'evaluation_sha256')):
            raise CWOPolicyError("peer-review return differs from the exact dispatched review target")
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode('utf-8')
    return _record_capture(store, dispatch_id, raw, 'host-capture-v1', canonical)
