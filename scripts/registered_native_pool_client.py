"""Finite offline ingress; client data never selects code or grants authority."""
from __future__ import annotations

import re


def validate_structure(request):
    """Validate local shape without importing a host, claiming or spending."""
    if type(request) is not dict or set(request) != {'version', 'mode', 'pool_id', 'workers'}:
        raise ValueError('Only structural pool client fields are supported; caller factories/imports are refused.')
    if type(request['version']) is not int or request['version'] != 1 or request['mode'] not in ('validate-only', 'execute'):
        raise ValueError('Unsupported pool client version or mode.')
    workers = request['workers']
    if type(workers) is not list or not 1 <= len(workers) <= 3:
        raise ValueError('Exactly N=1..3 distinct worker identities are required.')
    if any(type(item) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', item) is None
           for item in [request['pool_id'], *workers]) or len(set(workers)) != len(workers):
        raise ValueError('Bounded pool and distinct worker identities are required.')
    return {'structurally_valid': True, 'authority_validated': False,
            'model_calls': 0, 'dispatch_authorized': False}


def submit(request, *, host=None):
    """Use only a trusted parent's actual registered pool host; JSON cannot bootstrap one.

    A hostless validation describes shape only. With a protected host, the same
    request reaches its original authority checks, adoption and finite ledger.
    Host observations and exceptions pass through without inventing success.
    """
    structural = validate_structure(request)
    if host is None:
        if request['mode'] == 'validate-only':
            return structural
        raise ValueError('registered-pool-host-required')
    import registered_native_pool_host as pool
    if type(host) is not pool.RegisteredNativePoolHost:
        raise ValueError('The exact original registered pool host is required.')
    if getattr(host.run, '__func__', None) is not pool.RegisteredNativePoolHost.run:
        raise ValueError('The original bound pool host method is required.')
    return host.run(dict(request, workers=list(request['workers'])))
