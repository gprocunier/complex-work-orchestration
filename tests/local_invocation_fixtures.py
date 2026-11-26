"""Test-only isolation for modules that drive the wired local invocation route with fakes.

``dispatch_work.execute_local_envelope`` reserves against the invocation ledger before resolution. Modules
that exercise the HTTP machinery (not accounting) give every call a fresh ledger in a temporary directory, so no test
writes a ledger into the source tree and no test's aggregate budget is shared with another's. The patch is scoped to
the calling module and removed when it finishes.
"""

from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch



@contextmanager
def legacy_http_fixture():
    """Exercise the lower HTTP layer in isolation from whole-workload admission."""
    import dispatch_work
    from cwo_core import local_invocation

    original = dispatch_work._local_review_scope

    def lower_layer(envelope, post, preflight, qualified_review, workload, validate_configuration):
        if qualified_review is not None or workload is not None:
            return original(envelope, post, preflight, qualified_review, workload, validate_configuration)
        return local_invocation.reserved_local_invocation(envelope, post, preflight)

    with ExitStack() as stack:
        stack.enter_context(patch.object(dispatch_work, 'require_local_http_workload'))
        stack.enter_context(patch.object(dispatch_work, '_local_review_scope', side_effect=lower_layer))
        yield


def isolate_local_invocation_ledgers() -> None:
    """Call from ``setUpModule``: each reservation in this module gets its own temporary ledger."""
    from cwo_core import local_invocation
    from cwo_core.invocation_ledger import InvocationLedger
    from cwo_core import host_records
    import dispatch_work

    unittest.enterModuleContext(legacy_http_fixture())
    directory = tempfile.TemporaryDirectory(prefix="cwo-test-ledgers-")
    unittest.addModuleCleanup(directory.cleanup)
    fresh = patch.object(local_invocation, "open_ledger",
                         lambda: InvocationLedger(Path(tempfile.mkdtemp(dir=directory.name)) / "ledger"))
    fresh.start()
    unittest.addModuleCleanup(fresh.stop)
    def fresh_host_store():
        return host_records._OVERRIDE.get() or host_records.HostRecordStore.for_tests(
            Path(tempfile.mkdtemp(dir=directory.name)) / 'host')
    provenance = patch.object(dispatch_work, 'configured_store', side_effect=fresh_host_store)
    provenance.start()
    unittest.addModuleCleanup(provenance.stop)
