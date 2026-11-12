"""Transport to one trusted Codex app-server over stdio JSON-RPC.

``app_server`` holds the client and its constants, ``errors`` the exceptions it
raises, and ``private_io`` the owner-private file helpers it uses. The code
moved from ``scripts/run_native_pool_live_canaries.py``, which still re-exports
every moved name. The current client additionally enforces the native launch
hold. This package intentionally does not re-export symbols.
"""
