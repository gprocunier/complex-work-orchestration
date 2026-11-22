"""Load the public Codex catalog for CLI role selection when requested by policy."""

from __future__ import annotations

from collections.abc import Iterable
import os
from pathlib import Path
import shutil
import subprocess

from cwo_core.model_catalog_startup import public_model_catalog
from cwo_core.model_identities import configure_model_catalog, requires_model_catalog
from registered_app_server_transport import AppServerError, RegisteredAppServer


class _CatalogServer(RegisteredAppServer):
    """Reuse the stdio handshake with only the catalog RPC available."""

    def __init__(self, executable: str, codex_home: Path):
        self._executable = executable
        self._home = codex_home
        super().__init__(requested_model="model-list-only")

    def _default_executable(self) -> str:
        return self._executable

    def _requested_home(self) -> Path:
        return self._home

    def _launch_process(self, command, environment):
        return subprocess.Popen(
            [command[0], "app-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, umask=0o077, env=environment,
        )

    def _write_payload(self, payload, *, method, timeout):
        if payload.get("method") != method or method not in {"initialize", "initialized", "model/list"}:
            raise AppServerError("catalog-only-app-server-method-refused")
        if method == "model/list" and payload.get("params", {}).get("includeHidden") is not False:
            raise AppServerError("catalog-only-app-server-visibility-refused")
        return super()._write_payload(payload, method=method, timeout=timeout)


def configure_cli_model_catalog(
    roles: Iterable[str] | None = None, *, codex_home: Path | str | None = None,
) -> None:
    if not requires_model_catalog(roles):
        return
    executable = shutil.which("codex")
    if executable is None:
        raise SystemExit("Latest-in-family model selection requires an installed Codex app server")
    home = Path(codex_home or os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser().resolve()
    try:
        server = _CatalogServer(str(Path(executable).resolve()), home)
        try:
            catalog = public_model_catalog(lambda method, params: server.request(method, params, timeout=5))
        finally:
            server.close()
        configure_model_catalog(catalog)
    except (AppServerError, OSError, ValueError) as exc:
        raise SystemExit(f"Unable to resolve Codex models at startup: {exc}") from exc
