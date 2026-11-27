"""Local custody across Linux UIDs. Start the host from an isolated protected installation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import time

from .errors import CWOError
from .policy_schema import strict_json_loads


_CONFIG_FILE = Path("/etc/cwo/lead-authority.json")
_MAX_REQUEST = 512
_MAX_DOCUMENT = 4 * 1024 * 1024
_TIMEOUT = 3.0
_OPERATION = re.compile(r"[a-z][a-z0-9-]{0,63}")
_REFERENCE = re.compile(r"[0-9a-f]{64}")
_HEADER = struct.Struct("!I")
_CREDENTIALS = struct.Struct("=iII")


class AuthorityError(ValueError):
    """The requested approval, host identity or custody boundary was refused."""


@dataclass(frozen=True)
class AuthorityLayout:
    host_uid: int
    lead_uid: int
    source_root: Path
    config_root: Path
    state_root: Path
    socket_path: Path

    def __post_init__(self):
        if not all(type(uid) is int and 0 <= uid < 2**32 - 1 for uid in (self.host_uid, self.lead_uid)):
            raise AuthorityError("invalid authority principals")
        if self.lead_uid in (0, self.host_uid):
            raise AuthorityError("authority requires a separate unprivileged lead UID")
        for path in (self.source_root, self.config_root, self.state_root, self.socket_path):
            _canonical_path(path)


def _canonical_path(path):
    if not isinstance(path, Path) or path.anchor != "/" or not path.name or ".." in path.parts:
        raise AuthorityError("authority requires a fixed absolute path")


def _require_role(uid):
    if os.getuid() != uid or os.geteuid() != uid:
        raise AuthorityError("wrong authority principal")


def _check_owner(info, owners, *, ancestor=False):
    if info.st_uid not in owners:
        raise AuthorityError("authority directory owner is untrusted")
    sticky_root = ancestor and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
    if info.st_mode & 0o022 and not sticky_root:
        raise AuthorityError("authority path is writable by other principals")


@contextmanager
def _protected_directory(path, owners):
    if not hasattr(os, "O_PATH") or not hasattr(socket, "SO_PEERCRED"):
        raise AuthorityError("authority requires Linux Unix-socket peer credentials")
    flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_PATH
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            _check_owner(os.fstat(descriptor), owners, ancestor=True)
            following = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        _check_owner(os.fstat(descriptor), owners)
        yield descriptor
    finally:
        os.close(descriptor)


def _walk_error(failure):
    raise failure


def _check_protected_tree(path, owners):
    with _protected_directory(path, owners) as descriptor:
        for _, folders, files, current in os.fwalk(".", dir_fd=descriptor, onerror=_walk_error):
            for name in folders + files:
                info = os.stat(name, dir_fd=current, follow_symlinks=False)
                if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                    raise AuthorityError("authority installation contains an unsafe entry")
                _check_owner(info, owners)


def _validate_host(layout):
    _require_role(layout.host_uid)
    if not Path(__file__).absolute().is_relative_to(layout.source_root):
        raise AuthorityError("authority is running outside the protected installation")
    try:
        _check_protected_tree(layout.source_root, {0, layout.host_uid})
        with _protected_directory(layout.config_root, {0}), _protected_directory(
                layout.state_root, {0, layout.host_uid}) as state:
            info = os.fstat(state)
            if info.st_uid != layout.host_uid or stat.S_IMODE(info.st_mode) != 0o700:
                raise AuthorityError("authority state must be private to the host principal")
    except OSError as failure:
        raise AuthorityError("authority installation or state is unavailable") from failure


def _check_operation(operation):
    if type(operation) is not str or _OPERATION.fullmatch(operation) is None:
        raise AuthorityError("invalid authority operation")


def _check_request(operation, reference):
    _check_operation(operation)
    if type(reference) is not str or _REFERENCE.fullmatch(reference) is None:
        raise AuthorityError("invalid approval reference")


def _decode(raw):
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as failure:
        raise AuthorityError("invalid authority JSON") from failure
    if type(value) is not dict:
        raise AuthorityError("authority JSON requires an object")
    return value


def _encode(value, limit):
    if type(value) is not dict:
        raise AuthorityError("authority JSON requires an object")
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as failure:
        raise AuthorityError("invalid authority JSON") from failure
    if len(raw) > limit:
        raise AuthorityError("authority JSON exceeds its byte limit")
    return raw


class ApprovalStore:
    """Immutable operator decisions in the separately owned host directory."""

    def __init__(self, layout: AuthorityLayout):
        _validate_host(layout)
        self._layout = layout

    def publish(self, operation: str, payload: dict) -> str:
        from .private_artifact import PrivateArtifactError, PrivateDirectory

        _require_role(self._layout.host_uid)
        _check_operation(operation)
        if type(payload) is not dict:
            raise AuthorityError("approval payload requires an object")
        reference = secrets.token_hex(32)
        raw = _encode({"operation": operation, "reference": reference, "payload": payload}, _MAX_DOCUMENT)
        try:
            with PrivateDirectory.open(self._layout.state_root) as directory:
                directory.write(reference + ".json", raw)
        except PrivateArtifactError as failure:
            raise AuthorityError("could not retain approval") from failure
        return reference

    def require(self, operation: str, reference: str) -> dict:
        from .private_artifact import PrivateArtifactError, PrivateDirectory

        _require_role(self._layout.host_uid)
        _check_request(operation, reference)
        try:
            with PrivateDirectory.open(self._layout.state_root) as directory:
                record = _decode(directory.read(reference + ".json", max_bytes=_MAX_DOCUMENT))
        except PrivateArtifactError as failure:
            raise AuthorityError("approval is unavailable") from failure
        if set(record) != {"operation", "reference", "payload"} or type(record["payload"]) is not dict:
            raise AuthorityError("invalid retained approval")
        if (record["operation"], record["reference"]) != (operation, reference):
            raise AuthorityError("approval does not match this operation")
        return record["payload"]


def _peer_uid(connection):
    _, uid, _ = _CREDENTIALS.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size))
    return uid


def _receive_exact(connection, size, deadline):
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AuthorityError("authority request timed out")
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise AuthorityError("truncated authority frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _receive(connection, limit):
    deadline = time.monotonic() + _TIMEOUT
    size, = _HEADER.unpack(_receive_exact(connection, _HEADER.size, deadline))
    if not 0 < size <= limit:
        raise AuthorityError("invalid authority frame size")
    return _decode(_receive_exact(connection, size, deadline))


def _send(connection, value, limit):
    raw = _encode(value, limit)
    connection.settimeout(_TIMEOUT)
    connection.sendall(_HEADER.pack(len(raw)) + raw)


class AuthorityHost:
    """Serve one authenticated, allowlisted request at a time on a fixed socket."""

    def __init__(self, layout: AuthorityLayout, handlers: Mapping[str, Callable[[dict], dict]] | None = None):
        self._store = ApprovalStore(layout)
        self._layout = layout
        self._handlers = dict(handlers or {})
        for name in self._handlers:
            _check_operation(name)
        if not all(callable(handler) for handler in self._handlers.values()):
            raise AuthorityError("authority handlers must be callable")
        self._listener = None

    def __enter__(self):
        _require_role(self._layout.host_uid)
        if self._listener is not None:
            raise AuthorityError("authority host is already listening")
        path = self._layout.socket_path
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound = False
        try:
            with _protected_directory(path.parent, {0, self._layout.host_uid}):
                listener.bind(str(path))
                bound = True
            path.chmod(0o666)
            listener.listen(8)
        except BaseException:
            listener.close()
            if bound:
                path.unlink(missing_ok=True)
            raise
        self._listener = listener
        return self

    def __exit__(self, *_):
        self._listener.close()
        self._listener = None
        self._layout.socket_path.unlink(missing_ok=True)

    def _reply(self, message):
        if set(message) != {"operation", "reference"}:
            raise AuthorityError("unknown authority request fields")
        operation, reference = message["operation"], message["reference"]
        _check_operation(operation)
        handler = self._handlers.get(operation)
        if handler is None:
            raise AuthorityError("authority operation is unavailable")
        result = handler(self._store.require(operation, reference))
        return {"result": result}

    def serve_once(self) -> None:
        _require_role(self._layout.host_uid)
        if self._listener is None:
            raise AuthorityError("authority host is unavailable")
        connection, _ = self._listener.accept()
        with connection:
            try:
                if _peer_uid(connection) != self._layout.lead_uid:
                    return
                _send(connection, self._reply(_receive(connection, _MAX_REQUEST)), _MAX_DOCUMENT)
            except (CWOError, OSError, ValueError, KeyError, TypeError, RecursionError, SystemExit):
                try:
                    _send(connection, {"error": "authority request refused"}, _MAX_DOCUMENT)
                except OSError:
                    pass


class AuthorityClient:
    """Request an approved operation from a locally authenticated host."""

    def __init__(self, socket_path: Path, host_uid: int):
        _canonical_path(socket_path)
        if type(host_uid) is not int or not 0 <= host_uid < 2**32 - 1:
            raise AuthorityError("invalid authority host UID")
        self._socket_path = socket_path
        self._host_uid = host_uid

    def _connect(self, connection):
        path = self._socket_path
        with _protected_directory(path.parent, {0, self._host_uid}) as parent:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if info.st_uid != self._host_uid or not stat.S_ISSOCK(info.st_mode):
                raise AuthorityError("authority socket has an untrusted owner or type")
            connection.settimeout(_TIMEOUT)
            connection.connect(str(path))
            if _peer_uid(connection) != self._host_uid:
                raise AuthorityError("authority host UID does not match the protected configuration")

    def request(self, operation: str, reference: str) -> dict:
        _check_request(operation, reference)
        if not hasattr(os, "geteuid"):
            raise AuthorityError("authority requires Linux Unix-socket peer credentials")
        if self._host_uid == os.geteuid():
            raise AuthorityError("authority client requires a separate host UID")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                self._connect(connection)
                _send(connection, {"operation": operation, "reference": reference}, _MAX_REQUEST)
                response = _receive(connection, _MAX_DOCUMENT)
        except OSError as failure:
            raise AuthorityError("authority host is unavailable") from failure
        if set(response) == {"result"} and type(response["result"]) is dict:
            return response["result"]
        raise AuthorityError("authority request refused")


def _read_config(path):
    with _protected_directory(path.parent, {0}) as parent:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open(path.name, flags, dir_fd=parent), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
                raise AuthorityError("authority configuration file is untrusted")
            raw = stream.read(_MAX_REQUEST + 1)
    if len(raw) > _MAX_REQUEST:
        raise AuthorityError("authority configuration exceeds its byte limit")
    return _decode(raw)


def _configured_layout():
    try:
        fields = _read_config(_CONFIG_FILE)
    except OSError as failure:
        raise AuthorityError("authority is not configured") from failure
    names = {"schema_version", "host_uid", "lead_uid", "source_root", "state_root", "socket_path"}
    if set(fields) != names or type(fields["schema_version"]) is not int or fields["schema_version"] != 1:
        raise AuthorityError("invalid authority configuration")
    paths = (fields["source_root"], fields["state_root"], fields["socket_path"])
    if not all(type(path) is str for path in paths):
        raise AuthorityError("authority configuration paths must be strings")
    source, state, endpoint = map(Path, paths)
    return AuthorityLayout(fields["host_uid"], fields["lead_uid"], source, _CONFIG_FILE.parent, state, endpoint)


def configured_authority_layout() -> AuthorityLayout:
    """Load the administrator's fixed configuration under the host principal."""
    layout = _configured_layout()
    _require_role(layout.host_uid)
    return layout


def configured_authority_client() -> AuthorityClient:
    """Open the lead client using only the administrator's fixed configuration."""
    layout = _configured_layout()
    _require_role(layout.lead_uid)
    return AuthorityClient(layout.socket_path, layout.host_uid)


def configured_approval(operation: str, reference: str) -> dict:
    """Read an approval from either configured role, without changing principals."""
    layout = _configured_layout()
    if os.geteuid() == layout.host_uid:
        return ApprovalStore(layout).require(operation, reference)
    _require_role(layout.lead_uid)
    return AuthorityClient(layout.socket_path, layout.host_uid).request(operation, reference)
