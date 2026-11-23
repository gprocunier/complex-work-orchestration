"""Run-local HTTPS egress for the isolated registered N1 app server."""
from __future__ import annotations

from contextlib import ExitStack
import io
import ipaddress
import os
from pathlib import Path
import re
import select
import selectors
import socket
import sys
import threading
import time


PROVIDERS = frozenset({'api.openai.com', 'chatgpt.com'})
_PERSONAL_ACCESS_TOKEN_PROVIDERS = PROVIDERS | {'auth.openai.com'}
RELAY_SOURCE = Path(__file__).resolve()
RELAY_MOUNT = '/cwo/provider-network.py'
PROXY_PORT = 24671
_TIMEOUT = 5
_MAX_CONNECTIONS = 8
_CONNECT = re.compile(rb'CONNECT ([a-zA-Z0-9.-]{1,253}):443 HTTP/1\.[01]')
_READY = b'cwo-boundary-ready\n'
_MAX_ACCESS_TOKEN_BYTES = 4096  # Linux PIPE_BUF, so staging needs only one bounded write.
_ACCESS_TOKEN = re.compile(rb'at-[A-Za-z0-9._~+/-]+=*')


def _valid_access_token(value):
    return len(value) <= _MAX_ACCESS_TOKEN_BYTES and _ACCESS_TOKEN.fullmatch(value) is not None


def personal_access_token_bytes(value):
    if type(value) is str and len(value) <= _MAX_ACCESS_TOKEN_BYTES and value.isascii():
        encoded = value.encode('ascii')
        if _valid_access_token(encoded):
            return encoded
    raise ValueError('A bounded Codex personal access token is required.')


class ProviderNetworkError(RuntimeError):
    """The original network resources or durable denial evidence failed."""


class _Refused(Exception):
    """Only fixed, scrubbed reasons may enter the denial record."""


class _Reader:
    def __init__(self, stream):
        self.stream = stream
        self.pending = bytearray()
        self.deadline = time.monotonic() + _TIMEOUT

    def _receive(self, reason):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise _Refused(reason)
        self.stream.settimeout(seconds)
        try:
            data = self.stream.recv(4096)
        except OSError as failure:
            raise _Refused(reason) from failure
        if not data:
            raise _Refused(reason)
        self.pending.extend(data)

    def headers(self):
        marker = b'\r\n\r\n'
        while marker not in self.pending and len(self.pending) < 8192:
            self._receive('invalid-connect')
        end = self.pending.find(marker)
        if not 0 < end <= 8192 - len(marker):
            raise _Refused('invalid-connect')
        answer = bytes(self.pending[:end])
        del self.pending[:end + len(marker)]
        return answer

    def read(self, size):
        while len(self.pending) < size:
            self._receive('invalid-tls-client-hello')
        answer = bytes(self.pending[:size])
        del self.pending[:size]
        return answer


def _destination(reader, providers):
    first_line = reader.headers().split(b'\r\n', 1)[0]
    match = _CONNECT.fullmatch(first_line)
    if match is None:
        raise _Refused('invalid-connect')
    host = match[1].decode('ascii').lower()
    if host not in providers:
        raise _Refused('destination-not-allowed')
    return host


def _client_hello(reader):
    """Return the exact wire records and one ClientHello body."""
    wire, handshake = bytearray(), bytearray()
    for _ in range(8):
        header = reader.read(5)
        length = int.from_bytes(header[3:], 'big')
        if header[0] != 22 or header[1] != 3 or not 0 < length <= 16384:
            break
        fragment = reader.read(length)
        wire.extend(header + fragment)
        handshake.extend(fragment)
        if len(handshake) < 4:
            continue
        expected = 4 + int.from_bytes(handshake[1:4], 'big')
        if handshake[0] != 1 or expected > 65536 or len(handshake) > expected:
            break
        if len(handshake) == expected:
            return bytes(wire), bytes(handshake[4:])
    raise _Refused('invalid-tls-client-hello')


def _exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise _Refused('invalid-tls-client-hello')
    return data


def _vector(stream, width):
    return _exact(stream, int.from_bytes(_exact(stream, width), 'big'))


def _name(extension):
    data = io.BytesIO(extension)
    names = io.BytesIO(_vector(data, 2))
    if data.read(1) or _exact(names, 1) != b'\0':
        raise _Refused('invalid-tls-client-hello')
    host = _vector(names, 2).lower()
    if names.read(1):
        raise _Refused('invalid-tls-client-hello')
    return host


def _validate_tls_name(hello, host):
    data = io.BytesIO(hello)
    _exact(data, 34)  # legacy protocol version and 32-byte random value
    _vector(data, 1)  # legacy session ID
    _vector(data, 2)  # cipher suites
    _vector(data, 1)  # legacy compression methods
    extensions = _vector(data, 2)
    if data.read(1):
        raise _Refused('invalid-tls-client-hello')
    source = io.BytesIO(extensions)
    name = None
    while source.tell() < len(extensions):
        kind = _exact(source, 2)
        extension = _vector(source, 2)
        if kind == b'\xfe\x0d':
            raise _Refused('encrypted-client-hello')
        if kind == b'\0\0':
            if name is not None:
                raise _Refused('invalid-tls-client-hello')
            name = _name(extension)
    if name != host.encode('ascii'):
        raise _Refused('tls-server-name-mismatch')


def _public_address(family, address):
    ip = ipaddress.ip_address(address[0])
    if not ip.is_global or ip.is_multicast or ip.is_reserved:
        return False
    if family == socket.AF_INET6:
        return ip.version == 6 and ip.ipv4_mapped is None and address[3] == 0
    return family == socket.AF_INET and ip.version == 4


def _resolved_provider(host):
    try:
        answers = socket.getaddrinfo(host + '.', 443, type=socket.SOCK_STREAM,
                                     proto=socket.IPPROTO_TCP, flags=socket.AI_NUMERICSERV)
    except OSError as failure:
        raise _Refused('provider-resolution-failed') from failure
    addresses = list(dict.fromkeys((family, address) for family, _kind, _proto, _name, address in answers))
    if not addresses or any(not _public_address(family, addr) for family, addr in addresses):
        raise _Refused('provider-address-not-public')
    return addresses[:8]


def _dial_provider(host, deadline, stopped):
    for family, address in _resolved_provider(host):
        seconds = deadline - time.monotonic()
        if stopped.is_set() or seconds <= 0:
            break
        upstream = socket.socket(family, socket.SOCK_STREAM)
        try:
            upstream.settimeout(seconds)
            upstream.connect(address)
            return upstream
        except OSError:
            upstream.close()
    raise _Refused('provider-connect-failed')


def _bridge(left, right, stopped):
    peers = {left: right, right: left}
    try:
        with selectors.DefaultSelector() as selector:
            for stream in peers:
                stream.settimeout(_TIMEOUT)
                selector.register(stream, selectors.EVENT_READ)
            while peers and not stopped.is_set():
                for key, _ in selector.select(.25):
                    _transfer(selector, peers, key.fileobj)
    except OSError:
        return


def _transfer(selector, peers, stream):
    data = stream.recv(65536)
    if data:
        peers[stream].sendall(data)
    else:
        selector.unregister(stream)
        peers.pop(stream).shutdown(socket.SHUT_WR)


class _Connections:
    """Own at most a fixed number of concurrent streams."""

    def __init__(self, limit):
        self.limit = limit
        self.stopped = threading.Event()
        self.active = {}
        self.lock = threading.Lock()
        self.failure = None

    def start(self, client, handler):
        with self.lock:
            if self.stopped.is_set() or len(self.active) >= self.limit:
                client.close()
                return False
            task = threading.Thread(target=self._run, args=(client, handler), daemon=True)
            self.active[client] = task
            try:
                task.start()
            except BaseException:
                del self.active[client]
                client.close()
                raise
        return True

    def _run(self, client, handler):
        try:
            with client:
                handler(client)
        except Exception as failure:
            self.fail(failure)
        finally:
            with self.lock:
                del self.active[client]

    def fail(self, failure):
        with self.lock:
            if self.failure is None:
                self.failure = failure
        self.revoke()

    def revoke(self):
        self.stopped.set()
        with self.lock:
            for stream in self.active:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def join(self, deadline):
        with self.lock:
            tasks = tuple(self.active.values())
        for task in tasks:
            task.join(max(0, deadline - time.monotonic()))
        if any(task.is_alive() for task in tasks):
            raise ProviderNetworkError('The provider connection cleanup did not settle.')


def _handoff(control):
    """Open one local stream and pass its peer only to the original broker."""
    client, broker = socket.socketpair()
    try:
        with broker:
            if socket.send_fds(control, [b'1'], [broker.fileno()]) != 1:
                raise OSError('Provider connection handoff was incomplete.')
    except BaseException:
        client.close()
        raise
    return client


def _receive_handoff(control):
    message, descriptors, flags, _address = socket.recv_fds(control, 1, 1, socket.MSG_CMSG_CLOEXEC)
    if message == b'1' and len(descriptors) == 1 and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        return socket.socket(fileno=descriptors[0])
    for descriptor in descriptors:
        os.close(descriptor)
    raise ProviderNetworkError('The original relay handoff was invalid.')


class ProviderBroker:
    """The host owns DNS, endpoint policy and every outbound socket."""

    def __init__(self, record, *, allow_personal_access_token=False, allow_managed_login=False):
        self._record = record
        self._providers = (_PERSONAL_ACCESS_TOKEN_PROVIDERS
                           if allow_personal_access_token or allow_managed_login else PROVIDERS)
        self._connections = _Connections(_MAX_CONNECTIONS)
        self._control, self.child_socket = socket.socketpair(type=socket.SOCK_DGRAM)
        self._control.settimeout(.25)
        self.child_socket.settimeout(.25)
        self._closed = False
        self._owner = threading.Thread(target=self._serve, name='cwo-provider-broker', daemon=True)
        try:
            self._owner.start()
        except BaseException:
            self._control.close()
            self.child_socket.close()
            raise

    def _serve(self):
        try:
            while not self._connections.stopped.is_set():
                self._receive()
        except Exception as failure:
            self._connections.fail(failure)

    def _receive(self):
        try:
            client = _receive_handoff(self._control)
        except TimeoutError:
            return
        if not self._connections.start(client, self._handle) and not self._connections.stopped.is_set():
            self._record('connection-limit')

    def _handle(self, client):
        reader = _Reader(client)
        acknowledged = False
        try:
            host = _destination(reader, self._providers)
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            acknowledged = True
            wire, hello = _client_hello(reader)
            _validate_tls_name(hello, host)
            self._tunnel(client, host, wire + reader.pending)
        except _Refused as refusal:
            if not self._connections.stopped.is_set():
                self._record(str(refusal))
            if not acknowledged:
                _send_refusal(client)
        except OSError:
            return

    def _tunnel(self, client, host, initial):
        stopped = self._connections.stopped
        with _dial_provider(host, time.monotonic() + _TIMEOUT, stopped) as upstream:
            if not stopped.is_set():
                upstream.sendall(initial)
                _bridge(client, upstream, stopped)

    def revoke(self):
        self._connections.revoke()

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.revoke()
        deadline = time.monotonic() + _TIMEOUT + 1
        self._owner.join(max(0, deadline - time.monotonic()))
        self._control.close()
        self.child_socket.close()
        self._connections.join(deadline)
        if self._owner.is_alive():
            raise ProviderNetworkError('The provider broker cleanup did not settle.')
        if self._connections.failure is not None:
            raise ProviderNetworkError('The original provider broker or denial record failed.') from self._connections.failure


def _send_refusal(client):
    try:
        client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    except OSError:
        pass


def _serve_relay(listener, control):
    connections = _Connections(_MAX_CONNECTIONS * 2)

    def forward(client):
        with _handoff(control) as broker:
            _bridge(client, broker, connections.stopped)

    while not connections.stopped.is_set():
        connections.start(listener.accept()[0], forward)


def _fork_relay(listener, control, access_token_fd):
    if os.fork() != 0:
        return
    try:
        if access_token_fd != -1:
            os.close(access_token_fd)
        os.closerange(0, 3)
        _serve_relay(listener, control)
    finally:
        os._exit(74)


def _start_relay(descriptor, access_token_fd):
    with socket.socket(fileno=descriptor) as control, socket.socket() as listener:
        control.set_inheritable(False)
        control.settimeout(.25)
        listener.bind(('127.0.0.1', PROXY_PORT))
        listener.listen(_MAX_CONNECTIONS)
        _fork_relay(listener, control, access_token_fd)
    proxy = f'http://127.0.0.1:{PROXY_PORT}'
    os.environ.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy)


def _read_access_token(attachment):
    data = attachment.read(_MAX_ACCESS_TOKEN_BYTES + 1)
    if not _valid_access_token(data):
        raise SystemExit(73)
    return data.decode('ascii')


def _bootstrap(descriptor, access_token_fd, command):
    with ExitStack() as cleanup:
        attachment = (None if access_token_fd == -1
                      else cleanup.enter_context(os.fdopen(access_token_fd, 'rb')))
        _start_relay(descriptor, access_token_fd)
        os.write(1, _READY)
        if not select.select([0], [], [], 10)[0] or os.read(0, 1) != b'1':
            raise SystemExit(73)
        token = None if attachment is None else _read_access_token(attachment)
    if token is not None:
        os.environ['CODEX_ACCESS_TOKEN'] = token
    os.execv(command[0], command)


if __name__ == '__main__':
    _bootstrap(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:])
