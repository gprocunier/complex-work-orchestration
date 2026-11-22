"""Offline witnesses for the registered N1 provider network boundary."""
import errno
from pathlib import Path
import os
import queue
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import registered_provider_network as network  # noqa: E402
import registered_n1_factory as runtime  # noqa: E402

_EXAMPLE_TLS = Path(__file__).resolve().parent / 'fixtures/registered-provider-network/EXAMPLE-local-tls.pem'
_EXAMPLE_ACCESS_TOKEN = b'at-EXAMPLE-offline-qualification'


def _hello(host):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        return outgoing.read()
    raise AssertionError('A TLS client handshake must wait for its server')


class ProviderNetworkTests(unittest.TestCase):
    def setUp(self):
        self.denials = queue.Queue()
        self.broker = network.ProviderBroker(self.denials.put)
        self.addCleanup(self.broker.close)

    def client(self):
        client = network._handoff(self.broker.child_socket)
        self.addCleanup(client.close)
        client.settimeout(3)
        return client

    def test_provider_endpoint_receives_validated_tls_byte_stream(self):
        hello = _hello('chatgpt.com')
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        received = queue.Queue()

        def endpoint():
            with listener.accept()[0] as upstream:
                upstream.settimeout(3)
                with upstream.makefile('rb') as stream:
                    received.put(stream.read(len(hello)))
                upstream.sendall(b'synthetic provider response')

        backend = threading.Thread(target=endpoint, daemon=True)
        backend.start()
        self.addCleanup(backend.join, 4)
        with patch.object(network, '_dial_provider', side_effect=lambda *args: socket.create_connection(
                listener.getsockname(), timeout=2)) as dial:
            client = self.client()
            client.sendall(b'CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n')
            self.assertIn(b'200', client.recv(1024))
            client.sendall(hello)
            self.assertEqual(client.recv(1024), b'synthetic provider response')
            self.assertEqual(received.get(timeout=3), hello)
            self.assertEqual(dial.call_args.args[0], 'chatgpt.com')
        self.assertTrue(self.denials.empty())

    def test_non_provider_destination_is_recorded_without_dial_or_header_bytes(self):
        with patch.object(network, '_dial_provider') as dial:
            client = self.client()
            client.sendall(b'CONNECT denied.example:443 HTTP/1.1\r\nAuthorization: synthetic-secret\r\n\r\n')
            self.assertIn(b'403', client.recv(1024))
            self.assertEqual(self.denials.get(timeout=3), 'destination-not-allowed')
            dial.assert_not_called()

    def test_auth_host_without_attachment_is_refused_before_dial(self):
        with patch.object(network, '_dial_provider') as dial:
            client = self.client()
            client.sendall(b'CONNECT auth.openai.com:443 HTTP/1.1\r\n\r\n')
            self.assertIn(b'403', client.recv(1024))
            self.assertEqual(self.denials.get(timeout=3), 'destination-not-allowed')
            dial.assert_not_called()

    def test_attachment_keeps_exact_tls_name_and_connect_port(self):
        self.broker.close()
        self.broker = network.ProviderBroker(self.denials.put, allow_personal_access_token=True)
        self.addCleanup(self.broker.close)
        with patch.object(network, '_dial_provider') as dial:
            client = self.client()
            client.sendall(b'CONNECT auth.openai.com:8443 HTTP/1.1\r\n\r\n')
            self.assertIn(b'403', client.recv(1024))
            self.assertEqual(self.denials.get(timeout=3), 'invalid-connect')
            client = self.client()
            client.sendall(b'CONNECT auth.openai.com:443 HTTP/1.1\r\n\r\n')
            self.assertIn(b'200', client.recv(1024))
            client.sendall(_hello('chatgpt.com'))
            self.assertEqual(client.recv(1024), b'')
            self.assertEqual(self.denials.get(timeout=3), 'tls-server-name-mismatch')
            dial.assert_not_called()

    def test_a_different_tls_name_has_no_outbound_effect(self):
        with patch.object(network, '_dial_provider') as dial:
            client = self.client()
            client.sendall(b'CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n')
            self.assertIn(b'200', client.recv(1024))
            client.sendall(_hello('denied.example'))
            self.assertEqual(client.recv(1024), b'')
            self.assertEqual(self.denials.get(timeout=3), 'tls-server-name-mismatch')
            dial.assert_not_called()

    def test_a_private_provider_dns_result_is_refused(self):
        record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 443))
        with patch.object(network.socket, 'getaddrinfo', return_value=[record]) as resolve:
            self.assertEqual(self._refused_provider_hello(), 'provider-address-not-public')
            self.assertEqual(resolve.call_args.args[:2], ('chatgpt.com.', 443))

    def _refused_provider_hello(self):
        client = self.client()
        client.sendall(b'CONNECT chatgpt.com:443 HTTP/1.1\r\n\r\n')
        self.assertIn(b'200', client.recv(1024))
        client.sendall(_hello('chatgpt.com'))
        self.assertEqual(client.recv(1024), b'')
        return self.denials.get(timeout=3)

    def test_record_failure_revokes_broker(self):
        with patch.object(self.broker, '_record', side_effect=OSError('synthetic record failure')):
            client = self.client()
            client.sendall(b'CONNECT denied.example:443 HTTP/1.1\r\n\r\n')
            self.assertEqual(client.recv(1024), b'')
        with self.assertRaisesRegex(network.ProviderNetworkError, 'record'):
            self.broker.close()


_APP_SERVER = '''#!/usr/bin/python3 -I
import os, socket, ssl

try:
    open('appserver-should-not-write', 'w').close()
except OSError:
    pass
else:
    raise AssertionError('The app-server workspace must be read-only')

for entry in os.listdir('/proc/self/fd'):
    try:
        os.fstat(int(entry))
    except OSError:
        pass
    else:
        assert int(entry) <= 2

address = ('127.0.0.1', int(os.environ['HTTPS_PROXY'].rsplit(':', 1)[1]))
try:
    socket.create_connection(('127.0.0.1', int(open('provider-test.port').read())), timeout=1).close()
except OSError:
    pass
else:
    raise AssertionError('Unexpected direct host access')
with socket.create_connection(address, timeout=3) as stream:
    stream.sendall(b'CONNECT denied.example:443 HTTP/1.1\\r\\n\\r\\n')
    assert b'403' in stream.recv(1024)
token = os.environ.get('CODEX_ACCESS_TOKEN')
host = 'chatgpt.com' if token is None else 'auth.openai.com'
request = b'EXAMPLE provider request' if token is None else b'Authorization: Bearer ' + token.encode()
with socket.create_connection(address, timeout=3) as stream:
    stream.sendall(f'CONNECT {host}:443 HTTP/1.1\\r\\n\\r\\n'.encode())
    assert b'200' in stream.recv(1024)
    context = ssl.create_default_context(cafile='provider-test.pem')
    # The bundled loopback trust pin has just the model host name. The broker
    # still verifies the authority and requested TLS name for both witnesses.
    context.check_hostname = token is None
    with context.wrap_socket(stream, server_hostname=host) as tls:
        tls.sendall(request)
        assert tls.recv(1024) == b'EXAMPLE provider reply'
print('EXAMPLE provider reachable', flush=True)
os.read(0, 1)
'''

_OFFLINE_CHILD = '''import os, socket, sys

assert not any(name in os.environ for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'CODEX_ACCESS_TOKEN'))
assert not os.path.exists('/cwo/provider-network.py')
for entry in os.listdir('/proc/self/fd'):
    try:
        os.fstat(int(entry))
    except OSError:
        pass
    else:
        assert int(entry) <= 2
for port in sys.argv[1:]:
    try:
        socket.create_connection(('127.0.0.1', int(port)), timeout=1).close()
    except OSError:
        continue
    raise AssertionError('Unexpected provider or host access')
print('EXAMPLE child isolated')
'''


class ProviderAttachmentTests(unittest.TestCase):
    def attachment(self, data=_EXAMPLE_ACCESS_TOKEN):
        read, write = os.pipe()
        with os.fdopen(write, 'wb') as stream:
            stream.write(data)
        return read

    def test_early_gate_refusal_closes_without_reading_attachment(self):
        descriptor = self.attachment()
        with os.fdopen(os.dup(descriptor), 'rb') as witness:
            with (patch.object(network, '_start_relay'), patch.object(network.os, 'write'),
                  patch.object(network.select, 'select', return_value=([], [], [])),
                  patch.object(network.os, 'execv') as execute,
                  self.assertRaises(SystemExit) as refused):
                network._bootstrap(-1, descriptor, ['EXAMPLE-executable'])
            self.assertEqual(refused.exception.code, 73)
            execute.assert_not_called()
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual(witness.read(), _EXAMPLE_ACCESS_TOKEN)

    def test_malformed_descriptor_refuses_after_gate_without_exporting(self):
        descriptor = self.attachment(b'EXAMPLE-invalid-pipe-bytes')
        with (patch.object(network, '_start_relay'), patch.object(network.os, 'write'),
              patch.object(network.os, 'read', return_value=b'1'),
              patch.object(network.select, 'select', return_value=([0], [], [])),
              patch.object(network.os, 'environ', {}) as environment,
              patch.object(network.os, 'execv') as execute,
              self.assertRaises(SystemExit) as refused):
            network._bootstrap(-1, descriptor, ['EXAMPLE-executable'])
        self.assertEqual(refused.exception.code, 73)
        self.assertEqual(environment, {})
        execute.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_relay_closes_attachment_before_serving(self):
        descriptor = self.attachment()
        def serve(listener, control):
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertNotIn('CODEX_ACCESS_TOKEN', network.os.environ)
        with (patch.object(network.os, 'fork', return_value=0), patch.object(network.os, 'closerange'),
              patch.object(network.os, 'environ', {}), patch.object(network.os, '_exit', side_effect=SystemExit),
              patch.object(network, '_serve_relay', side_effect=serve) as run,
              self.assertRaises(SystemExit)):
            network._fork_relay('listener', 'control', descriptor)
        run.assert_called_once_with('listener', 'control')


class ProviderNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.launcher = '/usr/bin/bwrap'
        self.validator = str(Path('/usr/bin/python3').resolve())
        supported, reason = runtime.owned.atomic_spawn.supported()
        if not supported or not Path(self.launcher).is_file():
            self.skipTest(reason if not supported else 'The offline namespace prerequisite is unavailable')
        development = self.enterContext(tempfile.TemporaryDirectory(prefix='cwo-provider-test-', dir='/tmp'))
        root = Path(development).resolve()
        self.home, self.worker = root / 'home', root / 'worker'
        self.home.mkdir()
        (self.worker / '.git').mkdir(parents=True)
        executable = root / 'app-server'
        executable.write_text(_APP_SERVER)
        executable.chmod(0o700)
        self.records = queue.Queue()
        self.factory = SimpleNamespace(spec={'launcher': self.launcher, 'executable': str(executable),
            'validator': self.validator, 'configuration_files': {}}, host=SimpleNamespace(worker=self.worker),
            operation_id='EXAMPLE-provider-witness', server=None, require_effect=lambda: None,
            host_records=SimpleNamespace(assert_worker_roots_excluded=lambda roots: None),
            record=lambda stage, observation: self.records.put((stage, observation)),
            _take_provider_access_token=lambda: None,
            _protected_roots=lambda: ())
        self.lifetime = runtime._Containment(self.factory)
        self.addCleanup(self._close_lifetime)
        self.endpoint = self._synthetic_endpoint()
        (self.worker / 'provider-test.port').write_text(str(self.endpoint[1]))

    def _synthetic_endpoint(self):
        # Only the certificate enters the isolated client workspace. The
        # intentionally public test private key stays with the local endpoint.
        cert, end, _key = _EXAMPLE_TLS.read_bytes().partition(b'-----END CERTIFICATE-----\n')
        self.assertTrue(end)
        (self.worker / 'provider-test.pem').write_bytes(cert + end)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(_EXAMPLE_TLS)
        endpoint = self.enterContext(socket.socket())
        endpoint.bind(('127.0.0.1', 0))
        endpoint.listen(1)
        endpoint.settimeout(5)
        self.provider_request = queue.Queue()

        def serve():
            with endpoint.accept()[0] as stream:
                stream.settimeout(3)
                with context.wrap_socket(stream, server_side=True) as tls:
                    self.provider_request.put(tls.recv(1024))
                    tls.sendall(b'EXAMPLE provider reply')

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        self.addCleanup(server.join, 6)
        return endpoint.getsockname()

    def _run_offline_child(self, role):
        child = runtime._Containment(self.factory, role=role)
        self.assertEqual(child._provider_network_fds(), ())
        command = [self.validator, '-I', '-S', '-c', _OFFLINE_CHILD, str(network.PROXY_PORT), str(self.endpoint[1])]
        read_gate, write_gate = os.pipe()
        read_info, write_info = os.pipe()
        try:
            os.write(write_gate, b'1')
            argv = child._command(command, None, read_gate, write_info)
            return subprocess.run([*argv, '--', *command], pass_fds=(read_gate, write_info),
                                  capture_output=True, timeout=5, check=True)
        finally:
            for descriptor in (read_gate, write_gate, read_info, write_info):
                os.close(descriptor)

    @staticmethod
    def _only_child(pid):
        children = (Path('/proc') / str(pid) / 'task' / str(pid) / 'children').read_text().split()
        if len(children) != 1:
            raise AssertionError('Expected one owned child')
        return int(children[0])

    def _confirm_natural_exit_reaps_relay(self, process):
        cmd_pid = self._only_child(self.lifetime._namespace_pid)
        relay_pid = self._only_child(cmd_pid)
        relay = os.pidfd_open(relay_pid)
        try:
            self.assertFalse(select.select([relay], [], [], 0)[0])
            process.stdin.write('1')
            process.stdin.flush()
            self.assertTrue(select.select([relay], [], [], 5)[0])
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            os.close(relay)

    def _close_lifetime(self):
        lifetime = self.lifetime
        if lifetime.receipt is not None and not lifetime._ending:
            lifetime.terminate()
        if lifetime.controller is not None:
            lifetime.controller.close()
        if lifetime.process is not None:
            for stream in (lifetime.process.stdin, lifetime.process.stdout, lifetime.process.stderr):
                stream.close()

    def test_appserver_reaches_tls_provider_and_separate_children_cannot(self):
        # The signed permit path is exercised independently. Select only this
        # real launcher seam for the disposable, synthetic network witness.
        self.assertFalse(self.lifetime._provider_network_selected())
        with (patch.object(self.lifetime, '_provider_network_selected', return_value=True),
              patch.object(runtime.live_availability, 'N1_LIVE_AVAILABLE', True),
              patch.object(network, '_dial_provider', side_effect=lambda *_: socket.create_connection(
                  self.endpoint, timeout=2)) as dial):
            process = self.lifetime.launch([self.factory.spec['executable'], 'app-server', '--stdio'], self.home)
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertEqual(process.stdout.readline(), 'EXAMPLE provider reachable\n')
            self.assertEqual(self.provider_request.get(timeout=3), b'EXAMPLE provider request')
            for role in ('tool', 'validator'):
                self.assertEqual(self._run_offline_child(role).stdout, b'EXAMPLE child isolated\n')
            self.assertEqual(dial.call_count, 1)
            self.assertEqual(dial.call_args.args[0], 'chatgpt.com')
            self._confirm_natural_exit_reaps_relay(process)
            self.assertTrue(self.lifetime.terminate()['child_reaped'])
        self.assertFalse((self.worker / 'appserver-should-not-write').exists())
        self.assertEqual(self.records.get_nowait()[0], 'appserver-contained')
        self.assertEqual(self.records.get_nowait(), ('provider-network-denied', {'reason': 'destination-not-allowed'}))
        self.assertEqual(self.records.get_nowait()[0], 'appserver-terminated')
        self.assertTrue(self.records.empty())

    def test_appserver_delivers_attachment_over_auth_tls_and_separate_children_cannot(self):
        with (patch.object(self.lifetime, '_provider_network_selected', return_value=True),
              patch.object(self.factory, '_take_provider_access_token', return_value=_EXAMPLE_ACCESS_TOKEN),
              patch.object(runtime.live_availability, 'N1_LIVE_AVAILABLE', True),
              patch.object(network, '_dial_provider', side_effect=lambda *_: socket.create_connection(
                  self.endpoint, timeout=2)) as dial):
            process = self.lifetime.launch([self.factory.spec['executable'], 'app-server', '--stdio'], self.home)
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertEqual(process.stdout.readline(), 'EXAMPLE provider reachable\n')
            self.assertEqual(self.provider_request.get(timeout=3), b'Authorization: Bearer ' + _EXAMPLE_ACCESS_TOKEN)
            for role in ('tool', 'validator'):
                self.assertEqual(self._run_offline_child(role).stdout, b'EXAMPLE child isolated\n')
            self.assertEqual([call.args[0] for call in dial.call_args_list], ['auth.openai.com'])
            self._confirm_natural_exit_reaps_relay(process)
            self.assertTrue(self.lifetime.terminate()['child_reaped'])
        self.assertEqual(process.stderr.read(), '')
        self.assertNotIn(_EXAMPLE_ACCESS_TOKEN.decode(), repr(list(self.records.queue)))


class RegisteredMonitorExitTests(unittest.TestCase):
    def test_reaped_monitor_requires_original_identity_and_no_signal(self):
        lifetime = runtime._Containment(object())
        lifetime.receipt = object()
        lifetime.birth = SimpleNamespace(pid=371, receipt=lifetime.receipt, exit_confirmed=True, reaped=True)
        missing = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), '/proc/371/exe')
        complete = {'outcome': 'identity-unavailable', 'reason': str(missing), 'signals': [],
                    'child_pid': 371, 'child_exit_confirmed': True, 'child_reaped': True,
                    'registration_committed': True, 'receipt_available': False}
        lifetime.controller = SimpleNamespace(terminate=lambda *_args, **_kwargs: complete)
        self.assertIs(lifetime._terminate_monitor(), complete)

        for field, value in [('child_pid', 372), ('child_reaped', False), ('child_exit_confirmed', False),
                             ('receipt_available', True), ('signals', ['SIGTERM']), ('reason', 'unknown')]:
            with self.subTest(field=field):
                different = dict(complete, **{field: value})
                with patch.object(lifetime.controller, 'terminate', return_value=different):
                    with self.assertRaisesRegex(runtime.native.OfflineHostError, 'same-handle reaping'):
                        lifetime._terminate_monitor()
                    self.assertIs(lifetime.termination, different)

        lifetime.birth.reaped = False
        with self.assertRaisesRegex(runtime.native.OfflineHostError, 'same-handle reaping'):
            lifetime._terminate_monitor()


if __name__ == '__main__':
    unittest.main()
