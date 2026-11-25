"""Exercise the original foreground approval over a disposable MCP connection."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from threading import Thread
import unittest
from unittest.mock import patch

from tests import test_delegate_internal_work as native
from tests.test_registered_delegation_approval import fixture_preparation

import registered_delegation_approval as approval
import registered_delegation_foreground as foreground
import launch_architect


class ForegroundTests(unittest.TestCase):
    def setUp(self):
        self.inputs = native.make_workflow(self, from_setup=True)
        self.pending = approval.prepare_assignment(**fixture_preparation(self.inputs))
        self.project = self.inputs.case.host.target
        self.enterContext(patch.object(foreground.entry, 'retain_approved_assignment'))

    def connect(self, *, elicitation=True):
        front, controller = socket.socketpair()
        front.settimeout(5)
        self.addCleanup(front.close)
        source = self.enterContext(front.makefile('r', encoding='utf-8'))
        self.resolve = self.enterContext(patch.object(foreground, '_pending_assignment', return_value=self.pending))

        def run():
            with (controller, controller.makefile('r', encoding='utf-8') as read,
                  controller.makefile('w', encoding='utf-8') as write):
                foreground.serve(read, write, self.project)

        self.worker = Thread(target=run, daemon=True)
        self.worker.start()
        self.addCleanup(self.close, front)
        self.send = lambda **message: front.sendall((json.dumps({'jsonrpc': '2.0', **message}) + '\n').encode())
        self.receive = lambda: json.loads(source.readline())
        capabilities = {'elicitation': {'form': {}}} if elicitation else {}
        self.send(id=0, method='server/discover')
        self.assertEqual(self.receive()['error']['code'], -32601)
        self.send(id=1, method='initialize', params={'protocolVersion': '2025-11-25',
                  'clientInfo': {'name': 'EXAMPLE Codex', 'version': '0.172.0'}, 'capabilities': capabilities})
        self.assertEqual(self.receive()['result']['serverInfo']['name'], 'cwo-delegation')
        self.send(method='notifications/initialized')

    def close(self, front):
        front.shutdown(socket.SHUT_RDWR)
        self.worker.join(5)
        self.assertFalse(self.worker.is_alive())

    def request(self, **extra):
        self.send(id=2, method='tools/call', params={'name': 'authorize_assignment', 'arguments': {
            'task': self.inputs.task, 'baseline': 'EXAMPLE-baseline.json',
            'output_path': 'result.txt', 'output_text': native.F.fixtures.host_fixtures.OUTPUT.decode(), **extra}})

    def assert_unstarted(self):
        self.assertFalse(self.inputs.workflow.config.store.read_state()['operations'])
        self.assertFalse(self.inputs.fixture.spawned)

    def test_foreground_acceptance_retains_the_exact_assignment(self):
        self.connect()
        self.request()
        question = self.receive()
        self.assertEqual(question['method'], 'elicitation/create')
        self.assertIn(self.inputs.task, question['params']['message'])
        self.assertIn(str(self.project), question['params']['message'])
        self.assertIn('result.txt', question['params']['message'])
        self.assertIn(json.dumps(native.F.fixtures.host_fixtures.OUTPUT.decode()), question['params']['message'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.send(method='notifications/roots/list_changed')
        self.send(id=question['id'], result={'action': 'accept', 'content': {'approve': True}})
        self.assertFalse(self.receive()['result'].get('isError', False))
        retained = foreground.entry.retain_approved_assignment.call_args.args[0]
        scope, _directive = retained.config._standing_approval()
        self.assertEqual(scope, self.pending.approval_scope)
        self.assert_unstarted()

    def test_tool_arguments_cannot_provide_the_operator_decision(self):
        self.connect()
        self.request(action='accept')
        self.assertTrue(self.receive()['result']['isError'])
        self.resolve.assert_not_called()
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_replaced_output_bytes_are_refused_before_prompt(self):
        self.connect()
        self.request(output_text='EXAMPLE substituted text')
        self.assertTrue(self.receive()['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_declining_the_foreground_prompt_cannot_retain_assignment(self):
        self.connect()
        self.request()
        question = self.receive()
        self.send(id=question['id'], result={'action': 'decline'})
        self.assertTrue(self.receive()['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_cancelled_tool_call_cannot_retain_assignment(self):
        self.connect()
        self.request()
        question = self.receive()
        self.send(method='notifications/cancelled', params={'requestId': 2})
        self.send(id=question['id'], result={'action': 'accept', 'content': {'approve': True}})
        self.assertTrue(self.receive()['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_response_for_another_request_cannot_retain_assignment(self):
        self.connect()
        self.request()
        self.receive()
        self.send(id='EXAMPLE-wrong-request', result={'action': 'accept', 'content': {'approve': True}})
        self.assertTrue(self.receive()['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_empty_automatic_approval_does_not_replace_the_foreground_choice(self):
        self.connect()
        self.request()
        question = self.receive()
        self.assertEqual(question['params']['requestedSchema']['required'], ['approve'])
        self.assertIs(question['params']['_meta']['codex_requires_user_input'], True)
        self.send(id=question['id'], result={'action': 'accept', 'content': {}})
        self.assertTrue(self.receive()['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_retained_approval_does_not_prompt_again(self):
        self.connect()
        self.resolve.return_value = None
        self.request()
        response = self.receive()
        self.assertEqual(response['id'], 2)
        self.assertFalse(response['result']['isError'])
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()

    def test_client_without_foreground_prompt_support_cannot_retain_assignment(self):
        self.connect(elicitation=False)
        self.request()
        self.assertTrue(self.receive()['result']['isError'])
        self.resolve.assert_not_called()
        foreground.entry.retain_approved_assignment.assert_not_called()
        self.assert_unstarted()


class LauncherTests(unittest.TestCase):
    def launch(self, *arguments, terminal=True):
        with (patch.object(sys, 'argv', ['cwo-codex', *arguments]),
              patch.object(sys.stdin, 'isatty', return_value=terminal),
              patch.object(sys.stdout, 'isatty', return_value=terminal),
              patch.object(launch_architect, 'configure_cli_model_catalog'),
              patch.object(launch_architect.shutil, 'which', return_value='/tmp/EXAMPLE-bin/codex'),
              patch.object(launch_architect.os, 'execvp') as execvp):
            launch_architect.main()
        return execvp.call_args.args[1]

    def test_local_foreground_uses_installed_controller_in_selected_checkout(self):
        project = Path('/tmp/EXAMPLE project')
        command = self.launch('-C', str(project))
        settings = dict(item.split('=', 1) for item in command if item.startswith('mcp_servers.'))
        prefix = 'mcp_servers.cwo-delegation.'
        self.assertEqual(json.loads(settings[prefix + 'cwd']), str(project))
        self.assertEqual(json.loads(settings[prefix + 'command']), sys.executable)
        arguments = json.loads(settings[prefix + 'args'])
        self.assertEqual(Path(arguments[-3]), Path(foreground.__file__).resolve())
        self.assertEqual(arguments[-2:], [str(os.getpid()), '/tmp/EXAMPLE-bin/codex'])
        self.assertIn('--no-daemon', command)
        self.assertEqual(command[-2:], ['-C', str(project)])

    def test_remote_and_noninteractive_launches_have_no_foreground_authority_tool(self):
        self.assertFalse(any('mcp_servers.cwo-delegation' in item for item in self.launch('--remote=unix://')))
        self.assertFalse(any('mcp_servers.cwo-delegation' in item for item in self.launch(terminal=False)))

    def test_direct_script_with_framed_stdin_refuses_before_mcp_negotiation(self):
        direct = subprocess.run([sys.executable, foreground.__file__, str(os.getpid()), sys.executable],
                                input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(direct.returncode, 0)
        self.assertFalse(direct.stdout)
        self.assertIn('local cwo-codex foreground', direct.stderr)

    def test_registered_parent_keeps_both_transport_pipes(self):
        with TemporaryDirectory() as directory:
            codex = Path(directory) / 'codex'
            codex.symlink_to(sys.executable)
            child = dedent("""\
                import json, subprocess, sys
                arguments = json.loads(sys.argv[2].split('=', 1)[1])
                messages = [
                    {'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'}},
                    {'method': 'notifications/initialized'},
                    {'id': 2, 'method': 'tools/list'},
                ]
                frames = ''.join(json.dumps({'jsonrpc': '2.0', **message}) + '\\n' for message in messages)
                with subprocess.Popen([sys.executable, *arguments], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True) as outcome:
                    outcome.stdin.write(frames)
                    outcome.stdin.flush()
                    print(outcome.stdout.readline() + outcome.stdout.readline(), end='')
                    outcome.stdin.close()
                if outcome.returncode:
                    raise SystemExit(outcome.returncode)
                """)
            parent = dedent("""\
                import json, os, sys
                codex, script, child = sys.argv[1:]
                arguments = ['-B', '-E', '-s', script, str(os.getpid()), codex]
                registration = 'mcp_servers.cwo-delegation.args=' + json.dumps(arguments)
                os.execv(codex, [codex, '-c', child, '--no-daemon', registration])
                """)
            run = subprocess.run([sys.executable, '-c', parent, str(codex), foreground.__file__, child],
                                 cwd=directory, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        messages = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(messages[1]['result']['tools'][0]['name'], 'authorize_assignment')


if __name__ == '__main__':
    unittest.main()
