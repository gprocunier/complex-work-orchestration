"""Interpreter spellings share classification and typed-source refusal."""
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tests.test_checked_command import spec
from cwo_core.checked_command import classify_command_complexity, execute_checked_command


class InterpreterSourceTests(unittest.TestCase):
    def test_versioned_and_option_prefixed_inline_source_refuses_before_process(self):
        with tempfile.TemporaryDirectory() as root:
            for argv in ([sys.executable, '-c', 'print(1)'], ['python3.12','-I','-c','print(1)'],
                         ['python3.14','-X','dev','-cprint(1)'], ['python','-W','ignore','-Icprint(1)'],
                         ['sh','-ec','printf unsafe'], ['bash','-o','errexit','-c','printf unsafe'], ['bash','-m','-c','printf unsafe'],
                         ['bash','--rcfile','/dev/null','-c','printf unsafe'], ['sh','-mc','printf unsafe']):
                with self.subTest(argv=argv), patch('subprocess.Popen') as launch:
                    value=spec(root,argv=argv)
                    self.assertIn('interpreter-inline-source',classify_command_complexity(value)['reasons'])
                    result=execute_checked_command(value)
                    self.assertEqual(result['failure_class'],'typed-source-required')
                    self.assertFalse(result['execution_started']);launch.assert_not_called()

    def test_real_interpreter_option_matrix_and_zero_guard_launches(self):
        marker='CWO_SAFE_SOURCE_PROBE'
        shell_options=[['-c'],['-mc'],['-m','-c'],['-oc','errexit'],['-co','errexit'],
                       ['-Oc','nullglob'],['-cO','nullglob'],['-moc','errexit'],
                       ['-moOc','errexit','nullglob'],['-oOc','errexit','nullglob'],
                       ['--rcfile','/dev/null','-c'],['--init-file','/dev/null','-c'],
                       ['--noprofile','--norc','-c'],['+m','-oc','errexit'],
                       ['-o','errexit','-O','nullglob','-c'],['-xoc','errexit']]
        commands=[['bash',*options,'printf '+marker] for options in shell_options]
        commands += [[sys.executable,*options,'print("'+marker+'")'] for options in
                     (['-Ic'],['-I','-c'],['-W','ignore','-c'],['-X','dev','-c'],
                      ['-Xdev','-Iuc'],['--check-hash-based-pycs','never','-c'])]
        with tempfile.TemporaryDirectory() as root:
            for argv in commands:
                with self.subTest(argv=argv):
                    observed=subprocess.run(argv,capture_output=True,text=True,cwd=root,timeout=10)
                    self.assertEqual(observed.returncode,0,observed.stderr)
                    self.assertEqual(observed.stdout.strip(),marker)
                    with patch('subprocess.Popen',wraps=subprocess.Popen) as launch:
                        value=spec(root,argv=argv)
                        self.assertIn('interpreter-inline-source',classify_command_complexity(value)['reasons'])
                        result=execute_checked_command(value)
                        self.assertEqual(result['failure_class'],'typed-source-required')
                        launch.assert_not_called()
            with patch('subprocess.Popen',wraps=subprocess.Popen) as launch:
                self.assertEqual(execute_checked_command(spec(root))['execution_status'],'passed')
                self.assertEqual(launch.call_count,1)

    def test_script_module_and_version_positives(self):
        with tempfile.TemporaryDirectory() as root:
            for argv in ([sys.executable,'--version'], ['python3.14','script.py','-c'],
                         ['python3.14','-m','module','-c'], ['python3.14','-Immodule','-c'],
                         ['python3.14','-W','-c','script.py'], ['bash','--rcfile','-c','script.sh'], ['sh','script.sh','-c']):
                with self.subTest(argv=argv):
                    self.assertNotIn('interpreter-inline-source',classify_command_complexity(spec(root,argv=argv))['reasons'])
            self.assertEqual(execute_checked_command(spec(root))['execution_status'],'passed')
