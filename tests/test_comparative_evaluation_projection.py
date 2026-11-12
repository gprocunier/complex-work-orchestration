"""Study artifacts stay out of a real disposable installed skill."""
import json
import subprocess
import sys
import unittest
from tests import test_install_projection as fixture


class StudyProjectionTests(unittest.TestCase):
    def test_disposable_install_excludes_study_and_keeps_import_dependency_closure(self):
        install = fixture.InstallerProjectionTests('test_fresh_install_is_the_projection_and_its_resources_are_usable')
        install.setUp()
        self.addCleanup(install.tearDown)
        record = install.install()
        self.assertEqual(record['status'], 'current')
        manifest = fixture.checker.build_manifest(install.target)
        self.assertFalse((install.target / 'evaluation').exists())
        self.assertFalse(any(item['path'].startswith('evaluation/') for item in manifest['files']))
        # All75 frozen study paths, including protocol/hidden/probe/rehearsal/lock,
        # are excluded by the exact shared source/installed projection.
        study_files = [p.relative_to(fixture.ROOT) for p in (fixture.ROOT / 'evaluation').rglob('*') if p.is_file()]
        self.assertGreaterEqual(len(study_files), 75)
        for path in study_files:
            self.assertFalse((install.target / path).exists(), str(path))
        own = install.run_checker('--source-dir', str(install.target), '--installed-dir', str(install.target), '--check', source=install.target)
        self.assertEqual(own.returncode, 0, own.stdout + own.stderr)
        probe = '''import sys
from pathlib import Path
from unittest.mock import patch
root=Path(sys.argv[1]).resolve();sys.path.insert(0,str(root/'scripts'))
with patch('subprocess.Popen',side_effect=AssertionError('no process allowed')) as process,patch('urllib.request.urlopen',side_effect=AssertionError('no network allowed')) as network:
 from cwo_core import comparative_evaluation as study, frozen_protocol
 assert Path(study.__file__).resolve().is_relative_to(root)
 assert Path(frozen_protocol.__file__).resolve().is_relative_to(root)
 try:study.refuse_arm_execution('baseline',{'authorized':True})
 except study.HeldEffectRefused:pass
 else:raise AssertionError('held study effect did not refuse')
 assert process.call_count==network.call_count==0
print('installed dependency imports PASS; held arm refusal PASS; no process/network')
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(install.target)], capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(json.dumps({'case': 'actual disposable installed projection', 'excluded_study_files': len(study_files), 'evaluation_absent': True, 'installed_self_check': own.returncode, 'import_and_refusal_probe': result.stdout.strip()}))


if __name__ == '__main__':
    unittest.main()
