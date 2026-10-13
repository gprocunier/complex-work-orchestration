"""Causal images: positive pinning and rejection of changed bytes/modes/shapes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from cwo_core.maintenance_image import capture_control_image,require_control_image,MaintenanceImageError

class MaintenanceImageTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  for directory in ('scripts','policy','schemas','references','prompts'):(self.root/directory).mkdir()
  for name in ('SKILL.md','README.md','scripts/worker.py','policy/worker.yaml','schemas/worker.json'):
   (self.root/name).write_text('{}\n')
 def test_exact_image_accepts(self):
  value=capture_control_image(self.root);self.assertEqual(require_control_image(value,self.root),value)
 def test_causal_bytes_drift(self):
  value=capture_control_image(self.root);(self.root/'scripts/worker.py').write_text('changed')
  with self.assertRaises(MaintenanceImageError):require_control_image(value,self.root)
 def test_executable_mode_drift(self):
  value=capture_control_image(self.root);(self.root/'scripts/worker.py').chmod(0o700)
  with self.assertRaises(MaintenanceImageError):require_control_image(value,self.root)
 def test_new_causal_file_drift(self):
  value=capture_control_image(self.root);(self.root/'scripts/new.py').write_text('new')
  with self.assertRaises(MaintenanceImageError):require_control_image(value,self.root)
 def test_deleted_causal_file_drift(self):
  value=capture_control_image(self.root);(self.root/'scripts/worker.py').unlink()
  with self.assertRaises(MaintenanceImageError):require_control_image(value,self.root)
 def test_symlink_rejected(self):
  (self.root/'scripts/link.py').symlink_to(self.root/'README.md')
  with self.assertRaises(MaintenanceImageError):capture_control_image(self.root)
 def test_extra_or_wrong_type_fields_not_accepted(self):
  value=capture_control_image(self.root)
  for field,incorrect in [('version',True),('files',[]),('root',None),('extra',0)]:
   copy=json.loads(json.dumps(value));copy[field]=incorrect
   with self.subTest(field=field),self.assertRaises(MaintenanceImageError):require_control_image(copy,self.root)
 def test_cache_timestamp_and_private_artifacts_not_gates(self):
  value=capture_control_image(self.root);(self.root/'scripts/__pycache__').mkdir();(self.root/'scripts/__pycache__/derived.py').write_text('cache')
  (self.root/'models_cache.json').write_text('refresh');(self.root/'private.json').write_text('state')
  self.assertEqual(require_control_image(value,self.root),value)
