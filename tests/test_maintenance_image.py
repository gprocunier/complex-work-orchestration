"""Causal images: positive pinning and rejection of changed bytes/modes/shapes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Literal, NamedTuple
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from cwo_core.maintenance_image import capture_control_image,require_control_image,MaintenanceImageError

class ImageDriftCase(NamedTuple):
 original: str
 path: str
 operation: Literal["write", "mode", "delete"]
 value: str | int | None


class MaintenanceImageTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  for directory in ('scripts','policy','schemas','references','prompts'):(self.root/directory).mkdir()
  for name in ('SKILL.md','README.md','scripts/worker.py','policy/worker.yaml','schemas/worker.json'):
   (self.root/name).write_text('{}\n')
 def test_exact_image_accepts(self):
  value=capture_control_image(self.root);self.assertEqual(require_control_image(value,self.root),value)
 def test_causal_image_drift_rows(self):
  rows = (
   ImageDriftCase("test_causal_bytes_drift", "scripts/worker.py", "write", "changed"),
   ImageDriftCase("test_executable_mode_drift", "scripts/worker.py", "mode", 0o700),
   ImageDriftCase("test_new_causal_file_drift", "scripts/new.py", "write", "new"),
   ImageDriftCase("test_deleted_causal_file_drift", "scripts/worker.py", "delete", None),
  )
  for row in rows:
   with self.subTest(original=row.original):
    value = capture_control_image(self.root)
    path = self.root / row.path
    before = (path.read_bytes(), path.stat().st_mode & 0o7777) if path.exists() else None
    try:
     if row.operation == "write":
      path.write_text(row.value)
     elif row.operation == "mode":
      path.chmod(row.value)
     else:
      path.unlink()
     with self.assertRaises(MaintenanceImageError):
      require_control_image(value, self.root)
    finally:
     if before is None:
      path.unlink(missing_ok=True)
     else:
      path.write_bytes(before[0])
      path.chmod(before[1])
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
