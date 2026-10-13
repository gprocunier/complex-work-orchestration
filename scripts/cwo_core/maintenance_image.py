"""Causal installed control-image inventory; derived caches/private state excluded."""
from __future__ import annotations
import hashlib,os,stat
from pathlib import Path
from .native_pool_contracts import canonical_sha256
from .paths import REPO_ROOT

class MaintenanceImageError(ValueError):pass

def capture_control_image(root:Path|None=None)->dict:
 root=Path(root or REPO_ROOT)
 if not root.is_absolute() or root.is_symlink() or root.resolve()!=root:
  raise MaintenanceImageError('maintenance-image-root-invalid')
 paths=[]
 for directory,suffixes in [('scripts',{'.py','.sh'}),('policy',{'.yaml'}),('schemas',{'.json'}),('references',{'.md'}),('prompts',{'.md'})]:
  base=root/directory
  if not base.is_dir():raise MaintenanceImageError('maintenance-image-directory-missing:'+directory)
  paths.extend(p for p in base.rglob('*') if p.suffix in suffixes and '__pycache__' not in p.parts)
 paths.extend(root/name for name in ['SKILL.md','README.md'])
 files={}
 for path in sorted(paths):
  if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
   raise MaintenanceImageError('maintenance-image-path-invalid')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode):raise MaintenanceImageError('maintenance-image-file-invalid')
   with os.fdopen(fd,'rb',closefd=False) as handle:data=handle.read()
   after=os.fstat(fd);visible=path.stat(follow_symlinks=False)
   fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
   if any(getattr(before,k)!=getattr(after,k) or getattr(after,k)!=getattr(visible,k) for k in fields):
    raise MaintenanceImageError('maintenance-image-capture-drift')
   files[str(path.relative_to(root))]={'sha256':hashlib.sha256(data).hexdigest(),'executable':bool(before.st_mode&0o111)}
  finally:os.close(fd)
 value={'image_type':'cwo-maintenance-control-image','version':1,'root':str(root),'files':files}
 value['image_sha256']=canonical_sha256(value)
 return value

def require_control_image(value:dict,root:Path|None=None)->dict:
 if (type(value) is not dict or set(value)!={'image_type','version','root','files','image_sha256'}
  or type(value.get('version')) is not int or value['version']!=1
  or value.get('image_type')!='cwo-maintenance-control-image'
  or type(value.get('root')) is not str or type(value.get('files')) is not dict
  or type(value.get('image_sha256')) is not str):
  raise MaintenanceImageError('maintenance-image-shape-invalid')
 for name,entry in value['files'].items():
  if (type(name) is not str or type(entry) is not dict or set(entry)!={'sha256','executable'}
   or type(entry.get('sha256')) is not str or type(entry.get('executable')) is not bool):
   raise MaintenanceImageError('maintenance-image-file-shape-invalid')
 current=capture_control_image(root)
 if value!=current:raise MaintenanceImageError('maintenance-control-image-drift')
 return current
