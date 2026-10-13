"""Owned, bounded descriptor reader for routing evidence, NEVER a grant issuer."""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path
from typing import Any
from .operative_routing import _normalize_current_authority
from .native_precommit import canonical_sha256

class PrivateAuthorityInputError(ValueError):pass

def load_private_current_authority(path: str|Path,expected_sha256:str,*,maximum_bytes:int=2*1024*1024)->dict[str,Any]:
    if type(expected_sha256) is not str or len(expected_sha256)!=64 or any(c not in '0123456789abcdef' for c in expected_sha256):
        raise PrivateAuthorityInputError('current-authority hash is invalid')
    if type(maximum_bytes) is not int or maximum_bytes<1:raise PrivateAuthorityInputError('current-authority bound is invalid')
    p=Path(path)
    if not p.is_absolute() or '..' in p.parts or any(q.is_symlink() for q in (p,*p.parents)):
        raise PrivateAuthorityInputError('current-authority path must be absolute and non-symlink')
    fd=None
    try:
        fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)&0o077:
            raise PrivateAuthorityInputError('current-authority input must be an owned private regular file')
        if before.st_size>maximum_bytes:raise PrivateAuthorityInputError('current-authority input exceeds its bound')
        data=b''
        while len(data)<=maximum_bytes:
            part=os.read(fd,min(65536,maximum_bytes+1-len(data)))
            if not part:break
            data+=part
        after=os.fstat(fd)
        if len(data)>maximum_bytes or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise PrivateAuthorityInputError('current-authority input drifted during capture')
        if hashlib.sha256(data).hexdigest()!=expected_sha256:raise PrivateAuthorityInputError('current-authority raw hash mismatch')
        def pairs(entries):
            d={}
            for k,v in entries:
                if k in d:raise PrivateAuthorityInputError('current-authority duplicate JSON key')
                d[k]=v
            return d
        value=json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(PrivateAuthorityInputError('current-authority nonfinite JSON')))
        if type(value) is dict and value.get('authority_type')=='cwo-private-current-authority':
            if set(value)!={'authority_type','version','current_authority','current_authority_sha256'} or type(value['version']) is not int or value['version']!=1:
                raise PrivateAuthorityInputError('current-authority envelope is invalid')
            authority=_normalize_current_authority(value['current_authority'])
            if canonical_sha256(authority)!=value['current_authority_sha256']:
                raise PrivateAuthorityInputError('current-authority inner hash mismatch')
            return authority
        return _normalize_current_authority(value)
    except (OSError,ValueError,TypeError,UnicodeError,OverflowError) as e:
        if isinstance(e,PrivateAuthorityInputError):raise
        raise PrivateAuthorityInputError('current-authority input rejected: '+str(e)) from e
    finally:
        if fd is not None:os.close(fd)


def private_authority_arguments(path,raw_hash):
    if path is None and raw_hash is None:return {}
    if type(path) is not str or not path.strip() or raw_hash is None:
        raise PrivateAuthorityInputError('current-authority file and raw hash must be supplied together')
    return {'current_authority':load_private_current_authority(path,raw_hash)}
