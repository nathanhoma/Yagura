"""Owner-only Kerberos cache for optional MSSQL enumeration."""
import os
from pathlib import Path
import stat


def cache_path():
    raw = os.getenv('MSSQL_KRB5CCNAME', '')
    if raw.startswith('FILE:'):
        raw = raw[5:]
    if not raw or '\x00' in raw:
        return None
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink():
        return None
    try:
        info = path.stat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return None
    return str(path)
