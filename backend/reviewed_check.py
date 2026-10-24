"""Parse one human-reviewed command without invoking an implicit shell."""
import shlex


def validate(command, _host_ip=None):
    if (not isinstance(command, str) or not command.strip() or len(command) > 2000 or
            any(ord(char) < 32 or ord(char) == 127 for char in command)):
        raise ValueError('Propose one command of at most 2,000 characters, without control characters.')
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ValueError('The proposed command has invalid quoting.') from exc
    if not parts or len(parts) > 128 or parts[0].startswith('-'):
        raise ValueError('Propose one executable and at most 127 arguments.')
    if parts[:2] == ['nxc', 'mssql']:
        if len(parts) < 3 or parts[2] != _host_ip:
            raise ValueError('NetExec MSSQL must use the approved numeric source host.')
        if parts[3:] not in ([], ['--use-kcache', '-M', 'enum_links']):
            raise ValueError('NetExec MSSQL currently supports service metadata or Kerberos linked-server enumeration only.')
    return shlex.join(parts), parts[0], parts[1:]
