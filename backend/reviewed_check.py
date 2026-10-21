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
    return shlex.join(parts), parts[0], parts[1:]
