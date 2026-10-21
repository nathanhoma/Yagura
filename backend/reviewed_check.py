"""Narrow command grammar for human-reviewed AI checks.

Approval is required, but it is not a substitute for validating model output.
Only an Nmap TCP connect scan of the one approved host is executable here.
"""
import shlex


def validate(command, ip):
    if not isinstance(command, str) or not command.strip() or len(command) > 500 or '\n' in command or '\r' in command:
        raise ValueError('Propose one Nmap command of at most 500 characters.')
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ValueError('The proposed command has invalid quoting.') from exc
    if len(parts) < 6 or parts[:4] != ['nmap', '-n', '-Pn', '-sT'] or parts[-1] != ip:
        raise ValueError('Only a TCP connect Nmap scan of the selected host is supported.')
    options = parts[4:-1]
    if options[:2] == ['-sV', '--version-light']:
        options = options[2:]
    elif options[:1] == ['-sV']:
        options = options[1:]
    if len(options) != 2:
        raise ValueError('Choose either --top-ports or -p with explicit TCP ports.')
    if options[0] == '--top-ports':
        if not options[1].isdigit() or not 1 <= int(options[1]) <= 1000:
            raise ValueError('Top ports must be between 1 and 1000.')
    elif options[0] == '-p':
        ports = options[1].split(',')
        if not 1 <= len(ports) <= 64 or len(ports) != len(set(ports)) or any(
                not port.isdigit() or not 1 <= int(port) <= 65535 for port in ports):
            raise ValueError('Specify 1–64 distinct TCP ports between 1 and 65535.')
    else:
        raise ValueError('Choose either --top-ports or -p with explicit TCP ports.')
    return shlex.join(parts), parts[1:]
