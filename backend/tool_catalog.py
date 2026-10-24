"""Local, read-only documentation for AI-selected catalog tools."""
import os
import shutil
import subprocess
import tempfile

from .sensitive import redact


# These are executable names, not command templates. Only a selected tool's
# local help is read; help text is data and is never evaluated or executed.
TOOLS = (
    dict(id='nmap', purpose='Port, service, and protocol observations', help=['--help']),
    dict(id='curl', purpose='HTTP headers and responses', help=['--help']),
    dict(id='whatweb', purpose='Web technology fingerprinting', help=['--help']),
    dict(id='sslscan', purpose='TLS protocol and cipher observations', help=['--help']),
    dict(id='dnsrecon', purpose='DNS record enumeration', help=['--help']),
    dict(id='gobuster', purpose='Bounded web path discovery', help=['--help']),
    dict(id='smbclient', purpose='SMB service and share observations', help=['--help']),
    dict(id='nxc', purpose='SMB host and MSSQL service metadata', help=['--help']),
    dict(id='snmpwalk', purpose='SNMP metadata queries', help=['--help']),
    dict(id='dig', purpose='DNS record queries', help=['-h']),
    dict(id='openssl', purpose='TLS certificate inspection', help=['help']),
)

MAX_HELP_CHARS = 12000


def available_tools():
    return [dict(id=item['id'], purpose=item['purpose']) for item in TOOLS
            if shutil.which(item['id'])]


def read_help(tool_id, source='help', topic=None):
    item = next((item for item in TOOLS if item['id'] == tool_id), None)
    if item is None:
        raise ValueError('Tool is not in the local tool catalog.')
    if source not in ('help', 'man'):
        raise ValueError('Choose local help or man documentation.')
    if topic not in (None, 'mssql') or topic and (tool_id != 'nxc' or source != 'help'):
        raise ValueError('Choose a supported local tool help topic.')
    executable = shutil.which(tool_id)
    if not executable:
        raise ValueError('Selected tool is not installed.')
    man = shutil.which('man') if source == 'man' else None
    if source == 'man' and not man:
        raise ValueError('Local man command is not installed.')
    help_args = [topic, '--help'] if topic else item['help']
    invocation = [executable, *help_args] if source == 'help' else [man, '-P', 'cat', tool_id]
    try:
        with tempfile.TemporaryDirectory(prefix='yagura-help-') as home:
            env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL') if key in os.environ}
            env.update(HOME=home, XDG_CACHE_HOME=home, PAGER='cat', MANPAGER='cat',
                       MANWIDTH='100', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run(invocation, capture_output=True, text=True,
                                    errors='replace', timeout=6, check=False,
                                    stdin=subprocess.DEVNULL, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Local tool documentation could not be read.') from exc
    if source == 'man' and result.returncode:
        raise ValueError('Local man page is unavailable for this tool.')
    content = redact((result.stdout + '\n' + result.stderr).strip())[:MAX_HELP_CHARS]
    if not content:
        raise ValueError('Selected tool returned no local documentation.')
    return dict(tool=tool_id, source=source,
                invocation=[tool_id, *help_args] if source == 'help' else ['man', tool_id], text=content,
                truncated=len(result.stdout) + len(result.stderr) > MAX_HELP_CHARS)
