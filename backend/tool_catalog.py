"""Local, read-only tool documentation for human-reviewed AI checks."""
import os
import shutil
import subprocess

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
    dict(id='nxc', purpose='SMB host metadata', help=['--help']),
    dict(id='snmpwalk', purpose='SNMP metadata queries', help=['--help']),
    dict(id='dig', purpose='DNS record queries', help=['-h']),
    dict(id='openssl', purpose='TLS certificate inspection', help=['help']),
)

MAX_HELP_CHARS = 12000


def available_tools():
    return [dict(id=item['id'], purpose=item['purpose']) for item in TOOLS
            if shutil.which(item['id'])]


def read_help(tool_id):
    item = next((item for item in TOOLS if item['id'] == tool_id), None)
    if item is None:
        raise ValueError('Tool is not in the local tool catalog.')
    executable = shutil.which(tool_id)
    if not executable:
        raise ValueError('Selected tool is not installed.')
    try:
        result = subprocess.run([executable, *item['help']], capture_output=True, text=True,
                                errors='replace', timeout=6, check=False, stdin=subprocess.DEVNULL,
                                env={**os.environ, 'PAGER': 'cat', 'NO_COLOR': '1'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Local tool help could not be read.') from exc
    content = redact((result.stdout + '\n' + result.stderr).strip())[:MAX_HELP_CHARS]
    if not content:
        raise ValueError('Selected tool returned no local help.')
    return dict(tool=tool_id, invocation=[tool_id, *item['help']], text=content,
                truncated=len(result.stdout) + len(result.stderr) > MAX_HELP_CHARS)
