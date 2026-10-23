"""Bounded, target-pinned forms for automatically executed catalog tools.

The catalog supplies documentation, not authority. A generated command must
match one of these read-only forms before it can run without human review.
"""
import ipaddress
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

from .scope import ip_allowed, name_allowed
from .tool_catalog import TOOLS


WORDLIST = Path(__file__).with_name('recon_paths.txt').resolve()
SAFE_SCRIPTS = {'ssl-cert', 'smb-os-discovery', 'smb-protocols',
                'ssh2-enum-algos', 'rdp-enum-encryption', 'http-title', 'http-headers'}
CATALOG_IDS = {item['id'] for item in TOOLS}


def _fail(message):
    raise ValueError('Automatic catalog check: ' + message)


def _port(value):
    if not re.fullmatch(r'[1-9][0-9]{0,4}', value) or not 1 <= int(value) <= 65535:
        _fail('use one numeric TCP port from 1 to 65535.')
    return int(value)


def _resolver_allowed(value, host, scope):
    if value == host['ip']:
        return True
    try:
        address = ipaddress.ip_address(value)
        return any(ipaddress.ip_network(cidr).prefixlen == 32 and
                   address in ipaddress.ip_network(cidr) for cidr in scope['cidrs'])
    except (ValueError, KeyError):
        return False


def _url(value, host, *, literal=False):
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _fail('use a valid HTTP or HTTPS URL.')
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
            parsed.username or parsed.password or parsed.fragment or
            parsed.hostname not in ({host['ip']} if literal else {host['ip'], host.get('name', '').lower()})):
        _fail('use only the approved host in an HTTP or HTTPS URL without credentials or a fragment.')
    if port is not None:
        _port(str(port))
    return parsed, port or (443 if parsed.scheme == 'https' else 80)


def _nmap(args, host):
    if not args or args[-1] != host['ip'] or args.count(host['ip']) != 1:
        _fail('Nmap must have the exact approved IP as its sole final target.')
    flags = {'-n', '-Pn', '-sn', '-sT', '-sV', '-sU', '-F', '-O', '--open',
             '--reason', '--version-light', '--version-all'}
    i = 0
    while i < len(args) - 1:
        token = args[i]
        if token in flags:
            i += 1
        elif token in ('-p', '--script', '--max-retries', '--host-timeout', '-oX'):
            if i + 1 >= len(args) - 1:
                _fail('complete the Nmap option before the target IP.')
            value = args[i + 1]
            if token == '-p':
                ports = set()
                for part in value.split(','):
                    if '-' in part:
                        pair = part.split('-')
                        if len(pair) != 2:
                            _fail('use a bounded port list or range.')
                        low, high = _port(pair[0]), _port(pair[1])
                        if high < low or high - low > 1023:
                            _fail('scan at most 1,024 ports in one range.')
                        ports.update(range(low, high + 1))
                    else:
                        ports.add(_port(part))
                    if len(ports) > 1024:
                        _fail('scan at most 1,024 explicit ports.')
            elif token == '--script' and (not value or
                    any(script not in SAFE_SCRIPTS for script in value.split(','))):
                _fail('use only the catalogued read-only Nmap scripts.')
            elif token == '--max-retries' and value not in ('0', '1', '2'):
                _fail('set Nmap max retries to 0, 1, or 2.')
            elif token == '--host-timeout' and not re.fullmatch(r'(?:[1-9][0-9]?s|[1-2]m)', value):
                _fail('limit Nmap host timeout to at most two minutes.')
            elif token == '-oX' and value != '-':
                _fail('write Nmap XML only to standard output.')
            i += 2
        else:
            _fail('remove unsupported Nmap option ' + token[:40] + '.')


def _curl(args, host):
    if not args or args[0] != '-q':
        _fail('start curl with -q to ignore local configuration.')
    resolve = None
    no_proxy = False
    max_time = False
    seen = set()
    urls = []
    i = 1
    while i < len(args):
        token = args[i]
        if token in ('-sS', '-s', '-S', '-I', '--head'):
            i += 1
            continue
        if token in ('--noproxy', '--resolve', '--max-time', '-D', '-o', '-w') and i + 1 < len(args):
            if token in seen:
                _fail('do not repeat curl options.')
            seen.add(token)
            value = args[i + 1]
            if token == '--noproxy':
                no_proxy = value == '*'
            elif token == '--resolve':
                resolve = value
            elif token == '--max-time':
                max_time = bool(re.fullmatch(r'(?:[1-9]|1[0-5])', value))
            elif token == '-D' and value != '-':
                _fail('write headers only to standard output.')
            elif token == '-o' and value != '/dev/null':
                _fail('do not write response bodies to a local file.')
            elif token == '-w' and (len(value) > 100 or
                    not re.fullmatch(r"(?:%\{(?:http_code|ssl_verify_result|content_type|remote_ip)\}|[ :.,/\-])*", value)):
                _fail('use only bounded curl response metadata in -w.')
            i += 2
            continue
        if token.startswith('http://') or token.startswith('https://'):
            urls.append(token)
            i += 1
            continue
        _fail('remove unsupported curl option or argument ' + token[:40] + '.')
    if len(urls) != 1:
        _fail('use exactly one URL on the approved host.')
    if not no_proxy:
        _fail("add the exact option --noproxy '*' to bypass proxy configuration.")
    if not max_time:
        _fail('add --max-time followed by a whole number from 1 to 15.')
    parsed, port = _url(urls[0], host)
    if parsed.hostname != host['ip'] and resolve != f"{host['name']}:{port}:{host['ip']}":
        _fail('pin the approved hostname with --resolve name:port:approved-IP.')
    if parsed.hostname == host['ip'] and resolve:
        _fail('omit --resolve when the URL already uses the approved IP.')


def _whatweb(args, host):
    allowed = {'--follow-redirect=never', '--aggression=1', '--no-errors'}
    urls = [item for item in args if item.startswith(('http://', 'https://'))]
    if len(urls) != 1 or '--follow-redirect=never' not in args or any(item not in allowed and item != urls[0] for item in args):
        _fail('use one approved-IP URL with --follow-redirect=never and no proxy or output flags.')
    _url(urls[0], host, literal=True)


def _sslscan(args, host):
    targets = [item for item in args if item == host['ip'] or item.startswith(host['ip'] + ':')]
    if len(targets) != 1:
        _fail('use one literal approved-IP target for sslscan.')
    target = targets[0]
    if ':' in target:
        _port(target.rsplit(':', 1)[1])
    for item in args:
        if item == target or item in ('--no-colour', '--show-certificate'):
            continue
        if item.startswith('--sni-name=') and item[11:].lower() == host.get('name', '').lower():
            continue
        if item.startswith(('--timeout=', '--connect-timeout=')) and item.split('=', 1)[1] in tuple(str(n) for n in range(1, 11)):
            continue
        _fail('remove unsupported sslscan option ' + item[:40] + '.')


def _dnsrecon(args, host, scope):
    if len(args) != 6 or args[0] not in ('-d', '--domain') or args[2] not in ('-n', '--name_server') or args[4] not in ('-t', '--type') or args[5] != 'std':
        _fail('use dnsrecon -d approved-domain -n scoped-resolver -t std.')
    domain, resolver = args[1].lower().rstrip('.'), args[3]
    if not name_allowed(domain, scope) or not (host['name'] == domain or host['name'].endswith('.' + domain)):
        _fail('query only the approved host name or its saved domain suffix.')
    if not _resolver_allowed(resolver, host, scope):
        _fail('use the approved host or an explicit /32 resolver in the saved scope.')


def _gobuster(args, host):
    if not args or args[0] != 'dir':
        _fail('use only gobuster dir mode.')
    values = {}
    aliases = {'-u': 'url', '--url': 'url', '-w': 'wordlist', '--wordlist': 'wordlist',
               '-t': 'threads', '--threads': 'threads', '--timeout': 'timeout'}
    switches = {'--no-progress', '--no-color', '--quiet'}
    i = 1
    while i < len(args):
        token = args[i]
        if token in switches:
            i += 1
        elif token in ('-u', '--url', '-w', '--wordlist', '-t', '--threads', '--timeout') and i + 1 < len(args):
            key = aliases[token]
            if key in values:
                _fail('do not repeat Gobuster options.')
            values[key] = args[i + 1]
            i += 2
        else:
            _fail('remove unsupported Gobuster option ' + token[:40] + '.')
    url = values.get('url')
    wordlist = values.get('wordlist')
    threads = values.get('threads') or '1'
    timeout = values.get('timeout') or '2s'
    if not url or not wordlist or threads not in ('1', '2') or timeout not in ('1s', '2s', '3s', '4s', '5s'):
        _fail('use one URL, the bundled wordlist, at most two threads, and timeout at most 5s.')
    _url(url, host, literal=True)
    if Path(wordlist).resolve() != WORDLIST or not WORDLIST.is_file() or WORDLIST.stat().st_size > 4096:
        _fail('use the bundled backend/recon_paths.txt wordlist.')


def _smbclient(args, host):
    if len(args) < 3 or args[:2] != ['-L', host['ip']] or '-N' not in args:
        _fail('use smbclient -L approved-IP -N for anonymous share listing.')
    remaining = [item for item in args[2:] if item != '-N']
    if remaining not in ([], ['-g'], ['-m', 'SMB3'], ['-g', '-m', 'SMB3']):
        _fail('remove credentials, file operations, and unsupported smbclient options.')


def _nxc(args, host):
    if args[:2] != ['smb', host['ip']] or any(item not in ('--shares', '--disks') for item in args[2:]):
        _fail('use nxc smb approved-IP with only optional --shares or --disks.')


def _snmpwalk(args, host):
    if len(args) not in (4, 5) or args[:4] != ['-v2c', '-c', 'public', host['ip']]:
        _fail('use snmpwalk -v2c -c public approved-IP [numeric-OID].')
    if len(args) == 5 and not re.fullmatch(r'(?:\.?[0-9]+)(?:\.[0-9]+){0,20}', args[4]):
        _fail('use only a numeric SNMP OID.')


def _dig(args, host, scope):
    resolvers = [item[1:] for item in args if item.startswith('@')]
    if len(resolvers) != 1 or not _resolver_allowed(resolvers[0], host, scope):
        _fail('use the approved host or an explicit /32 resolver in the saved scope.')
    remaining = [item for item in args if not item.startswith('@') and item not in
                 ('+time=2', '+tries=1', '+short', '+noall', '+answer', '+ttlid')]
    if remaining == ['-x', host['ip']]:
        return
    if len(remaining) != 2 or remaining[1] not in ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV'):
        _fail('query the approved name or reverse IP with one DNS record type.')
    name = remaining[0].lower().rstrip('.')
    if not name_allowed(name, scope) or not (host['name'] == name or host['name'].endswith('.' + name)):
        _fail('query only the approved host name or its saved domain suffix.')


def _openssl(args, host):
    if not args or args[0] != 's_client':
        _fail('use only openssl s_client.')
    i = 1
    connect = None
    seen = set()
    while i < len(args):
        token = args[i]
        if token in ('-brief', '-showcerts', '-tls1_2', '-tls1_3'):
            i += 1
        elif token in ('-connect', '-servername') and i + 1 < len(args):
            if token in seen:
                _fail('do not repeat openssl target options.')
            seen.add(token)
            value = args[i + 1]
            if token == '-connect':
                connect = value
            elif value.lower() != host.get('name', '').lower():
                _fail('use only the approved hostname for TLS SNI.')
            i += 2
        else:
            _fail('remove unsupported openssl option ' + token[:40] + '.')
    if not connect or not connect.startswith(host['ip'] + ':'):
        _fail('connect only to approved-IP:port.')
    _port(connect.rsplit(':', 1)[1])


def validate_auto_command(command, host, scope):
    """Raise when a generated catalog command is not safe to run unattended."""
    try:
        parts = shlex.split(command)
    except ValueError:
        _fail('use valid single-process shell quoting.')
    if not parts or parts[0] not in CATALOG_IDS:
        _fail('choose an installed catalog executable.')
    if not ip_allowed(host['ip'], scope) or not name_allowed(host.get('name'), scope):
        _fail('the approved target changed or is outside the saved scope.')
    program, args = parts[0], parts[1:]
    if program == 'nmap':
        _nmap(args, host)
    elif program == 'curl':
        _curl(args, host)
    elif program == 'whatweb':
        _whatweb(args, host)
    elif program == 'sslscan':
        _sslscan(args, host)
    elif program == 'dnsrecon':
        _dnsrecon(args, host, scope)
    elif program == 'gobuster':
        _gobuster(args, host)
    elif program == 'smbclient':
        _smbclient(args, host)
    elif program == 'nxc':
        _nxc(args, host)
    elif program == 'snmpwalk':
        _snmpwalk(args, host)
    elif program == 'dig':
        _dig(args, host, scope)
    elif program == 'openssl':
        _openssl(args, host)
    return command
