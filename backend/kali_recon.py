"""Bounded adapters for four optional Kali reconnaissance binaries.

Web tools receive a loopback proxy that can connect only to the selected IP
and port. DNS and TLS tools receive a literal target IP, never a name to
resolve. The normalized report omits response bodies and authentication data.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.outbound import require_private_pin
from backend.scope import DOMAIN_LABEL
from backend.web_contacts import origin

PATHS = ('login', 'admin', 'api', 'docs', 'swagger', 'swagger-ui', 'openapi.json',
         'graphql', 'health', 'status', 'dashboard', 'auth', 'assets', 'static',
         'uploads', 'backup', 'backups', 'metrics', '.well-known/security.txt')
MAX_OUTPUT = 250_000


def _run(args, timeout=35):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                            env={**os.environ, 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '',
                                 'http_proxy': '', 'https_proxy': '', 'all_proxy': ''})
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError('Tool output exceeded the bounded size.')
    if result.returncode:
        raise ValueError((result.stderr or result.stdout or 'Tool failed.')[:500])
    return result.stdout


class PinnedProxy(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, ip, name, port):
        self.target_ip, self.target_name, self.target_port = ip, name, port
        self.request_count = 0
        self.request_lock = threading.Lock()
        super().__init__(('127.0.0.1', 0), ProxyHandler)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass

    def _allowed(self, authority):
        return authority.lower().rstrip('.') == f'{self.server.target_name}:{self.server.target_port}'

    def _permit_request(self):
        with self.server.request_lock:
            if self.server.request_count >= len(PATHS) + 4:
                self.send_error(429)
                return False
            self.server.request_count += 1
            return True

    def do_CONNECT(self):
        if not self._allowed(self.path):
            self.send_error(403)
            return
        if not self._permit_request():
            return
        try:
            remote = socket.create_connection((self.server.target_ip, self.server.target_port), timeout=5)
            remote.settimeout(5)
            self.connection.settimeout(5)
            self.send_response(200, 'Connection Established')
            self.end_headers()
            sockets = (self.connection, remote)
            total = 0
            while total < 2_000_000:
                ready, _, _ = select.select(sockets, [], [], 8)
                if not ready:
                    break
                for source in ready:
                    chunk = source.recv(min(65536, 2_000_000 - total))
                    if not chunk:
                        return
                    (remote if source is self.connection else self.connection).sendall(chunk)
                    total += len(chunk)
        except (OSError, TimeoutError):
            pass
        finally:
            try:
                remote.close()
            except UnboundLocalError:
                pass
            self.close_connection = True

    def do_GET(self):
        self._forward()

    def do_HEAD(self):
        self._forward()

    def _forward(self):
        parsed = urlsplit(self.path)
        if parsed.scheme != 'http' or not self._allowed(parsed.netloc) or parsed.username or parsed.password:
            self.send_error(403)
            return
        if not self._permit_request():
            return
        try:
            with socket.create_connection((self.server.target_ip, self.server.target_port), timeout=5) as remote:
                remote.settimeout(5)
                path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
                request = (f'{self.command} {path} HTTP/1.0\r\nHost: {self.server.target_name}:{self.server.target_port}\r\n'
                           'User-Agent: Yagura-Kali-Recon/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n')
                remote.sendall(request.encode('ascii'))
                total = 0
                while total < 300_000:
                    chunk = remote.recv(min(65536, 300_000 - total))
                    if not chunk:
                        break
                    self.connection.sendall(chunk)
                    total += len(chunk)
        except (OSError, TimeoutError):
            self.close_connection = True
        self.close_connection = True


def _web(tool, url, ip):
    scheme, name, port = origin(url)
    if tool == 'whatweb' and scheme != 'http':
        raise ValueError('Installed WhatWeb does not verify TLS certificates; use HTTP only.')
    parsed = urlsplit(url)
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Web check requires a root URL.')
    with tempfile.TemporaryDirectory(prefix='yagura-recon-') as directory:
        proxy = PinnedProxy(ip, name, port)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            proxy_url = f'http://127.0.0.1:{proxy.server_port}'
            if tool == 'whatweb':
                output = _run(['whatweb', '--aggression', '1', '--follow-redirect=never',
                               '--max-threads', '1', '--open-timeout', '5', '--read-timeout', '5',
                               '--color=never', '--quiet', '--proxy', f'127.0.0.1:{proxy.server_port}',
                               '--log-json=-', url], 30)
                rows = json.loads(output)
                if not isinstance(rows, list) or len(rows) != 1 or rows[0].get('target') != url:
                    raise ValueError('WhatWeb did not return the selected target.')
                row = rows[0]
                plugins = row.get('plugins') or {}
                if not isinstance(plugins, dict) or len(plugins) > 100:
                    raise ValueError('Invalid WhatWeb plugin report.')
                technologies = []
                for name, value in plugins.items():
                    if not re.fullmatch(r'[A-Za-z0-9_.+ -]{1,64}', name) or not isinstance(value, dict):
                        continue
                    versions = value.get('version') or []
                    version = str(versions[0]) if isinstance(versions, list) and versions else ''
                    technologies.append({'name': name, 'version': version[:40] if re.fullmatch(r'[0-9A-Za-z._+-]{1,40}', version) else ''})
                return {'tool': tool, 'url': url, 'ip': ip, 'status': row.get('http_status'),
                        'technologies': technologies[:60]}
            wordlist = Path(directory) / 'paths.txt'
            wordlist.write_text('\n'.join(PATHS) + '\n')
            output = _run(['gobuster', 'dir', '-u', url, '-w', str(wordlist), '-t', '1',
                           '--timeout', '2s', '--no-progress', '--no-color', '--quiet',
                           '--proxy', proxy_url], 42)
            paths = []
            for line in output.splitlines():
                match = re.fullmatch(r'\s*/?([^\s]+)\s+\(Status:\s*(\d{3})\)\s*\[Size:\s*(\d+)\].*', line)
                if match and match.group(1).rstrip('/') in PATHS:
                    paths.append({'path': '/' + match.group(1), 'status': int(match.group(2)),
                                  'size': int(match.group(3))})
            return {'tool': tool, 'url': url, 'ip': ip, 'paths': paths, 'checked': len(PATHS)}
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=2)


def _sslscan(url, ip):
    _, name, port = origin(url)
    output = _run(['sslscan', '--xml=-', '--timeout=5', '--connect-timeout=5',
                   f'--sni-name={name}', f'{ip}:{port}'], 40)
    root = ET.fromstring(output)
    row = root.find('ssltest')
    if row is None or row.get('host') != ip or row.get('port') != str(port):
        raise ValueError('sslscan result target differs from selected service.')
    protocols = sorted({f"{p.get('type', '').upper()} {p.get('version', '')}".strip()
                        for p in row.findall('protocol') if p.get('enabled') == '1'})
    ciphers = []
    for cipher in row.findall('cipher'):
        if cipher.get('status') not in ('accepted', 'preferred'):
            continue
        version, name, bits = (cipher.get(key, '') for key in ('sslversion', 'cipher', 'bits'))
        if (re.fullmatch(r'(?:TLS|SSL)v?[0-9.]{1,8}', version) and
                re.fullmatch(r'[A-Za-z0-9_+-]{1,100}', name) and
                re.fullmatch(r'[0-9]{1,4}', bits)):
            ciphers.append({'protocol': version, 'name': name, 'bits': int(bits),
                            'preferred': cipher.get('status') == 'preferred'})
    return {'tool': 'sslscan', 'url': url, 'ip': ip, 'protocols': protocols[:20],
            'cipherCount': len(ciphers), 'ciphers': ciphers[:100]}


def _dnsrecon(zone, ip):
    if len(zone) > 253 or len(zone.split('.')) < 2 or not all(DOMAIN_LABEL.fullmatch(label) for label in zone.split('.')):
        raise ValueError('A selected DNS zone is required.')
    with tempfile.TemporaryDirectory(prefix='yagura-dns-') as directory:
        path = Path(directory) / 'records.json'
        _run(['dnsrecon', '-d', zone, '-n', ip, '-t', 'std', '--tcp', '--threads', '1', '--lifetime', '3',
              '--disable_check_recursion', '--disable_check_bindversion', '-j', str(path)], 40)
        rows = json.loads(path.read_text()) if path.exists() else []
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('Invalid dnsrecon record count.')
    records = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind = str(row.get('type') or '').upper()
        record_name = str(row.get('name') or row.get('domain') or '').rstrip('.').lower()
        value = str(row.get('address') or row.get('target') or row.get('mname') or '')
        if (kind in ('A', 'AAAA', 'MX', 'NS', 'SOA', 'CNAME', 'SRV') and
                re.fullmatch(r'[a-z0-9.-]{1,253}', record_name) and
                re.fullmatch(r'[A-Za-z0-9.:_-]{1,253}', value)):
            records.append({'type': kind, 'name': record_name[:253], 'value': value})
    return {'tool': 'dnsrecon', 'zone': zone, 'ip': ip, 'records': records[:100]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=('whatweb', 'sslscan', 'dnsrecon', 'gobuster'))
    parser.add_argument('--url')
    parser.add_argument('--zone')
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    try:
        ip = require_private_pin(args.ip)
        if args.tool == 'dnsrecon':
            report = _dnsrecon(args.zone or '', ip)
        elif args.tool == 'sslscan':
            report = _sslscan(args.url or '', ip)
        else:
            report = _web(args.tool, args.url or '', ip)
        print(json.dumps(report, ensure_ascii=False))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired, ET.ParseError, json.JSONDecodeError) as exc:
        print(str(exc)[:500], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
