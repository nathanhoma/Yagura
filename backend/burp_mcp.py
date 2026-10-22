"""Narrow client for PortSwigger's local Burp MCP SSE server.

Only a fixed, body-free GET to a literal approved IP is exposed. Burp's other
MCP tools (history, config, Intruder, scanner) are deliberately unavailable.
"""
import json
import re
from urllib.parse import urljoin, urlsplit

from .outbound import require_private_pin
from .web_contacts import origin


BASE = 'http://127.0.0.1:9876'
MAX_REPLY = 262144


def _bounded_lines(response):
    while True:
        line = response.raw.readline(MAX_REPLY + 1)
        if not line:
            return
        if len(line) > MAX_REPLY:
            raise ValueError('Burp MCP event is too large.')
        yield line.rstrip(b'\r\n')


def _events(lines):
    event, data = '', []
    for raw in lines:
        line = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
        if len(line) > MAX_REPLY:
            raise ValueError('Burp MCP event is too large.')
        if not line:
            if data:
                yield event or 'message', '\n'.join(data)
            event, data = '', []
        elif line.startswith('event:'):
            event = line[6:].strip()
        elif line.startswith('data:'):
            data.append(line[5:].lstrip())


def _post(session, endpoint, payload):
    response = session.post(endpoint, json=payload, timeout=8, allow_redirects=False)
    response.raise_for_status()


def _reply(events, request_id):
    for event, data in events:
        if event != 'message' or len(data) > MAX_REPLY:
            continue
        try:
            obj = json.loads(data)
        except ValueError:
            continue
        if obj.get('id') == request_id:
            if obj.get('error'):
                raise ValueError('Burp MCP rejected the request.')
            return obj.get('result') or {}
    raise ValueError('Burp MCP did not return a response.')


def _call(session, endpoint, events, request_id, method, params=None):
    _post(session, endpoint, {'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params or {}})
    return _reply(events, request_id)


def run_get(url, pinned_ip):
    """Return response metadata, never raw response content or credentials."""
    try:
        import requests
    except ImportError as exc:
        raise ValueError('Burp MCP integration requires the Python requests package.') from exc
    scheme, hostname, port = origin(url)
    pinned_ip = require_private_pin(pinned_ip)
    if urlsplit(url).path not in ('', '/') or urlsplit(url).query or urlsplit(url).fragment:
        raise ValueError('Burp MCP check is limited to the site root.')
    # The transport is fixed to loopback; a remote URL from MCP is never trusted.
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(BASE + '/sse', stream=True, timeout=(3, 20),
                             allow_redirects=False, headers={'Accept': 'text/event-stream', 'Accept-Encoding': 'identity'}) as stream:
                stream.raise_for_status()
                events = _events(_bounded_lines(stream))
                event, data = next(events)
                if event != 'endpoint':
                    raise ValueError('Burp MCP did not provide a message endpoint.')
                endpoint = urljoin(BASE + '/', data)
                parts = urlsplit(endpoint)
                if parts.scheme != 'http' or parts.hostname != '127.0.0.1' or parts.port != 9876 or not parts.path.startswith('/message'):
                    raise ValueError('Burp MCP returned an unsafe message endpoint.')
                _call(session, endpoint, events, 1, 'initialize', {'protocolVersion': '2024-11-05',
                      'capabilities': {}, 'clientInfo': {'name': 'Yagura', 'version': '1'}})
                _post(session, endpoint, {'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                host_header = hostname if port in (80, 443) else f'{hostname}:{port}'
                content = f'GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Yagura-Burp-Check/1.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n'
                result = _call(session, endpoint, events, 2, 'tools/call', {'name': 'send_http1_request',
                    'arguments': {'content': content, 'targetHostname': pinned_ip,
                                  'targetPort': port, 'usesHttps': scheme == 'https'}})
    except (requests.RequestException, StopIteration) as exc:
        raise ValueError('Burp MCP is unavailable. Start Burp and enable its MCP extension on localhost:9876.') from exc
    if result.get('isError'):
        raise ValueError('Burp MCP could not complete the request.')
    text = '\n'.join(item.get('text', '') for item in result.get('content', []) if item.get('type') == 'text')
    if not text or 'denied by Burp Suite' in text:
        raise ValueError('Burp MCP request was denied or returned no response.')
    match = re.search(r'HTTP/\d(?:\.\d)?\s+(\d{3})\b', text)
    if not match:
        raise ValueError('Burp MCP response did not contain an HTTP status.')
    mime = re.search(r'(?im)^content-type:\s*([^;\r\n]+)', text)
    return {'status': match.group(1), 'mime': mime.group(1)[:80] if mime else ''}
