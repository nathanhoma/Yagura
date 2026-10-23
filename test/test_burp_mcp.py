import json
import io
import unittest
from unittest.mock import patch

from backend.burp_mcp import run_get
from backend.tool_imports import parse_burp_live


HOST = {'id': 'host-test', 'kind': 'host', 'ip': '192.168.56.10',
        'name': 'www.lab.test', 'state': 'up', 'local': False}
SCOPE = {'cidrs': ['192.168.56.0/24'], 'domains': [], 'matchMode': 'and'}


class FakeResponse:
    def __init__(self, lines=()):
        self.lines = lines
        self.raw = io.BytesIO(b'\n'.join(lines) + b'\n')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_lines(self):
        return iter(self.lines)


class FakeSession:
    def __init__(self, endpoint='/message?sessionId=local'):
        self.endpoint = endpoint
        self.posts = []
        self.trust_env = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url, **kwargs):
        events = [('endpoint', self.endpoint), ('message', json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2024-11-05'}})),
                  ('message', json.dumps({'jsonrpc': '2.0', 'id': 2, 'result': {'content': [
                      {'type': 'text', 'text': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: SECRET\r\n\r\nsecret body'}]}}))]
        lines = []
        for kind, value in events:
            lines.extend([f'event: {kind}'.encode(), f'data: {value}'.encode(), b''])
        return FakeResponse(lines)

    def post(self, endpoint, json, **kwargs):
        self.posts.append((endpoint, json))
        return FakeResponse()


class BurpMcpTests(unittest.TestCase):
    def test_fixed_request_and_metadata_only_import(self):
        fake = FakeSession()
        with patch('requests.Session', return_value=fake):
            result = run_get('https://www.lab.test:443/', HOST['ip'])
        self.assertEqual(result, {'status': '200', 'mime': 'text/html'})
        self.assertFalse(fake.trust_env)
        self.assertEqual([x[1].get('method') for x in fake.posts], ['initialize', 'notifications/initialized', 'tools/call'])
        call = fake.posts[-1][1]['params']
        self.assertEqual(call['name'], 'send_http1_request')
        self.assertEqual(call['arguments']['targetHostname'], HOST['ip'])
        self.assertEqual(call['arguments']['content'].split('\r\n')[0], 'GET / HTTP/1.1')
        parsed = parse_burp_live(HOST, SCOPE, 'https://www.lab.test:443/', result)
        saved = parsed['evidence'][0]['output']
        self.assertIn('HTTP 200', parsed['findings'][-1]['detail'])
        self.assertNotIn('SECRET', saved)
        self.assertNotIn('secret body', saved)

    def test_external_mcp_endpoint_and_target_are_rejected(self):
        with patch('requests.Session', return_value=FakeSession('http://outside.test/message')):
            with self.assertRaisesRegex(ValueError, 'unsafe message endpoint'):
                run_get('http://www.lab.test/', HOST['ip'])
        with self.assertRaisesRegex(ValueError, 'Public'):
            run_get('http://www.lab.test/', '8.8.8.8')


if __name__ == '__main__':
    unittest.main()
