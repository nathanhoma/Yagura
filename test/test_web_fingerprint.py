import json
import unittest

from backend import findings as F
from backend.server import invocation, parse_check_result
from backend.web_fingerprint import fingerprint
from backend.workflow import workflow


class WebFingerprintTests(unittest.TestCase):
    def test_curated_signals_without_body_or_secret_headers(self):
        calls = []
        def fetch(url, ip, timeout, accept_error=False):
            calls.append((url, ip, timeout, accept_error))
            return 200, {'content-type': 'text/html', 'server': 'nginx/1.24.0',
                         'set-cookie': 'session=SECRET', 'x-powered-by': 'PHP/8.2.1'}, (
                '<meta name="generator" content="WordPress 6.7.2">'
                '<script src="/wp-content/theme.js"></script>'
                '<a href="https://outside.test/?token=SECRET">outside</a>')
        report = fingerprint('https://www.lab.test:443/', '192.168.56.10', fetch)
        self.assertEqual(calls, [('https://www.lab.test:443/', '192.168.56.10', 5, True)])
        names = {item['name']: item['version'] for item in report['technologies']}
        self.assertEqual(names, {'nginx': '1.24.0', 'PHP': '8.2.1', 'WordPress': '6.7.2'})
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('outside.test', json.dumps(report))

    def test_check_is_scoped_and_result_target_is_exact(self):
        doc = F.empty()
        F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for www.lab.test (192.168.56.10)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'}))
        self.assertFalse(any(c['catalogId'] == 'web-fingerprint' for c in workflow(doc)['candidates']))
        candidate = next(c for c in workflow(doc, '192.168.56.10/32')['candidates'] if c['catalogId'] == 'web-fingerprint')
        self.assertEqual(invocation(candidate, doc)[2], 'web-fingerprint')
        report = fingerprint('http://www.lab.test:80/', '192.168.56.10',
            lambda *args, **kwargs: (200, {'server': 'Apache/2.4.59'}, ''))
        parsed = parse_check_result(candidate, 'web-fingerprint', json.dumps(report))
        self.assertIn('Apache/2.4.59', parsed['findings'][0]['detail'])
        with self.assertRaisesRegex(ValueError, 'target differs'):
            parse_check_result(candidate, 'web-fingerprint', json.dumps({**report, 'ip': '192.168.56.11'}))
        with self.assertRaisesRegex(ValueError, 'root page'):
            fingerprint('http://www.lab.test:80/login?token=SECRET', '192.168.56.10',
                lambda *args, **kwargs: None)


if __name__ == '__main__':
    unittest.main()
