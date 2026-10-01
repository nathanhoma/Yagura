import json
import unittest

from backend import findings as F
from backend.analysis import scoped_document
from backend.discovery import dns_review, parse_dns_answer
from backend.outbound import require_private_pin, require_web_origin
from backend.sensitive import redact, sanitize_document
from backend.web_inventory import inventory


class SafetyReviewTests(unittest.TestCase):
    def test_secret_values_are_removed_from_output_and_marked_evidence(self):
        self.assertNotIn('abc123', redact('password=abc123 Authorization: Bearer abc123 {"access_token":"abc123"}'))
        parsed = F.parse_import(dict(tool='evidence', ip='10.1.51.5', title='Credential found',
                                     output='password=abc123', sensitive=True))
        safe = sanitize_document(parsed)
        self.assertEqual(safe['evidence'][0]['output'], '[REDACTED: sensitive evidence]')
        self.assertTrue(all('abc123' not in json.dumps(row) for row in safe['findings']))

    def test_group_scope_and_web_target_gate(self):
        doc = F.empty()
        for ip, name in [('100.96.1.21', 'www.elec.01.crimsonia.net'),
                         ('100.96.1.23', 'kc-proxy.elec.01.crimsonia.net')]:
            ev = dict(id=F.uid('evidence'), tool='manual', command='note', output='', observedAt=F.now(), importedAt=F.now())
            doc['evidence'].append(ev)
            doc['findings'].append(F.record('host', dict(ip=ip, name=name, aliases=[], state='up', local=False, title=ip, detail=''), ev['id'], F.now()))
        scope = {'cidrs': ['100.96.1.0/24'], 'domains': ['crimsonia.net']}
        host = doc['findings'][0]
        host['approval'] = dict(ip=host['ip'], name=host['name'], scope=scope)
        selected = scoped_document(doc, authorized_cidr=scope, host_ids=[host['id']])
        self.assertEqual(len(selected['findings']), 1)
        with self.assertRaises(ValueError):
            scoped_document(doc, authorized_cidr=scope, host_ids=[f['id'] for f in doc['findings']])
        self.assertEqual(require_web_origin('https://www.elec.01.crimsonia.net/', host, scope), host['ip'])
        with self.assertRaises(ValueError):
            require_web_origin('https://outside.test/', host, scope)
        with self.assertRaises(ValueError):
            require_private_pin('8.8.8.8')

    def test_web_inventory_retains_denials_and_redirects_without_following_external(self):
        called = []
        def fetch(url, ip, timeout):
            called.append(url)
            if '/login' in url:
                return 401, {'content-type': 'text/html'}, '<title>Login needed</title><form action="/session" method="post"><input name="user"></form>'
            return 302, {'location': '/login?token=secret'}, ''
        report = inventory('http://www.lab.test/', '192.168.56.10', fetch)
        self.assertEqual([p['status'] for p in report['pages']], [302, 401])
        self.assertEqual(report['redirects'][0]['queryNames'], ['token'])
        self.assertNotIn('secret', json.dumps(report))
        self.assertEqual(len(report['forms']), 1)
        self.assertEqual(called, ['http://www.lab.test/', 'http://www.lab.test/login?token=secret'])
