import json
import unittest

from backend import findings as F
from backend.server import invocation, parse_check_result
from backend.web_inventory import inventory
from backend.workflow import workflow


class AddedChecksTests(unittest.TestCase):
    def setUp(self):
        self.doc = F.empty()
        F.merge_parsed(self.doc, F.parse_import(dict(tool='nmap', output=(
            'Nmap scan report for www.lab.test (192.168.56.10)\nHost is up.\n'
            '22/tcp open ssh\n80/tcp open http\n445/tcp open microsoft-ds\n'
            '2049/tcp open nfs\nNmap done: 1 IP address (1 host up) scanned'))))

    def test_scoped_service_checks_and_fixed_invocation(self):
        self.assertEqual(workflow(self.doc)['candidates'], [])
        candidates = workflow(self.doc, '192.168.56.10/32')['candidates']
        kinds = {c['catalogId'] for c in candidates}
        self.assertTrue({'dns-ptr', 'web-inventory', 'ssh-hostkey', 'smb-security', 'nfs-exports', 'nuclei-git'} <= kinds)
        ssh = next(c for c in candidates if c['catalogId'] == 'ssh-hostkey')
        self.assertEqual(invocation(ssh, self.doc), ('nmap', ['-n', '-Pn', '-sT', '-p', '22', '--script', 'ssh-hostkey', '-oX', '-', '192.168.56.10'], 'nmap'))
        nuclei = next(c for c in candidates if c['catalogId'] == 'nuclei-git')
        program, args, tool = invocation(nuclei, self.doc)
        self.assertEqual((program, tool), ('nuclei', 'nuclei-git'))
        self.assertEqual(args[:2], ['-u', 'http://192.168.56.10:80/'])
        self.assertIn('-dr', args)

    def test_existing_check_results_become_evidence(self):
        candidates = workflow(self.doc, '192.168.56.10/32')['candidates']
        headers = next(c for c in candidates if c['catalogId'] == 'http-headers')
        parsed = parse_check_result(headers, 'http-headers', 'HTTP/1.1 200 OK\nServer: lab\n')
        F.merge_parsed(self.doc, parsed)
        self.assertTrue(any(f['title'] == 'HTTP response headers' and f['serviceId'] == headers['serviceIds'][0] for f in self.doc['findings']))
        self.assertEqual(self.doc['evidence'][-1]['output'], 'HTTP/1.1 200 OK\nServer: lab\n')

    def test_httpx_and_nuclei_jsonl_import(self):
        ip = '192.168.56.10'
        for tool, row, title in [
            ('httpx', {'url': f'http://{ip}/', 'status_code': 200, 'title': 'Lab', 'tech': ['nginx']}, 'HTTP probe'),
            ('nuclei', {'matched-at': f'http://{ip}/', 'template-id': 'example', 'info': {'name': 'Example', 'severity': 'low'}}, 'Nuclei: Example'),
        ]:
            parsed = F.parse_import(dict(tool=tool, output=json.dumps(row)))
            self.assertTrue(any(f['title'] == title for f in parsed['findings']))

    def test_curated_nuclei_output_is_linked_and_scoped(self):
        candidate = next(c for c in workflow(self.doc, '192.168.56.10/32')['candidates'] if c['catalogId'] == 'nuclei-git')
        row = {'template-id': 'yagura-git-head-exposure', 'matched-at': 'http://192.168.56.10:80/.git/HEAD'}
        parsed = parse_check_result(candidate, 'nuclei-git', json.dumps(row))
        self.assertIn('matched', parsed['findings'][0]['detail'])
        with self.assertRaises(ValueError):
            parse_check_result(candidate, 'nuclei-git', json.dumps({**row, 'matched-at': 'http://192.168.56.11/.git/HEAD'}))

    def test_web_inventory_is_bounded_to_same_origin(self):
        seen = []
        def fetch(url, ip, timeout):
            seen.append(url)
            return 200, {'content-type': 'text/html', 'server': 'test'}, '<title>Lab</title><a href="/login">Login</a><a href="http://other.test/">Outside</a>'
        report = inventory('http://www.lab.test:80/', '192.168.56.10', fetch)
        self.assertEqual(seen, ['http://www.lab.test:80/', 'http://www.lab.test:80/login'])
        self.assertEqual(len(report['pages']), 2)
        self.assertTrue(all('other.test' not in route for route in report['routes']))


if __name__ == '__main__':
    unittest.main()
