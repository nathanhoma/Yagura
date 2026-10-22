import json
import unittest

from backend import findings as F
from backend.kali_recon import _web
from backend.server import edited_invocation, invocation, parse_check_result
from backend.workflow import workflow


class KaliReconTests(unittest.TestCase):
    def setUp(self):
        self.doc = F.empty()
        F.merge_parsed(self.doc, F.parse_import({'tool': 'nmap', 'output': (
            'Nmap scan report for www.lab.test (192.168.56.10)\nHost is up.\n'
            '53/tcp open domain\n80/tcp open http\n443/tcp open https\n'
            'Nmap done: 1 IP address (1 host up) scanned')}))
        self.checks = {c['catalogId']: c for c in workflow(self.doc, '192.168.56.10/32')['candidates']}

    def test_four_checks_are_scoped_and_fixed(self):
        self.assertFalse(workflow(self.doc)['candidates'])
        for kind in ('whatweb', 'gobuster', 'sslscan', 'dnsrecon'):
            with self.subTest(kind=kind):
                candidate = self.checks[kind]
                program, args, tool = invocation(candidate, self.doc)
                self.assertEqual(tool, kind)
                self.assertIn('192.168.56.10', args)
                self.assertTrue(program.endswith('python3') or program.endswith('python'))
                with self.assertRaises(ValueError):
                    edited_invocation(candidate, self.doc, candidate['command'] + ' --extra')
        self.assertEqual(len([c for c in workflow(self.doc, '192.168.56.10/32')['candidates']
                              if c['catalogId'] == 'whatweb']), 1)
        with self.assertRaisesRegex(ValueError, 'does not verify TLS'):
            _web('whatweb', 'https://www.lab.test:443/', '192.168.56.10')

    def test_reports_are_linked_and_target_checked(self):
        examples = {
            'whatweb': {'status': 200, 'technologies': [{'name': 'Apache', 'version': '2.4.59'}]},
            'gobuster': {'checked': 7, 'paths': [{'path': '/robots.txt', 'status': 200, 'size': 5}]},
            'sslscan': {'protocols': ['TLS 1.2', 'TLS 1.3']},
            'dnsrecon': {'records': [{'type': 'A', 'name': 'www.lab.test', 'value': '192.168.56.10'}]},
        }
        for kind, fields in examples.items():
            with self.subTest(kind=kind):
                candidate = self.checks[kind]
                report = {'tool': kind, 'ip': '192.168.56.10',
                          ('name' if kind == 'dnsrecon' else 'url'): candidate['command'].split('--name ' if kind == 'dnsrecon' else '--url ')[1].split()[0], **fields}
                parsed = parse_check_result(candidate, kind, json.dumps(report))
                self.assertEqual(parsed['findings'][0]['serviceId'], candidate['serviceIds'][0])
                with self.assertRaisesRegex(ValueError, 'target differs'):
                    parse_check_result(candidate, kind, json.dumps({**report, 'ip': '192.168.56.11'}))

    def test_proxy_blocks_other_destinations(self):
        from backend.kali_recon import PinnedProxy
        import http.client
        proxy = PinnedProxy('127.0.0.1', 'www.lab.test', 80)
        import threading
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', proxy.server_port, timeout=2)
            conn.request('GET', 'http://other.test:80/')
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
            conn = http.client.HTTPConnection('127.0.0.1', proxy.server_port, timeout=2)
            conn.request('CONNECT', 'other.test:443')
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        finally:
            proxy.shutdown()
            proxy.server_close()


if __name__ == '__main__':
    unittest.main()
