import json
import unittest
from unittest.mock import patch

from backend import findings as F
from backend.kali_recon import _web, _sslscan, _dnsrecon
from backend.server import edited_invocation, invocation, parse_check_result
from backend.workflow import workflow


class KaliReconTests(unittest.TestCase):
    def setUp(self):
        self.doc = F.empty()
        F.merge_parsed(self.doc, F.parse_import({'tool': 'nmap', 'output': (
            'Nmap scan report for www.lab.test (192.168.56.10)\nHost is up.\n'
            '22/tcp open ssh\n53/tcp open domain\n80/tcp open http\n443/tcp open https\n'
            '3389/tcp open ms-wbt-server\n'
            'Nmap done: 1 IP address (1 host up) scanned')}))
        self.checks = {c['catalogId']: c for c in workflow(self.doc, '192.168.56.10/32')['candidates']}

    def add_web_lead(self):
        host = next(f for f in self.doc['findings'] if f['kind'] == 'host')
        service = next(f for f in self.doc['findings'] if f['kind'] == 'service' and f['port'] == 80)
        self.doc['findings'].append(F.record('observation', dict(hostId=host['id'], serviceId=service['id'],
                          title='Web routes', detail='http://www.lab.test:80/login'),
                          self.doc['evidence'][0]['id'], F.now()))
        return service

    def test_four_checks_are_scoped_and_fixed(self):
        self.assertFalse(workflow(self.doc)['candidates'])
        self.assertNotIn('gobuster', self.checks)
        self.add_web_lead()
        self.checks = {c['catalogId']: c for c in workflow(self.doc, '192.168.56.10/32')['candidates']}
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
        self.assertIn('--zone lab.test', self.checks['dnsrecon']['command'])
        self.assertTrue({'ssh-algorithms', 'rdp-encryption'} <= self.checks.keys())
        self.assertEqual(invocation(self.checks['ssh-algorithms'], self.doc)[2], 'nmap')
        self.assertEqual(invocation(self.checks['rdp-encryption'], self.doc)[2], 'nmap')
        with self.assertRaisesRegex(ValueError, 'does not verify TLS'):
            _web('whatweb', 'https://www.lab.test:443/', '192.168.56.10')

    def test_reports_are_linked_and_target_checked(self):
        self.add_web_lead()
        self.checks = {c['catalogId']: c for c in workflow(self.doc, '192.168.56.10/32')['candidates']}
        examples = {
            'whatweb': {'status': 200, 'technologies': [{'name': 'Apache', 'version': '2.4.59'}]},
            'gobuster': {'checked': 19, 'paths': [{'path': '/login', 'status': 200, 'size': 5}]},
            'sslscan': {'protocols': ['TLS 1.2', 'TLS 1.3'], 'cipherCount': 1,
                        'ciphers': [{'protocol': 'TLSv1.3', 'name': 'TLS_AES_128_GCM_SHA256', 'bits': 128, 'preferred': True}]},
            'dnsrecon': {'records': [{'type': 'A', 'name': 'lab.test', 'value': '192.168.56.10'}]},
        }
        for kind, fields in examples.items():
            with self.subTest(kind=kind):
                candidate = self.checks[kind]
                report = {'tool': kind, 'ip': '192.168.56.10',
                          ('zone' if kind == 'dnsrecon' else 'url'): candidate['command'].split('--zone ' if kind == 'dnsrecon' else '--url ')[1].split()[0], **fields}
                parsed = parse_check_result(candidate, kind, json.dumps(report))
                self.assertEqual(parsed['findings'][0]['serviceId'], candidate['serviceIds'][0])
                with self.assertRaisesRegex(ValueError, 'target differs'):
                    parse_check_result(candidate, kind, json.dumps({**report, 'ip': '192.168.56.11'}))

    def test_dns_zone_choices_are_distinct_and_bounded_to_scope(self):
        host = next(f for f in self.doc['findings'] if f['kind'] == 'host')
        host['name'] = 'dc1.dev.lab.test'
        scope = {'cidrs': ['192.168.56.10/32'], 'domains': ['lab.test'], 'matchMode': 'and'}
        host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': scope}
        candidates = [c for c in workflow(self.doc, scope)['candidates'] if c['catalogId'] == 'dnsrecon']
        self.assertEqual({c['command'].split('--zone ')[1].split()[0] for c in candidates}, {'dev.lab.test', 'lab.test'})
        self.assertEqual(len({c['id'] for c in candidates}), 2)
        for candidate in candidates:
            self.assertEqual(invocation(candidate, self.doc)[2], 'dnsrecon')

    def test_sslscan_cipher_xml_is_normalized(self):
        xml = ('<document><ssltest host="192.168.56.10" port="443">'
               '<protocol type="tls" version="1.3" enabled="1"/>'
               '<cipher status="preferred" sslversion="TLSv1.3" bits="128" cipher="TLS_AES_128_GCM_SHA256"/>'
               '<cipher status="rejected" sslversion="TLSv1.2" bits="40" cipher="RC4"/>'
               '</ssltest></document>')
        with patch('backend.kali_recon._run', return_value=xml):
            report = _sslscan('https://www.lab.test:443/', '192.168.56.10')
        self.assertEqual(report['cipherCount'], 1)
        self.assertEqual(report['ciphers'][0]['name'], 'TLS_AES_128_GCM_SHA256')

    def test_dnsrecon_uses_selected_zone_and_literal_resolver(self):
        def write_fixture(args, timeout):
            from pathlib import Path
            self.assertEqual(args[args.index('-d') + 1], 'dev.lab.test')
            self.assertEqual(args[args.index('-n') + 1], '192.168.56.10')
            self.assertIn('--tcp', args)
            self.assertNotIn('-a', args)
            Path(args[-1]).write_text(json.dumps([
                {'type': 'ScanInfo'},
                {'domain': 'dev.lab.test', 'type': 'NS', 'target': 'ns.dev.lab.test', 'address': '192.168.56.10'},
                {'domain': 'dev.lab.test', 'type': 'TXT', 'address': 'secret=ignored'},
            ]))
            return ''
        with patch('backend.kali_recon._run', side_effect=write_fixture):
            report = _dnsrecon('dev.lab.test', '192.168.56.10')
        self.assertEqual(report['zone'], 'dev.lab.test')
        self.assertEqual(report['records'], [{'type': 'NS', 'name': 'dev.lab.test', 'value': '192.168.56.10'}])

    def test_ssh_and_rdp_script_results_stop_repeated_suggestions(self):
        for kind, port, script in (('ssh-algorithms', 22, 'ssh2-enum-algos'),
                                   ('rdp-encryption', 3389, 'rdp-enum-encryption')):
            with self.subTest(kind=kind):
                candidate = self.checks[kind]
                xml = (f'<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="192.168.56.10"/>'
                       f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
                       f'<service name="{script}"/><script id="{script}" output="example"/>'
                       f'</port></ports></host></nmaprun>')
                F.merge_parsed(self.doc, parse_check_result(candidate, 'nmap', xml))
                self.assertFalse(any(c['catalogId'] == kind for c in workflow(self.doc, '192.168.56.10/32')['candidates']))

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
