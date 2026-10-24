from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.analysis import analyze, build_context, validate_result
from backend.llm import LlmService, LlmError, private_url
from backend.llm_metrics import LlmMetrics
from backend.server import Workspace, valid_cidr
from backend.workflow import workflow


FIXTURES = Path(__file__).parent / 'fixtures'


def imported():
    doc = F.empty()
    F.merge_parsed(doc, F.parse_import(dict(tool='nmap', output=(FIXTURES / 'nmap.xml').read_text(), observedAt='2026-09-29T12:00:00Z')))
    return doc


class FakeLlm:
    def configuration(self):
        return {'model': None}

    def complete(self, *args, **kwargs):
        raise RuntimeError('test model unavailable')


class BackendTests(unittest.TestCase):
    def test_imported_ptr_does_not_replace_approved_hostname(self):
        scope = {'cidrs': ['10.3.20.0/23'], 'domains': ['03.crimsonia.net'], 'matchMode': 'and'}
        doc = F.empty()
        F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for files.caf.03.crimsonia.net (10.3.20.4)\nHost is up.\n'
            'Nmap done: 1 IP address (1 host up) scanned'}))
        host = next(f for f in doc['findings'] if f['kind'] == 'host')
        host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': scope}
        F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for fs.caf.03.crimsonia.net (10.3.20.4)\nHost is up.\n'
            'Nmap done: 1 IP address (1 host up) scanned'}))
        self.assertEqual(host['name'], 'files.caf.03.crimsonia.net')
        from backend.scope import approved_host
        self.assertTrue(approved_host(host, scope))

    def test_llm_metrics_keep_per_run_totals_beyond_recent_call_log(self):
        with tempfile.TemporaryDirectory() as folder:
            metrics = LlmMetrics(Path(folder) / 'llm-metrics.json')
            metrics.path.write_text('[]')  # Existing installations stored a list.
            with metrics.for_run('run-1', 'tool selection'):
                for _ in range(101):
                    metrics.record({'inputChars': 120, 'promptTokens': 40,
                                    'completionTokens': 10})
            with metrics.for_run('run-1', 'result review'):
                metrics.record({'inputChars': 200, 'promptTokens': None,
                                'completionTokens': None})
            metrics.record({'inputChars': 9, 'promptTokens': 2,
                            'completionTokens': 1})
            summary = metrics.run_summary('run-1')
            self.assertEqual(summary['callCount'], 102)
            self.assertEqual(summary['inputTokens'], 4040)
            self.assertEqual(summary['outputTokens'], 1010)
            self.assertEqual(summary['inputTokenCalls'], 101)
            self.assertEqual(summary['maxInputChars'], 200)
            self.assertEqual(summary['stages'], {'tool selection': 101, 'result review': 1})
            self.assertEqual(len(metrics.history()), 100)
            self.assertNotIn('runId', metrics.history()[0])

    def test_llm_metrics_capture_usage_and_truncation_without_content(self):
        llm = LlmService(model='test-model')
        rows = []
        llm.on_completion = rows.append
        llm.call = lambda route, body=None: {'choices': [{'message': {'content': '{"answer":"secret-value"}'}, 'finish_reason': 'stop'}],
                                               'usage': {'prompt_tokens': 42, 'completion_tokens': 8, 'total_tokens': 50}}
        llm.complete([{'role': 'user', 'content': 'password=secret-value'}], max_tokens=100)
        self.assertEqual((rows[0]['promptTokens'], rows[0]['completionTokens'], rows[0]['finishReason']), (42, 8, 'stop'))
        self.assertEqual(rows[0]['inputChars'], len('password=secret-value'))
        self.assertNotIn('secret-value', str(rows))
        llm.call = lambda route, body=None: {'choices': [{'message': {'content': '{"partial":true}'}, 'finish_reason': 'length'}]}
        with self.assertRaisesRegex(LlmError, 'truncated'):
            llm.complete([{'role': 'user', 'content': 'test'}], max_tokens=100)
        self.assertEqual((rows[1]['status'], rows[1]['finishReason'], rows[1]['outputChars']),
                         ('invalid-response', 'length', len('{"partial":true}')))
        self.assertIsNone(rows[1]['promptTokens'])

    def test_llm_timeout_allows_ten_minutes_and_remains_bounded(self):
        self.assertEqual(LlmService(timeout_ms=180000).timeout, 180)
        self.assertEqual(LlmService(timeout_ms=300000).timeout, 300)
        self.assertEqual(LlmService(timeout_ms=600000).timeout, 600)
        self.assertEqual(LlmService(timeout_ms=900000).timeout, 600)
        self.assertEqual(LlmService().timeout, 30)

    def test_all_import_formats_link_records(self):
        for tool, filename, count in [('nmap', 'nmap.xml', 1), ('nmap', 'nmap.txt', 1), ('ip addr', 'addr.json', 2), ('ip addr', 'addr.txt', 4), ('ip neigh', 'neigh.json', 2), ('ip neigh', 'neigh.txt', 3), ('ping', 'ping.txt', 1)]:
            with self.subTest(filename=filename):
                parsed = F.parse_import(dict(tool=tool, output=(FIXTURES / filename).read_text()))
                self.assertEqual(len([f for f in parsed['findings'] if f['kind'] == 'host']), count)
                ids = {f['id']: f for f in parsed['findings']}
                for f in parsed['findings']:
                    if f.get('hostId'):
                        self.assertEqual(ids[f['hostId']]['kind'], 'host')
                    if f.get('serviceId'):
                        self.assertEqual(ids[f['serviceId']]['kind'], 'service')

    def test_reimport_preserves_reviewed_changes_and_evidence(self):
        doc = imported()
        host = next(f for f in doc['findings'] if f['kind'] == 'host')
        F.edit_finding(doc, host, {'name': 'Corrected'})
        count = len(doc['findings'])
        parsed = F.parse_import(dict(tool='nmap', output=(FIXTURES / 'nmap.xml').read_text(), observedAt='2026-09-30T12:00:00Z'))
        summary = F.merge_parsed(doc, parsed)
        self.assertEqual(len(doc['findings']), count)
        self.assertEqual(summary['added'], 0)
        self.assertEqual(host['name'], 'Corrected')
        self.assertEqual(len(host['evidenceIds']), 2)

    def test_workflow_scope_and_model_fallback(self):
        doc = imported()
        self.assertEqual(workflow(doc)['candidates'], [])
        candidates = workflow(doc, '192.168.56.10/32')['candidates']
        self.assertTrue(any(c['catalogId'] == 'http-headers' for c in candidates))
        self.assertIn('sudo -n nmap -n -Pn -O --top-ports 100 --max-retries 1 -oX - 192.168.56.10', [c['command'] for c in candidates])
        self.assertTrue(all('{' not in c['command'] for c in candidates))
        self.assertEqual(workflow(doc, '192.168.56.11/32')['candidates'], [])
        result = analyze(doc, {}, FakeLlm())
        self.assertEqual(result['status'], 'fallback')
        self.assertTrue(result['assessments'])
        self.assertEqual(result['suggestions'], [])
        os_output = 'Nmap scan report for 192.168.56.10\nHost is up.\n80/tcp open http\nOS details: Linux 5.x\nNmap done: 1 IP address (1 host up) scanned\n'
        F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'command': 'nmap -n -Pn -O 192.168.56.10', 'output': os_output}))
        self.assertTrue(any(f.get('title') == 'Nmap OS guess' and 'Linux 5.x' in f.get('detail', '') for f in doc['findings']))
        self.assertFalse(any(c['catalogId'] == 'nmap-os' for c in workflow(doc, '192.168.56.10/32')['candidates']))
        context = build_context(doc)
        with self.assertRaises(Exception):
            validate_result({'assessments': [{'findingIds': ['invented'], 'evidenceIds': ['invented'], 'interpretation': 'bad', 'uncertainties': []}], 'suggestions': []}, context)

    def test_os_scan_xml_saves_an_os_guess(self):
        xml = ('<nmaprun><host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>'
               '<ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>'
               '<os><osmatch name="Linux 5.x" accuracy="92"/><osmatch name="FreeBSD 12" accuracy="89"/></os></host></nmaprun>')
        parsed = F.parse_import({'tool': 'nmap', 'command': 'sudo -n nmap -n -Pn -O --top-ports 100 --max-retries 1 -oX - 192.168.56.10', 'output': xml})
        guesses = [f for f in parsed['findings'] if f.get('title') == 'Nmap OS guess']
        self.assertEqual([f['detail'] for f in guesses], ['Linux 5.x (92% accuracy)'])

    def test_storage_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(findings_file=Path(directory) / 'findings.json')
            doc = imported()
            workspace.save(doc)
            self.assertEqual(workspace.load(), doc)
            self.assertTrue(workspace.findings_file.exists())
        for cidr in ('192.168.56.0/24', '10.0.0.0/22', '127.0.0.1/32'):
            self.assertTrue(valid_cidr(cidr))
        for cidr in ('8.8.8.0/24', '192.168.0.0/21', '192.168.300.1/24'):
            self.assertFalse(valid_cidr(cidr))
        self.assertTrue(private_url('http://127.0.0.1:11434/v1'))
        self.assertFalse(private_url('http://user:password@localhost/v1'))

    def test_explicit_https_gateway_url(self):
        host = 'llm-gateway.xs.network'
        base = f'https://{host}/v1'
        self.assertFalse(private_url(base))
        self.assertTrue(private_url(base, host))
        self.assertTrue(LlmService(base, trusted_https_host=host).configuration()['allowed'])
        for url in (f'http://{host}/v1', f'https://other.{host}/v1',
                    f'https://{host}.example/v1', f'https://user:pass@{host}/v1',
                    f'https://{host}/v1?x=1', f'https://{host}/v1#fragment'):
            with self.subTest(url=url):
                self.assertFalse(private_url(url, host))

    def test_ping_no_reply_and_xml_reject(self):
        result = F.parse_import({'tool': 'ping', 'output': 'PING 192.168.56.10 (192.168.56.10) 56(84) bytes of data.\n3 packets transmitted, 0 received, 100% packet loss'})
        self.assertEqual(result['findings'][0]['state'], 'no-response')
        with self.assertRaises(ValueError):
            F.parse_import({'tool': 'nmap', 'output': '<nmaprun><host></nmaprun>'})

    def test_nmap_pn_does_not_prove_reachability_without_open_port(self):
        start = '<nmaprun args="nmap -Pn -sT --top-ports 100 192.168.56.10"><host><status state="up" reason="user-set"/><address addr="192.168.56.10" addrtype="ipv4"/><ports>'
        end = '</ports></host></nmaprun>'
        no_open = F.parse_import({'tool': 'nmap', 'output': start + '<extraports state="filtered" count="100"/>' + end})
        host = next(f for f in no_open['findings'] if f['kind'] == 'host')
        self.assertEqual(host['state'], 'unknown')
        self.assertIn('assumed', next(f['detail'] for f in no_open['findings'] if f['kind'] == 'observation'))
        opened = F.parse_import({'tool': 'nmap', 'output': start + '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>' + end})
        self.assertEqual(next(f['state'] for f in opened['findings'] if f['kind'] == 'host'), 'up')
        text = 'Nmap scan report for 192.168.56.10\nHost is up.\nAll 100 scanned ports on 192.168.56.10 are filtered\nNmap done: 1 IP address (1 host up) scanned\n'
        parsed = F.parse_import({'tool': 'nmap', 'command': 'nmap -n -Pn -sT --top-ports 100 192.168.56.10', 'output': text})
        self.assertEqual(next(f['state'] for f in parsed['findings'] if f['kind'] == 'host'), 'unknown')
        open_text = ('Nmap scan report for 192.168.56.10\nHost is up.\n'
                     'PORT    STATE SERVICE\n443/tcp open  https\n'
                     'Nmap done: 1 IP address (1 host up) scanned\n')
        opened_text = F.parse_import({'tool': 'nmap', 'command': 'nmap -n -Pn -sT -p 443 192.168.56.10',
                                      'output': open_text})
        self.assertEqual(next(f['state'] for f in opened_text['findings'] if f['kind'] == 'host'), 'up')
        self.assertEqual(next(f['detail'] for f in opened_text['findings'] if f['kind'] == 'observation'),
                         'Host responded on an open port.')

    def test_model_adapter_selects_advertised_ids(self):
        llm = LlmService('http://127.0.0.1:11434/v1')
        calls = []
        def call(route, body=None):
            calls.append((route, body))
            if route == '/models':
                return {'data': [{'id': 'local-model'}]}
            return {'choices': [{'message': {'content': '{"assessments":[],"suggestions":[]}'}}]}
        llm.call = call
        self.assertEqual(llm.health()['model'], 'local-model')
        self.assertEqual(llm.complete([])['model'], 'local-model')
        self.assertEqual(calls[-1][1]['model'], 'local-model')
        with self.assertRaises(LlmError):
            llm.complete([], model='invented')


if __name__ == '__main__':
    unittest.main()
