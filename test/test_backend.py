from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.analysis import analyze, build_context, validate_result
from backend.llm import LlmService, LlmError, private_url
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
        candidates = workflow(doc)['candidates']
        self.assertTrue(any(c['catalogId'] == 'http-headers' for c in candidates))
        self.assertTrue(all('{' not in c['command'] for c in candidates))
        result = analyze(doc, {}, FakeLlm())
        self.assertEqual(result['status'], 'fallback')
        self.assertTrue(result['assessments'])
        context = build_context(doc)
        with self.assertRaises(Exception):
            validate_result({'assessments': [{'findingIds': ['invented'], 'evidenceIds': ['invented'], 'interpretation': 'bad', 'uncertainties': []}], 'suggestions': []}, context)

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

    def test_ping_no_reply_and_xml_reject(self):
        result = F.parse_import({'tool': 'ping', 'output': 'PING 192.168.56.10 (192.168.56.10) 56(84) bytes of data.\n3 packets transmitted, 0 received, 100% packet loss'})
        self.assertEqual(result['findings'][0]['state'], 'no-response')
        with self.assertRaises(ValueError):
            F.parse_import({'tool': 'nmap', 'output': '<nmaprun><host></nmaprun>'})

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
