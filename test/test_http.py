import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from backend.server import Workspace, create_server


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        def runner(program, args, timeout):
            self.calls.append((program, args))
            return {'ok': False, 'stdout': '', 'stderr': 'test tool unavailable'}
        self.workspace = Workspace(findings_file=Path(self.tmp.name) / 'findings.json', runner=runner)
        self.server = create_server(port=0, workspace=self.workspace)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.shutdown)
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def call(self, path, method='GET', body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    def test_import_review_analysis_and_export(self):
        output = (Path(__file__).parent / 'fixtures/nmap.xml').read_text()
        payload = {'tool': 'nmap', 'output': output}
        status, preview = self.call('/api/import/preview', 'POST', payload)
        self.assertEqual(status, 200)
        self.assertFalse(self.workspace.findings_file.exists())
        status, doc = self.call('/api/import', 'POST', payload)
        self.assertEqual(status, 201)
        host = next(f for f in doc['findings'] if f['kind'] == 'host')
        status, result = self.call('/api/analysis', 'POST', {'hostId': host['id']})
        self.assertEqual(status, 200)
        self.assertEqual(result['source'], 'built-in')
        self.assertFalse(result['stale'])
        self.assertEqual(self.call('/api/analysis/latest')[1]['analysis'], result)
        status, updated = self.call('/api/findings/' + host['id'], 'PATCH', {'name': 'Reviewed'})
        self.assertEqual(status, 200)
        self.assertEqual(next(f for f in updated['findings'] if f['id'] == host['id'])['name'], 'Reviewed')
        self.assertTrue(self.call('/api/analysis/latest')[1]['analysis']['stale'])
        self.assertEqual(self.call('/api/export')[1], self.call('/api/findings')[1])
        self.assertEqual(self.call('/server.js')[0], 404)
        self.assertEqual(self.call('/.env')[0], 404)

    def test_authorized_fixed_check_and_invalid_body(self):
        status, note = self.call('/api/findings', 'POST', {'ip': '10.0.4.80', 'title': 'Target', 'detail': 'Authorized lab target'})
        self.assertEqual(status, 201)
        self.assertEqual(self.call('/api/workflow')[1]['candidates'], [])
        self.assertEqual(self.call('/api/workflow?cidr=10.0.4.81/32')[1]['candidates'], [])
        self.assertEqual(self.call('/api/suggest', 'POST', {})[1]['suggestions'], [])
        candidate = next(c for c in self.call('/api/workflow?cidr=10.0.4.80/32')[1]['candidates'] if c['catalogId'] == 'nmap-ports')
        self.assertEqual(self.call('/api/checks/run', 'POST', {'candidateId': candidate['id']})[0], 400)
        self.assertEqual(self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True, 'command': 'arbitrary'})[0], 400)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True})[0], 400)
        self.assertEqual(self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True, 'authorizedCidr': '10.0.4.81/32'})[0], 400)
        status, result = self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True, 'authorizedCidr': '10.0.4.80/32'})
        self.assertEqual(status, 200)
        self.assertEqual(self.calls, [('nmap', ['-n', '-Pn', '-sT', '--top-ports', '100', '10.0.4.80'])])
        self.assertEqual(result['command'], candidate['command'])
        self.assertEqual(self.call('/api/analysis', 'POST', {'findings': []})[0], 400)

    def test_model_result_only_uses_server_candidates(self):
        class FakeModel:
            base = 'http://127.0.0.1:11434/v1'
            def configuration(self):
                return {'model': 'test-model'}
            def complete(self, messages, **kwargs):
                context = json.loads(messages[1]['content'])
                finding = next(f for f in context['findings'] if f['kind'] == 'service')
                return {'model': 'test-model', 'data': {
                    'assessments': [{'findingIds': [finding['id']], 'evidenceIds': [finding['evidenceIds'][0]], 'interpretation': 'Observed service needs review.', 'uncertainties': ['No access evidence.']}],
                    'suggestions': [{'candidateId': context['candidates'][0]['id'], 'command': 'invented command'}]}}
        self.workspace.llm = FakeModel()
        output = (Path(__file__).parent / 'fixtures/nmap.xml').read_text()
        self.call('/api/import', 'POST', {'tool': 'nmap', 'output': output})
        status, result = self.call('/api/analysis', 'POST', {'authorizedCidr': '192.168.56.10/32'})
        self.assertEqual(status, 200)
        self.assertEqual(result['source'], 'local model')
        self.assertEqual(len(result['assessments']), 1)
        self.assertNotEqual(result['suggestions'][0]['command'], 'invented command')

    def test_os_check_uses_fixed_scoped_nmap_arguments(self):
        output = (Path(__file__).parent / 'fixtures/nmap.xml').read_text()
        self.call('/api/import', 'POST', {'tool': 'nmap', 'output': output})
        candidates = self.call('/api/workflow?cidr=192.168.56.10/32')[1]['candidates']
        candidate = next(c for c in candidates if c['catalogId'] == 'nmap-os')
        self.assertEqual(self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True, 'authorizedCidr': '192.168.56.11/32'})[0], 400)
        status, result = self.call('/api/checks/run', 'POST', {'candidateId': candidate['id'], 'authorized': True, 'authorizedCidr': '192.168.56.10/32'})
        self.assertEqual(status, 200)
        self.assertEqual(result['command'], 'nmap -n -Pn -O 192.168.56.10')
        self.assertEqual(self.calls, [('nmap', ['-n', '-Pn', '-O', '192.168.56.10'])])


if __name__ == '__main__':
    unittest.main()
