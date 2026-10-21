import json
from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.autonomy import MAX_RESPONSE_TOKENS
from backend.server import Workspace


class FakeLlm:
    def __init__(self, invalid=False):
        self.prompts = []
        self.invalid = invalid
        self.response_limits = []

    def assert_configuration(self):
        pass

    def complete(self, messages, max_tokens=400, model=''):
        self.response_limits.append(max_tokens)
        user = json.loads(messages[1]['content'])
        self.prompts.append(user)
        if self.invalid:
            candidate_id = 'outside-scope:invented'
        elif len(self.prompts) == 1:
            candidate_id = next(c['id'] for c in user['context']['candidates'] if c['catalogId'] == 'http-headers')
        else:
            candidate_id = None
        return {'model': 'fake', 'data': {'candidateId': candidate_id,
                                        'reason': 'The last response determines the next step.',
                                        'expectedEvidence': 'HTTP status and headers'}}


class AutonomyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        self.llm = FakeLlm()
        def runner(program, args, timeout):
            self.calls.append((program, args, timeout))
            return {'ok': True, 'stdout': 'HTTP/1.1 200 OK\nSet-Cookie: session=very-secret\n', 'stderr': ''}
        self.ws = Workspace(findings_file=Path(self.tmp.name) / 'findings.json', llm=self.llm, runner=runner)
        self.scope = self.ws.save_scope({'cidrs': ['100.96.1.0/24'], 'domains': ['03.crimsonia.net']})
        doc = F.parse_import({'tool': 'nmap', 'output': 'Nmap scan report for web.03.crimsonia.net (100.96.1.70)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'})
        self.host = next(f for f in doc['findings'] if f['kind'] == 'host')
        self.host['approval'] = {'ip': self.host['ip'], 'name': self.host['name'], 'scope': self.scope}
        self.ws.save(doc)

    def test_each_result_reaches_next_ai_decision_and_history_hides_cookie(self):
        run = self.ws.autonomy.start(self.host['id'], self.scope)
        self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['id'], run['id'])
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual([e['type'] for e in saved['events']], ['decision', 'check', 'decision', 'stop'])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.llm.response_limits, [MAX_RESPONSE_TOKENS, MAX_RESPONSE_TOKENS])
        self.assertEqual(self.llm.prompts[1]['lastResult']['outcome'], 'completed')
        self.assertIn('[REDACTED]', json.dumps(self.llm.prompts[1]))
        self.assertNotIn('very-secret', json.dumps(self.llm.prompts[1]))
        self.assertNotIn('very-secret', self.ws.findings_file.read_text())
        self.assertTrue(self.ws.autonomy.file.exists())

    def test_invented_candidate_never_runs(self):
        self.ws.llm = FakeLlm(invalid=True)
        self.ws.autonomy.start(self.host['id'], self.scope)
        self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'stopped')
        self.assertIn('outside', saved['stopReason'])
        self.assertEqual(self.calls, [])

    def test_restarted_running_history_is_interrupted_not_resumed(self):
        self.ws.autonomy._save({'runs': [{'id': 'old', 'status': 'running', 'events': []}]})
        restarted = Workspace(findings_file=self.ws.findings_file, llm=self.llm, runner=self.ws.runner)
        self.assertEqual(restarted.autonomy.history()['runs'][0]['status'], 'interrupted')
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
