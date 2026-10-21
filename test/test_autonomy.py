import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend import findings as F
from backend.autonomy import MAX_RESPONSE_TOKENS
from backend.reviewed_check import validate as validate_reviewed_check
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

    def test_temporary_uncapped_mode_runs_more_than_three_checks(self):
        class RepeatedHeaders(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                user = json.loads(messages[1]['content'])
                self.prompts.append(user)
                choice = next((c['id'] for c in user['context']['candidates']
                               if c['catalogId'] == 'http-headers'), None)
                return {'model': 'fake', 'data': {'candidateId': choice,
                        'reason': 'Inspect the next recorded web service.',
                        'expectedEvidence': 'HTTP response headers'}}

        doc = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for web.03.crimsonia.net (100.96.1.70)\nHost is up.\n'
            '80/tcp open http\n8000/tcp open http\n8080/tcp open http\n8888/tcp open http\n'
            'Nmap done: 1 IP address (1 host up) scanned'})
        host = next(f for f in doc['findings'] if f['kind'] == 'host')
        host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        model = RepeatedHeaders()
        with patch.dict(os.environ, {'YAGURA_AUTONOMY_UNCAPPED': '1'}):
            ws = Workspace(findings_file=self.ws.findings_file, llm=model, runner=self.ws.runner)
        ws.save(doc)
        self.assertIsNone(ws.autonomy.limits()['maxChecks'])
        ws.autonomy.start(host['id'], self.scope)
        ws.autonomy.thread.join(3)
        run = ws.autonomy.history()['runs'][0]
        self.assertEqual(run['status'], 'completed')
        self.assertIsNone(run['maxChecks'])
        self.assertEqual(len([e for e in run['events'] if e['type'] == 'check']), 4)
        self.assertEqual(len(self.calls), 4)

    def test_exhausted_catalog_waits_for_review_and_revision_before_execution(self):
        class ProposalLlm(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                self.prompts.append(json.loads(messages[1]['content']))
                if len(self.prompts) == 1:
                    command = 'nmap -n -Pn -sT -p 8443 100.96.1.70'
                elif len(self.prompts) == 2:
                    command = 'nmap -n -Pn -sT -p 9443 100.96.1.70'
                else:
                    command = None
                return {'model': 'fake', 'data': {'command': command,
                        'reason': 'Check another approved TCP port.',
                        'expectedEvidence': 'Open or closed port state.'}}

        self.ws.llm = ProposalLlm()
        self.ws.runner = lambda program, args, timeout: self.calls.append((program, args, timeout)) or {
            'ok': True, 'stdout': 'Nmap scan report for web.03.crimsonia.net (100.96.1.70)\nHost is up.\n9443/tcp open ssl/https\nNmap done: 1 IP address (1 host up) scanned', 'stderr': ''}
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            run = self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
            pending = self.ws.autonomy.history()['runs'][0]
            self.assertEqual(pending['status'], 'awaiting-approval')
            self.assertEqual(self.calls, [])
            old = pending['pendingProposal']
            revised = self.ws.autonomy.revise(run['id'], old['id'], old['revision'],
                                               'Use TCP port 9443 instead.', self.scope)
            new = revised['pendingProposal']
            self.assertEqual(new['revision'], old['revision'] + 1)
            self.assertIn('9443', new['command'])
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.ws.autonomy.approve(run['id'], old['id'], old['revision'], old['command'], self.scope)
            self.assertEqual(self.calls, [])
            self.ws.autonomy.approve(run['id'], new['id'], new['revision'], new['command'], self.scope)
            self.ws.autonomy.thread.join(3)
            saved = self.ws.autonomy.history()['runs'][0]
            self.assertEqual(saved['status'], 'completed')
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0][0], 'nmap')
            self.assertEqual([e['type'] for e in saved['events']],
                             ['proposal', 'proposal', 'approval', 'check', 'stop'])

    def test_reviewed_command_grammar_blocks_extra_destinations_and_scripts(self):
        good, args = validate_reviewed_check('nmap -n -Pn -sT -p 80,443 100.96.1.70', '100.96.1.70')
        self.assertEqual(good, 'nmap -n -Pn -sT -p 80,443 100.96.1.70')
        self.assertEqual(args[-1], '100.96.1.70')
        for command in ('nmap -n -Pn -sT --script vuln -p 80 100.96.1.70',
                        'nmap -n -Pn -sT -p 80 100.96.1.71',
                        'nmap -n -Pn -sT -p 80 100.96.1.70; whoami',
                        'nmap -n -Pn -sT -p 80 100.96.1.70 8.8.8.8'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                validate_reviewed_check(command, '100.96.1.70')


if __name__ == '__main__':
    unittest.main()
