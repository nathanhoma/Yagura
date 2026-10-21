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
                    command = 'nxc smb 100.96.1.70'
                elif len(self.prompts) == 2:
                    command = 'smbclient -L //100.96.1.70 -N'
                else:
                    command = None
                return {'model': 'fake', 'data': {'command': command,
                        'reason': 'Inspect the selected host.',
                        'expectedEvidence': 'Service and share information.',
                        'reviewNotes': 'One approved host; no credential supplied.'}}

        self.ws.llm = ProposalLlm()
        self.ws.runner = lambda program, args, timeout: self.calls.append((program, args, timeout)) or {
            'ok': True, 'stdout': 'Sharename Type Comment\npublic Disk Example share', 'stderr': ''}
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            run = self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
            pending = self.ws.autonomy.history()['runs'][0]
            self.assertEqual(pending['status'], 'awaiting-approval')
            self.assertEqual(self.calls, [])
            old = pending['pendingProposal']
            revised = self.ws.autonomy.revise(run['id'], old['id'], old['revision'],
                                               'Use smbclient share listing instead.', self.scope)
            new = revised['pendingProposal']
            self.assertEqual(new['revision'], old['revision'] + 1)
            self.assertIn('smbclient', new['command'])
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.ws.autonomy.approve(run['id'], old['id'], old['revision'], old['command'], self.scope)
            self.assertEqual(self.calls, [])
            self.ws.autonomy.approve(run['id'], new['id'], new['revision'], new['command'], self.scope)
            self.ws.autonomy.thread.join(3)
            saved = self.ws.autonomy.history()['runs'][0]
            self.assertEqual(saved['status'], 'completed')
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0][0], 'smbclient')
            self.assertEqual(self.calls[0][1], ['-L', '//100.96.1.70', '-N'])
            self.assertEqual([e['type'] for e in saved['events']],
                             ['proposal', 'proposal', 'approval', 'check', 'stop'])

    def test_reviewed_command_parser_accepts_any_program_without_implicit_shell(self):
        good, program, args = validate_reviewed_check('nxc smb 100.96.1.70 --shares', '100.96.1.70')
        self.assertEqual(good, 'nxc smb 100.96.1.70 --shares')
        self.assertEqual(program, 'nxc')
        self.assertEqual(args, ['smb', '100.96.1.70', '--shares'])
        for command in ('', 'nmap -p 80 100.96.1.70\nwhoami',
                        'nxc smb "unterminated', '-u user', 'nxc smb 100.96.1.70\x00'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                validate_reviewed_check(command, '100.96.1.70')

    def test_group_surveys_each_host_then_flags_and_deepens_with_citations(self):
        second = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for api.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        other = next(f for f in second['findings'] if f['kind'] == 'host')
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        doc = self.ws.load()
        F.merge_parsed(doc, second)
        other = next(f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == other['ip'])
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        self.ws.save(doc)
        def candidate(cid, hid, kind):
            host = next(f for f in doc['findings'] if f['id'] == hid)
            return dict(id=cid, hostId=hid, catalogId=kind, title=cid, reason='Recorded service',
                        findingIds=[hid], evidenceIds=host['evidenceIds'], command=f'ping -c 1 {host["ip"]}')
        rows = [candidate('baseline-1', self.host['id'], 'nmap-service'),
                candidate('baseline-2', other['id'], 'nmap-service'),
                candidate('deepen-1', self.host['id'], 'http-headers')]
        class GroupLlm(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                user = json.loads(messages[1]['content'])
                self.prompts.append(user)
                if 'previousFlags' not in user:
                    return {'model': 'fake', 'data': {'command': None, 'reason': 'No further check.',
                        'expectedEvidence': '', 'reviewNotes': ''}}
                options = {c['id'] for c in user['context']['candidates']}
                flag = {'hostId': self_host, 'reason': 'More service detail than the peer host.',
                        'uncertainty': 'The service response needs review.',
                        'findingIds': [self_host], 'evidenceIds': [host_evidence]}
                return {'model': 'fake', 'data': {'flags': [flag],
                    'candidateId': 'deepen-1' if 'deepen-1' in options else None,
                    'reason': 'Compare the detailed service response.'}}
        self_host = self.host['id']
        host_evidence = next(f for f in doc['findings'] if f['id'] == self_host)['evidenceIds'][0]
        self.ws.llm = GroupLlm()
        checks = []
        def execute(cid, scope, **kwargs):
            checks.append(cid)
            return dict(outcome='completed', imported=True, warning='', evidenceIds=[], output='ok', stderr='')
        with patch('backend.autonomy.workflow', return_value={'candidates': rows}), patch.object(self.ws, 'execute_candidate', side_effect=execute):
            run = self.ws.autonomy.start_group([self_host, other['id']], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['id'], run['id'])
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual(checks, ['baseline-1', 'baseline-2', 'deepen-1'])
        self.assertEqual(saved['surveyedHostIds'], [self_host, other['id']])
        self.assertEqual(saved['flags'][0]['findingIds'], [self_host])
        self.assertEqual(saved['flags'][0]['evidenceIds'], [host_evidence])
        self.assertEqual(len([e for e in saved['events'] if e['type'] == 'comparison']), 2)

    def test_group_rejects_unapproved_host_before_any_check(self):
        other = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for api.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        doc = self.ws.load()
        F.merge_parsed(doc, other)
        self.ws.save(doc)
        other_id = next(f['id'] for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == '100.96.1.71')
        with self.assertRaises(ValueError):
            self.ws.autonomy.start_group([self.host['id'], other_id], self.scope)
        self.assertEqual(self.calls, [])

    def test_group_rejects_cross_host_evidence_misattribution(self):
        second = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for api.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        doc = self.ws.load()
        F.merge_parsed(doc, second)
        other = next(f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == '100.96.1.71')
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        self.ws.save(doc)
        class BadComparison(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                return {'model': 'fake', 'data': {'flags': [{
                    'hostId': self_host, 'reason': 'Wrong evidence source.',
                    'uncertainty': 'Unknown.', 'findingIds': [self_host],
                    'evidenceIds': [other_evidence]}], 'candidateId': None, 'reason': ''}}
        self_host = self.host['id']
        other_evidence = other['evidenceIds'][0]
        self.ws.llm = BadComparison()
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            self.ws.autonomy.start_group([self_host, other['id']], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'stopped')
        self.assertIn('linked evidence', saved['stopReason'])
        self.assertEqual(self.calls, [])

    def test_scope_discovery_selects_ip_only_hosts_and_starts_group_loop(self):
        scope = self.ws.save_scope({'cidrs': ['100.96.1.0/28'], 'domains': []})
        class EmptyComparison(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                return {'model': 'fake', 'data': {'flags': [], 'candidateId': None,
                    'reason': 'No differentiated host yet.'}}
        self.ws.llm = EmptyComparison()
        def runner(program, args, timeout):
            self.calls.append((program, args, timeout))
            addresses = ['100.96.1.1', '100.96.1.2'] if '-sn' in args else [args[-1]]
            output = ''.join(f'Nmap scan report for {ip}\nHost is up.\n' for ip in addresses)
            return {'ok': True, 'stdout': output +
                    f'Nmap done: {len(addresses)} IP addresses ({len(addresses)} hosts up) scanned',
                    'stderr': ''}
        self.ws.runner = runner
        run = self.ws.autonomy.start_discover_group(scope, [])
        self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['id'], run['id'])
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual(saved['mode'], 'discover-group')
        self.assertEqual(len(saved['hostIds']), 2)
        self.assertEqual(len([e for e in saved['events'] if e['type'] == 'discovery']), 1)
        self.assertEqual(len([e for e in saved['events'] if e['type'] == 'comparison']), 1)
        self.assertTrue(all(call[0] == 'nmap' for call in self.calls))

    def test_scope_discovery_retries_failed_segment_on_resume(self):
        scope = self.ws.save_scope({'cidrs': ['100.96.1.0/28'], 'domains': []})
        class EmptyComparison(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                return {'model': 'fake', 'data': {'flags': [], 'candidateId': None, 'reason': 'Done.'}}
        self.ws.llm = EmptyComparison()
        attempts = []
        def runner(program, args, timeout):
            if '-sn' in args:
                attempts.append(args[-1])
                if len(attempts) == 1:
                    return {'ok': False, 'stdout': '', 'stderr': 'temporary tool failure'}
                return {'ok': True, 'stdout':
                    'Nmap scan report for 100.96.1.1\nHost is up.\n'
                    'Nmap scan report for 100.96.1.2\nHost is up.\n'
                    'Nmap done: 2 IP addresses (2 hosts up) scanned', 'stderr': ''}
            return {'ok': True, 'stdout': f'Nmap scan report for {args[-1]}\nHost is up.\n'
                'Nmap done: 1 IP address (1 host up) scanned', 'stderr': ''}
        self.ws.runner = runner
        run = self.ws.autonomy.start_discover_group(scope, [])
        self.ws.autonomy.thread.join(3)
        self.assertEqual(self.ws.autonomy.history()['runs'][0]['status'], 'awaiting-discovery')
        self.ws.autonomy.resume_discover_group(run['id'], scope)
        self.ws.autonomy.thread.join(3)
        self.assertEqual(self.ws.autonomy.history()['runs'][0]['status'], 'completed')
        self.assertEqual(attempts, ['100.96.1.0/28', '100.96.1.0/28'])


if __name__ == '__main__':
    unittest.main()
