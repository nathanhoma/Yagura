import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from backend import findings as F
from backend.autonomy import FLAG_PROMPT, FLAG_RESPONSE_TOKENS, MAX_RESPONSE_TOKENS, TOOL_SELECTION_PROMPT
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
        if messages[0]['content'] == FLAG_PROMPT:
            return {'model': 'fake', 'data': {'flag': None}}
        user = json.loads(messages[1]['content'])
        self.prompts.append(user)
        if self.invalid:
            candidate_id = 'outside-scope:invented'
        elif len(self.prompts) == 1:
            candidate_id = next((c['id'] for c in user['context']['candidates'] if c['catalogId'] == 'http-headers'), None)
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

    def test_first_ai_check_is_generated_and_waits_for_exact_approval(self):
        class ToolLlm(FakeLlm):
            def __init__(self):
                super().__init__()
                self.selected = 0
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == FLAG_PROMPT:
                    return {'model': 'fake', 'data': {'flag': None}}
                self.prompts.append(json.loads(messages[1]['content']))
                if messages[0]['content'] == TOOL_SELECTION_PROMPT:
                    self.selected += 1
                    return {'model': 'fake', 'data': {'toolId': 'curl' if self.selected == 1 else None,
                        'reason': 'Inspect the approved web host.'}}
                return {'model': 'fake', 'data': {'command': 'curl -I http://100.96.1.70/',
                    'reason': 'Inspect HTTP headers.', 'expectedEvidence': 'HTTP status and headers',
                    'reviewNotes': 'One approved destination.'}}

        self.ws.llm = ToolLlm()
        with patch('backend.autonomy.available_tools', return_value=[{'id': 'curl', 'purpose': 'HTTP'}]), \
             patch('backend.autonomy.read_help', return_value={'tool': 'curl', 'invocation': ['curl', '--help'], 'text': 'usage', 'truncated': False}):
            run = self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
            pending = self.ws.autonomy.history()['runs'][0]
            self.assertEqual(pending['status'], 'awaiting-approval')
            self.assertEqual(self.calls, [])
            proposal = pending['pendingProposal']
            self.assertTrue(proposal['catalogued'])
            self.ws.autonomy.approve(run['id'], proposal['id'], proposal['revision'], proposal['command'], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual([e['type'] for e in saved['events']], ['proposal', 'approval', 'check', 'flag-review', 'stop'])
        self.assertEqual(len(self.calls), 1)
        self.assertIn('[REDACTED]', json.dumps(self.ws.load()))
        self.assertNotIn('very-secret', self.ws.findings_file.read_text())

    def test_invented_tool_never_runs(self):
        class InventedTool(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                return {'model': 'fake', 'data': {'toolId': 'invented-tool', 'reason': 'Try it.'}}
        self.ws.llm = InventedTool()
        with patch('backend.autonomy.available_tools', return_value=[{'id': 'curl', 'purpose': 'HTTP'}]):
            self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'stopped')
        self.assertIn('outside the installed catalog', saved['stopReason'])
        self.assertEqual(self.calls, [])

    def test_restarted_running_history_is_interrupted_not_resumed(self):
        self.ws.autonomy._save({'runs': [{'id': 'old', 'status': 'running', 'events': []}]})
        restarted = Workspace(findings_file=self.ws.findings_file, llm=self.llm, runner=self.ws.runner)
        self.assertEqual(restarted.autonomy.history()['runs'][0]['status'], 'interrupted')
        self.assertEqual(self.calls, [])

    def test_ai_mode_has_no_check_count_limit_and_no_fixed_check_runs(self):
        class RepeatedHeaders(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == FLAG_PROMPT:
                    return {'model': 'fake', 'data': {'flag': None}}
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
        ws = Workspace(findings_file=self.ws.findings_file, llm=model, runner=self.ws.runner)
        ws.save(doc)
        self.assertIsNone(ws.autonomy.limits()['maxChecks'])
        self.assertIsNone(ws.autonomy.limits()['groupMaxChecks'])
        ws.autonomy.start(host['id'], self.scope)
        ws.autonomy.thread.join(3)
        run = ws.autonomy.history()['runs'][0]
        self.assertEqual(run['status'], 'completed')
        self.assertIsNone(run['maxChecks'])
        self.assertEqual(len([e for e in run['events'] if e['type'] == 'check']), 0)
        self.assertEqual(len(self.calls), 0)

    def test_group_mode_records_no_count_limit(self):
        doc = self.ws.load()
        extra = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for other.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'})
        other = next(f for f in extra['findings'] if f['kind'] == 'host')
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        F.merge_parsed(doc, extra)
        ws = Workspace(findings_file=self.ws.findings_file, llm=self.llm, runner=self.ws.runner)
        ws.save(doc)
        with patch.object(ws.autonomy, '_group_worker'):
            run = ws.autonomy.start_group([self.host['id'], other['id']], self.scope)
            ws.autonomy.thread.join(3)
        self.assertIsNone(run['maxChecks'])
        self.assertEqual(ws.autonomy.limits()['groupMaxSeconds'], 1800)

    def test_group_survey_accepts_more_than_eight_approved_hosts(self):
        doc = self.ws.load()
        for number in range(71, 80):
            parsed = F.parse_import({'tool': 'nmap', 'output':
                f'Nmap scan report for host{number}.03.crimsonia.net (100.96.1.{number})\n'
                'Host is up.\nNmap done: 1 IP address (1 host up) scanned'})
            F.merge_parsed(doc, parsed)
        hosts = [h for h in doc['findings'] if h['kind'] == 'host']
        for host in hosts:
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        self.ws.save(doc)
        with patch.object(self.ws.autonomy, '_group_worker') as worker:
            run = self.ws.autonomy.start_group([h['id'] for h in hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        self.assertEqual(len(run['hostIds']), 10)
        self.assertIsNone(self.ws.autonomy.limits()['groupMaxHosts'])
        worker.assert_called_once()

    def test_selected_group_survey_can_resume_without_repeating_hosts(self):
        run = {'id': 'resume-selected-survey', 'mode': 'group', 'phase': 'survey',
            'status': 'awaiting-discovery', 'scope': self.scope, 'model': 'server default',
            'hostIds': ['one', 'two'], 'surveyedHostIds': ['one'], 'events': []}
        self.ws.autonomy._save({'runs': [run]})
        with patch.object(self.ws.autonomy, '_group_worker') as worker:
            self.ws.autonomy.resume_discover_group(run['id'], self.scope)
            self.ws.autonomy.thread.join(3)
        worker.assert_called_once()
        self.assertEqual(self.ws.autonomy.history()['runs'][0]['surveyedHostIds'], ['one'])

    def test_selected_group_survey_pauses_at_time_limit(self):
        run = {'id': 'timed-survey', 'mode': 'group', 'phase': 'survey',
               'hostIds': ['one', 'two'], 'surveyedHostIds': ['one'], 'events': []}
        with patch.object(self.ws.autonomy, '_group_state', return_value=(run, {}, {})), \
                patch.object(self.ws.autonomy, '_pause_discovery') as pause, \
                patch('backend.autonomy.time.monotonic', side_effect=[0, 1801]):
            self.ws.autonomy._group_worker(run['id'], self.scope, '', threading.Event())
        pause.assert_called_once()
        self.assertEqual(pause.call_args.args[:2], (run['id'], 'awaiting-discovery'))

    def test_exhausted_catalog_waits_for_review_and_revision_before_execution(self):
        class ProposalLlm(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == FLAG_PROMPT:
                    return {'model': 'fake', 'data': {'flag': None}}
                self.prompts.append(json.loads(messages[1]['content']))
                if messages[0]['content'] == TOOL_SELECTION_PROMPT:
                    return {'model': 'fake', 'data': {'toolId': 'nxc' if len(self.prompts) == 1 else 'smbclient',
                            'reason': 'Inspect the selected SMB service.'}}
                if len(self.prompts) == 2:
                    command = 'nxc smb 100.96.1.70'
                elif len(self.prompts) == 4:
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
        with patch('backend.autonomy.workflow', return_value={'candidates': []}), \
             patch('backend.autonomy.available_tools', return_value=[{'id': 'nxc', 'purpose': 'SMB'}, {'id': 'smbclient', 'purpose': 'SMB'}]), \
             patch('backend.autonomy.read_help', side_effect=lambda tool: {'tool': tool, 'invocation': [tool, '--help'], 'text': 'usage', 'truncated': False}):
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
                     ['proposal', 'proposal', 'approval', 'check', 'flag-review', 'stop'])

    def test_reviewed_command_parser_accepts_any_program_without_implicit_shell(self):
        good, program, args = validate_reviewed_check('nxc smb 100.96.1.70 --shares', '100.96.1.70')
        self.assertEqual(good, 'nxc smb 100.96.1.70 --shares')
        self.assertEqual(program, 'nxc')
        self.assertEqual(args, ['smb', '100.96.1.70', '--shares'])
        for command in ('', 'nmap -p 80 100.96.1.70\nwhoami',
                        'nxc smb "unterminated', '-u user', 'nxc smb 100.96.1.70\x00'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                validate_reviewed_check(command, '100.96.1.70')

    def test_ai_command_must_use_documented_tool_and_never_runs_before_review(self):
        class MismatchLlm(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == TOOL_SELECTION_PROMPT:
                    return {'model': 'fake', 'data': {'toolId': 'nmap', 'reason': 'Inspect the host.'}}
                return {'model': 'fake', 'data': {'command': 'curl http://100.96.1.70/',
                    'reason': 'Inspect the host.', 'expectedEvidence': 'HTTP response.',
                    'reviewNotes': 'One destination.'}}

        self.ws.llm = MismatchLlm()
        with patch('backend.autonomy.workflow', return_value={'candidates': []}), \
             patch('backend.autonomy.available_tools', return_value=[{'id': 'nmap', 'purpose': 'Ports'}]), \
             patch('backend.autonomy.read_help', return_value={'tool': 'nmap', 'invocation': ['nmap', '--help'], 'text': 'usage', 'truncated': False}):
            self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
        run = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(run['status'], 'stopped')
        self.assertIn('different executable', run['stopReason'])
        self.assertEqual(self.calls, [])

    def test_unlisted_installed_tool_requires_human_review_without_running_help(self):
        class UnlistedLlm(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == TOOL_SELECTION_PROMPT:
                    return {'model': 'fake', 'data': {'toolId': None, 'unlistedTool': 'otherutil',
                        'reason': 'Review its output.'}}
                return {'model': 'fake', 'data': {'command': 'otherutil 100.96.1.70',
                    'reason': 'Inspect the host.', 'expectedEvidence': 'Service output.',
                    'reviewNotes': 'Human must verify tool behavior.'}}

        self.ws.llm = UnlistedLlm()
        with patch('backend.autonomy.available_tools', return_value=[{'id': 'nmap', 'purpose': 'Ports'}]), \
             patch('backend.autonomy.shutil.which', return_value='/usr/bin/otherutil'), \
             patch('backend.autonomy.read_help') as read_help:
            self.ws.autonomy.start(self.host['id'], self.scope)
            self.ws.autonomy.thread.join(3)
        pending = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(pending['status'], 'awaiting-approval')
        self.assertFalse(pending['pendingProposal']['catalogued'])
        self.assertIsNone(pending['pendingProposal']['helpInvocation'])
        self.assertEqual(self.calls, [])
        read_help.assert_not_called()

    def test_group_surveys_each_host_with_reviewed_tool_then_selects_deep_dive(self):
        second = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for api.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        doc = self.ws.load()
        F.merge_parsed(doc, second)
        other = next(f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == '100.96.1.71')
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        self.ws.save(doc)

        class GroupModel(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                if messages[0]['content'] == FLAG_PROMPT:
                    return {'model': 'fake', 'data': {'flag': None}}
                user = json.loads(messages[1]['content'])
                if messages[0]['content'] == TOOL_SELECTION_PROMPT:
                    return {'model': 'fake', 'data': {'toolId': 'curl' if len(self.prompts) < 2 else None,
                        'reason': 'Check this surveyed host.'}}
                self.prompts.append(user)
                return {'model': 'fake', 'data': {'command': 'curl -I http://' + user['hostIp'] + '/',
                    'reason': 'Read the recorded service.', 'expectedEvidence': 'HTTP response.',
                    'reviewNotes': 'One approved destination.'}}

        self.ws.llm = GroupModel()
        with patch('backend.autonomy.available_tools', return_value=[{'id': 'curl', 'purpose': 'HTTP'}]), \
             patch('backend.autonomy.read_help', return_value={'tool': 'curl', 'invocation': ['curl', '--help'], 'text': 'usage', 'truncated': False}), \
             patch.object(self.ws.autonomy, '_worker') as deep_dive:
            run = self.ws.autonomy.start_group([self.host['id'], other['id']], self.scope)
            self.ws.autonomy.thread.join(3)
            for expected in [self.host['id'], other['id']]:
                pending = self.ws.autonomy.history()['runs'][0]
                self.assertEqual(pending['status'], 'awaiting-approval')
                self.assertEqual(pending['hostId'], expected)
                proposal = pending['pendingProposal']
                self.ws.autonomy.approve(run['id'], proposal['id'], proposal['revision'], proposal['command'], self.scope)
                self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['phase'], 'deep-dive')
        self.assertEqual(saved['surveyedHostIds'], [self.host['id'], other['id']])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len([e for e in saved['events'] if e['type'] == 'deep-dive-selection']), 1)
        deep_dive.assert_called_once()

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

    def test_group_deep_dive_approval_resumes_one_host_worker(self):
        command = 'nmap -n -Pn -sT -p 80 100.96.1.70'
        run = dict(id='group-review', mode='group', phase='deep-dive', status='awaiting-approval',
            hostId=self.host['id'], hostIp='', hostName='2 selected hosts',
            hostSnapshots={self.host['id']: {'ip': self.host['ip'], 'name': self.host['name']}},
            scope=self.scope, model='server default', events=[],
            pendingProposal=dict(id='proposal-1', revision=1, command=command))
        self.ws.autonomy._save({'runs': [run]})
        with patch.object(self.ws.autonomy, '_worker') as worker, patch.object(self.ws.autonomy, '_group_worker') as group_worker:
            self.ws.autonomy.approve('group-review', 'proposal-1', 1, command, self.scope)
            self.ws.autonomy.thread.join(3)
        worker.assert_called_once()
        self.assertEqual(worker.call_args.args[1], self.host['id'])
        group_worker.assert_not_called()

    def test_check_review_rejects_cross_host_evidence_misattribution(self):
        second = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for api.03.crimsonia.net (100.96.1.71)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        doc = self.ws.load()
        F.merge_parsed(doc, second)
        other = next(f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == '100.96.1.71')
        other['approval'] = {'ip': other['ip'], 'name': other['name'], 'scope': self.scope}
        self.ws.save(doc)
        class BadReview(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                user = json.loads(messages[1]['content'])
                return {'model': 'fake', 'data': {'flag': {
                    'reason': 'Wrong evidence source.', 'uncertainty': 'Unknown.',
                    'findingIds': [user['findings'][0]['id']], 'evidenceIds': [other_evidence]}}}
        self_host = self.host['id']
        other_evidence = other['evidenceIds'][0]
        self.ws.llm = BadReview()
        self.ws.autonomy._save({'runs': [dict(id='review-run', status='running', events=[], flags=[])]})
        self.ws.autonomy._review_check_result('review-run', self_host, self.scope, '',
            dict(outcome='completed', imported=True, evidenceIds=self.host['evidenceIds']))
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['flags'], [])
        self.assertEqual(saved['events'][0]['type'], 'flag-review-error')
        self.assertIn('unlinked evidence', saved['events'][0]['reason'])

    def test_check_review_flags_only_new_linked_evidence(self):
        class NotableReview(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                user = json.loads(messages[1]['content'])
                finding = user['findings'][0]
                return {'model': 'fake', 'data': {'flag': {
                    'reason': 'Review this recorded service.', 'uncertainty': 'Access is unverified.',
                    'findingIds': [finding['id']], 'evidenceIds': [finding['evidenceIds'][0]]}}}
        self.ws.llm = NotableReview()
        self.ws.autonomy._save({'runs': [dict(id='review-run', status='running', events=[], flags=[])]})
        self.ws.autonomy._review_check_result('review-run', self.host['id'], self.scope, '',
            dict(outcome='completed', imported=True, evidenceIds=self.host['evidenceIds']))
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['events'][0]['type'], 'flag-review')
        self.assertEqual(saved['flags'][0]['hostId'], self.host['id'])
        self.assertEqual(saved['flags'][0]['evidenceIds'], [self.host['evidenceIds'][0]])

    def test_rule_lead_delta_reaches_check_review_only_for_new_evidence(self):
        class CaptureReview(FakeLlm):
            def complete(self, messages, max_tokens=400, model=''):
                self.prompts.append(json.loads(messages[1]['content']))
                return {'model': 'fake', 'data': {'flag': None}}

        self.ws.llm = CaptureReview()
        self.ws.autonomy._save({'runs': [dict(id='review-run', status='running', events=[], flags=[])]})
        output = ('<nmaprun args="nmap -sV 100.96.1.70"><host><status state="up"/>'
                  '<address addr="100.96.1.70" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
                  '<state state="open"/><service name="http" product="nginx" version="1.2.3"/>'
                  '</port></ports></host></nmaprun>')
        before = self.ws.autonomy._rule_flags(self.host['id'], self.scope)
        parsed = F.parse_import({'tool': 'nmap', 'output': output})
        doc = self.ws.load()
        F.merge_parsed(doc, parsed)
        self.ws.save(doc)
        evidence_id = parsed['evidence'][0]['id']
        self.ws.autonomy._review_check_result('review-run', self.host['id'], self.scope, '',
            dict(outcome='completed', imported=True, evidenceIds=[evidence_id], ruleFlagsBefore=before))
        changes = self.ws.llm.prompts[-1]['ruleChanges']
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['change'], 'new')
        self.assertEqual(changes[0]['kind'], 'software')
        self.assertEqual(changes[0]['evidenceIds'], [evidence_id])
        self.assertEqual(self.ws.autonomy.history()['runs'][0]['events'][-1]['ruleChanges'], changes)

        before = self.ws.autonomy._rule_flags(self.host['id'], self.scope)
        parsed = F.parse_import({'tool': 'nmap', 'output': output})
        doc = self.ws.load()
        F.merge_parsed(doc, parsed)
        self.ws.save(doc)
        self.ws.autonomy._review_check_result('review-run', self.host['id'], self.scope, '',
            dict(outcome='completed', imported=True, evidenceIds=[parsed['evidence'][0]['id']],
                 ruleFlagsBefore=before))
        self.assertEqual(self.ws.llm.prompts[-1]['ruleChanges'], [])

    def test_scope_discovery_selects_ip_only_hosts_and_starts_group_loop(self):
        scope = self.ws.save_scope({'cidrs': ['100.96.1.0/28'], 'domains': []})
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
        self.assertFalse(any(e['type'] == 'comparison' for e in saved['events']))
        self.assertTrue(all(call[0] == 'nmap' for call in self.calls))

    def test_scope_discovery_retries_failed_segment_on_resume(self):
        scope = self.ws.save_scope({'cidrs': ['100.96.1.0/28'], 'domains': []})
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

    def test_scope_discovery_selects_all_approved_hosts_not_first_four(self):
        doc = self.ws.load()
        for number in range(71, 80):
            parsed = F.parse_import({'tool': 'nmap', 'output':
                f'Nmap scan report for host{number}.03.crimsonia.net (100.96.1.{number})\n'
                'Host is up.\nNmap done: 1 IP address (1 host up) scanned'})
            F.merge_parsed(doc, parsed)
        for host in (f for f in doc['findings'] if f['kind'] == 'host'):
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        self.ws.save(doc)
        selected = self.ws.autonomy._auto_group_hosts(self.scope)
        self.assertEqual(len(selected), 10)
        self.assertEqual(set(selected), {f['id'] for f in doc['findings'] if f['kind'] == 'host'})

    def test_scope_survey_resume_keeps_completed_hosts(self):
        run = {'id': 'resume-survey', 'mode': 'discover-group', 'phase': 'survey',
            'status': 'awaiting-discovery', 'scope': self.scope, 'model': 'server default',
            'hostIds': ['one', 'two'], 'surveyedHostIds': ['one'], 'events': []}
        self.ws.autonomy._save({'runs': [run]})
        with patch.object(self.ws.autonomy, '_group_worker') as group_worker, \
                patch.object(self.ws.autonomy, '_discover_group_worker') as discovery_worker:
            self.ws.autonomy.resume_discover_group(run['id'], self.scope)
            self.ws.autonomy.thread.join(3)
        group_worker.assert_called_once()
        discovery_worker.assert_not_called()
        self.assertEqual(self.ws.autonomy.history()['runs'][0]['surveyedHostIds'], ['one'])

    def test_inventory_survey_uses_all_approved_inventory_hosts(self):
        doc = self.ws.load()
        for number in range(71, 80):
            parsed = F.parse_import({'tool': 'nmap', 'output':
                f'Nmap scan report for host{number}.03.crimsonia.net (100.96.1.{number})\n'
                'Host is up.\nNmap done: 1 IP address (1 host up) scanned'})
            F.merge_parsed(doc, parsed)
        hosts = [h for h in doc['findings'] if h['kind'] == 'host']
        for host in hosts:
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        self.ws.save(doc)
        self.ws.save_discovery({'hosts': [{'ip': h['ip'], 'scope': self.scope,
            'approved': True, 'approvedName': h['name']} for h in hosts],
            'inventory': [{'ip': h['ip'], 'name': h['name'], 'scope': self.scope,
            'status': 'verified'} for h in hosts]})
        with patch.object(self.ws.autonomy, '_group_worker') as worker:
            run = self.ws.autonomy.start_inventory_survey(self.scope)
            self.ws.autonomy.thread.join(3)
        self.assertEqual(len(run['hostIds']), 10)
        self.assertEqual(run['source'], 'inventory')
        worker.assert_called_once()


if __name__ == '__main__':
    unittest.main()
