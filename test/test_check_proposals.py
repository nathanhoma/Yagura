from pathlib import Path
import shlex
import tempfile
import unittest

from backend import findings as F
from backend.server import Workspace


class ProposalModel:
    def __init__(self, mode='valid'):
        self.mode = mode

    def complete(self, messages, **kwargs):
        import json
        candidates = json.loads(messages[1]['content'])['context']['candidates']
        row = next(c for c in candidates if c['catalogId'] == 'http-headers')
        if self.mode == 'unsupported':
            return {'model': 'fake', 'data': {'candidateId': None, 'command': None,
                                             'reason': 'No supported check fits.'}}
        if self.mode == 'manual':
            return {'model': 'fake', 'data': {'candidateId': None,
                                             'command': 'custom-inspect --host web.03.crimsonia.net --mode review',
                                             'reason': 'This needs a tool outside the bounded catalog.'}}
        parts = shlex.split(row['command'])
        parts[-1] = parts[-1].rstrip('/') + ('/login' if self.mode != 'other-host' else '/login?next=https://outside.example')
        return {'model': 'fake', 'data': {'candidateId': row['id'], 'command': shlex.join(parts),
                                         'reason': 'Inspect login response headers.'}}


class CheckProposalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        def runner(program, args, timeout):
            self.calls.append((program, args))
            return {'ok': True, 'stdout': 'HTTP/1.1 302 Found\nLocation: /auth\n', 'stderr': ''}
        self.ws = Workspace(findings_file=Path(self.tmp.name) / 'findings.json',
                            llm=ProposalModel(), runner=runner)
        self.scope = self.ws.save_scope({'cidrs': ['100.96.1.0/24'], 'domains': ['03.crimsonia.net']})
        doc = F.parse_import({'tool': 'nmap', 'output': 'Nmap scan report for web.03.crimsonia.net (100.96.1.70)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'})
        self.host = next(f for f in doc['findings'] if f['kind'] == 'host')
        self.host['approval'] = {'ip': self.host['ip'], 'name': self.host['name'], 'scope': self.scope}
        self.ws.save(doc)

    def test_ai_command_saved_then_revalidated_at_run(self):
        proposed = self.ws.check_proposals.propose(self.host['id'], self.scope, 'Check /login response headers')
        self.assertTrue(proposed['added'])
        self.assertEqual(self.calls, [])
        proposal = self.ws.check_proposals.list()['proposals'][0]
        self.assertFalse(proposal['stale'])
        self.assertIn('/login', proposal['command'])
        result = self.ws.check_proposals.run(proposal['id'], self.scope)
        self.assertEqual(result['outcome'], 'completed')
        self.assertEqual(self.calls[0][0], 'curl')
        self.assertEqual(self.calls[0][1][-1], 'http://web.03.crimsonia.net:80/login')
        self.assertEqual(self.ws.check_proposals.list()['proposals'][0]['lastOutcome'], 'completed')

    def test_unsupported_and_query_destination_do_not_add(self):
        self.ws.llm = ProposalModel('unsupported')
        self.assertFalse(self.ws.check_proposals.propose(self.host['id'], self.scope, 'Try an unsupported check')['added'])
        self.ws.llm = ProposalModel('other-host')
        with self.assertRaises(ValueError):
            self.ws.check_proposals.propose(self.host['id'], self.scope, 'Check the login redirect')
        self.assertEqual(self.ws.check_proposals.list()['proposals'], [])
        self.assertEqual(self.calls, [])

    def test_scope_change_marks_saved_proposal_stale_and_blocks_run(self):
        proposal = self.ws.check_proposals.propose(self.host['id'], self.scope, 'Check /login response headers')['proposal']
        self.ws.save_scope({'cidrs': ['100.96.2.0/24'], 'domains': ['03.crimsonia.net']})
        self.assertTrue(self.ws.check_proposals.list()['proposals'][0]['stale'])
        with self.assertRaises(ValueError):
            self.ws.check_proposals.run(proposal['id'], self.ws.load_scope())
        self.assertEqual(self.calls, [])

    def test_manual_proposal_needs_human_review_and_is_never_executable(self):
        self.ws.llm = ProposalModel('manual')
        proposal = self.ws.check_proposals.propose(self.host['id'], self.scope,
                                                   'Use a custom tool to inspect this host')['proposal']
        self.assertEqual(proposal['kind'], 'manual')
        self.assertEqual(proposal['reviewStatus'], 'pending')
        self.assertEqual(self.calls, [])
        with self.assertRaises(ValueError):
            self.ws.check_proposals.review(proposal['id'], self.scope, proposal['command'], 'approve', False)
        with self.assertRaises(ValueError):
            self.ws.check_proposals.review(proposal['id'], self.scope, 'changed command', 'approve', True)
        reviewed = self.ws.check_proposals.review(proposal['id'], self.scope, proposal['command'], 'approve', True)
        self.assertEqual(reviewed['reviewStatus'], 'approved')
        with self.assertRaises(ValueError):
            self.ws.check_proposals.run(proposal['id'], self.scope)
        self.assertEqual(self.calls, [])

    def test_only_reviewed_and_recorded_manual_result_enters_reference_catalog(self):
        self.ws.llm = ProposalModel('manual')
        proposal = self.ws.check_proposals.propose(self.host['id'], self.scope,
                                                   'Use a custom tool to inspect this host')['proposal']
        self.assertEqual(self.ws.check_proposals.catalog_entries(), [])
        with self.assertRaises(ValueError):
            self.ws.check_proposals.record_manual_execution(proposal['id'], self.scope,
                proposal['command'], 'observed output', True)
        self.ws.check_proposals.review(proposal['id'], self.scope, proposal['command'], 'approve', True)
        self.assertEqual(self.ws.check_proposals.catalog_entries(), [])
        with self.assertRaises(ValueError):
            self.ws.check_proposals.record_manual_execution(proposal['id'], self.scope,
                'changed command', 'observed output', True)
        with self.assertRaises(ValueError):
            self.ws.check_proposals.record_manual_execution(proposal['id'], self.scope,
                proposal['command'], 'observed output', False)
        recorded = self.ws.check_proposals.record_manual_execution(proposal['id'], self.scope,
            proposal['command'], 'observed output', True)
        entries = self.ws.check_proposals.catalog_entries()
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]['executable'])
        self.assertEqual(entries[0]['command'], proposal['command'])
        self.assertEqual(entries[0]['evidenceId'], recorded['manualEvidenceId'])
        self.assertEqual(len(self.calls), 0)
        evidence = next(ev for ev in self.ws.load()['evidence'] if ev['id'] == recorded['manualEvidenceId'])
        self.assertTrue(evidence['sensitive'])
        with self.assertRaises(ValueError):
            self.ws.check_proposals.record_manual_execution(proposal['id'], self.scope,
                proposal['command'], 'second output', True)


if __name__ == '__main__':
    unittest.main()
