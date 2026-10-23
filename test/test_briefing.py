import json
from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.briefing import answer_question
from backend.server import Workspace


class BriefingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = Workspace(findings_file=Path(self.tmp.name) / 'findings.json',
                            runner=lambda *args: self.fail('A briefing executed a command.'))
        self.scope = self.ws.save_scope({'cidrs': ['100.96.1.0/24'], 'domains': ['lab.test']})
        doc = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for web.lab.test (100.96.1.70)\nHost is up.\n'
            '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
        self.host = next(f for f in doc['findings'] if f['kind'] == 'host')
        self.host['approval'] = {'ip': self.host['ip'], 'name': self.host['name'], 'scope': self.scope}
        self.ws.save(doc)

    def test_answer_cites_supplied_linked_evidence(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                self.max_tokens = max_tokens
                context = json.loads(messages[1]['content'])['context']
                finding = context['findings'][0]
                return {'model': 'fake', 'data': {'supported': True,
                    'answer': 'The approved host has a recorded observation.',
                    'uncertainty': 'Its current state needs confirmation.',
                    'findingIds': [finding['id']], 'evidenceIds': finding['evidenceIds'],
                    'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'What is recorded?')
        self.assertTrue(result['supported'])
        self.assertEqual(self.ws.llm.max_tokens, 32768)
        self.assertEqual(result['findingIds'], [self.host['id']])

    def test_answer_receives_redacted_recent_conversation(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                self.payload = json.loads(messages[1]['content'])
                finding = self.payload['context']['findings'][0]
                return {'model': 'fake', 'data': {'supported': True,
                    'answer': 'Saved evidence exists.', 'uncertainty': '',
                    'findingIds': [finding['id']], 'evidenceIds': finding['evidenceIds'],
                    'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'What about that host?', history=[
            {'role': 'user', 'content': 'web.lab.test password is abc123'},
            {'role': 'assistant', 'content': 'It has an HTTPS service.'}])
        self.assertTrue(result['supported'])
        self.assertNotIn('abc123', str(self.ws.llm.payload))
        self.assertEqual(len(self.ws.llm.payload['recentConversation']), 2)

    def test_invented_evidence_is_rejected(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                context = json.loads(messages[1]['content'])['context']
                return {'model': 'fake', 'data': {'supported': True, 'answer': 'Claim',
                    'uncertainty': '', 'findingIds': [context['findings'][0]['id']],
                    'evidenceIds': ['invented'], 'candidateIds': []}}
        self.ws.llm = Model()
        with self.assertRaisesRegex(ValueError, 'outside the supplied context'):
            answer_question(self.ws, 'What is recorded?')

    def test_invalid_citations_are_retried_once_with_verified_references(self):
        class Model:
            calls = 0
            def complete(self, messages, max_tokens=0, model=''):
                self.calls += 1
                finding = json.loads(messages[1]['content'])['context']['findings'][0]
                return {'model': 'fake', 'data': {'supported': True, 'answer': 'Recorded host.',
                    'uncertainty': '', 'findingIds': [finding['id']],
                    'evidenceIds': ['invented'] if self.calls == 1 else finding['evidenceIds'],
                    'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'What is recorded?')
        self.assertEqual(self.ws.llm.calls, 2)
        self.assertTrue(result['supported'])

    def test_unsupported_answer_does_not_echo_model_claim(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                return {'model': 'fake', 'data': {'supported': False,
                    'answer': 'Invented access.', 'findingIds': [], 'evidenceIds': [], 'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'Can I access it?')
        self.assertFalse(result['supported'])
        self.assertNotIn('Invented', result['answer'])

    def test_every_cited_finding_requires_its_own_linked_evidence(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                context = json.loads(messages[1]['content'])['context']
                rows = [row for row in context['findings'] if row['kind'] in ('service', 'observation')
                        and (row['kind'] == 'service' or row.get('title') == 'Independent note')]
                return {'model': 'fake', 'data': {'supported': True, 'answer': 'Two claims.',
                    'uncertainty': '', 'findingIds': [row['id'] for row in rows],
                    'evidenceIds': rows[0]['evidenceIds'], 'candidateIds': []}}
        self.ws.llm = Model()
        # The imported host and service share an Nmap source, so use a second independent
        # observation to prove a citation cannot be borrowed from another finding.
        doc = self.ws.load()
        second = F.parse_import({'tool': 'evidence', 'title': 'Independent note',
                                 'ip': self.host['ip'], 'output': 'Separate observation.'})
        F.merge_parsed(doc, second)
        self.ws.save(doc)
        with self.assertRaisesRegex(ValueError, 'outside the supplied context'):
            answer_question(self.ws, 'What is recorded?')

    def test_reads_all_approved_hosts_then_fetches_relevant_detail(self):
        doc = self.ws.load()
        for number in range(71, 81):
            imported = F.parse_import({'tool': 'nmap', 'output':
                f'Nmap scan report for node{number}.lab.test (100.96.1.{number})\n'
                'Host is up.\n443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
            for finding in imported['findings']:
                if finding['kind'] == 'host' and number != 80:
                    finding['approval'] = {'ip': finding['ip'], 'name': finding['name'], 'scope': self.scope}
            doc['findings'].extend(imported['findings'])
            doc['evidence'].extend(imported['evidence'])
        self.ws.save(doc)
        class Model:
            def __init__(self):
                self.calls = []
            def complete(self, messages, max_tokens=0, model=''):
                payload = json.loads(messages[1]['content'])
                self.calls.append(payload)
                if 'context' not in payload:
                    self.max_selection_tokens = max_tokens
                    self.assert_inventory = payload['inventory']
                    return {'model': 'fake', 'data': {'hostIds': [payload['inventory']['hosts'][-1]['id']]}}
                finding = payload['context']['findings'][0]
                return {'model': 'fake', 'data': {'supported': True,
                    'answer': 'The selected host has a saved response.', 'uncertainty': '',
                    'findingIds': [finding['id']], 'evidenceIds': finding['evidenceIds'],
                    'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'What was seen on node79?')
        self.assertTrue(result['supported'])
        self.assertEqual(len(self.ws.llm.calls), 2)
        self.assertEqual(self.ws.llm.max_selection_tokens, 2048)
        self.assertEqual(self.ws.llm.assert_inventory['approvedHosts'], 10)
        self.assertNotIn('node80.lab.test', str(self.ws.llm.assert_inventory))
        self.assertEqual(self.ws.llm.calls[1]['detailHostIds'], [self.ws.llm.assert_inventory['hosts'][-1]['id']])


if __name__ == '__main__':
    unittest.main()
