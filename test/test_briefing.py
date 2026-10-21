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
        result = answer_question(self.ws, 'What is recorded?', [self.host['id']])
        self.assertTrue(result['supported'])
        self.assertEqual(self.ws.llm.max_tokens, 1600)
        self.assertEqual(result['findingIds'], [self.host['id']])

    def test_unapproved_host_and_invented_evidence_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            answer_question(self.ws, 'What is recorded?', ['invented'])
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                context = json.loads(messages[1]['content'])['context']
                return {'model': 'fake', 'data': {'supported': True, 'answer': 'Claim',
                    'uncertainty': '', 'findingIds': [context['findings'][0]['id']],
                    'evidenceIds': ['invented'], 'candidateIds': []}}
        self.ws.llm = Model()
        with self.assertRaisesRegex(ValueError, 'outside the supplied context'):
            answer_question(self.ws, 'What is recorded?', [self.host['id']])

    def test_unsupported_answer_does_not_echo_model_claim(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                return {'model': 'fake', 'data': {'supported': False,
                    'answer': 'Invented access.', 'findingIds': [], 'evidenceIds': [], 'candidateIds': []}}
        self.ws.llm = Model()
        result = answer_question(self.ws, 'Can I access it?', [self.host['id']])
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
            answer_question(self.ws, 'What is recorded?', [self.host['id']])


if __name__ == '__main__':
    unittest.main()
