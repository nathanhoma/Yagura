import json
from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.briefing import answer_question
from backend.credential_leads import credential_leads, reveal_credential
from backend.server import Workspace
from backend.sensitive import redact


class CredentialLeadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = Workspace(findings_file=Path(self.tmp.name) / 'findings.json',
                            runner=lambda *args: self.fail('Recognition executed a command.'))
        self.scope = self.ws.save_scope({'cidrs': ['100.96.3.0/24'], 'domains': ['lab.test']})
        doc = F.empty()
        for ip, name in [('100.96.3.20', 'paste.dev.lab.test'),
                         ('100.96.3.50', 'argusai.elec.lab.test')]:
            parsed = F.parse_import({'tool': 'nmap', 'output':
                f'Nmap scan report for {name} ({ip})\nHost is up.\n'
                '443/tcp open https\nNmap done: 1 IP address (1 host up) scanned'})
            F.merge_parsed(doc, parsed)
        for host in (f for f in doc['findings'] if f['kind'] == 'host'):
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        self.ws.save(doc)
        self.output = 'A' * 16000 + '\nKeiran.Reeves@elec.lab.test:sample-secret-123\n' + 'B' * 16000
        parsed = F.parse_import({'tool': 'evidence', 'ip': '100.96.3.20',
                                 'name': 'paste.dev.lab.test', 'title': 'Paste page',
                                 'output': self.output})
        doc = self.ws.load()
        F.merge_parsed(doc, parsed)
        self.ws.save(doc)

    def test_finds_middle_of_long_evidence_and_related_approved_host(self):
        leads = credential_leads(self.ws.load(), self.scope)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]['principal'], 'Keiran.Reeves@elec.lab.test')
        self.assertEqual(leads[0]['relatedApprovedHosts'][0]['name'], 'argusai.elec.lab.test')
        self.assertNotIn('sample-secret-123', json.dumps(leads))

    def test_briefing_can_cite_recognized_lead_without_secret(self):
        class Model:
            def complete(self, messages, max_tokens=0, model=''):
                payload = json.loads(messages[1]['content'])
                self.payload = payload
                lead = payload['context']['credentialLeads'][0]
                return {'model': 'fake', 'data': {'supported': True,
                    'answer': 'A saved paste contains an unverified account candidate for ELEC.',
                    'uncertainty': 'The candidate has not been tested for login.',
                    'findingIds': [lead['sourceFindingId']],
                    'evidenceIds': [lead['evidenceId']], 'candidateIds': []}}
        self.ws.llm = Model()
        answer = answer_question(self.ws, 'What credential leads exist?')
        self.assertTrue(answer['supported'])
        self.assertEqual(len(self.ws.llm.payload['context']['credentialLeads']), 1)
        self.assertNotIn('sample-secret-123', json.dumps(self.ws.llm.payload))
        self.assertEqual(answer['evidenceIds'],
                         [self.ws.llm.payload['context']['credentialLeads'][0]['evidenceId']])

    def test_unapproved_source_is_not_used(self):
        doc = self.ws.load()
        source = next(f for f in doc['findings'] if f['kind'] == 'host'
                      and f['name'] == 'paste.dev.lab.test')
        source.pop('approval')
        self.ws.save(doc)
        self.assertEqual(credential_leads(self.ws.load(), self.scope), [])

    def test_sensitive_output_is_not_exposed_as_a_lead(self):
        doc = self.ws.load()
        for evidence in doc['evidence']:
            if 'sample-secret-123' in evidence['output']:
                evidence['sensitive'] = True
        self.ws.save(doc)
        self.assertEqual(credential_leads(self.ws.load(), self.scope), [])
        self.assertEqual(redact('Keiran.Reeves@elec.lab.test:sample-secret-123'),
                         'Keiran.Reeves@elec.lab.test:[REDACTED]')

    def test_named_keys_and_bearer_tokens_are_listed_without_values(self):
        doc = self.ws.load()
        F.merge_parsed(doc, F.parse_import({'tool': 'evidence', 'ip': '100.96.3.20',
            'title': 'Configuration',
            'output': 'api_key="sample-api-key-123"\nAuthorization: Bearer sample-bearer-token-123'}))
        self.ws.save(doc)
        leads = credential_leads(self.ws.load(), self.scope)
        by_kind = {row['kind']: row for row in leads}
        self.assertIn('named-secret', by_kind)
        self.assertIn('bearer-token', by_kind)
        self.assertNotIn('sample-api-key-123', json.dumps(leads))
        self.assertEqual(reveal_credential(self.ws.load(), self.scope,
                         by_kind['named-secret']['id'])['value'], 'sample-api-key-123')


if __name__ == '__main__':
    unittest.main()
