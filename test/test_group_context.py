from pathlib import Path
import tempfile
import unittest

from backend import findings as F
from backend.analysis import scoped_document
from backend.group_context import fresh_candidates, read_requests, seed_context
from backend.server import Workspace


class GroupContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = Workspace(findings_file=Path(self.tmp.name) / 'findings.json',
                            runner=lambda *args: self.fail('A context read executed a command.'))
        self.scope = self.ws.save_scope({'cidrs': ['100.96.1.0/24'], 'domains': ['03.crimsonia.net']})
        doc = F.parse_import({'tool': 'nmap', 'output':
            'Nmap scan report for one.03.crimsonia.net (100.96.1.70)\nHost is up.\n'
            '80/tcp open http\nNmap scan report for two.03.crimsonia.net (100.96.1.71)\n'
            'Host is up.\n443/tcp open https\nNmap done: 2 IP addresses (2 hosts up) scanned'})
        for host in (f for f in doc['findings'] if f['kind'] == 'host'):
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': self.scope}
        self.ws.save(doc)
        self.doc = self.ws.load()
        self.hosts = [f for f in self.doc['findings'] if f['kind'] == 'host']
        self.selected = scoped_document(self.doc, None, self.scope,
                                        [h['id'] for h in self.hosts])

    def test_seed_is_balanced_and_candidate_references_are_visible(self):
        first = self.hosts[0]
        candidate = {'id': 'next', 'hostId': first['id'], 'catalogId': 'nmap-ports',
                     'title': 'Check ports', 'reason': 'Known host', 'findingIds': [first['id']],
                     'evidenceIds': first['evidenceIds'], 'command': 'nmap -n -Pn -sT --top-ports 100 100.96.1.70'}
        context = seed_context(self.selected, [h['id'] for h in self.hosts], [candidate])
        self.assertEqual(len(context['hosts']), 2)
        fids = {f['id'] for f in context['findings']}
        eids = {e['id'] for e in context['evidence']}
        self.assertTrue(all(h['id'] in fids for h in self.hosts))
        for finding in context['findings']:
            self.assertTrue(set(finding['evidenceIds']) <= eids)
        self.assertEqual(context['citationPairs'], [
            {'hostId': finding.get('hostId', finding['id']), 'findingId': finding['id'],
             'evidenceId': eid}
            for finding in context['findings'] for eid in finding['evidenceIds']])
        for row in context['candidates']:
            self.assertTrue(set(row['findingIds']) <= fids)
            self.assertTrue(set(row['evidenceIds']) <= eids)

    def test_reads_are_scoped_and_never_execute_commands(self):
        first = self.hosts[0]
        evidence_id = first['evidenceIds'][0]
        result = read_requests([{'tool': 'list_findings', 'hostId': first['id']},
                                {'tool': 'get_evidence', 'evidenceIds': [evidence_id]}],
                               self.selected, [first['id']], [], [])
        self.assertEqual(result[0]['hostId'], first['id'])
        shown_evidence = {e['id'] for e in result[0]['evidence']}
        self.assertTrue(shown_evidence)
        self.assertTrue(all(set(f['evidenceIds']) <= shown_evidence for f in result[0]['items']))
        self.assertEqual(result[1]['items'][0]['id'], evidence_id)
        with self.assertRaisesRegex(ValueError, 'unselected'):
            read_requests([{'tool': 'list_findings', 'hostId': self.hosts[1]['id']}],
                          self.selected, [first['id']], [], [])
        with self.assertRaisesRegex(ValueError, 'saved evidence'):
            read_requests([{'tool': 'get_evidence', 'evidenceIds': ['invented']}],
                          self.selected, [first['id']], [], [])
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            read_requests([{'tool': 'run_command', 'hostId': first['id']}],
                          self.selected, [first['id']], [], [])

    def test_recent_identical_command_is_not_suggested_again(self):
        command = 'curl -q --noproxy * -I http://one.03.crimsonia.net/'
        candidate = {'command': command}
        self.selected['evidence'].append({'id': 'new', 'tool': 'http-headers',
            'command': command, 'output': 'HTTP/1.1 200 OK', 'observedAt': F.now()})
        self.assertEqual(fresh_candidates(self.selected, [candidate]), [])
        self.assertEqual(fresh_candidates(self.selected, [{'command': 'other'}]), [{'command': 'other'}])



if __name__ == '__main__':
    unittest.main()
