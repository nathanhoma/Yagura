import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend import findings as F
from backend.analysis import scoped_document
from backend.group_context import fresh_candidates, read_requests, seed_context
from backend.llm import LlmError
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

    def test_group_can_read_saved_evidence_before_final_decision(self):
        host_id = self.hosts[0]['id']
        evidence_id = 'older-linked-evidence'
        doc = self.ws.load()
        doc['evidence'].append({'id': evidence_id, 'tool': 'manual', 'command': '',
            'output': 'Older observed web note.', 'observedAt': '2020-01-01T00:00:00+00:00',
            'importedAt': '2020-01-01T00:00:00+00:00', 'format': 'text'})
        next(f for f in doc['findings'] if f['id'] == host_id)['evidenceIds'].append(evidence_id)
        self.ws.save(doc)
        class ReadingModel:
            def __init__(self):
                self.prompts = []
            def assert_configuration(self):
                pass
            def complete(self, messages, max_tokens=400, model=''):
                self.prompts.append(messages)
                user = json.loads(messages[1]['content'])
                if 'previousFlags' not in user:
                    return {'model': 'fake', 'data': {'command': None, 'reason': 'No further check.',
                        'expectedEvidence': '', 'reviewNotes': ''}}
                if len(messages) == 2:
                    return {'model': 'fake', 'data': {'readRequests': [
                        {'tool': 'get_evidence', 'evidenceIds': [evidence_id]}]}}
                result = json.loads(messages[-1]['content'])['readResults']
                assert result[0]['items'][0]['id'] == evidence_id
                assert {'hostId': host_id, 'findingId': host_id, 'evidenceId': evidence_id} in \
                    json.loads(messages[-1]['content'])['allowedCitationPairs']
                return {'model': 'fake', 'data': {'flags': [{'hostId': host_id,
                    'reason': 'One host has a distinct saved observation.',
                    'uncertainty': 'The observation needs confirmation.',
                    'findingIds': [host_id], 'evidenceIds': [evidence_id]}],
                    'candidateId': None, 'reason': 'No current catalog check resolves it.'}}
        model = ReadingModel()
        self.ws.llm = model
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            run = self.ws.autonomy.start_group([h['id'] for h in self.hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['id'], run['id'])
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual([e['type'] for e in saved['events']].count('context-read'), 1)
        self.assertEqual([e['type'] for e in saved['events']].count('comparison'), 1)
        self.assertEqual(saved['flags'][0]['evidenceIds'], [evidence_id])
        self.assertEqual(len(model.prompts), 3)

    def test_invalid_citation_gets_one_bounded_correction(self):
        class RepairModel:
            def __init__(self):
                self.calls = 0
            def assert_configuration(self):
                pass
            def complete(self, messages, max_tokens=400, model=''):
                self.calls += 1
                if self.calls == 1:
                    return {'model': 'fake', 'data': {'flags': [{
                        'hostId': host_id, 'reason': 'Possible difference',
                        'uncertainty': 'Needs evidence', 'findingIds': [host_id],
                        'evidenceIds': ['invented']}], 'candidateId': None, 'reason': ''}}
                correction = json.loads(messages[-1]['content'])
                assert correction['validationError'].startswith('Comparison cited evidence ID invented')
                assert correction['allowedCitationPairs']
                assert correction['invalidCitations'][0]['evidenceId'] == 'invented'
                return {'model': 'fake', 'data': {'flags': [], 'candidateId': None,
                                                'reason': 'No supported flag.'}}
        host_id = self.hosts[0]['id']
        model = RepairModel()
        self.ws.llm = model
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            self.ws.autonomy.start_group([h['id'] for h in self.hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual(model.calls, 2)
        self.assertEqual(sum(e['type'] == 'context-repair' for e in saved['events']), 1)
        repair = next(e for e in saved['events'] if e['type'] == 'context-repair')
        self.assertEqual(repair['submittedFlags'][0]['evidenceIds'], ['invented'])
        self.assertEqual(repair['invalidCitations'][0]['evidenceId'], 'invented')

    def test_visible_evidence_must_pair_with_a_cited_finding(self):
        doc = self.ws.load()
        host_id = self.hosts[0]['id']
        service = next(f for f in doc['findings'] if f.get('kind') == 'service' and f.get('hostId') == host_id)
        evidence_id = 'service-only-evidence'
        doc['evidence'].append({'id': evidence_id, 'tool': 'manual', 'command': '',
            'output': 'Service-specific observation.', 'observedAt': '2099-01-01T00:00:00+00:00',
            'importedAt': '2099-01-01T00:00:00+00:00', 'format': 'text'})
        service['evidenceIds'].append(evidence_id)
        self.ws.save(doc)

        class PairModel:
            def __init__(self):
                self.calls = 0
            def assert_configuration(self):
                pass
            def complete(self, messages, max_tokens=400, model=''):
                if 'previousFlags' not in json.loads(messages[1]['content']):
                    return {'model': 'fake', 'data': {'command': None, 'reason': 'No useful check.',
                                                      'expectedEvidence': '', 'reviewNotes': ''}}
                self.calls += 1
                flag = {'hostId': host_id, 'reason': 'Inspect the service-specific result.',
                        'uncertainty': 'Further validation is needed.',
                        'evidenceIds': [evidence_id]}
                if self.calls == 1:
                    initial = json.loads(messages[1]['content'])['context']['citationPairs']
                    assert {'hostId': host_id, 'findingId': service['id'], 'evidenceId': evidence_id} in initial
                    assert {'hostId': host_id, 'findingId': host_id, 'evidenceId': evidence_id} not in initial
                    return {'model': 'fake', 'data': {'flags': [{**flag, 'findingIds': [host_id]}],
                                                     'candidateId': None, 'reason': ''}}
                correction = json.loads(messages[-1]['content'])
                assert correction['invalidCitations'] == [{
                    'hostId': host_id, 'evidenceId': evidence_id,
                    'citedFindingIds': [host_id], 'allowedFindingIds': [service['id']]}]
                return {'model': 'fake', 'data': {'flags': [{**flag, 'findingIds': [service['id']]}],
                                                 'candidateId': None, 'reason': ''}}

        model = PairModel()
        self.ws.llm = model
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            self.ws.autonomy.start_group([h['id'] for h in self.hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        run = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(run['status'], 'completed')
        self.assertEqual(model.calls, 2)
        self.assertEqual(run['flags'][0]['findingIds'], [service['id']])
        self.assertEqual(run['events'][-2]['type'], 'comparison')

    def test_invalid_context_host_gets_one_bounded_correction(self):
        host_id = self.hosts[0]['id']
        class RepairModel:
            def __init__(self):
                self.calls = 0
            def assert_configuration(self):
                pass
            def complete(self, messages, max_tokens=400, model=''):
                self.calls += 1
                if self.calls == 1:
                    return {'model': 'fake', 'data': {'readRequests': [
                        {'tool': 'list_findings', 'hostId': 'unselected'}]}}
                if self.calls == 2:
                    correction = json.loads(messages[-1]['content'])
                    assert host_id in correction['selectedHostIds']
                    return {'model': 'fake', 'data': {'readRequests': [
                        {'tool': 'list_findings', 'hostId': host_id}]}}
                return {'model': 'fake', 'data': {'flags': [], 'candidateId': None,
                                                'reason': 'No supported flag.'}}
        model = RepairModel()
        self.ws.llm = model
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            self.ws.autonomy.start_group([h['id'] for h in self.hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'completed')
        self.assertEqual(model.calls, 3)
        repair = next(e for e in saved['events'] if e['type'] == 'context-request-repair')
        self.assertEqual(repair['submittedRequests'][0]['hostId'], 'unselected')
        self.assertEqual(sum(e['type'] == 'context-read' for e in saved['events']), 1)

    def test_group_response_uses_128k_limit_without_same_limit_retry(self):
        class TruncatedModel:
            def __init__(self):
                self.limits = []
            def assert_configuration(self):
                pass
            def complete(self, messages, max_tokens=400, model=''):
                self.limits.append(max_tokens)
                raise LlmError('invalid-response', 'The local model response was truncated.')
        model = TruncatedModel()
        self.ws.llm = model
        with patch('backend.autonomy.workflow', return_value={'candidates': []}):
            self.ws.autonomy.start_group([h['id'] for h in self.hosts], self.scope)
            self.ws.autonomy.thread.join(3)
        saved = self.ws.autonomy.history()['runs'][0]
        self.assertEqual(saved['status'], 'stopped')
        self.assertEqual(model.limits, [131072])
        self.assertEqual(sum(e['type'] == 'model-retry' for e in saved['events']), 0)


if __name__ == '__main__':
    unittest.main()
