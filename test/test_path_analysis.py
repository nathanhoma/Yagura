import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from backend import findings as F
from backend.analysis import analyze, build_context, encoded, MAX_CONTEXT, scoped_document, validate_hypotheses, validate_result
from backend.llm import LlmError
from backend.server import Workspace, invocation, parse_check_result
from backend.web_exposure import inspect, PATHS
from backend.web_inventory import inventory
from backend.workflow import COMMAND_CATALOG, workflow
from backend.investigation_catalog import REFERENCE_CHECKS


def document():
    doc = F.empty()
    for ip in ('192.168.56.10', '192.168.56.11'):
        F.merge_parsed(doc, F.parse_import(dict(tool='nmap', output=f'Nmap scan report for {ip}\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned')))
    return doc


def hypothesis(context):
    steps = []
    for host in [f for f in context['findings'] if f['kind'] == 'host']:
        steps.append(dict(claim='Possible connection requiring verification', status='hypothesis',
                          findingIds=[host['id']], evidenceIds=host['evidenceIds'][:1]))
    return dict(title='Cross-host hypothesis', summary='Investigate related hosts', steps=steps,
                prerequisites=['Known identity'], missingEvidence=['Authentication result'], counterevidence=[],
                investigations=[dict(objective='Verify identity', hostIds=[steps[-1]['findingIds'][0]],
                                     expectedEvidence='Identity or failure', decisionImpact='Support or reject the proposed connection')])


class EvidenceImportTests(unittest.TestCase):
    def test_link_and_preserve_full_output(self):
        doc = document()
        output = 'configuration\n' + 'x' * 5000
        payload = dict(tool='evidence', ip='192.168.56.10', title='Configuration', output=output, command='manual read')
        F.merge_parsed(doc, F.parse_import(payload))
        self.assertEqual(len([f for f in doc['findings'] if f['kind'] == 'host']), 2)
        note = next(f for f in doc['findings'] if f['title'] == 'Configuration')
        host = next(f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == payload['ip'])
        self.assertEqual(note['hostId'], host['id'])
        self.assertEqual(doc['evidence'][-1]['output'], output)
        self.assertEqual(doc['evidence'][-1]['command'], 'manual read')
        F.merge_parsed(doc, F.parse_import(payload))
        self.assertEqual(len([f for f in doc['findings'] if f['title'] == 'Configuration']), 1)

    def test_unlinked_evidence_and_rejected_inputs(self):
        parsed = F.parse_import(dict(tool='evidence', output='Transcript'))
        self.assertIsNone(parsed['findings'][0]['hostId'])
        for update in ({'ip': 'bad'}, {'ip': ['bad']}, {'title': 'x' * 161}, {'output': ''}, {'output': 'あ' * 270000}):
            with self.subTest(update=list(update)):
                with self.assertRaises(ValueError):
                    F.parse_import(dict(tool='evidence', output='Transcript', **{k:v for k,v in update.items() if k != 'output'}) if 'output' not in update else dict(tool='evidence', **update))


class PathAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.doc = document()
        self.context = build_context(self.doc, '192.168.56.0/24')
        self.path = hypothesis(self.context)

    def test_cross_host_and_manual_investigation(self):
        paths, rejected = validate_hypotheses([self.path], self.context)
        self.assertEqual(rejected, 0)
        self.assertEqual(len(paths[0]['steps']), 2)
        self.assertFalse(paths[0]['investigations'][0]['executable'])

    def test_invalid_references_types_and_limits(self):
        for section, key, value in [('step','findingIds',['missing']), ('step','evidenceIds',['missing']),
                                    ('step','findingIds',[{}]), ('step','status','confirmed'),
                                    ('step','claim',None), ('investigation','hostIds',['missing']),
                                    ('investigation','expectedEvidence',3)]:
            path = copy.deepcopy(self.path)
            target = path['steps'][0] if section == 'step' else path['investigations'][0]
            target[key] = value
            with self.subTest(section=section, key=key, value=value):
                with self.assertRaises(LlmError):
                    validate_hypotheses([path], self.context)
        for update in ({'steps': []}, {'steps': self.path['steps'] * 5}, {'prerequisites': 'bad'}, {'investigations': [{}] * 7}):
            with self.assertRaises(LlmError):
                validate_hypotheses([{**self.path, **update}], self.context)
        with self.assertRaises(LlmError):
            validate_hypotheses({}, self.context)

    def test_evidence_must_link_to_each_cited_finding(self):
        path = copy.deepcopy(self.path)
        path['steps'][0]['evidenceIds'] = self.path['steps'][1]['evidenceIds']
        with self.assertRaises(LlmError):
            validate_hypotheses([path], self.context)

    def test_partial_rejection_and_legacy_response(self):
        paths, rejected = validate_hypotheses([self.path, {}], self.context)
        self.assertEqual((len(paths), rejected), (1, 1))
        self.assertEqual(validate_result({'assessments': [], 'suggestions': []}, self.context)['hypotheses'], [])
        good_step = self.path['steps'][0]
        response = dict(assessments=[dict(findingIds=good_step['findingIds'], evidenceIds=good_step['evidenceIds'],
                                          interpretation='Observed host is up', uncertainties=[])],
                        suggestions=[], hypotheses=[{}])
        validated = validate_result(response, self.context)
        self.assertEqual(len(validated['assessments']), 1)
        self.assertEqual(validated['hypotheses'], [])
        self.assertEqual(validated['rejected'], 1)

    def test_format_error_identifies_fields_without_echoing_values(self):
        with self.assertRaises(LlmError) as caught:
            validate_result({'assessments': 'private-value', 'suggestions': {}}, self.context)
        self.assertEqual(caught.exception.code, 'invalid-response')
        self.assertIn('assessments (str)', str(caught.exception))
        self.assertIn('suggestions (dict)', str(caught.exception))
        self.assertNotIn('private-value', str(caught.exception))
        with self.assertRaises(LlmError) as missing:
            validate_result({'analysis': {'assessments': [], 'suggestions': []}}, self.context)
        self.assertIn('assessments (missing)', str(missing.exception))
        self.assertIn('suggestions (missing)', str(missing.exception))
        with self.assertRaises(LlmError) as malformed:
            validate_result({'assessments': [{'findingIds': [{}], 'evidenceIds': [[]],
                                              'interpretation': 'bad', 'uncertainties': []}],
                             'suggestions': [{'candidateId': []}]}, self.context)
        self.assertEqual(malformed.exception.code, 'ungrounded-response')

    def test_analysis_retries_format_once_and_keeps_evidence_validation(self):
        anchor = next(f for f in self.context['findings'] if f['kind'] == 'host')
        valid = dict(assessments=[dict(findingIds=[anchor['id']], evidenceIds=anchor['evidenceIds'],
                                        interpretation='Recorded host responds', uncertainties=[])], suggestions=[])
        llm = Mock()
        llm.complete.side_effect = [dict(model='mock-model', data={'analysis': valid}),
                                    dict(model='mock-model', data=valid)]
        result = analyze(self.doc, {'authorizedCidr': '192.168.56.0/24'}, llm)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(result['assessments']), 1)
        self.assertEqual(llm.complete.call_count, 2)
        retry_messages = llm.complete.call_args_list[1].args[0]
        self.assertEqual(len(retry_messages), 3)
        self.assertIn('top-level arrays', retry_messages[-1]['content'])
        self.assertTrue(any('retried' in warning for warning in result['warnings']))

    def test_analysis_falls_back_after_two_format_errors_and_never_retries_transport(self):
        llm = Mock()
        llm.configuration.return_value = {'model': 'mock-model'}
        llm.complete.return_value = dict(model='mock-model', data={'analysis': {}})
        result = analyze(self.doc, {'authorizedCidr': '192.168.56.0/24'}, llm)
        self.assertEqual(result['status'], 'fallback')
        self.assertEqual(result['error']['code'], 'invalid-response')
        self.assertIn('assessments (missing)', result['error']['message'])
        self.assertEqual(llm.complete.call_count, 2)
        llm.reset_mock()
        llm.complete.return_value = dict(model='mock-model', data={
            'assessments': [{'findingIds': ['invented'], 'evidenceIds': ['invented'],
                             'interpretation': 'Unsupported claim', 'uncertainties': []}],
            'suggestions': []})
        result = analyze(self.doc, {'authorizedCidr': '192.168.56.0/24'}, llm)
        self.assertEqual(result['status'], 'fallback')
        self.assertEqual(result['error']['code'], 'ungrounded-response')
        self.assertEqual(llm.complete.call_count, 2)
        llm.reset_mock()
        llm.complete.side_effect = LlmError('unreachable', 'Model endpoint unavailable.')
        result = analyze(self.doc, {'authorizedCidr': '192.168.56.0/24'}, llm)
        self.assertEqual(result['status'], 'fallback')
        self.assertEqual(llm.complete.call_count, 1)

    def test_speculative_step_requires_a_cited_anchor_and_named_gap(self):
        path = copy.deepcopy(self.path)
        path['steps'][1]['findingIds'] = []
        path['steps'][1]['evidenceIds'] = []
        paths, rejected = validate_hypotheses([path], self.context)
        self.assertEqual(rejected, 0)
        self.assertEqual(paths[0]['steps'][1]['status'], 'hypothesis')
        path['missingEvidence'] = []
        with self.assertRaises(LlmError):
            validate_hypotheses([path], self.context)
        path['missingEvidence'] = ['Authentication result']
        path['steps'][0]['evidenceIds'] = []
        with self.assertRaises(LlmError):
            validate_hypotheses([path], self.context)

    def test_analysis_persistence_stale_and_fallback(self):
        llm = Mock()
        llm.complete.return_value = dict(model='mock-model', data=dict(assessments=[], suggestions=[], hypotheses=[self.path]))
        result = analyze(self.doc, {'authorizedCidr': '192.168.56.0/24'}, llm)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(result['hypotheses']), 1)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(findings_file=Path(directory) / 'findings.json')
            workspace.save(self.doc)
            workspace.save_analysis(result)
            self.assertEqual(json.loads(workspace.analysis_file.read_text())['hypotheses'], result['hypotheses'])
            self.assertFalse(workspace.stale(result))
            F.merge_parsed(self.doc, F.parse_import(dict(tool='evidence', ip='192.168.56.10', output='New result')))
            workspace.save(self.doc)
            self.assertTrue(workspace.stale(result))
        llm.complete.side_effect = RuntimeError('Unavailable')
        llm.configuration.return_value = {'model': 'mock-model'}
        self.assertEqual(analyze(self.doc, {}, llm)['hypotheses'], [])

    def test_context_limits_and_excerpt(self):
        F.merge_parsed(self.doc, F.parse_import(dict(tool='evidence', output='BEGIN' + 'x' * 5000 + 'END')))
        context = build_context(self.doc)
        self.assertLessEqual(len(encoded(context)), MAX_CONTEXT)
        self.assertTrue(context['truncated'])
        excerpt = next(e for e in context['evidence'] if e['tool'] == 'evidence')['output']
        self.assertTrue(excerpt.startswith('BEGIN'))
        self.assertTrue(excerpt.endswith('END'))
        self.assertTrue(context['evidence'])

    def test_dense_high_priority_evidence_keeps_host_anchors_and_observations(self):
        hosts = [f for f in self.doc['findings'] if f['kind'] == 'host']
        for host in hosts:
            service = next(f for f in self.doc['findings'] if f['kind'] == 'service' and f['hostId'] == host['id'])
            for index in range(10):
                ev = dict(id=F.uid('evidence'), tool='web-exposure', command=f'probe {index}',
                          output='response ' + 'x' * 800, observedAt=F.now(), format='json')
                self.doc['evidence'].append(ev)
                self.doc['findings'].append(F.record('observation',
                    dict(hostId=host['id'], serviceId=service['id'], title=f'Web probe {index}', detail='Recorded response'),
                    ev['id'], ev['observedAt']))
        context = build_context(self.doc, '192.168.56.0/24')
        self.assertEqual({h['id'] for h in hosts},
                         {f['id'] for f in context['findings'] if f['kind'] == 'host'})
        self.assertEqual(2, len([f for f in context['findings'] if f['kind'] == 'service']))
        self.assertTrue(any(f['kind'] == 'observation' for f in context['findings']))
        self.assertTrue(context['evidence'])
        self.assertLessEqual(len(encoded(context)), MAX_CONTEXT)

    def test_analysis_does_not_claim_model_completion_with_empty_context(self):
        doc = F.empty()
        doc['findings'].append(F.record('host', dict(ip='192.168.56.10', name='', state='unknown',
            local=False, title='192.168.56.10', detail=''), None, F.now()))
        llm = Mock()
        result = analyze(doc, {}, llm)
        self.assertEqual(result['status'], 'no-context')
        self.assertEqual(result['source'], 'built-in')
        llm.complete.assert_not_called()

    def test_dns_approval_anchor_is_compact(self):
        doc = F.empty()
        ev = dict(id=F.uid('evidence'), tool='dns-review', command='Explicit host approval',
                  output=json.dumps(dict(ip='192.168.56.10', name='web.lab.test', review='x' * 10000)),
                  observedAt=F.now(), format='json')
        doc['evidence'].append(ev)
        doc['findings'].append(F.record('host', dict(ip='192.168.56.10', name='web.lab.test',
            state='unknown', local=False, title='192.168.56.10', detail=''), ev['id'], ev['observedAt']))
        context = build_context(doc)
        self.assertEqual(len(context['findings']), 1)
        self.assertEqual(json.loads(context['evidence'][0]['output']),
                         {'ip': '192.168.56.10', 'name': 'web.lab.test'})

    def test_authorized_range_excludes_unrelated_and_local_hosts(self):
        outside = F.parse_import(dict(tool='evidence', ip='10.0.9.20', output='Unrelated host'))
        F.merge_parsed(self.doc, outside)
        local = next(f for f in self.doc['findings'] if f['kind'] == 'host' and f['ip'] == '192.168.56.11')
        local['local'] = True
        selected = scoped_document(self.doc, authorized_cidr='192.168.56.0/24')
        self.assertEqual([f['ip'] for f in selected['findings'] if f['kind'] == 'host'], ['192.168.56.10'])
        context = build_context(selected, '192.168.56.0/24')
        self.assertLessEqual(len(encoded(context)), MAX_CONTEXT)
        self.assertTrue(all(f.get('ip') != '10.0.9.20' for f in context['findings']))


class InvestigationChecksTests(unittest.TestCase):
    def test_catalog_reference_checks_never_become_candidates(self):
        doc = document()
        self.assertEqual(len(COMMAND_CATALOG), len({c['id'] for c in COMMAND_CATALOG}))
        references = {c['id'] for c in REFERENCE_CHECKS}
        candidates = workflow(doc, '192.168.56.0/24')['candidates']
        self.assertFalse(references & {c['catalogId'] for c in candidates})
        candidate = next(c for c in candidates if c['catalogId'] == 'web-exposure')
        program, args, tool = invocation(candidate, doc)
        self.assertEqual(tool, 'web-exposure')
        self.assertEqual(args[-2:], ['--ip', '192.168.56.10'])
        with self.assertRaises(ValueError):
            invocation({**candidate, 'catalogId': 'ssh-auth'}, doc)
        self.assertEqual(workflow(doc, '10.0.0.0/24')['candidates'], [])

    def test_exposure_fixed_requests_and_errors(self):
        with patch('backend.web_exposure.fetch_page') as fetch:
            fetch.side_effect = [(200, {}, 'ref: refs/heads/main'), (302, {'location':'http://outside.test'}, ''), RuntimeError('failure')] + [(404, {}, 'missing')] * 3
            report = inspect('http://lab.test:8080/', '192.168.56.10')
            self.assertEqual(fetch.call_count, len(PATHS))
            self.assertEqual([call.args[0] for call in fetch.call_args_list], ['http://lab.test:8080' + path for path in PATHS])
            self.assertEqual(len(report['errors']), 1)
            self.assertEqual(report['pages'][1]['status'], 302)
            candidate = next(c for c in workflow(document(), '192.168.56.0/24')['candidates'] if c['catalogId'] == 'web-exposure')
            parsed = parse_check_result(candidate, 'web-exposure', json.dumps(report))
            self.assertTrue(any(f['title'] == 'Web metadata probe errors' for f in parsed['findings']))
            self.assertEqual(parsed['evidence'][0]['output'], json.dumps(report))
        with patch('backend.web_exposure.fetch_page') as fetch:
            for ip in ('8.8.8.8', '::1', 'invalid'):
                with self.assertRaises(ValueError):
                    inspect('http://lab.test/', ip)
            fetch.assert_not_called()

    def test_form_parameters_no_values_and_external_links(self):
        fetch = Mock(return_value=(200, {'content-type':'text/html'}, '<form action="/upload.action" method="post" enctype="multipart/form-data"><input type="file" name="csr"><input name="token" value="SECRET"></form><a href="/docs?page=intro">Docs</a><a href="http://outside.test/?page=x">External</a>'))
        report = inventory('http://lab.test/', '192.168.56.10', fetch)
        form = report['forms'][0]
        self.assertEqual(form['action'], 'http://lab.test/upload.action')
        self.assertEqual(form['enctype'], 'multipart/form-data')
        self.assertIn({'name':'csr', 'type':'file'}, form['fields'])
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertEqual(report['parameters'][0]['names'], ['page'])
        self.assertEqual(fetch.call_count, 1)
        self.assertTrue(all('outside.test' not in route for route in report['routes']))

    def test_redirect_loop_is_bounded(self):
        fetch = Mock(side_effect=lambda url, *_: (302, {'location':url + 'x'}, ''))
        report = inventory('http://lab.test/', '192.168.56.10', fetch)
        self.assertEqual(fetch.call_count, 5)
        self.assertEqual(len(report['pages']), 5)
        self.assertEqual(len(report['redirects']), 5)
