import unittest

from backend.scope import discovery_allowed, host_allowed, normalize_scope
from backend.workflow import workflow
from backend import findings as F


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = normalize_scope({
            'cidrs': ['100.101.5.0/24', '100.96.1.0/24', '10.1.51.0/24'],
            'domains': ['Crimsonia.NET.'],
        })

    def test_shared_space_and_multiple_ranges(self):
        self.assertEqual(self.scope['cidrs'], ['10.1.51.0/24', '100.96.1.0/24', '100.101.5.0/24'])
        self.assertEqual(self.scope['domains'], ['crimsonia.net'])
        self.assertTrue(host_allowed({'ip': '100.96.1.70', 'name': 'ca-website.cca.01.crimsonia.net'}, self.scope))
        self.assertTrue(host_allowed({'ip': '10.1.51.5', 'name': 'crimsonia.net'}, self.scope))
        self.assertFalse(host_allowed({'ip': '100.96.1.70', 'name': 'fakecrimsonia.net'}, self.scope))
        self.assertFalse(host_allowed({'ip': '8.8.8.8', 'name': 'crimsonia.net'}, self.scope))
        self.assertFalse(host_allowed({'ip': '100.101.4.10', 'name': 'crimsonia.net'}, self.scope))

    def test_invalid_entries_fail_closed(self):
        for value in (
            {'cidrs': ['8.8.8.8/32'], 'domains': []},
            {'cidrs': ['100.96.0.0/16'], 'domains': []},
            {'cidrs': [], 'domains': ['crimsonia.net']},
            {'cidrs': ['10.1.51.0/24'], 'domains': ['*.crimsonia.net']},
            {'cidr': '10.1.51.0/24', 'domains': []},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_scope(value)

    def test_domain_bound_discovery_requires_recorded_single_host(self):
        rows = [{'kind': 'host', 'ip': '100.96.1.70', 'name': 'ca-website.cca.01.crimsonia.net'}]
        self.assertTrue(discovery_allowed('100.96.1.70/32', self.scope, rows))
        self.assertFalse(discovery_allowed('100.96.1.0/24', self.scope, rows))
        self.assertFalse(discovery_allowed('100.96.1.71/32', self.scope, rows))
        self.assertFalse(discovery_allowed('100.96.1.70/32', self.scope, [{'kind': 'host', 'ip': '100.96.1.70', 'name': 'other.net'}]))

    def test_candidate_requires_both_ip_and_domain(self):
        doc = F.empty()
        for ip, name in (('100.96.1.70', 'ca-website.cca.01.crimsonia.net'),
                         ('10.1.51.5', 'other.net'), ('8.8.8.8', 'crimsonia.net')):
            ev = {'id': F.uid('evidence'), 'tool': 'evidence', 'command': 'test', 'output': '',
                  'observedAt': F.now(), 'importedAt': F.now(), 'format': 'text'}
            doc['evidence'].append(ev)
            doc['findings'].append(F.record('host', {'ip': ip, 'name': name, 'aliases': [], 'state': 'up', 'local': False,
                                                     'title': ip, 'detail': ''}, ev['id'], F.now()))
        candidates = workflow(doc, self.scope)['candidates']
        self.assertTrue(candidates)
        self.assertEqual({c['command'].split()[-1] for c in candidates if c['catalogId'] == 'nmap-ports'}, {'100.96.1.70'})
