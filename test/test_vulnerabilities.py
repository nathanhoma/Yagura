import unittest

from backend import findings as F
from backend.vulnerabilities import catalog, match_versions


SCOPE = {'cidrs': ['192.168.56.0/24'], 'domains': [], 'matchMode': 'and'}


def add_service(doc, ip, product, version):
    output = (f'<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="{ip}"/>'
              f'<ports><port protocol="tcp" portid="80"><state state="open"/>'
              f'<service name="http" product="{product}" version="{version}"/>'
              f'</port></ports></host></nmaprun>')
    F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output': output}))


class VulnerabilityTests(unittest.TestCase):
    def test_catalog_has_unique_bounded_vendor_entries(self):
        rows = catalog()['entries']
        self.assertGreaterEqual(len(rows), 10)
        self.assertEqual(len({row['id'] for row in rows}), len(rows))
        self.assertTrue(all(row['source'].startswith('https://') and row['condition'] for row in rows))

    def test_nginx_branch_fix_is_not_misread_as_vulnerable(self):
        doc = F.empty()
        add_service(doc, '192.168.56.10', 'nginx', '1.28.3 (Ubuntu)')
        result = match_versions(doc, SCOPE)
        ids = {match['cveId'] for match in result['matches']}
        self.assertIn('CVE-2026-15176', ids)
        self.assertNotIn('CVE-2026-27654', ids)
        self.assertTrue(all(match['status'] == 'possible' and match['findingIds'] and match['evidenceIds']
                            for match in result['matches']))

    def test_apache_banner_is_matched_only_on_approved_service(self):
        doc = F.empty()
        add_service(doc, '192.168.56.10', '', '')
        service = next(f for f in doc['findings'] if f['kind'] == 'service')
        ev = F.parse_import({'tool': 'evidence', 'output': 'placeholder'})['evidence'][0]
        ev['tool'] = 'web-inventory'
        doc['evidence'].append(ev)
        observation = F.record('observation', {'hostId': service['hostId'], 'serviceId': service['id'],
            'title': 'Web inventory', 'detail': 'http://192.168.56.10/ · HTTP 200 · Home · Apache/2.4.58 (Ubuntu)'},
            ev['id'], F.now())
        doc['findings'].append(observation)
        result = match_versions(doc, SCOPE)
        ids = {match['cveId'] for match in result['matches']}
        self.assertIn('CVE-2023-38709', ids)
        self.assertIn(observation['id'], next(m for m in result['matches'] if m['cveId'] == 'CVE-2023-38709')['findingIds'])
        self.assertEqual(match_versions(doc, {'cidrs': ['192.168.57.0/24'], 'domains': []})['matches'], [])
        self.assertEqual(match_versions(doc, {'cidrs': ['192.168.56.0/24'], 'domains': ['example.test']})['matches'], [])

    def test_partial_version_and_other_apache_product_are_ignored(self):
        doc = F.empty()
        add_service(doc, '192.168.56.10', 'nginx', '1.28')
        add_service(doc, '192.168.56.11', 'Apache Tomcat', '2.4.58')
        self.assertEqual(match_versions(doc, SCOPE)['matches'], [])

    def test_newer_banner_supersedes_old_version(self):
        doc = F.empty()
        add_service(doc, '192.168.56.10', 'nginx', '1.28.1')
        service = next(f for f in doc['findings'] if f['kind'] == 'service')
        ev = {'id': F.uid('evidence'), 'tool': 'http-headers', 'command': 'curl', 'output': 'Server: nginx/1.30.6',
              'observedAt': F.now()}
        doc['evidence'].append(ev)
        obs = F.record('observation', {'hostId': service['hostId'], 'serviceId': service['id'],
            'title': 'HTTP response headers', 'detail': 'HTTP/1.1 200 OK\nServer: nginx/1.30.6\n'}, ev['id'], '2027-01-01T00:00:00Z')
        doc['findings'].append(obs)
        result = match_versions(doc, SCOPE)
        self.assertEqual(result['observedCount'], 1)
        self.assertFalse(any(match['observedVersion'] == '1.28.1' for match in result['matches']))
        self.assertFalse(any(match['cveId'] == 'CVE-2026-15176' for match in result['matches']))


if __name__ == '__main__':
    unittest.main()
