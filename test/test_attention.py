import unittest

from backend import findings as F
from backend.attention import review_flags


SCOPE = {'cidrs': ['192.168.56.0/24'], 'domains': [], 'matchMode': 'and'}


def import_nmap(doc, ip, version, *, os_name=''):
    os_xml = f'<os><osmatch name="{os_name}" accuracy="85"/></os>' if os_name else ''
    xml = f'<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="{ip}"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="{version}"/></port></ports>{os_xml}</host></nmaprun>'
    F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output': xml}))


class AttentionTests(unittest.TestCase):
    def test_flags_versions_os_and_cross_host_difference_with_evidence(self):
        doc = F.empty()
        import_nmap(doc, '192.168.56.10', '1.20', os_name='Linux 5.x')
        import_nmap(doc, '192.168.56.11', '1.24')
        flags = review_flags(doc, SCOPE)
        self.assertEqual([f['kind'] for f in flags].count('software'), 2)
        self.assertEqual([f['kind'] for f in flags].count('os'), 1)
        self.assertEqual([f['kind'] for f in flags].count('version-difference'), 2)
        self.assertTrue(all(f['findingIds'] and f['evidenceIds'] for f in flags))
        self.assertTrue(all('vulnerability' not in f['title'].lower() for f in flags))

    def test_rebuild_reflects_correction_and_scope(self):
        doc = F.empty()
        import_nmap(doc, '192.168.56.10', '1.20')
        import_nmap(doc, '192.168.57.10', '1.21')
        flags = review_flags(doc, SCOPE)
        self.assertEqual(len(flags), 1)
        service = next(f for f in doc['findings'] if f['kind'] == 'service' and f['hostId'] == flags[0]['hostId'])
        service['version'] = ''
        service['product'] = ''
        self.assertEqual(review_flags(doc, SCOPE), [])

    def test_multiple_os_guesses_collapse_to_latest_and_product_without_version_is_not_flagged(self):
        doc = F.empty()
        import_nmap(doc, '192.168.56.10', '', os_name='Linux 4.x')
        import_nmap(doc, '192.168.56.10', '', os_name='Linux 5.x')
        flags = review_flags(doc, SCOPE)
        self.assertEqual([f['kind'] for f in flags], ['os'])
        self.assertIn('Linux 5.x', flags[0]['reason'])

    def test_unapproved_domain_host_is_not_flagged(self):
        doc = F.empty()
        import_nmap(doc, '192.168.56.10', '1.20')
        domain_scope = {'cidrs': ['192.168.56.0/24'], 'domains': ['example.test'], 'matchMode': 'and'}
        self.assertEqual(review_flags(doc, domain_scope), [])


if __name__ == '__main__':
    unittest.main()
