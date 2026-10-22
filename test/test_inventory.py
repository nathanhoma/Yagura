import unittest

from backend.inventory import parse_inventory, verify_inventory_host
from backend.scope import normalize_scope


SCOPE = normalize_scope({'cidrs': ['100.95.95.2/32'],
                         'domains': ['03.crimsonia.net'], 'matchMode': 'or'})


class InventoryTests(unittest.TestCase):
    def test_providentia_team_placeholders_and_scope_filter(self):
        content = '''<host><fqdn>www.dev.<strong>[ team_nr_str ]</strong>.crimsonia.net</fqdn>
          <connection-address><span>100.99.<strong>[ team_nr ]</strong>.57</span>
          <span class="hidden">100.99.1.57</span></connection-address></host>
          <host><fqdn>fw.dev.[ team_nr_str ].crimsonia.net</fqdn>
          <connection-address>100.99.1[ team_nr_str ].5</connection-address></host>
          <host><fqdn>ws[seq].dev.[ team_nr_str ].crimsonia.net</fqdn>
          <connection-address>10.[ team_nr ].40.1</connection-address></host>
          <host><fqdn>outside.04.crimsonia.net</fqdn><connection-address>100.99.4.3</connection-address></host>'''
        result = parse_inventory(content, '03', 'dev.03.crimsonia.net', SCOPE)
        self.assertEqual(result['hosts'], [
            {'name': 'www.dev.03.crimsonia.net', 'ip': '100.99.3.57'},
            {'name': 'fw.dev.03.crimsonia.net', 'ip': '100.99.103.5'}])
        self.assertEqual(result['issues'][0]['reason'], 'Unresolved template')
        self.assertEqual(result['totalRows'], 4)

    def test_dns_mismatch_never_becomes_verified(self):
        host = {'name': 'www.dev.03.crimsonia.net', 'ip': '100.99.3.57'}
        def runner(program, args, timeout):
            return {'ok': True, 'stdout': f'{host["name"]}. 60 IN A 100.99.3.99\n', 'stderr': ''}
        result = verify_inventory_host(host, ['100.95.95.2'], SCOPE, runner)
        self.assertEqual(result['status'], 'dns-mismatch')
        self.assertEqual(result['addresses'], ['100.99.3.99'])

    def test_team_and_suffix_are_required(self):
        html = '<host><fqdn>www.dev.[ team_nr_str ].crimsonia.net</fqdn><connection-address>100.99.[ team_nr ].57</connection-address></host>'
        for team, suffix in [('3', 'dev.03.crimsonia.net'), ('03', 'other.example')]:
            with self.subTest(team=team, suffix=suffix), self.assertRaises(ValueError):
                parse_inventory(html, team, suffix, SCOPE)
