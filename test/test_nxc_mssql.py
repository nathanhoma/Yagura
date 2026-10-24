import unittest

from backend.findings import parse_import


class NetExecMssqlImportTests(unittest.TestCase):
    def test_service_and_link_names_remain_source_host_observations(self):
        output = (
            'MSSQL  100.96.1.70  1433  SQLDEV  [*] Windows Server (name:SQLDEV) (EncryptionReq:True)\n'
            'ENUM_LINKS  100.96.1.70  1433  SQLDEV  [+] Linked servers found:\n'
            'ENUM_LINKS  100.96.1.70  1433  SQLDEV  [*] - CAFSQL\n'
            'ENUM_LINKS  100.96.1.71  1433  OTHER   [*] - OUTSIDE\n'
        )
        doc = parse_import({'tool': 'nxc-mssql', 'ip': '100.96.1.70',
                            'command': 'nxc mssql 100.96.1.70', 'output': output})
        hosts = [f for f in doc['findings'] if f['kind'] == 'host']
        services = [f for f in doc['findings'] if f['kind'] == 'service']
        observations = [f for f in doc['findings'] if f['kind'] == 'observation']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['ip'], '100.96.1.70')
        self.assertEqual([(s['port'], s['state']) for s in services], [(1433, 'open')])
        self.assertEqual([o['title'] for o in observations],
                         ['NetExec MSSQL service metadata', 'Linked MSSQL server candidate'])
        self.assertIn('CAFSQL', observations[1]['detail'])
        self.assertNotIn('OUTSIDE', doc['evidence'][0]['output'])

    def test_requires_service_metadata_for_the_selected_ip(self):
        with self.assertRaisesRegex(ValueError, 'selected host'):
            parse_import({'tool': 'nxc-mssql', 'ip': '100.96.1.70',
                          'output': 'MSSQL 100.96.1.71 1433 OTHER [*] Windows Server'})


if __name__ == '__main__':
    unittest.main()
