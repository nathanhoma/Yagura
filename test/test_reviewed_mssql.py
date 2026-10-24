import unittest

from backend.reviewed_check import validate


class ReviewedMssqlTests(unittest.TestCase):
    def test_mssql_source_is_pinned_and_cli_secrets_are_rejected(self):
        command = 'nxc mssql 100.96.1.70 --use-kcache -M enum_links'
        normalized, program, args = validate(command, '100.96.1.70')
        self.assertEqual(normalized, command)
        self.assertEqual(program, 'nxc')
        self.assertEqual(args[:2], ['mssql', '100.96.1.70'])
        for value in ('nxc mssql 100.96.1.71',
                      'nxc mssql 100.96.1.70 -p secret',
                      'nxc mssql 100.96.1.70 --password=secret',
                      'nxc mssql 100.96.1.70 -H abcdef',
                      'nxc mssql 100.96.1.70 -M link_xpcmd',
                      'nxc mssql 100.96.1.70 -x whoami',
                      'nxc mssql 100.96.1.70 --use-kcache -M enum_links 100.96.1.71'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value, '100.96.1.70')


if __name__ == '__main__':
    unittest.main()
