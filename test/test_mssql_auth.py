import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from backend.auto_command import validate_auto_command
from backend.mssql_auth import cache_path
from backend.server import run_command


class MssqlKerberosTests(unittest.TestCase):
    def setUp(self):
        self.host = {'ip': '100.96.1.70', 'name': 'sql.dev.03.crimsonia.net'}
        self.scope = {'cidrs': ['100.96.1.0/24'], 'domains': ['03.crimsonia.net'],
                      'matchMode': 'and'}

    def test_owner_only_regular_cache_enables_exact_read_only_enumeration(self):
        with tempfile.TemporaryDirectory() as folder:
            ticket = Path(folder) / 'ticket'
            ticket.write_bytes(b'test ticket placeholder')
            ticket.chmod(0o600)
            command = 'nxc mssql 100.96.1.70 --use-kcache -M enum_links'
            with patch.dict(os.environ, {'MSSQL_KRB5CCNAME': 'FILE:' + str(ticket)}):
                self.assertEqual(cache_path(), str(ticket))
                self.assertEqual(validate_auto_command(command, self.host, self.scope), command)
                completed = subprocess.CompletedProcess([], 0, stdout='metadata', stderr='')
                with patch('backend.server.subprocess.run', return_value=completed) as run:
                    self.assertTrue(run_command('nxc', command.split()[1:])['ok'])
                    self.assertEqual(run.call_args.kwargs['env']['KRB5CCNAME'], 'FILE:' + str(ticket))
                    run_command('nmap', ['-n', '100.96.1.70'])
                    self.assertNotIn('KRB5CCNAME', run.call_args.kwargs['env'])

    def test_missing_unsafe_and_symlink_caches_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            ticket = Path(folder) / 'ticket'
            ticket.write_bytes(b'test ticket placeholder')
            link = Path(folder) / 'link'
            link.symlink_to(ticket)
            command = 'nxc mssql 100.96.1.70 --use-kcache -M enum_links'
            for value, mode in ((str(ticket), 0o644), (str(link), 0o600),
                                (str(Path(folder) / 'absent'), 0o600), ('relative', 0o600)):
                ticket.chmod(mode)
                with self.subTest(value=value), patch.dict(os.environ, {'MSSQL_KRB5CCNAME': value}):
                    self.assertIsNone(cache_path())
                    with self.assertRaises(ValueError):
                        validate_auto_command(command, self.host, self.scope)
                    with patch('backend.server.subprocess.run') as run:
                        self.assertFalse(run_command('nxc', command.split()[1:])['ok'])
                        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
