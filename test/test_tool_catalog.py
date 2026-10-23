import subprocess
import unittest
from unittest.mock import patch

from backend.tool_catalog import available_tools, read_help


class ToolCatalogTests(unittest.TestCase):
    def test_catalog_contains_only_installed_names_and_no_commands(self):
        with patch('backend.tool_catalog.shutil.which', side_effect=lambda name: '/usr/bin/' + name if name == 'nmap' else None):
            self.assertEqual(available_tools(), [{'id': 'nmap', 'purpose': 'Port, service, and protocol observations'}])

    def test_reads_only_selected_local_help_without_shell(self):
        completed = subprocess.CompletedProcess(['nmap', '--help'], 0, stdout='Usage: nmap\n', stderr='')
        with patch('backend.tool_catalog.shutil.which', return_value='/usr/bin/nmap'), \
             patch('backend.tool_catalog.subprocess.run', return_value=completed) as run:
            result = read_help('nmap')
        self.assertEqual(result['invocation'], ['nmap', '--help'])
        self.assertIn('Usage: nmap', result['text'])
        self.assertEqual(run.call_args.args[0], ['/usr/bin/nmap', '--help'])
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_unknown_or_missing_tool_cannot_read_help(self):
        with self.assertRaisesRegex(ValueError, 'catalog'):
            read_help('sh')
        with patch('backend.tool_catalog.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'not installed'):
                read_help('nmap')

    def test_reads_local_man_page_without_pager_or_shell(self):
        completed = subprocess.CompletedProcess(['man', '-P', 'cat', 'nmap'], 0,
                                                stdout='NMAP(1)\n', stderr='')
        with patch('backend.tool_catalog.shutil.which', side_effect=lambda name: '/usr/bin/' + name), \
             patch('backend.tool_catalog.subprocess.run', return_value=completed) as run:
            result = read_help('nmap', 'man')
        self.assertEqual(result['source'], 'man')
        self.assertEqual(result['invocation'], ['man', 'nmap'])
        self.assertEqual(run.call_args.args[0], ['/usr/bin/man', '-P', 'cat', 'nmap'])
        self.assertFalse(run.call_args.kwargs.get('shell', False))
