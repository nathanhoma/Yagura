import shlex
import os
import subprocess
import unittest
from unittest.mock import patch

from backend.auto_command import WORDLIST, prepare_auto_command, validate_auto_command
from backend.server import run_command


class AutoCommandTests(unittest.TestCase):
    def setUp(self):
        self.host = {'ip': '100.96.1.70', 'name': 'web.03.crimsonia.net'}
        self.scope = {'cidrs': ['100.96.1.0/24', '100.96.2.53/32'],
                      'domains': ['03.crimsonia.net'], 'matchMode': 'and'}

    def check(self, command):
        self.assertEqual(validate_auto_command(command, self.host, self.scope), command)

    def reject(self, command):
        with self.assertRaisesRegex(ValueError, 'Automatic catalog check'):
            validate_auto_command(command, self.host, self.scope)

    def test_each_catalogued_tool_has_a_bounded_automatic_form(self):
        commands = [
            'nmap -Pn -sT -F -n 100.96.1.70',
            "curl -q -sS -I --noproxy '*' --resolve web.03.crimsonia.net:443:100.96.1.70 --max-time 5 https://web.03.crimsonia.net/",
            'whatweb --follow-redirect=never http://100.96.1.70/',
            'sslscan --no-colour --sni-name=web.03.crimsonia.net 100.96.1.70:443',
            'dnsrecon -d 03.crimsonia.net -n 100.96.2.53 -t std',
            shlex.join(['gobuster', 'dir', '-u', 'http://100.96.1.70/', '-w', str(WORDLIST), '-t', '1', '--timeout', '2s']),
            'smbclient -L 100.96.1.70 -N',
            'nxc smb 100.96.1.70 --shares',
            'snmpwalk -v2c -c public 100.96.1.70 1.3.6.1.2.1',
            'dig @100.96.2.53 web.03.crimsonia.net A',
            'openssl s_client -connect 100.96.1.70:443 -servername web.03.crimsonia.net -brief',
        ]
        for command in commands:
            with self.subTest(program=command.split()[0]):
                self.check(command)

    def test_other_targets_credentials_redirects_and_side_effects_are_rejected(self):
        for command in (
            'nmap -Pn -sT -F -n 100.96.1.70 100.96.1.71',
            'nmap -Pn --script vuln 100.96.1.70',
            'nmap -Pn --script-args http.proxy=http://evil.example 100.96.1.70',
            'nmap -Pn -oN /tmp/report 100.96.1.70',
            "curl -q --noproxy '*' --max-time 5 -L http://100.96.1.70/",
            "curl -q --noproxy '*' --max-time 5 http://100.96.1.71/",
            "curl -q --noproxy '*' --max-time 5 http://user:pass@100.96.1.70/",
            'whatweb http://100.96.1.70/',
            'whatweb --follow-redirect=always http://100.96.1.70/',
            'sslscan --xml=/tmp/report 100.96.1.70:443',
            'dnsrecon -d 03.crimsonia.net -n 100.96.1.99 -t std',
            'gobuster dir -u http://100.96.1.70/ -w /etc/passwd',
            'gobuster dir -u http://100.96.1.70/ -w backend/recon_paths.txt --follow-redirect',
            'smbclient //100.96.1.70/share -N -c get secret',
            'nxc smb 100.96.1.70 -u admin -p password',
            'snmpwalk -v2c -c private 100.96.1.70',
            'dig @8.8.8.8 web.03.crimsonia.net A',
            'openssl s_client -connect 100.96.1.71:443 -servername web.03.crimsonia.net',
        ):
            with self.subTest(command=command):
                self.reject(command)

    def test_scope_change_blocks_automatic_command(self):
        self.scope['domains'] = ['other.example']
        self.reject('nmap -sn 100.96.1.70')

    def test_curl_repair_feedback_names_the_missing_constraint(self):
        with self.assertRaisesRegex(ValueError, "--noproxy"):
            validate_auto_command('curl -q --max-time 5 http://100.96.1.70/', self.host, self.scope)
        with self.assertRaisesRegex(ValueError, "--max-time"):
            validate_auto_command("curl -q --noproxy '*' http://100.96.1.70/", self.host, self.scope)

    def test_curl_is_pinned_and_bounded_before_automatic_validation(self):
        command = prepare_auto_command('curl -sS -I https://web.03.crimsonia.net/', self.host)
        self.check(command)
        self.assertIn('--resolve web.03.crimsonia.net:443:100.96.1.70', command)
        self.assertIn("--noproxy '*'", command)
        self.assertIn('--max-time 10', command)
        self.assertEqual(prepare_auto_command('curl -L http://100.96.1.70/', self.host).split()[0], 'curl')
        self.reject(prepare_auto_command('curl -L http://100.96.1.70/', self.host))

    def test_https_ip_url_uses_approved_name_for_certificate_verification(self):
        command = prepare_auto_command('curl -sS -I https://100.96.1.70/', self.host)
        self.check(command)
        self.assertIn('https://web.03.crimsonia.net/', command)
        self.assertIn('--resolve web.03.crimsonia.net:443:100.96.1.70', command)
        self.assertNotIn('https://100.96.1.70/', command)

    def test_tool_process_gets_no_model_key_or_proxy_configuration(self):
        completed = subprocess.CompletedProcess(['nmap', '--version'], 0, stdout='Nmap', stderr='')
        with patch.dict(os.environ, {'LLM_API_KEY': 'secret', 'HTTPS_PROXY': 'http://proxy.example'}, clear=False), \
             patch('backend.server.subprocess.run', return_value=completed) as run:
            result = run_command('nmap', ['--version'])
        self.assertTrue(result['ok'])
        env = run.call_args.kwargs['env']
        self.assertNotIn('LLM_API_KEY', env)
        self.assertNotIn('HTTPS_PROXY', env)
        self.assertNotEqual(env['HOME'], os.environ.get('HOME'))
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
