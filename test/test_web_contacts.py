import unittest
from unittest.mock import patch, Mock

from backend.web_contacts import discover, fetch_page, website_url, MAX_PAGES
from backend.server import invocation
from backend.workflow import workflow
from backend import findings as F


class WebsiteContactsTests(unittest.TestCase):
    def test_extracts_text_entities_and_mailto_with_sources(self):
        pages = {
            'http://www.lab.test:80/': '<p>Contact: ops&#64;lab.test</p><a href="/contact">Contact</a><script>hidden@lab.test</script><a href="mailto:ops%40lab.test?subject=Hello">Write us</a>',
            'http://www.lab.test:80/contact': '<a href="mailto:ops@lab.test">Team</a>',
        }
        def fetch(url, ip, timeout):
            self.assertEqual(ip, '192.168.56.10')
            return 200, {'content-type': 'text/html'}, pages[url]
        result = discover('http://www.lab.test:80/', '192.168.56.10', fetch)
        self.assertEqual(result['status'], 'exactly_one')
        self.assertEqual(result['contacts'], [{'address': 'ops@lab.test', 'sources': list(pages)}])
        self.assertIn('whole-site uniqueness is not established', result['coverage'])

    def test_follows_only_same_origin_and_limits_requests(self):
        called = []
        def fetch(url, ip, timeout):
            called.append(url)
            return 200, {'content-type': 'text/html'}, '<a href="https://other.test/">Other</a><a href="http://www.lab.test:81/">Port</a>' + ''.join(f'<a href="/{i}">{i}</a>' for i in range(20))
        report = discover('http://www.lab.test:80/', '10.1.1.1', fetch)
        self.assertEqual(len(called), MAX_PAGES)
        self.assertTrue(all(url.startswith('http://www.lab.test:80/') for url in called))
        self.assertEqual(report['status'], 'none')

    def test_external_redirect_is_not_followed(self):
        calls = []
        def fetch(url, *args):
            calls.append(url)
            return 302, {'location': 'http://external.test/'}, ''
        report = discover('http://www.lab.test/', '10.1.1.1', fetch)
        self.assertEqual(len(calls), 1)
        self.assertTrue(report['errors'])
        self.assertEqual(report['pages'], [])

    def test_multiple_addresses_and_plain_text(self):
        report = discover('http://www.lab.test/', '10.1.1.1', lambda *a: (200, {'content-type': 'text/plain'}, 'one@lab.test <two@lab.test>'))
        self.assertEqual(report['status'], 'multiple')
        self.assertEqual(report['count'], 2)

    def test_scope_and_hostname_validation(self):
        with self.assertRaises(ValueError):
            discover('http://www.lab.test/', '8.8.8.8', lambda *a: self.fail('Out-of-scope fetch'))
        with self.assertRaises(ValueError):
            discover('http://user:secret@www.lab.test/', '10.1.1.1')
        self.assertEqual(website_url({'ip': '10.1.1.1', 'name': 'www.lab.test'}, {'port': 443}), 'https://www.lab.test:443/')
        self.assertEqual(website_url({'ip': '10.1.1.1', 'name': 'bad; command'}, {'port': 80}), 'http://10.1.1.1:80/')

    def test_fetch_pins_transport_ip_and_preserves_hostname(self):
        response = Mock(status=200)
        response.isclosed.return_value = False
        response.getheaders.return_value = [('Content-Type', 'text/html')]
        response.headers.get_content_charset.return_value = 'utf-8'
        response.read1.side_effect = [b'<p>ops@lab.test</p>', b'']
        conn = Mock()
        conn.getresponse.return_value = response
        with patch('backend.web_contacts.socket.create_connection') as connect, patch('backend.web_contacts.http.client.HTTPConnection', return_value=conn) as connection:
            status, _, body = fetch_page('http://www.lab.test:8080/contact', '10.1.1.1', 5)
        connect.assert_called_once_with(('10.1.1.1', 8080), timeout=5)
        connection.assert_called_once_with('www.lab.test', 8080, timeout=5)
        self.assertEqual(conn.request.call_args.args, ('GET', '/contact'))
        self.assertEqual(status, 200)
        self.assertIn('ops@lab.test', body)
        response.close.assert_called_once()

    def test_inventory_transport_preserves_forbidden_response(self):
        response = Mock(status=403)
        response.isclosed.return_value = False
        response.getheaders.return_value = [('Content-Type', 'text/html')]
        response.headers.get_content_charset.return_value = 'utf-8'
        response.read1.side_effect = [b'<title>Forbidden</title>', b'']
        conn = Mock()
        conn.getresponse.return_value = response
        with patch('backend.web_contacts.socket.create_connection'), patch('backend.web_contacts.http.client.HTTPConnection', return_value=conn):
            status, _, body = fetch_page('http://www.lab.test:8080/', '10.1.1.1', 5, accept_error=True)
        self.assertEqual(status, 403)
        self.assertIn('Forbidden', body)

    def test_web_candidate_uses_recorded_hostname_and_service(self):
        doc = F.empty()
        F.merge_parsed(doc, F.parse_import({'tool': 'nmap', 'output': 'Nmap scan report for www.lab.test (192.168.56.10)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'}))
        self.assertEqual(workflow(doc)['candidates'], [])
        candidate = next(c for c in workflow(doc, '192.168.56.10/32')['candidates'] if c['catalogId'] == 'web-contacts')
        program, args, tool = invocation(candidate, doc)
        self.assertIn('http://www.lab.test:80/', args)
        self.assertEqual(args[-2:], ['--ip', '192.168.56.10'])
        self.assertEqual(tool, 'web-contacts')
        self.assertTrue(program)


if __name__ == '__main__':
    unittest.main()
