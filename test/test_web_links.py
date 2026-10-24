import unittest

from backend.web_links import observed_links


class WebLinksTests(unittest.TestCase):
    def test_saved_middle_href_is_available_without_cross_origin_or_secret_urls(self):
        host = {'ip': '100.99.3.59', 'name': 'pastebin.dev.03.crimsonia.net'}
        evidence = [{'id': 'evidence-1', 'command': "curl -q http://100.99.3.59/",
                     'output': ('x' * 500 + '<a href="/paste.php?id=1">My Password</a>' +
                                '<a href="https://outside.example/">Outside</a>' +
                                '<a href="/view?token=private">Token</a>' + 'x' * 500)}]
        links = observed_links(evidence, host)
        self.assertEqual(links, [{'url': 'http://100.99.3.59/paste.php?id=1',
                                  'label': 'My Password', 'sourceEvidenceId': 'evidence-1'}])


if __name__ == '__main__':
    unittest.main()
