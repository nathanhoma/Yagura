import json
import unittest

from backend.tool_imports import parse_export


SCOPE = {'cidrs': ['192.168.56.0/24'], 'domains': [], 'matchMode': 'and'}
HOST = {'id': 'host-test', 'kind': 'host', 'ip': '192.168.56.10',
        'name': 'www.lab.test', 'state': 'up', 'local': False}


class ToolImportTests(unittest.TestCase):
    def test_wappalyzer_technology_is_linked_without_extra_fields(self):
        output = json.dumps([{'url': 'https://www.lab.test/login?token=secret',
            'technologies': [{'name': 'Example CMS', 'versions': ['2.4.1'],
                              'unrelatedPrivateField': 'SECRET'}]},
            {'url': 'https://outside.test/', 'technologies': [{'name': 'Other'}]}])
        result = parse_export({'tool': 'wappalyzer', 'output': output}, HOST, SCOPE)
        self.assertEqual([f['kind'] for f in result['findings']], ['host', 'service', 'observation'])
        self.assertIn('Example CMS', result['findings'][-1]['title'])
        self.assertIn('2.4.1', result['findings'][-1]['detail'])
        self.assertNotIn('secret', result['evidence'][0]['output'])
        self.assertNotIn('SECRET', result['evidence'][0]['output'])
        self.assertIn('1 export entries', result['warnings'][-1])

    def test_burp_issue_export_ignores_http_messages_and_external_hosts(self):
        output = '''<?xml version="1.0"?>
<!DOCTYPE issues [<!ELEMENT issues (issue*)><!ELEMENT issue ANY>]>
<issues><issue><host ip="192.168.56.10">https://www.lab.test</host>
<path>/admin?session=secret</path><name>Missing security header</name>
<severity>Low</severity><confidence>Certain</confidence>
<requestresponse><request>Authorization: Bearer SECRET</request></requestresponse>
</issue><issue><host ip="192.168.56.11">https://other.test</host>
<path>/</path><name>External issue</name></issue></issues>'''
        result = parse_export({'tool': 'burp', 'output': output}, HOST, SCOPE)
        saved = result['evidence'][0]['output']
        self.assertIn('Missing security header', saved)
        self.assertNotIn('SECRET', saved)
        self.assertNotIn('secret', saved)
        self.assertNotIn('External issue', saved)
        self.assertEqual(result['findings'][-1]['title'], 'Burp issue: Missing security header')

    def test_burp_saved_item_records_status_without_response_body(self):
        output = '''<items><item><url>http://www.lab.test:8080/docs?q=secret</url>
<method>GET</method><status>403</status><mimetype>HTML</mimetype>
<response base64="true">SECRET</response></item></items>'''
        result = parse_export({'tool': 'burp', 'output': output}, HOST, SCOPE)
        self.assertIn('HTTP 403', result['findings'][-1]['detail'])
        self.assertNotIn('secret', result['evidence'][0]['output'])
        self.assertNotIn('SECRET', result['evidence'][0]['output'])

    def test_entity_and_out_of_scope_host_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_export({'tool': 'burp', 'output': '<!DOCTYPE issues [<!ENTITY x "bad">]><issues><issue/></issues>'}, HOST, SCOPE)
        with self.assertRaises(ValueError):
            parse_export({'tool': 'wappalyzer', 'output': '{}'},
                         {**HOST, 'ip': '8.8.8.8'}, SCOPE)


if __name__ == '__main__':
    unittest.main()
