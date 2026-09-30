import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
import tempfile
import unittest

from backend.email_drafts import DraftStore, DraftConflict, validate_fields, export_eml, discovered_contacts, generate_draft


class EmailDraftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'email-drafts.json'
        self.store = DraftStore(self.path)

    def test_partial_drafts_persist_without_sender_and_conflicts_are_rejected(self):
        draft = self.store.put({'subject': 'Review request', 'body': 'First version'}, [])
        self.assertEqual(draft['sender'], '')
        self.assertEqual(DraftStore(self.path).load()['drafts'][0], draft)
        updated = self.store.put({'body': 'Second version', 'revision': 1}, [], draft['id'])
        self.assertEqual(updated['subject'], 'Review request')
        self.assertEqual(updated['revision'], 2)
        with self.assertRaises(DraftConflict):
            self.store.put({'body': 'Stale edit', 'revision': 1}, [], draft['id'])
        with self.assertRaises(DraftConflict):
            self.store.delete(draft['id'], 1)
        self.assertEqual(self.store.load()['drafts'][0]['body'], 'Second version')
        self.store.delete(draft['id'], 2)
        self.assertEqual(self.store.load()['drafts'], [])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_header_injection_and_metadata_are_rejected(self):
        for payload in [{'to': 'a@example.test\r\nBcc: b@example.test'}, {'subject': 'Hello\nBcc: b@example.test'}, {'senderName': 'Team\r\nCc: b@example.test'}, {'to': 'a@example.test,b@example.test'}, {'sender': 'not an email'}, {'status': 'sent'}, {'body': 7}, {'body': 'x' * 20001}]:
            with self.subTest(payload=str(payload)[:100]):
                with self.assertRaises(ValueError):
                    self.store.put(payload, [])
        self.assertFalse(self.path.exists())

    def test_export_is_a_plain_text_draft_without_invented_sender_or_internal_notes(self):
        fields = validate_fields({'to': 'contact@example.test', 'subject': '確認依頼', 'body': '<b>Plain text</b>\nBcc: stays in body', 'notes': 'Internal instructor context'})
        message = BytesParser(policy=policy.default).parsebytes(export_eml(fields))
        self.assertEqual(message['X-Unsent'], '1')
        self.assertIsNone(message['From'])
        self.assertIsNone(message['Bcc'])
        self.assertEqual(message['Subject'], '確認依頼')
        self.assertEqual(message.get_content_type(), 'text/plain')
        self.assertIn('<b>Plain text</b>', message.get_content())
        self.assertNotIn('Internal instructor context', str(message))
        fields.update(sender='team@example.test', senderName='Exercise Team')
        message = BytesParser(policy=policy.default).parsebytes(export_eml(fields))
        self.assertEqual(message['From'].addresses[0].addr_spec, 'team@example.test')
        self.assertEqual(message['From'].addresses[0].display_name, 'Exercise Team')

    def test_discovered_contacts_are_linked_and_provenance_is_server_derived(self):
        doc = {'findings': [{'evidenceIds': ['ev-1']}], 'evidence': [dict(id='ev-1', tool='web-contacts', output=json.dumps({'contacts': [dict(address='contact@example.test', sources=['https://example.test/contact'])]})), dict(id='orphan', tool='web-contacts', output=json.dumps({'contacts': [dict(address='old@example.test', sources=[])]}))]}
        contacts = discovered_contacts(doc)
        self.assertEqual(len(contacts), 1)
        draft = self.store.put({'to': 'contact@example.test'}, contacts)
        self.assertEqual(draft['sourceEvidenceIds'], ['ev-1'])
        self.assertEqual(draft['sourceUrls'], ['https://example.test/contact'])
        updated = self.store.put({'subject': 'Review', 'revision': 1}, [], draft['id'])
        self.assertEqual(updated['sourceEvidenceIds'], ['ev-1'])
        updated = self.store.put({'to': 'manual@example.test', 'revision': 2}, [], draft['id'])
        self.assertEqual(updated['sourceEvidenceIds'], [])

    def test_model_generation_returns_only_editable_content(self):
        class Model:
            def complete(self, messages, **kwargs):
                self.messages = messages
                return {'data': {'subject': 'Exercise coordination', 'body': 'Hello,\n[Details to be confirmed]'}}
        model = Model()
        result = generate_draft(model, {'brief': 'Ask for a meeting', 'model': ''})
        self.assertEqual(set(result), {'subject', 'body'})
        self.assertFalse(self.path.exists())
        self.assertEqual(json.loads(model.messages[1]['content'])['brief'], 'Ask for a meeting')
        with self.assertRaises(ValueError):
            generate_draft(model, {'brief': '', 'sender': 'invented@example.test'})
        class BadModel:
            def complete(self, *args, **kwargs):
                return {'data': {'subject': 'Hi\nBcc: a@example.test', 'body': 'Hello'}}
        with self.assertRaises(ValueError):
            generate_draft(BadModel(), {'brief': 'Hello'})


if __name__ == '__main__':
    unittest.main()
