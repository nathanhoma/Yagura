from pathlib import Path
import tempfile
import threading
import unittest

from backend import findings as F
from backend.activity import ActivityTracker
from backend.server import Workspace
from backend.workflow import workflow


class ActivityTests(unittest.TestCase):
    def test_tracker_redacts_query_values_and_separates_running_from_recent(self):
        tracker = ActivityTracker()
        item = tracker.begin('check', 'HTTP headers', 'curl http://lab.test/login?code=secret-value', 'lab.test',
                             progress={'completed': 0, 'total': 3, 'unit': 'checks'})
        active = tracker.snapshot()['active']
        self.assertEqual(len(active), 1)
        self.assertIn('[REDACTED]', active[0]['command'])
        self.assertNotIn('secret-value', active[0]['command'])
        tracker.update(item, progress={'completed': 1, 'total': 3, 'unit': 'checks'})
        self.assertEqual(tracker.snapshot()['active'][0]['progress']['completed'], 1)
        tracker.finish(item, 'no-response', 'No ICMP reply')
        self.assertEqual(tracker.snapshot()['active'], [])
        self.assertEqual(tracker.snapshot()['recent'][0]['outcome'], 'no-response')

    def test_check_is_visible_while_runner_waits(self):
        with tempfile.TemporaryDirectory() as directory:
            entered, release = threading.Event(), threading.Event()
            def runner(program, args, timeout):
                entered.set()
                release.wait(2)
                return {'ok': True, 'stdout': 'HTTP/1.1 200 OK\n', 'stderr': ''}
            ws = Workspace(findings_file=Path(directory) / 'findings.json', runner=runner)
            scope = ws.save_scope({'cidrs': ['100.96.1.0/24'], 'domains': ['03.crimsonia.net']})
            doc = F.parse_import({'tool': 'nmap', 'output': 'Nmap scan report for web.03.crimsonia.net (100.96.1.70)\nHost is up.\n80/tcp open http\nNmap done: 1 IP address (1 host up) scanned'})
            host = next(f for f in doc['findings'] if f['kind'] == 'host')
            host['approval'] = {'ip': host['ip'], 'name': host['name'], 'scope': scope}
            ws.save(doc)
            candidate = next(c for c in workflow(doc, scope)['candidates'] if c['catalogId'] == 'http-headers')
            result = {}
            thread = threading.Thread(target=lambda: result.update(ws.execute_candidate(candidate['id'], scope)))
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                active = ws.activity.snapshot()['active']
                self.assertEqual(len(active), 1)
                self.assertEqual(active[0]['kind'], 'check')
                self.assertIn('curl', active[0]['command'])
                self.assertIn('web.03.crimsonia.net', active[0]['target'])
            finally:
                release.set()
                thread.join(3)
            self.assertEqual(result['outcome'], 'completed')
            self.assertEqual(ws.activity.snapshot()['active'], [])
            self.assertEqual(ws.activity.snapshot()['recent'][0]['outcome'], 'completed')


if __name__ == '__main__':
    unittest.main()
