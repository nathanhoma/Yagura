"""Small in-memory activity feed for the global progress drawer."""
import re
import threading

from .findings import now, uid
from .sensitive import redact


def safe_command(value):
    command = redact(value or '')
    return re.sub(r'([?&][^=\s&]+)=([^&\s]+)', r'\1=[REDACTED]', command)[:500]


class ActivityTracker:
    def __init__(self):
        self.lock = threading.RLock()
        self.items = []

    def begin(self, kind, title, command='', target='', detail='', progress=None):
        item = dict(id=uid('activity'), kind=kind, title=redact(title)[:160],
                    command=safe_command(command), target=redact(target)[:160],
                    detail=redact(detail)[:300], progress=progress, state='running',
                    outcome=None, startedAt=now(), updatedAt=now(), endedAt=None)
        with self.lock:
            self.items.insert(0, item)
            self.items = self.items[:40]
        return item['id']

    def update(self, activity_id, *, detail=None, progress=None, command=None):
        with self.lock:
            item = next((row for row in self.items if row['id'] == activity_id), None)
            if item is None or item['state'] != 'running':
                return
            if detail is not None:
                item['detail'] = redact(detail)[:300]
            if progress is not None:
                item['progress'] = progress
            if command is not None:
                item['command'] = safe_command(command)
            item['updatedAt'] = now()

    def finish(self, activity_id, outcome, detail=''):
        with self.lock:
            item = next((row for row in self.items if row['id'] == activity_id), None)
            if item is None or item['state'] != 'running':
                return
            item.update(state='finished', outcome=outcome, detail=redact(detail)[:300],
                        updatedAt=now(), endedAt=now())

    def snapshot(self):
        with self.lock:
            active = [row.copy() for row in self.items if row['state'] == 'running']
            recent = [row.copy() for row in self.items if row['state'] == 'finished'][:8]
        return dict(active=active, recent=recent, serverTime=now())
