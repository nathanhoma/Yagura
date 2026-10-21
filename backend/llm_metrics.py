"""Bounded, content-free measurements of model calls."""
import json
import threading
from datetime import datetime, timezone
from uuid import uuid4


class LlmMetrics:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def history(self):
        with self.lock:
            try:
                data = json.loads(self.path.read_text())
                return data if isinstance(data, list) else []
            except (FileNotFoundError, OSError, ValueError):
                return []

    def record(self, row):
        with self.lock:
            try:
                data = json.loads(self.path.read_text())
                if not isinstance(data, list):
                    data = []
            except (FileNotFoundError, OSError, ValueError):
                data = []
            item = {'id': str(uuid4()), 'at': datetime.now(timezone.utc).isoformat(), **row}
            data = [item] + data[:99]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + '.tmp')
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
            temporary.chmod(0o600)
            temporary.replace(self.path)
