"""Bounded, content-free measurements of model calls and per-run totals."""
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4


class LlmMetrics:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.context = threading.local()

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
        except (FileNotFoundError, OSError, ValueError):
            return {'calls': [], 'runs': {}}
        if isinstance(data, list):
            return {'calls': data, 'runs': {}}
        if isinstance(data, dict):
            return {'calls': data.get('calls', []) if isinstance(data.get('calls'), list) else [],
                    'runs': data.get('runs', {}) if isinstance(data.get('runs'), dict) else {}}
        return {'calls': [], 'runs': {}}

    @contextmanager
    def for_run(self, run_id, stage):
        previous = getattr(self.context, 'value', None)
        self.context.value = (run_id, stage)
        try:
            yield
        finally:
            self.context.value = previous

    def history(self):
        with self.lock:
            return self._load()['calls']

    def run_summary(self, run_id):
        with self.lock:
            return self._load()['runs'].get(run_id)

    def record(self, row):
        context = getattr(self.context, 'value', None)
        item = {'id': str(uuid4()), 'at': datetime.now(timezone.utc).isoformat(), **row}
        if context:
            item['runId'], item['stage'] = context
        with self.lock:
            data = self._load()
            data['calls'] = [item] + data['calls'][:99]
            if context:
                run_id, stage = context
                runs = data['runs']
                summary = runs.setdefault(run_id, dict(callCount=0, inputTokenCalls=0,
                    outputTokenCalls=0, inputTokens=0, outputTokens=0, maxInputTokens=0,
                    maxInputChars=0, peakOutputTokens=0, stages={}))
                summary['callCount'] += 1
                summary['stages'][stage] = summary['stages'].get(stage, 0) + 1
                summary['lastAt'] = item['at']
                summary['maxInputChars'] = max(summary['maxInputChars'], row.get('inputChars') or 0)
                for key, count_key, total_key, maximum_key in (
                    ('promptTokens', 'inputTokenCalls', 'inputTokens', 'maxInputTokens'),
                    ('completionTokens', 'outputTokenCalls', 'outputTokens', 'peakOutputTokens')):
                    value = row.get(key)
                    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                        summary[count_key] += 1
                        summary[total_key] += value
                        summary[maximum_key] = max(summary[maximum_key], value)
                if len(runs) > 30:
                    oldest = min(runs, key=lambda key: runs[key].get('lastAt', ''))
                    del runs[oldest]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + '.tmp')
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
            temporary.chmod(0o600)
            temporary.replace(self.path)
