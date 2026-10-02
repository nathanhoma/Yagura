"""Default-safe presentation and export of potentially sensitive evidence.

Pattern matching is a backstop, not a secret detector. Operators can mark an
entire evidence item sensitive at import time.
"""
import copy
import re


MASK = '[REDACTED]'
PATTERNS = (
    re.compile(r'(?i)(["\']?(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\']?)[^\s,;"\']+'),
    re.compile(r'(?i)(\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)\S+'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
)


def redact(value):
    text = str(value)
    for pattern in PATTERNS:
        text = pattern.sub(lambda match: (match.group(1) if match.lastindex else '') + MASK, text)
    return text


def sanitize_document(doc):
    safe = copy.deepcopy(doc)
    sensitive_ids = {ev['id'] for ev in safe.get('evidence', []) if ev.get('sensitive')}
    for ev in safe.get('evidence', []):
        ev['command'] = redact(ev.get('command', ''))
        ev['output'] = '[REDACTED: sensitive evidence]' if ev['id'] in sensitive_ids else redact(ev.get('output', ''))
    for finding in safe.get('findings', []):
        for key in ('detail', 'title', 'name', 'product', 'version'):
            if isinstance(finding.get(key), str):
                finding[key] = redact(finding[key])
        if sensitive_ids.intersection(finding.get('evidenceIds', [])):
            finding['detail'] = '[REDACTED: sensitive evidence]'
    return safe
