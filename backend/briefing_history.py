"""Bounded, redacted conversation context for one briefing request."""

import re

from .sensitive import MASK, redact


MAX_HISTORY_MESSAGES = 8
MAX_HISTORY_ITEM_CHARS = 600
MAX_HISTORY_CHARS = 3200

_NATURAL_SECRETS = (
    re.compile(r'(?i)(\b(?:password|passwd|api key|access token|refresh token|client secret)\s+(?:is|was)\s+)\S+'),
    re.compile(r'((?:パスワード|APIキー|アクセストークン)\s*(?:は|:|：)\s*)\S+'),
)


def redact_chat(value):
    text = redact(value)
    for pattern in _NATURAL_SECRETS:
        text = pattern.sub(lambda match: match.group(1) + MASK, text)
    return text


def normalize_history(history):
    if history is None:
        return []
    if not isinstance(history, list) or len(history) > MAX_HISTORY_MESSAGES:
        raise ValueError('Supply at most eight recent conversation messages.')
    result = []
    total = 0
    for item in history:
        if (not isinstance(item, dict) or set(item) != {'role', 'content'} or
                item['role'] not in ('user', 'assistant') or
                not isinstance(item['content'], str) or
                not 1 <= len(item['content'].strip()) <= MAX_HISTORY_ITEM_CHARS):
            raise ValueError('Conversation history must contain short user or assistant messages.')
        content = redact_chat(item['content'].strip())
        total += len(content)
        if total > MAX_HISTORY_CHARS:
            raise ValueError('Recent conversation context is too long.')
        result.append({'role': item['role'], 'content': content})
    return result
