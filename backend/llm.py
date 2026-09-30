import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

from .workflow import is_local_ip


def private_url(value):
    try:
        url = urllib.parse.urlsplit(value)
        host = (url.hostname or '').lower()
        return url.scheme in ('http', 'https') and bool(url.netloc) and not url.username and not url.password and not url.query and not url.fragment and (host == 'localhost' or host.endswith('.localhost') or host == '::1' or is_local_ip(host))
    except ValueError:
        return False


class LlmError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise LlmError('provider-error', 'The local model redirected the request.')


class LlmService:
    def __init__(self, base='', model='', key='', timeout_ms=30000):
        self.base, self.model, self.key = base.rstrip('/'), model, key
        self.resolved_model = ''
        try:
            self.timeout = max(.1, min(60, int(timeout_ms) / 1000))
        except (TypeError, ValueError):
            self.timeout = 30
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)

    def configuration(self):
        return dict(configured=bool(self.base), allowed=bool(self.base) and private_url(self.base), model=self.model or self.resolved_model or None, autoSelect=not bool(self.model))

    def assert_configuration(self):
        if not self.base:
            raise LlmError('not-configured', 'Configure LLM_BASE_URL to enable the local model.')
        if not private_url(self.base):
            raise LlmError('blocked', 'LLM_BASE_URL must use localhost or a private IP without credentials, query strings, or fragments.')

    def call(self, route, body=None):
        self.assert_configuration()
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Content-Type': 'application/json'}
        if self.key:
            headers['Authorization'] = f'Bearer {self.key}'
        request = urllib.request.Request(self.base + route, data=data, headers=headers, method='POST' if data is not None else 'GET')
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise LlmError('authentication' if exc.code in (401, 403) else 'provider-error', f'The local model returned HTTP {exc.code}.')
        except (socket.timeout, TimeoutError):
            raise LlmError('timeout', 'The local model request timed out.')
        except (urllib.error.URLError, ConnectionError, OSError):
            raise LlmError('unreachable', 'The local model endpoint could not be reached.')
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise LlmError('invalid-response', 'The local model returned an unreadable response.')

    def models(self):
        data = self.call('/models')
        if not isinstance(data, dict) or not isinstance(data.get('data'), list):
            raise LlmError('invalid-response', 'The model list is not in OpenAI-compatible format.')
        return list(dict.fromkeys(x['id'] for x in data['data'] if isinstance(x, dict) and isinstance(x.get('id'), str) and x['id'].strip()))

    def select_model(self, models=None, requested=''):
        if requested:
            if requested not in (models if models is not None else self.models()):
                raise LlmError('model-unavailable', 'The selected model is not in the endpoint model list.')
            return requested
        if self.model or self.resolved_model:
            return self.model or self.resolved_model
        models = models if models is not None else self.models()
        if len(models) != 1:
            raise LlmError('model-required', 'Several models are available. Set LLM_MODEL explicitly.' if models else 'No model is available. Start a model and set LLM_MODEL.')
        self.resolved_model = models[0]
        return self.resolved_model

    def health(self):
        models = []
        try:
            models = self.models()
            selected = self.select_model(models)
            if selected not in models:
                raise LlmError('model-unavailable', 'The configured LLM_MODEL is not in the endpoint model list.')
            return {**self.configuration(), 'status': 'ready', 'model': selected, 'models': models}
        except LlmError as exc:
            return {**self.configuration(), 'status': exc.code, 'message': str(exc), 'models': models}

    def complete(self, messages, max_tokens=1600, model=''):
        selected = self.select_model(requested=model)
        data = self.call('/chat/completions', dict(model=selected, temperature=.1, max_tokens=max_tokens, response_format={'type': 'json_object'}, messages=messages))
        try:
            choice = data['choices'][0]
            raw = choice['message']['content']
            if choice.get('finish_reason') == 'length':
                raise LlmError('invalid-response', 'The local model response was truncated.')
            if not isinstance(raw, str) or not raw.strip():
                raise LlmError('invalid-response', 'The local model returned no JSON content.')
            raw = re.sub(r'^```(?:json)?\s*([\s\S]*?)\s*```$', r'\1', raw.strip(), flags=re.I)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise LlmError('invalid-response', 'The local model content must be a JSON object.')
            return dict(data=parsed, model=selected)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            raise LlmError('invalid-response', 'The local model content was not valid JSON.')
