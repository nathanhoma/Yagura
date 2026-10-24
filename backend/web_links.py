"""Small, same-origin link index from saved web evidence for the next AI step."""

from html.parser import HTMLParser
import re
import shlex
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

from .sensitive import redact


SENSITIVE_QUERY = re.compile(r'password|passwd|secret|token|auth|session|api[_-]?key', re.I)
INTERESTING = re.compile(r'password|credential|secret|token|paste|login', re.I)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.current = {'href': dict(attrs).get('href', ''), 'text': ''}

    def handle_data(self, data):
        if self.current is not None:
            self.current['text'] += data

    def handle_endtag(self, tag):
        if tag == 'a' and self.current is not None:
            self.links.append(self.current)
            self.current = None


def _command_url(command):
    try:
        return next((part for part in shlex.split(command)
                     if part.startswith(('http://', 'https://'))), '')
    except ValueError:
        return ''


def observed_links(evidence, host, limit=16):
    """Expose exact saved hrefs, never guessed or cross-origin destinations."""
    rows = []
    for item in reversed(evidence):
        source = _command_url(item.get('command', ''))
        if not source or '<a' not in str(item.get('output', '')).lower():
            continue
        base = urlsplit(source)
        if base.hostname not in (host['ip'], (host.get('name') or '').lower()):
            continue
        parser = _Links()
        parser.feed(str(item.get('output') or ''))
        for link in parser.links[:100]:
            href = str(link['href']).strip()
            if not href or href.startswith(('#', 'javascript:', 'data:')):
                continue
            try:
                target = urlsplit(urldefrag(urljoin(source, href)).url)
                if (target.scheme != base.scheme or target.netloc.lower() != base.netloc.lower() or
                        target.username or target.password or len(target.geturl()) > 250 or
                        any(SENSITIVE_QUERY.search(key) for key, _ in parse_qsl(target.query))):
                    continue
            except ValueError:
                continue
            label = redact(' '.join(link['text'].split()))[:90]
            rows.append({'url': target.geturl(), 'label': label,
                         'sourceEvidenceId': item['id']})
    unique = list({row['url']: row for row in reversed(rows)}.values())
    unique.reverse()
    unique.sort(key=lambda row: not INTERESTING.search(row['label'] + ' ' + row['url']))
    return unique[:limit]
