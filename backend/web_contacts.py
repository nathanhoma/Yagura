"""Bounded public-page contact discovery; no forms, scripts, or external links."""
import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from html.parser import HTMLParser
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

MAX_PAGES = 5
MAX_BYTES = 256 * 1024
MAX_CONTACTS = 25
EMAIL = re.compile(r"(?<![\w.+%-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+(?![\w-])", re.I)
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', re.I)


def website_url(host, service):
    name = str(host.get('name') or '').rstrip('.')
    name = name.lower() if DNS_NAME.fullmatch(name) else host['ip']
    scheme = 'https' if service.get('tunnel') == 'ssl' or 'https' in service.get('name', '').lower() or service['port'] in (443, 8443) else 'http'
    return f"{scheme}://{name}:{service['port']}/"


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('Only HTTP(S) URLs without credentials are accepted.')
    if any(ord(c) < 33 or ord(c) > 126 for c in url) or len(url) > 512:
        raise ValueError('Invalid page URL.')
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.mailto, self.links = [], [], []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'template'):
            self.ignored += 1
        if tag != 'a' or self.ignored:
            return
        href = dict(attrs).get('href') or ''
        if href.lower().startswith('mailto:'):
            self.mailto.append(unquote(href[7:].split('?', 1)[0]))
        else:
            self.links.append(href)

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'template'):
            self.ignored = max(0, self.ignored - 1)
        elif tag not in ('a', 'span', 'b', 'i', 'em', 'strong'):
            self.text.append(' ')

    def handle_data(self, data):
        if not self.ignored:
            self.text.append(data)

    def addresses(self):
        return list(dict.fromkeys(a for value in [''.join(self.text), *self.mailto] for a in EMAIL.findall(value) if len(a) <= 254))


def fetch_page(url, ip, timeout):
    """Connect to the scoped IP while retaining the site's Host header and TLS SNI."""
    scheme, hostname, port = origin(url)
    connection = http.client.HTTPConnection(hostname, port, timeout=timeout)
    response = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        connection.sock = sock
        if scheme == 'https':
            connection.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=hostname)
            sock = connection.sock
        parsed = urlsplit(url)
        request_path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
        connection.request('GET', request_path, headers={'User-Agent': 'Yagura-Exercise-Contact-Check/1.0', 'Accept': 'text/html,text/plain', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        status, headers = response.status, dict(response.getheaders())
        headers = {key.lower(): value for key, value in headers.items()}
        if status in (301, 302, 303, 307, 308):
            return status, headers, ''
        if status != 200:
            raise ValueError(f'HTTP {status}')
        mime = headers.get('content-type', '').split(';')[0].strip().lower()
        if mime not in ('text/html', 'application/xhtml+xml', 'text/plain'):
            raise ValueError('Page is not HTML or plain text.')
        if headers.get('content-encoding', 'identity').lower() != 'identity':
            raise ValueError('Compressed responses are not supported.')
        # read1 avoids waiting for the full body indefinitely when a peer trickles bytes.
        deadline, chunks, length = time.monotonic() + timeout, [], 0
        while length <= MAX_BYTES and not response.isclosed():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Page read deadline exceeded.')
            # HTTPResponse can own the socket after a Connection: close response.
            sock.settimeout(remaining)
            chunk = response.read1(min(16384, MAX_BYTES + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        if length > MAX_BYTES:
            raise ValueError('Page exceeds the 256 KB limit.')
        charset = response.headers.get_content_charset() or 'utf-8'
        try:
            text = b''.join(chunks).decode(charset, errors='replace')
        except LookupError:
            text = b''.join(chunks).decode('utf-8', errors='replace')
        return status, headers, text
    finally:
        if response is not None:
            response.close()
        connection.close()


def discover(url, ip, fetcher=fetch_page):
    address = ipaddress.ip_address(ip)
    local_ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16')
    if address.version != 4 or not any(address in ipaddress.ip_network(net) for net in local_ranges):
        raise ValueError('Use the recorded private/local IPv4 target.')
    site = origin(url)
    queue, seen, visited, errors, contacts = [url], set(), [], [], {}
    deadline = time.monotonic() + 30
    while queue and len(seen) < MAX_PAGES and len(contacts) < MAX_CONTACTS:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            errors.append(dict(url=current, error='Overall time limit reached.'))
            break
        try:
            status, headers, text = fetcher(current, str(address), min(5, remaining))
            if status in (301, 302, 303, 307, 308):
                target = urldefrag(urljoin(current, headers.get('location', '')))[0]
                if origin(target) != site or target in seen:
                    raise ValueError('Redirect leaves the site or repeats an already visited URL.')
                queue.insert(0, target)
                continue
            parser = PageParser()
            if headers.get('content-type', '').startswith('text/plain'):
                parser.text.append(text)
            else:
                parser.feed(text)
            visited.append(current)
            for email in parser.addresses():
                key = email.casefold()
                if key not in contacts:
                    if len(contacts) >= MAX_CONTACTS:
                        break
                    contacts[key] = dict(address=email, sources=[])
                if current not in contacts[key]['sources']:
                    contacts[key]['sources'].append(current)
            # Breadth-first crawl, contact/about links first, within the same origin.
            for href in sorted(parser.links, key=lambda h: not re.search(r'contact|about', h, re.I)):
                try:
                    target = urldefrag(urljoin(current, href))[0]
                    parts = urlsplit(target)
                    if origin(target) == site and not parts.query and not re.search(r'\.(?:pdf|jpg|jpeg|png|gif|zip|css|js|svg|ico)$', parts.path, re.I) and target not in seen and target not in queue and len(queue) < 30:
                        queue.append(target)
                except ValueError:
                    continue
        except (OSError, ValueError, http.client.HTTPException) as exc:
            errors.append(dict(url=current, error=str(exc)[:200]))
    count = len(contacts)
    return dict(url=url, connectedIp=str(address), contacts=list(contacts.values()), count=count,
                status='exactly_one' if count == 1 else 'multiple' if count else 'none', pages=visited, errors=errors,
                coverage='At most 5 same-origin pages, 256 KB each, 25 distinct addresses. No JavaScript execution. Counts apply only to inspected pages; whole-site uniqueness is not established.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    try:
        result = discover(args.url, args.ip)
        print(json.dumps(result, ensure_ascii=True))
        return 0 if result['pages'] else 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
