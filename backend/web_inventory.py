"""Bounded, IP-pinned inventory of a recorded web service."""
import argparse
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import sys
import uuid
from urllib.parse import urljoin, urlsplit, parse_qsl
from xml.etree import ElementTree

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.web_contacts import fetch_page, origin


class PageLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ''
        self.in_title = False
        self.links = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and len(self.forms) < 20:
            self.current_form = dict(action=attrs.get('action', '')[:512], method=attrs.get('method', 'get')[:20],
                                     enctype=attrs.get('enctype', '')[:100], fields=[])
            self.forms.append(self.current_form)
        if tag in ('input', 'textarea', 'select') and self.current_form is not None and len(self.current_form['fields']) < 50:
            self.current_form['fields'].append(dict(name=attrs.get('name', '')[:160], type=attrs.get('type', tag)[:40]))
        if tag == 'title':
            self.in_title = True
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def evidence_url(url):
    """Keep route context but never persist query values from auth redirects."""
    return urlsplit(url)._replace(query='', fragment='').geturl()[:512]


def discovery_hints(url, robots, sitemap):
    """Extract bounded same-origin route hints without requesting listed paths."""
    site = origin(url)
    hints = []

    def add(source, value, directive):
        if len(hints) >= 100 or not value or len(value) > 512:
            return
        target = urljoin(url, value.strip())
        try:
            if origin(target) != site:
                return
        except ValueError:
            return
        path = urlsplit(target).path or '/'
        if source == 'robots.txt' and ('*' in path or '$' in path):
            return
        item = dict(source=source, url=evidence_url(target), directive=directive)
        if item not in hints:
            hints.append(item)

    if robots:
        for line in robots.splitlines()[:1000]:
            line = line.split('#', 1)[0].strip()
            if ':' not in line:
                continue
            key, value = (part.strip() for part in line.split(':', 1))
            if key.lower() in ('allow', 'disallow'):
                add('robots.txt', value, key.lower())
    if sitemap and '<!DOCTYPE' not in sitemap.upper() and '<!ENTITY' not in sitemap.upper():
        try:
            root = ElementTree.fromstring(sitemap)
            for element in root.iter():
                if element.tag.rsplit('}', 1)[-1] == 'loc' and element.text:
                    add('sitemap.xml', element.text, 'listed')
        except ElementTree.ParseError:
            pass
    return hints


def inventory(url, ip, fetch=None):
    address = ipaddress.ip_address(ip)
    if address.version != 4 or not any(address in ipaddress.ip_network(net) for net in
                                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16')):
        raise ValueError('Use the recorded private/local IPv4 target.')
    origin(url)
    native_fetch = fetch is None
    if fetch is None:
        fetch = lambda address, pinned_ip, timeout: fetch_page(address, pinned_ip, timeout, accept_error=True)
    site = urlsplit(url)
    pending, seen, pages, routes, errors = [url], set(), [], set(), []
    forms, parameters, redirects = [], [], []
    while pending and len(seen) < 12 and len(pages) < 5:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            status, headers, body = fetch(current, ip, 5)
            location = headers.get('location', '')
            parser = PageLinks()
            if 'html' in headers.get('content-type', '').lower():
                parser.feed(body)
            page = dict(url=evidence_url(current), status=status, title=parser.title.strip()[:160],
                        server=headers.get('server', '')[:160], contentType=headers.get('content-type', '')[:160],
                        bytes=len(body.encode()), bodyHash=hashlib.sha256(body.encode()).hexdigest() if body else '')
            pages.append(page)
            if 300 <= status < 400 and location:
                dest = urlsplit(urljoin(current, location))
                same_site = (dest.scheme, dest.netloc) == (site.scheme, site.netloc)
                # Never retain token-bearing query values in redirect evidence.
                clean = dest._replace(query='', fragment='').geturl()
                redirects.append(dict(fromUrl=evidence_url(current), toUrl=clean[:512], status=status,
                                      queryNames=list(dict.fromkeys(name[:160] for name, _ in parse_qsl(dest.query, max_num_fields=100))),
                                      followed=same_site))
                if same_site:
                    pending.append(dest._replace(fragment='').geturl())
                continue
            for form in parser.forms:
                if len(forms) < 20:
                    action = urlsplit(urljoin(current, form['action']))
                    forms.append({**form, 'page': evidence_url(current), 'action': action._replace(query='', fragment='').geturl()[:512],
                                  'actionQueryNames': list(dict.fromkeys(name[:160] for name, _ in parse_qsl(action.query, max_num_fields=100))),
                                  'sameOrigin': (action.scheme, action.netloc) == (site.scheme, site.netloc)})
            for href in parser.links:
                dest = urlsplit(urljoin(current, href))
                if (dest.scheme, dest.netloc) != (site.scheme, site.netloc):
                    continue
                if dest.query and len(parameters) < 50:
                    parameters.append(dict(url=dest._replace(query='', fragment='').geturl()[:512], names=list(dict.fromkeys(name[:160] for name, _ in parse_qsl(dest.query, max_num_fields=100)))))
                route = dest._replace(query='', fragment='').geturl()
                if len(route) > 512:
                    continue
                routes.add(route)
                if len(pending) < 12 and route not in seen and any(word in dest.path.lower() for word in ('login', 'sign', 'auth', 'api', 'contact', 'about')):
                    pending.append(route)
        except Exception as exc:
            errors.append(f'{evidence_url(current)}: {str(exc)[:160]}')
    metadata, hints = [], []
    for path in ('/robots.txt', '/sitemap.xml'):
        target = f'{site.scheme}://{site.netloc}{path}'
        try:
            status, headers, body = fetch(target, ip, 5)
            metadata.append(dict(url=target, status=status, contentType=headers.get('content-type', '')[:160]))
            if status == 200:
                hints.extend(discovery_hints(url, body if path == '/robots.txt' else '',
                                             body if path == '/sitemap.xml' else ''))
        except Exception as exc:
            errors.append(f'{target}: {str(exc)[:160]}')
    hints = list(dict(((h['source'], h['url'], h['directive']), h) for h in hints).values())[:100]
    baseline = None
    if native_fetch:
        marker = 'yagura-missing-' + uuid.uuid4().hex
        probe = f'{site.scheme}://{site.netloc}/{marker}'
        try:
            status, headers, body = fetch(probe, ip, 5)
            parser = PageLinks()
            if 'html' in headers.get('content-type', '').lower():
                parser.feed(body)
            baseline = dict(status=status, title=parser.title.strip()[:160], bytes=len(body.encode()),
                            bodyHash=hashlib.sha256(body.encode()).hexdigest() if body else '')
            for page in pages:
                page['looksLikeNotFound'] = bool(page['status'] == baseline['status'] and
                    page['title'] == baseline['title'] and abs(page['bytes'] - baseline['bytes']) <= max(100, baseline['bytes'] // 10))
        except Exception as exc:
            errors.append(f'Not-found baseline: {str(exc)[:160]}')
    return dict(url=url, ip=ip, pages=pages, routes=sorted(routes)[:50], forms=forms, parameters=parameters,
                redirects=redirects, metadata=metadata, discoveryHints=hints,
                notFoundBaseline=baseline, errors=errors,
                coverage='Up to five same-origin pages, robots.txt, sitemap.xml, and one not-found baseline. Listed paths are recorded but not requested. Cross-origin redirects are not followed; forms are not submitted.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    print(json.dumps(inventory(args.url, args.ip)))
