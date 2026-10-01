"""Bounded, IP-pinned inventory of a recorded web service."""
import argparse
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit, parse_qsl

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


def inventory(url, ip, fetch=fetch_page):
    address = ipaddress.ip_address(ip)
    if address.version != 4 or not any(address in ipaddress.ip_network(net) for net in
                                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16')):
        raise ValueError('Use the recorded private/local IPv4 target.')
    origin(url)
    site = urlsplit(url)
    pending, seen, pages, routes, errors = [url], set(), [], set(), []
    forms, parameters = [], []
    while pending and len(seen) < 12 and len(pages) < 5:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            status, headers, body = fetch(current, ip, 5)
            location = headers.get('location', '')
            if 300 <= status < 400 and location:
                dest = urlsplit(urljoin(current, location))
                if (dest.scheme, dest.netloc) == (site.scheme, site.netloc):
                    pending.append(dest._replace(fragment='').geturl())
                else:
                    errors.append(f'External redirect skipped: {current}')
                continue
            parser = PageLinks()
            if 'html' in headers.get('content-type', '').lower():
                parser.feed(body)
            pages.append(dict(url=current, status=status, title=parser.title.strip()[:160],
                              server=headers.get('server', '')[:160], contentType=headers.get('content-type', '')[:160]))
            for form in parser.forms:
                if len(forms) < 20:
                    forms.append({**form, 'page': current, 'action': urljoin(current, form['action'])})
            for href in parser.links:
                dest = urlsplit(urljoin(current, href))
                if (dest.scheme, dest.netloc) != (site.scheme, site.netloc):
                    continue
                if dest.query and len(parameters) < 50:
                    parameters.append(dict(url=dest._replace(fragment='').geturl()[:512], names=list(dict.fromkeys(name[:160] for name, _ in parse_qsl(dest.query, max_num_fields=100)))))
                route = dest._replace(query='', fragment='').geturl()
                if len(route) > 512:
                    continue
                routes.add(route)
                if len(pending) < 12 and route not in seen and any(word in dest.path.lower() for word in ('login', 'sign', 'auth', 'api', 'contact', 'about')):
                    pending.append(route)
        except Exception as exc:
            errors.append(f'{current}: {str(exc)[:160]}')
    return dict(url=url, ip=ip, pages=pages, routes=sorted(routes)[:50], forms=forms, parameters=parameters, errors=errors,
                coverage='Up to five same-origin pages; linked routes are discovered, not all fetched.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    print(json.dumps(inventory(args.url, args.ip)))
