"""Small local technology fingerprint using Yagura's IP-pinned web transport.

This is intentionally a curated signal set, not a general browser or crawler.
Only the root page is fetched; raw headers and HTML are never returned or saved.
"""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.web_contacts import fetch_page, origin


HEADER_PRODUCTS = {
    'server': ('nginx', 'Apache', 'Microsoft-IIS', 'Caddy', 'LiteSpeed', 'OpenResty'),
    'x-powered-by': ('PHP', 'ASP.NET', 'Express', 'Next.js'),
    'x-generator': ('WordPress', 'Drupal', 'Joomla', 'Ghost'),
}
GENERATOR_PRODUCTS = ('WordPress', 'Drupal', 'Joomla', 'Ghost', 'MediaWiki', 'Hugo', 'Docusaurus')
KNOWN_TECHNOLOGIES = frozenset({*GENERATOR_PRODUCTS, *(item for values in HEADER_PRODUCTS.values() for item in values),
                                'Next.js', 'Angular', 'Cloudflare', 'Vite'})
VERSION = r'([0-9][0-9A-Za-z._-]{0,30})'


class Signals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generator = ''
        self.paths = []
        self.next_data = False
        self.angular_version = ''

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == 'meta' and str(attrs.get('name') or '').lower() == 'generator':
            self.generator = str(attrs.get('content') or '')[:100]
        if tag in ('script', 'link') and len(self.paths) < 200:
            self.paths.append(str(attrs.get('src') or attrs.get('href') or '')[:300])
        if tag == 'script' and attrs.get('id') == '__NEXT_DATA__':
            self.next_data = True
        if attrs.get('ng-version'):
            self.angular_version = str(attrs['ng-version'])[:40]


def _version(text, product):
    match = re.search(r'(?<![\w-])' + re.escape(product) + r'(?:[/ ]' + VERSION + r')?', text, re.I)
    return match.group(1) if match and match.group(1) else ''


def fingerprint(url, ip, fetcher=fetch_page):
    scheme, name, port = origin(url)
    parsed = urlsplit(url)
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Technology fingerprint is limited to the root page.')
    status, headers, html = fetcher(url, ip, 5, accept_error=True)
    technologies = {}

    def add(product, version, source, confidence):
        if product not in KNOWN_TECHNOLOGIES:
            return
        version = version if re.fullmatch(VERSION, version or '') else ''
        previous = technologies.get(product)
        if not previous or (version and not previous['version']):
            technologies[product] = {'name': product, 'version': version, 'source': source, 'confidence': confidence}

    for key, products in HEADER_PRODUCTS.items():
        value = headers.get(key, '')[:200]
        for product in products:
            if re.search(r'(?<![\w-])' + re.escape(product) + r'(?![\w-])', value, re.I):
                add(product, _version(value, product), key + ' header', 'high')
    if headers.get('cf-ray'):
        add('Cloudflare', '', 'cf-ray header', 'high')
    if html:
        parser = Signals()
        parser.feed(html)
        for product in GENERATOR_PRODUCTS:
            if re.search(r'(?<![\w-])' + re.escape(product) + r'(?![\w-])', parser.generator, re.I):
                add(product, _version(parser.generator, product), 'generator meta tag', 'high')
        paths = '\n'.join(parser.paths)
        if '/wp-content/' in paths or '/wp-includes/' in paths:
            add('WordPress', '', 'page asset path', 'medium')
        if '/sites/default/' in paths:
            add('Drupal', '', 'page asset path', 'medium')
        if '/_next/static/' in paths or parser.next_data:
            add('Next.js', '', 'page asset marker', 'high')
        if '/@vite/client' in paths:
            add('Vite', '', 'page asset path', 'high')
        if parser.angular_version:
            add('Angular', parser.angular_version, 'ng-version attribute', 'high')
    return {'url': f'{scheme}://{name}:{port}/', 'ip': ip, 'status': status,
            'technologies': sorted(technologies.values(), key=lambda item: item['name']),
            'coverage': 'One root-page GET; no redirects, scripts, forms, or linked pages were followed.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(fingerprint(args.url, args.ip), ensure_ascii=False))
    except (OSError, ValueError, TimeoutError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
