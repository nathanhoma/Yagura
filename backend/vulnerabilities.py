"""Offline, evidence-linked version triage against a small vendor-advisory snapshot."""
from functools import lru_cache
import json
from pathlib import Path
import re

from .scope import approved_host, normalize_scope


CATALOG_PATH = Path(__file__).with_name('vulnerability_catalog.json')
VERSION = re.compile(r'^\s*(\d+\.\d+\.\d+)(?![\d.])')
BANNER = re.compile(r'(?i)(?<![\w.-])(nginx|apache)/(\d+\.\d+\.\d+)(?![\d.])')
SOURCE_TOOLS = frozenset(('nmap', 'web-inventory', 'http-headers', 'httpx'))


def version_tuple(value):
    match = VERSION.match(str(value))
    if not match:
        return None
    pieces = tuple(int(piece) for piece in match.group(1).split('.'))
    return pieces + (0,) * (3 - len(pieces))


@lru_cache(maxsize=1)
def catalog():
    data = json.loads(CATALOG_PATH.read_text())
    if data.get('schemaVersion') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('Unsupported vulnerability catalog.')
    seen = set()
    for item in data['entries']:
        if (item.get('id') in seen or not re.fullmatch(r'CVE-\d{4}-\d{4,}', item.get('id', '')) or
                item.get('product') not in ('nginx', 'apache-http-server') or
                not item.get('affected') or not all(isinstance(pair, list) and len(pair) == 2 and
                version_tuple(pair[0]) is not None and version_tuple(pair[1]) is not None and
                version_tuple(pair[0]) <= version_tuple(pair[1]) for pair in item['affected'])):
            raise ValueError('Invalid vulnerability catalog entry.')
        seen.add(item['id'])
    return data


def service_product(value):
    name = str(value or '').strip().lower()
    if name == 'nginx' or re.match(r'^nginx\s+\d+\.\d+\.\d+(?:\s|$)', name):
        return 'nginx'
    if name in ('apache httpd', 'apache http server') or re.match(r'^apache (?:httpd|http server)\s+\d+\.\d+\.\d+(?:\s|$)', name):
        return 'apache-http-server'
    return None


def banner_signals(value):
    return [('nginx' if match[1].lower() == 'nginx' else 'apache-http-server', match[2])
            for match in BANNER.finditer(str(value or ''))]


def match_versions(doc, scope):
    """Return possible matches; a banner and version do not prove applicability."""
    data = catalog()
    scope = normalize_scope(scope)
    if not scope['cidrs']:
        return {'catalog': {k: data[k] for k in ('asOf', 'coverage')}, 'entryCount': len(data['entries']),
                'observedCount': 0, 'matches': []}
    rows = doc.get('findings', [])
    hosts = {f['id']: f for f in rows if f.get('kind') == 'host' and approved_host(f, scope)}
    services = {f['id']: f for f in rows if f.get('kind') == 'service' and f.get('state') == 'open' and f.get('hostId') in hosts}
    evidence = {e['id']: e for e in doc.get('evidence', []) if e.get('tool') in SOURCE_TOOLS}
    signals = {}

    def record(service, product, version, finding, rank):
        if version_tuple(version) is None:
            return
        source_ids = [eid for eid in finding.get('evidenceIds', []) if eid in evidence]
        if not source_ids:
            return
        key = (service['id'], product)
        signals.setdefault(key, []).append({'version': VERSION.match(str(version)).group(1),
            'findingId': finding['id'], 'evidenceIds': source_ids, 'lastSeen': finding.get('lastSeen') or '', 'rank': rank})

    for service in services.values():
        product = service_product(service.get('product'))
        if product:
            version = service.get('version') or re.sub(r'^\S+(?:\s+httpd|\s+HTTP Server)?\s+', '', service.get('product', ''))
            record(service, product, version, service, 2)
        for product, version in banner_signals(service.get('product')):
            record(service, product, version, service, 2)

    for finding in rows:
        if finding.get('kind') != 'observation':
            continue
        service = services.get(finding.get('serviceId'))
        if not service:
            continue
        title, detail = finding.get('title'), str(finding.get('detail') or '')
        if title == 'HTTP response headers':
            values = [line.split(':', 1)[1].strip() for line in detail.splitlines() if line.lower().startswith('server:')]
        elif title == 'Web inventory':
            values = [line.rsplit(' · ', 1)[-1] for line in detail.splitlines() if ' · ' in line]
        elif title == 'Web technologies':
            values = [detail]
        else:
            continue
        for value in values:
            for product, version in banner_signals(value):
                record(service, product, version, finding, 1)

    matches = []
    for (service_id, product), observed in signals.items():
        latest = max(observed, key=lambda item: (item['lastSeen'], item['rank']))
        version = latest['version']
        corroborating = [item for item in observed if item['version'] == version]
        finding_ids = list(dict.fromkeys(item['findingId'] for item in corroborating))
        evidence_ids = list(dict.fromkeys(eid for item in corroborating for eid in item['evidenceIds']))
        service = services[service_id]
        for entry in data['entries']:
            if entry['product'] != product or not any(version_tuple(start) <= version_tuple(version) <= version_tuple(end)
                                                    for start, end in entry['affected']):
                continue
            matches.append({'id': f'{service_id}:{entry["id"]}', 'cveId': entry['id'], 'title': entry['title'],
                'product': product, 'observedVersion': version, 'hostId': service['hostId'], 'serviceId': service_id,
                'findingIds': finding_ids, 'evidenceIds': evidence_ids, 'condition': entry['condition'],
                'source': entry['source'], 'lastSeen': latest['lastSeen'], 'status': 'possible'})
    matches.sort(key=lambda item: (hosts[item['hostId']]['ip'], services[item['serviceId']]['port'], item['cveId']))
    return {'catalog': {k: data[k] for k in ('asOf', 'coverage')}, 'entryCount': len(data['entries']),
            'observedCount': len(signals), 'matches': matches[:500]}
