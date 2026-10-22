"""Parse a supplied Providentia inventory into scoped, untrusted host seeds."""

from html.parser import HTMLParser
import ipaddress
import re

from .discovery import dns_review, parse_dns_answer, validate_resolvers
from .findings import now
from .scope import host_allowed, name_allowed, normalize_scope


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'hidden' in attrs.get('class', '').split():
            self.hidden += 1

    def handle_endtag(self, tag):
        if self.hidden and tag == 'span':
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _text(fragment):
    parser = _VisibleText()
    parser.feed(fragment)
    return ''.join(parser.parts)


def parse_inventory(content, team_number, suffix, scope):
    """Return exact IP/name pairs only; this does not authorize or scan them."""
    if not isinstance(content, str) or len(content) > 2_500_000:
        raise ValueError('Supply a Providentia HTML inventory of at most 2.5 MB.')
    if not isinstance(team_number, str) or not re.fullmatch(r'0[1-9]|[1-9][0-9]', team_number):
        raise ValueError('Supply a two-digit team number.')
    scope = normalize_scope(scope)
    suffix = str(suffix).strip().lower().rstrip('.')
    if not suffix or not scope['domains'] or not name_allowed(suffix, scope):
        raise ValueError('Choose a hostname suffix inside the saved domain scope.')
    blocks = re.findall(r'<host\b[^>]*>(.*?)</host>', content, flags=re.I | re.S)
    if not blocks:
        raise ValueError('No Providentia host rows were found in the HTML inventory.')
    selected, issues, seen, seen_ips = [], [], set(), set()
    for block in blocks:
        fqdn = re.search(r'<fqdn\b[^>]*>(.*?)</fqdn>', block, flags=re.I | re.S)
        connection = re.search(r'<connection-address\b[^>]*>(.*?)</connection-address>', block, flags=re.I | re.S)
        if not fqdn or not connection:
            continue
        name = re.sub(r'\s+', '', _text(fqdn.group(1)).lower())
        address = re.sub(r'\s+', '', _text(connection.group(1)).lower())
        name = re.sub(r'\[team_nr_str\]', team_number, name)
        address = re.sub(r'\[team_nr_str\]', team_number, address)
        address = re.sub(r'\[team_nr\]', str(int(team_number)), address)
        if not (name == suffix or name.endswith('.' + suffix)):
            continue
        if '[' in name or '[' in address:
            issues.append({'name': name, 'address': address[:80], 'reason': 'Unresolved template'})
            continue
        try:
            ip = str(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError:
            issues.append({'name': name, 'address': address[:80], 'reason': 'No concrete IPv4 address'})
            continue
        if not host_allowed({'ip': ip, 'name': name}, scope):
            issues.append({'name': name, 'address': ip, 'reason': 'Outside saved scope'})
            continue
        if name in seen:
            issues.append({'name': name, 'address': ip, 'reason': 'Duplicate hostname'})
            continue
        if ip in seen_ips:
            issues.append({'name': name, 'address': ip, 'reason': 'IP listed for another hostname'})
            continue
        seen.add(name)
        seen_ips.add(ip)
        selected.append({'name': name, 'ip': ip})
    if not selected:
        raise ValueError('No concrete hosts matched the chosen suffix and saved scope.')
    if len(selected) > 64:
        raise ValueError('Choose a narrower hostname suffix (maximum 64 hosts per import).')
    return {'hosts': selected, 'issues': issues[:100], 'totalRows': len(blocks)}


def verify_inventory_host(host, resolvers, scope, runner):
    """Require each resolver to map the inventory name to its exact listed IP."""
    validate_resolvers(resolvers, scope)
    queries = []
    answers = []
    for resolver in resolvers:
        result = runner('dig', ['@' + resolver, '+time=2', '+tries=1', '+noall', '+answer',
                                '+ttlid', host['name'], 'A'], 5)
        records = parse_dns_answer(result.get('stdout', ''), 'A') if result.get('ok') else []
        addresses = sorted({r['value'] for r in records if r['name'] == host['name']})
        answers.append(addresses)
        queries.append({'resolver': resolver, 'queriedAt': now(), 'qtype': 'A',
                        'question': host['name'], 'records': records,
                        'error': str(result.get('stderr', ''))[:200] if not result.get('ok') else ''})
    if all(not row for row in answers):
        return {'status': 'no-answer', 'queries': queries, 'addresses': [], 'dns': None}
    if any(row != [host['ip']] for row in answers):
        return {'status': 'dns-mismatch', 'queries': queries,
                'addresses': sorted({ip for row in answers for ip in row}), 'dns': None}
    review = dns_review(host['ip'], resolvers, scope, runner, host['name'])
    status = 'verified' if host['name'] in review['candidates'] and not review['conflicting'] else 'dns-review-needed'
    return {'status': status, 'queries': queries, 'addresses': [host['ip']], 'dns': review}
