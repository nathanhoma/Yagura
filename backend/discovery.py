"""Quarantined CIDR discovery and resolver-attributed DNS review."""
import ipaddress
import json
import re

from .findings import now
from .scope import ip_allowed, name_allowed, normalize_scope, valid_cidr


def contained_range(cidr, scope):
    if not valid_cidr(cidr):
        return False
    requested = ipaddress.ip_network(cidr.strip(), strict=False)
    return any(requested.subnet_of(ipaddress.ip_network(item)) for item in normalize_scope(scope)['cidrs'])


def resolver_allowed(ip, scope):
    """DNS queries never use system fallback or a public resolver."""
    return ip_allowed(ip, scope)


def parse_dns_answer(output, expected_type):
    records = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[2].upper() != 'IN' or parts[3].upper() != expected_type:
            continue
        try:
            ttl = int(parts[1])
        except ValueError:
            continue
        value = parts[4].rstrip('.').lower()
        if expected_type == 'A':
            try:
                if ipaddress.ip_address(value).version != 4:
                    continue
            except ValueError:
                continue
        elif not re.fullmatch(r'[a-z0-9.-]{1,253}', value):
            continue
        records.append(dict(name=parts[0].rstrip('.').lower(), type=expected_type,
                            value=value, ttl=ttl))
    return records[:20]


def dns_review(ip, resolvers, scope, runner):
    if not ip_allowed(ip, scope):
        raise ValueError('DNS target must be inside the saved CIDRs.')
    if not isinstance(resolvers, list) or not 1 <= len(resolvers) <= 4 or len(resolvers) != len(set(resolvers)):
        raise ValueError('Choose one to four distinct internal resolver IPs.')
    if not all(resolver_allowed(item, scope) for item in resolvers):
        raise ValueError('Each resolver must be an IP inside the saved CIDRs; public DNS is not allowed.')
    queries, names = [], set()
    for resolver in resolvers:
        args = ['@' + resolver, '+time=2', '+tries=1', '+noall', '+answer', '+ttlid', '-x', ip]
        result = runner('dig', args, 5)
        records = parse_dns_answer(result.get('stdout', ''), 'PTR') if result.get('ok') else []
        queries.append(dict(resolver=resolver, queriedAt=now(), qtype='PTR', question=ip,
                            records=records, error=str(result.get('stderr', ''))[:200] if not result.get('ok') else ''))
        names.update(r['value'] for r in records if name_allowed(r['value'], scope))
    for name in sorted(names)[:8]:
        for resolver in resolvers:
            args = ['@' + resolver, '+time=2', '+tries=1', '+noall', '+answer', '+ttlid', name, 'A']
            result = runner('dig', args, 5)
            queries.append(dict(resolver=resolver, queriedAt=now(), qtype='A', question=name,
                                records=(parse_dns_answer(result.get('stdout', ''), 'CNAME') +
                                         parse_dns_answer(result.get('stdout', ''), 'A')) if result.get('ok') else [],
                                error=str(result.get('stderr', ''))[:200] if not result.get('ok') else ''))
    candidates = sorted(name for name in names if any(q['qtype'] == 'A' and q['question'] == name and
                        any(record['type'] == 'A' and record['value'] == ip for record in q['records']) for q in queries))
    signatures = {(q['resolver'], q['qtype'], q['question']): tuple(sorted(r['value'] for r in q['records'])) for q in queries}
    conflicting = any(len({values for (resolver, kind, question), values in signatures.items()
                        if kind == qtype and question == queried}) > 1
                      for qtype, queried in {(kind, question) for _, kind, question in signatures})
    return dict(queries=queries, candidates=candidates, conflicting=conflicting,
                reviewedAt=now(), scope=normalize_scope(scope))


def approval_name(record, name, scope, reason=''):
    name = str(name).strip().lower().rstrip('.')
    if record.get('scope') != normalize_scope(scope) or not name_allowed(name, scope):
        raise ValueError('Discovery scope or host name is no longer authorized.')
    review = record.get('dns') or {}
    if name not in review.get('candidates', []):
        raise ValueError('Approve only a PTR name whose A answer included this IP.')
    if review.get('conflicting') and len(str(reason).strip()) < 8:
        raise ValueError('Conflicting resolver answers require a review reason.')
    return name
