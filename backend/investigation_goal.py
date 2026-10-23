"""Resolve an investigation instruction against saved, scoped host records."""

import hashlib
import json
import re

from .scope import host_allowed


ELIGIBLE_INVENTORY = frozenset(('verified', 'no-answer', 'inventory-only'))
MAX_CHOICES = 64
PORT_SCAN_INTENT = re.compile(r'ポート.{0,8}(?:スキャン|調査|確認)|\bport[ -]?scan\b|\b(?:scan|check|enumerate)\s+(?:the\s+)?ports?\b', re.I)
ALL_HOSTS_INTENT = re.compile(r'全(?:ての)?(?:対象)?ホスト|すべての(?:対象)?ホスト|全対象|\b(?:all|every)\s+(?:approved\s+|exercise\s+|in-scope\s+)?(?:hosts?|targets?)\b|\bentire\s+scope\b', re.I)


def all_host_port_scan(goal):
    return bool(PORT_SCAN_INTENT.search(goal) and ALL_HOSTS_INTENT.search(goal))


def port_scan_targets(scope, discovery, document):
    """Snapshot exact approved IP/name pairs for a whole-scope port scan."""
    rows = _candidates(scope, discovery, document)
    targets = [_record(ip, name, status, document, scope) for (ip, name), status in rows.items()]
    pairs = sorted((row for row in targets if row['approved']), key=lambda row: (row['ip'], row['name']))
    approved, seen_ips = [], set()
    for row in pairs:
        if row['ip'] not in seen_ips:
            approved.append(row)
            seen_ips.add(row['ip'])
    signature = [(row['hostId'], row['ip'], row['name']) for row in approved]
    token = hashlib.sha256(json.dumps(signature, separators=(',', ':')).encode()).hexdigest()
    return {'mode': 'port-scan-all', 'hosts': approved, 'hostCount': len(approved),
            'excludedUnapproved': len(targets) - len(approved), 'targetSet': token,
            'profile': 'TCP top 100 ports per host; no service or OS detection'}


def _record(ip, name, status, document, scope):
    host = next((h for h in document['findings'] if h.get('kind') == 'host' and
                 h.get('ip') == ip and h.get('name') == name and
                 h.get('approval', {}).get('ip') == ip and h['approval'].get('name') == name and
                 h['approval'].get('scope') == scope), None)
    return {'ip': ip, 'name': name, 'inventoryStatus': status,
            'approved': host is not None, 'hostId': host['id'] if host else None}


def _candidates(scope, discovery, document):
    rows = {}
    for row in discovery.get('inventory', []):
        if row.get('scope') == scope and row.get('status') in ELIGIBLE_INVENTORY and host_allowed(row, scope):
            rows[(row['ip'], row['name'])] = row['status']
    for host in document.get('findings', []):
        if host.get('kind') != 'host' or not host.get('approval') or not host_allowed(host, scope):
            continue
        name = host.get('name') or host['ip']
        if (host['approval'].get('ip') == host['ip'] and host['approval'].get('name') == name and
                host['approval'].get('scope') == scope):
            rows.setdefault((host['ip'], name), 'approved')
    return rows


def _mentioned(goal, token):
    return bool(re.search(r'(?<![a-zA-Z0-9_.-])' + re.escape(token) +
                          r'(?![a-zA-Z0-9_.-])', goal, re.I))


def _ranked_choices(goal, rows, document, scope, exact):
    if exact:
        pairs = sorted(exact, key=lambda pair: (not _record(pair[0], pair[1], rows[pair], document, scope)['approved'],
                                                 pair[1], pair[0]))
    else:
        words = {part for part in re.findall(r'[a-zA-Z0-9-]{3,}', goal.lower())
                 if part not in {'the', 'and', 'for', 'host', 'check', 'scan', 'test', 'dev', 'net'}}
        scored = []
        for ip, name in rows:
            labels = name.lower().split('.')
            score = sum(3 if word in labels else 1 if word in name.lower() or word in ip else 0
                        for word in words)
            scored.append((score, ip, name))
        scored.sort(key=lambda row: (-row[0], not _record(row[1], row[2], rows[(row[1], row[2])],
                                                        document, scope)['approved'], row[2], row[1]))
        pairs = [(ip, name) for _, ip, name in scored]
    return [_record(ip, name, rows[(ip, name)], document, scope) for ip, name in pairs[:MAX_CHOICES]], len(pairs)


def resolve_goal_target(goal, scope, discovery, document, selected_target=None):
    """Return one exact target or choices; never infer authorization from DNS text."""
    if not isinstance(goal, str) or not 5 <= len(goal.strip()) <= 500:
        raise ValueError('Describe an investigation goal in 5–500 characters.')
    rows = _candidates(scope, discovery, document)
    if not rows:
        raise ValueError('No eligible inventory or approved hosts exist in the saved scope.')
    exact = [(ip, name) for ip, name in rows if
             _mentioned(goal, ip) or (name != ip and _mentioned(goal, name))]
    if all_host_port_scan(goal):
        if selected_target is not None or exact:
            raise ValueError('Choose either all approved hosts or one named host for a port scan.')
        result = port_scan_targets(scope, discovery, document)
        if not result['hostCount']:
            raise ValueError('Approve hosts in the saved scope before scanning all hosts.')
        return result
    if selected_target is not None:
        if (not isinstance(selected_target, dict) or set(selected_target) != {'ip', 'name'} or
                not isinstance(selected_target['ip'], str) or not isinstance(selected_target['name'], str)):
            raise ValueError('Choose one exact saved IP/name pair.')
        pair = (selected_target['ip'], selected_target['name'])
        if pair not in rows or (exact and pair not in exact):
            raise ValueError('Selected target is not an eligible match for this instruction.')
        return _record(*pair, rows[pair], document, scope)
    if len(exact) == 1:
        ip, name = exact[0]
        return _record(ip, name, rows[(ip, name)], document, scope)
    choices, total = _ranked_choices(goal, rows, document, scope, exact)
    return {'needsSelection': True, 'reason': 'multiple-matches' if exact else 'no-exact-match',
            'candidates': choices, 'totalCandidates': total}
