"""Resolve an explicit investigation target from saved, scoped host records."""

import re

from .scope import host_allowed


ELIGIBLE_INVENTORY = frozenset(('verified', 'no-answer', 'inventory-only'))


def resolve_goal_target(goal, scope, discovery, document):
    if not isinstance(goal, str) or not 5 <= len(goal.strip()) <= 500:
        raise ValueError('Describe an investigation goal in 5–500 characters.')
    candidates = {}
    for row in discovery.get('inventory', []):
        if row.get('scope') != scope or row.get('status') not in ELIGIBLE_INVENTORY:
            continue
        if host_allowed(row, scope):
            candidates[(row['ip'], row['name'])] = row['status']
    for host in document.get('findings', []):
        if host.get('kind') != 'host' or not host.get('approval') or not host_allowed(host, scope):
            continue
        name = host.get('name') or host['ip']
        candidates.setdefault((host['ip'], name), 'approved')
    matches = []
    for (ip, name), status in candidates.items():
        tokens = (ip, name) if name != ip else (ip,)
        if any(re.search(r'(?<![a-zA-Z0-9_.-])' + re.escape(token) + r'(?![a-zA-Z0-9_.-])', goal, re.I)
               for token in tokens):
            matches.append((ip, name, status))
    if len(matches) != 1:
        raise ValueError('Name or IP exactly one saved inventory host in the instruction.' if not matches else
                         'Instruction names multiple hosts; investigate one exact host at a time.')
    ip, name, status = matches[0]
    host = next((h for h in document['findings'] if h.get('kind') == 'host' and
                 h.get('ip') == ip and h.get('name') == name and
                 h.get('approval', {}).get('ip') == ip and h['approval'].get('scope') == scope), None)
    return {'ip': ip, 'name': name, 'inventoryStatus': status,
            'approved': host is not None, 'hostId': host['id'] if host else None}
