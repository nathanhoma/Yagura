"""Evidence-linked review flags derived from the current scoped inventory.

Flags are leads, not vulnerability or access assertions. Rebuilding them from the
saved findings makes additions, corrections, and deletions immediately visible.
"""
import re

from .scope import approved_host, normalize_scope


def review_flags(doc, scope, host_id=None):
    scope = normalize_scope(scope)
    if not scope['cidrs']:
        return []
    findings = doc.get('findings', [])
    evidence = {e['id'] for e in doc.get('evidence', [])}
    hosts = {f['id']: f for f in findings if f.get('kind') == 'host' and
             (host_id is None or f['id'] == host_id) and approved_host(f, scope)}
    services = [f for f in findings if f.get('kind') == 'service' and f.get('hostId') in hosts and f.get('state') == 'open']
    observations = [f for f in findings if f.get('kind') == 'observation' and f.get('hostId') in hosts]
    flags = []

    def add(kind, finding, title, reason, extra_ids=()):
        ids = list(dict.fromkeys([finding['id'], *extra_ids]))
        sources = list(dict.fromkeys(eid for f in findings if f.get('id') in ids
                                     for eid in f.get('evidenceIds', []) if eid in evidence))
        if not sources:
            return
        flags.append({'id': f'{kind}:{finding["id"]}', 'kind': kind, 'hostId': finding.get('hostId', finding['id']),
                      'serviceId': finding.get('serviceId') or (finding['id'] if finding.get('kind') == 'service' else None),
                      'title': title[:160], 'reason': reason[:500], 'findingIds': ids, 'evidenceIds': sources,
                      'lastSeen': finding.get('lastSeen')})

    for item in services:
        product, version = str(item.get('product') or '').strip(), str(item.get('version') or '').strip()
        if version:
            label = ' '.join(part for part in (product, version) if part)
            add('software', item, f'Software identified: {label}',
                f'{item["port"]}/{item["protocol"]} reports {label}. Confirm the version and assess relevance; identification alone does not establish a vulnerability.')

    latest_os = {}
    for item in observations:
        if item.get('title') == 'Nmap OS guess' and item.get('detail') and 'No exact OS matches' not in item['detail']:
            previous = latest_os.get(item['hostId'])
            if not previous or str(item.get('lastSeen') or '') >= str(previous.get('lastSeen') or ''):
                latest_os[item['hostId']] = item

    for item in observations:
        title, detail = str(item.get('title') or ''), str(item.get('detail') or '')
        lowered = detail.lower()
        if title == 'Nmap OS guess' and latest_os.get(item.get('hostId')) is item:
            add('os', item, 'OS fingerprint to review',
                f'Nmap reported {detail[:230]}. This is a fingerprint estimate; confirm it before relying on the platform or version.')
        elif title == 'Curated Nuclei exposure check' and detail.startswith('Exposed Git HEAD'):
            add('exposure', item, 'Git metadata exposure indicated',
                'The curated check matched Git HEAD metadata. Inspect the linked response to confirm exposure and impact.')
        elif title.startswith('Nuclei:'):
            add('template-match', item, title,
                f'A template reported a match: {detail[:260]}. Validate the response and applicability before drawing a conclusion.')
        elif title == 'Web metadata response: /.git/HEAD' and re.search(r'\bHTTP 200\b', detail):
            add('exposure', item, 'Git metadata response to review',
                'The metadata path returned HTTP 200. Review the linked content; a status code alone does not prove repository exposure.')
        elif title in ('SMB share listing', 'NetExec anonymous SMB shares') and re.search(r'\b(?:READ|WRITE|Disk)\b', detail, re.I):
            add('anonymous-share', item, 'Anonymous SMB share response',
                'A no-credential share listing contains share entries. Review access and permissions in the linked output.')
        elif title == 'Web form metadata' and ('password' in lowered or 'login' in lowered):
            add('auth-surface', item, 'Authentication form found',
                'Web form metadata mentions login or password fields. Identify the service and authentication flow before further testing.')
        elif title == 'Web technologies' and re.search(r'\b[a-z][a-z0-9_.-]*[/ ]\d+\.\d+(?:\.\d+)?\b', detail, re.I):
            add('web-software', item, 'Web software details to review',
                'The web response contains software or version details. Verify the product and version in the linked evidence.')
        elif title == 'Web inventory' and any(re.search(r'\b[a-z][a-z0-9_.-]*/\d+\.\d+(?:\.\d+)?\b', line.rsplit(' · ', 1)[-1], re.I)
                                                   for line in detail.splitlines() if ' · ' in line):
            add('web-software', item, 'Web server version to review',
                'A web response reported a server version. Verify the header and product in the linked evidence.')

    return sorted(flags, key=lambda f: (f['hostId'], f['kind'], f['id']))[:500]
