"""Find credential-shaped leads in saved evidence without exposing their values."""

import re
import hashlib

from .analysis import scoped_document
from .sensitive import redact


EMAIL_PAIR = re.compile(
    r'(?<![\w@])([A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,}))\s*:\s*([^\s<>"\']{4,})',
    re.I,
)
MAX_LEADS = 20


def credential_leads(document, scope, host_ids=None, limit=MAX_LEADS):
    """Return evidence-linked candidates from approved source hosts only.

    Detection establishes a credential-shaped string, never that the secret is
    valid or that an account can access a related host. No secret is returned.
    """
    selected = scoped_document(document, None, scope)
    hosts = {row['id']: row for row in selected['findings'] if row['kind'] == 'host'}
    allowed_sources = set(host_ids) if host_ids is not None else set(hosts)
    finding_by_evidence = {}
    for finding in selected['findings']:
        source_id = finding['id'] if finding['kind'] == 'host' else finding.get('hostId')
        if source_id not in allowed_sources:
            continue
        for evidence_id in finding.get('evidenceIds', []):
            # Prefer an observation over the host record as the citation.
            if finding['kind'] != 'host' or evidence_id not in finding_by_evidence:
                finding_by_evidence[evidence_id] = (finding['id'], source_id)
    leads, seen = [], set()
    for evidence in selected['evidence']:
        if evidence.get('sensitive'):
            continue
        linked = finding_by_evidence.get(evidence['id'])
        if not linked:
            continue
        finding_id, source_id = linked
        for match in EMAIL_PAIR.finditer(str(evidence.get('output') or '')):
            principal, domain, secret = match.groups()
            if secret.startswith(('/', ':')) or secret.lower() in ('[redacted]', 'redacted', 'unknown'):
                continue
            key = (source_id, evidence['id'], principal.lower())
            if key in seen:
                continue
            seen.add(key)
            lead_id = 'cred-' + hashlib.sha256(
                (evidence['id'] + '\0' + principal.lower()).encode()).hexdigest()[:24]
            related = [dict(hostId=host['id'], name=host.get('name') or host['ip'])
                       for host in hosts.values() if host['id'] != source_id and
                       (host.get('name') or '').lower().endswith('.' + domain.lower())]
            leads.append(dict(id=lead_id, sourceHostId=source_id,
                              sourceHostName=hosts[source_id].get('name') or hosts[source_id]['ip'],
                              sourceFindingId=finding_id,
                              evidenceId=evidence['id'], principal=principal,
                              accountDomain=domain.lower(), relatedApprovedHosts=related[:8],
                              sourceCommand=redact(str(evidence.get('command') or ''))[:300],
                              observedAt=evidence.get('observedAt'),
                              status='unverified-candidate'))
            if len(leads) >= limit:
                return leads
    return leads


def reveal_credential(document, scope, lead_id):
    """Resolve one currently scoped lead to its exact saved value on demand."""
    if not isinstance(lead_id, str) or not re.fullmatch(r'cred-[0-9a-f]{24}', lead_id):
        raise ValueError('Choose a saved credential candidate.')
    allowed = {row['id']: row for row in credential_leads(document, scope, limit=500)}
    lead = allowed.get(lead_id)
    if not lead:
        raise ValueError('Credential candidate is no longer available in the approved scope.')
    evidence = next(row for row in document['evidence'] if row['id'] == lead['evidenceId'])
    for match in EMAIL_PAIR.finditer(str(evidence.get('output') or '')):
        if match.group(1).lower() == lead['principal'].lower():
            return {'id': lead_id, 'value': match.group(3), 'principal': lead['principal']}
    raise ValueError('Credential candidate changed; refresh the list.')
