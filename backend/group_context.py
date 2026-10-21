"""Bounded, read-only context for cross-host AI comparisons.

The model can request more saved evidence, but this module never executes a check.
All documents passed here must already be scoped and sanitized by the caller.
"""
from datetime import datetime, timezone


MAX_READ_ROUNDS = 3
MAX_READ_REQUESTS = 3
RECENT_CHECK_SECONDS = 24 * 60 * 60
FINDING_FIELDS = ('id', 'kind', 'hostId', 'serviceId', 'ip', 'name', 'state',
                  'port', 'protocol', 'product', 'version', 'tunnel')


def _recent(value, seconds=RECENT_CHECK_SECONDS):
    try:
        when = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - when).total_seconds()
        return 0 <= age <= seconds
    except (AttributeError, TypeError, ValueError):
        return False


def fresh_candidates(doc, candidates):
    """Avoid rerunning an identical, recently recorded command across runs."""
    commands = {e.get('command') for e in doc['evidence']
                if e.get('command') and e.get('output') and _recent(e.get('observedAt'))}
    return [c for c in candidates if c['command'] not in commands]


def _host_id(finding):
    return finding['id'] if finding['kind'] == 'host' else finding.get('hostId')


def _finding(finding, evidence_ids=None):
    row = {key: finding[key] for key in FINDING_FIELDS if key in finding}
    if finding['kind'] == 'observation':
        row['title'] = str(finding.get('title') or '')[:120]
        row['detail'] = str(finding.get('detail') or '')[:180]
    row['evidenceIds'] = list(evidence_ids if evidence_ids is not None else finding['evidenceIds'][:3])
    return row


def _evidence(evidence, limit=280, offset=0):
    output = evidence.get('output', '')
    return {'id': evidence['id'], 'tool': evidence.get('tool', ''),
            'command': evidence.get('command', '')[:120],
            'output': output[offset:offset + limit], 'outputLength': len(output),
            'offset': offset, 'excerptTruncated': offset + limit < len(output),
            'observedAt': evidence.get('observedAt', '')}


def _candidate(candidate, finding_ids, evidence_ids):
    return {key: candidate[key] for key in ('id', 'hostId', 'catalogId', 'title', 'reason')} | {
        'findingIds': [fid for fid in candidate['findingIds'] if fid in finding_ids],
        'evidenceIds': [eid for eid in candidate['evidenceIds'] if eid in evidence_ids]}


def seed_context(doc, host_ids, candidates):
    """Give every selected host a small, citation-closed starting view."""
    findings = {f['id']: f for f in doc['findings']}
    evidence = {e['id']: e for e in doc['evidence']}
    result = {'hosts': [], 'findings': [], 'evidence': [], 'candidates': [],
              'limits': {'readRounds': MAX_READ_ROUNDS, 'requestsPerRound': MAX_READ_REQUESTS}}
    used_evidence = set()
    for host_id in host_ids:
        host = findings[host_id]
        related = [f for f in doc['findings'] if f.get('hostId') == host_id]
        services = sorted((f for f in related if f['kind'] == 'service'),
                          key=lambda f: (f.get('state') != 'open', f.get('port', 65536)))
        observations = sorted((f for f in related if f['kind'] == 'observation'),
                              key=lambda f: f.get('lastSeen', ''), reverse=True)
        result['hosts'].append({'id': host_id, 'ip': host['ip'], 'name': host.get('name'),
                                'state': host.get('state'), 'serviceCount': len(services),
                                'observationCount': len(observations),
                                'evidenceCount': len({eid for f in [host] + related for eid in f['evidenceIds']})})
        for finding in [host] + services[:2] + observations[:2]:
            linked = [evidence[eid] for eid in finding['evidenceIds'] if eid in evidence]
            if not linked:
                continue
            chosen = max(linked, key=lambda e: (e.get('tool') != 'dns-review', e.get('observedAt', '')))
            result['findings'].append(_finding(finding, [chosen['id']]))
            if chosen['id'] not in used_evidence:
                result['evidence'].append(_evidence(chosen))
                used_evidence.add(chosen['id'])
    fids = {f['id'] for f in result['findings']}
    eids = {e['id'] for e in result['evidence']}
    for candidate in candidates:
        if (len(result['candidates']) >= 12 or
                not set(candidate['findingIds']) <= fids or
                not set(candidate['evidenceIds']) & eids):
            continue
        result['candidates'].append(_candidate(candidate, fids, eids))
    result['truncated'] = (len(result['findings']) < len(doc['findings']) or
                           len(result['evidence']) < len(doc['evidence']) or
                           len(result['candidates']) < len(candidates))
    return result


def read_requests(requests, doc, host_ids, candidates, run_events):
    """Resolve a small batch against one immutable, approved findings snapshot."""
    if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_READ_REQUESTS:
        raise ValueError('Request one to three read-only context operations.')
    hosts = set(host_ids)
    findings = {f['id']: f for f in doc['findings']}
    evidence = {e['id']: e for e in doc['evidence']}
    results = []
    for request in requests:
        if not isinstance(request, dict):
            raise ValueError('A context request must be an object.')
        tool = request.get('tool')
        if tool in ('list_findings', 'list_candidates', 'get_check_history'):
            host_id = request.get('hostId')
            if not isinstance(host_id, str) or host_id not in hosts:
                raise ValueError('Context request referred to an unselected host.')
            offset = request.get('offset', 0)
            if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 1000:
                raise ValueError('Context request offset was invalid.')
            if tool == 'list_findings':
                kind = request.get('kind')
                if kind not in (None, 'host', 'service', 'observation'):
                    raise ValueError('Context finding kind was invalid.')
                rows = [f for f in doc['findings'] if _host_id(f) == host_id and
                        (kind is None or f['kind'] == kind)]
                rows.sort(key=lambda f: (f.get('lastSeen', ''), f['id']), reverse=True)
                results.append({'tool': tool, 'hostId': host_id, 'offset': offset,
                                'total': len(rows), 'items': [_finding(f) for f in rows[offset:offset + 6]]})
            elif tool == 'list_candidates':
                rows = [c for c in candidates if c['hostId'] == host_id]
                selected = rows[offset:offset + 4]
                refs = {fid for c in selected for fid in c['findingIds']}
                shown_evidence = []
                for candidate in selected:
                    for fid in candidate['findingIds']:
                        finding = findings.get(fid)
                        if not finding:
                            continue
                        eid = next((eid for eid in candidate['evidenceIds']
                                    if eid in finding['evidenceIds'] and eid in evidence), None)
                        if eid and eid not in shown_evidence and len(shown_evidence) < 8:
                            shown_evidence.append(eid)
                shown_findings = {fid for fid in refs if fid in findings and
                                  any(eid in shown_evidence for eid in findings[fid]['evidenceIds'])}
                results.append({'tool': tool, 'hostId': host_id, 'offset': offset,
                                'total': len(rows), 'items': [_candidate(c, shown_findings, set(shown_evidence)) for c in selected],
                                'findings': [_finding(findings[fid],
                                    [eid for eid in findings[fid]['evidenceIds'] if eid in shown_evidence])
                                    for fid in sorted(shown_findings)],
                                'evidence': [_evidence(evidence[eid], 220) for eid in shown_evidence]})
            else:
                rows = [e for e in run_events if e.get('hostId') == host_id and
                        e.get('type') in ('survey', 'check')]
                saved = [e for e in doc['evidence'] if e.get('command') and
                         any(e['id'] in f['evidenceIds'] for f in doc['findings']
                             if _host_id(f) == host_id)]
                saved.sort(key=lambda e: e.get('observedAt', ''), reverse=True)
                results.append({'tool': tool, 'hostId': host_id, 'offset': offset,
                                'total': len(rows), 'items': [{key: e[key] for key in
                                    ('type', 'at', 'candidateId', 'outcome', 'summary') if key in e}
                                    for e in rows[offset:offset + 6]],
                                'recentCommands': [{'command': e['command'][:120],
                                    'tool': e['tool'], 'observedAt': e.get('observedAt', '')}
                                    for e in saved[:6]]})
        elif tool == 'get_evidence':
            ids = request.get('evidenceIds')
            offset = request.get('offset', 0)
            if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 20000:
                raise ValueError('Evidence excerpt offset was invalid.')
            if (not isinstance(ids, list) or not 1 <= len(ids) <= 4 or
                    any(not isinstance(eid, str) or eid not in evidence for eid in ids) or
                    len(ids) != len(set(ids))):
                raise ValueError('Request one to four saved evidence IDs from selected hosts.')
            linked = [f for f in doc['findings'] if any(eid in f['evidenceIds'] for eid in ids)]
            results.append({'tool': tool, 'offset': offset,
                            'items': [_evidence(evidence[eid], 800, offset) for eid in ids],
                            'findings': [_finding(f, [eid for eid in ids if eid in f['evidenceIds']])
                                         for f in linked[:12]]})
        else:
            raise ValueError('Unknown read-only context operation.')
    return results
