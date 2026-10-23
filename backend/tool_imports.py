"""Read-only imports of selected-host Wappalyzer and Burp exports.

Only normalized metadata is persisted. Raw HTTP messages, cookies, and form values
from Burp exports are never copied into Yagura evidence.
"""
import json
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree

from . import findings as F
from .outbound import require_target
from .web_contacts import origin


TOOLS = frozenset(('wappalyzer', 'burp'))


def _text(value, limit=160):
    return ' '.join(str(value or '').split())[:limit]


def _site_url(value, host):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        scheme, name, port = origin(value)
    except (ValueError, TypeError):
        return None
    expected = str(host.get('name') or host['ip']).lower().rstrip('.')
    if name not in (expected, host['ip']):
        return None
    path = urlsplit(value).path or '/'
    if len(path) > 400:
        return None
    return f'{scheme}://{name}:{port}{path}', port, scheme


def _wappalyzer(output, host):
    try:
        source = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError('Wappalyzer export must be JSON.') from exc
    rows = source if isinstance(source, list) else [source]
    if not 1 <= len(rows) <= 100 or any(not isinstance(row, dict) for row in rows):
        raise ValueError('Wappalyzer export must contain 1–100 website objects.')
    results, skipped = [], 0
    for row in rows:
        site = _site_url(row.get('url'), host)
        if not site:
            skipped += 1
            continue
        technologies = row.get('technologies')
        if not isinstance(technologies, list):
            raise ValueError('Wappalyzer technologies must be a list.')
        for tech in technologies[:100]:
            if not isinstance(tech, dict) or not _text(tech.get('name')):
                continue
            versions = tech.get('versions') or []
            if not isinstance(versions, list):
                versions = []
            results.append(dict(url=site[0], port=site[1], scheme=site[2],
                                name=_text(tech['name']), versions=[_text(v, 60) for v in versions[:5] if _text(v, 60)]))
    return results[:200], skipped


def _burp(output, host):
    if '<!ENTITY' in output.upper() or re.search(r'<!DOCTYPE[^>]*\b(?:SYSTEM|PUBLIC)\b', output, re.I):
        raise ValueError('XML entity declarations and external DTDs are not supported.')
    try:
        root = ElementTree.fromstring(output)
    except ElementTree.ParseError as exc:
        raise ValueError('Burp export must be valid XML.') from exc
    if root.tag not in ('issues', 'items'):
        raise ValueError('Choose a Burp issues or saved-items XML export.')
    nodes = root.findall('issue' if root.tag == 'issues' else 'item')
    if not 1 <= len(nodes) <= 1000:
        raise ValueError('Burp export must contain 1–1000 issues or saved items.')
    results, skipped = [], 0
    for item in nodes:
        host_node = item.find('host')
        exported_ip = host_node.get('ip') if host_node is not None else None
        if exported_ip and exported_ip != host['ip']:
            skipped += 1
            continue
        target = item.findtext('url') or item.findtext('location')
        if not target and host_node is not None:
            base = _text(host_node.text, 255)
            target = base.rstrip('/') + '/' + (item.findtext('path') or '').lstrip('/')
        site = _site_url(target, host)
        if not site:
            skipped += 1
            continue
        if root.tag == 'issues':
            name = _text(item.findtext('name'))
            if name:
                results.append(dict(kind='issue', url=site[0], port=site[1], scheme=site[2],
                                    name=name, severity=_text(item.findtext('severity'), 40),
                                    confidence=_text(item.findtext('confidence'), 40)))
        else:
            results.append(dict(kind='history', url=site[0], port=site[1], scheme=site[2],
                                method=_text(item.findtext('method'), 16),
                                status=_text(item.findtext('status'), 12),
                                mime=_text(item.findtext('mimetype'), 80)))
    return results[:500], skipped


def parse_export(data, host, scope):
    tool = data.get('tool')
    if tool not in TOOLS:
        raise ValueError('Choose Wappalyzer or Burp export.')
    require_target(host, scope)
    output = data.get('output')
    if not isinstance(output, str) or not output.strip() or len(output.encode()) > 800000:
        raise ValueError('Provide an export of at most 800 KB.')
    rows, skipped = (_wappalyzer(output, host) if tool == 'wappalyzer' else _burp(output, host))
    if not rows:
        raise ValueError('No records matched the selected approved host.')
    time = F.timestamp(data.get('observedAt'))
    sanitized = dict(tool=tool, host=host['ip'], name=host.get('name', ''), records=rows)
    ev = dict(id=F.uid('evidence'), tool=tool, command=f'Imported {tool} export',
              output=json.dumps(sanitized, ensure_ascii=False), observedAt=time,
              importedAt=F.now(), format='json', sensitive=False)
    h = F.record('host', dict(ip=host['ip'], aliases=[], name=host.get('name', ''),
                              state='unknown', local=False, title=host['ip'], detail=''), ev['id'], time)
    findings, services = [h], {}
    for row in rows:
        key = row['port']
        if key not in services:
            services[key] = F.record('service', dict(hostId=h['id'], port=key, protocol='tcp',
                state='unknown', name='https' if row['scheme'] == 'https' else 'http',
                product='', version='', tunnel='', title=f'{key}/tcp', detail=''), ev['id'], time)
            findings.append(services[key])
        if tool == 'wappalyzer':
            title = 'Web technology: ' + row['name']
            detail = row['url'] + (' · versions ' + ', '.join(row['versions']) if row['versions'] else '')
        elif row['kind'] == 'issue':
            title = 'Burp issue: ' + row['name']
            detail = row['url'] + ' · severity ' + row['severity'] + ' · confidence ' + row['confidence']
        else:
            title = 'Burp HTTP history'
            detail = row['url'] + ' · ' + row['method'] + ' · HTTP ' + row['status'] + ' · ' + row['mime']
        findings.append(F.record('observation', dict(hostId=h['id'], serviceId=services[key]['id'],
                           title=title[:160], detail=detail[:4000]), ev['id'], time))
    warnings = ['Imported tool results are observations requiring review; no target request was made.']
    if skipped:
        warnings.append(f'{skipped} export entries did not match the selected approved host and were skipped.')
    return dict(schemaVersion=F.SCHEMA_VERSION, findings=findings, evidence=[ev], warnings=warnings)
