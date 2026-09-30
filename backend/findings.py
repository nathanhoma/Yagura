import copy
import datetime as dt
import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET


SCHEMA_VERSION = 1


def uid(prefix):
    return f'{prefix}-{uuid.uuid4()}'


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def timestamp(value=None):
    if not value:
        return now()
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    except (TypeError, ValueError):
        raise ValueError('Use an ISO timestamp for observedAt.')


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def empty():
    return dict(schemaVersion=SCHEMA_VERSION, findings=[], evidence=[])


def record(kind, fields, evidence_id, time):
    return dict(id=uid(kind), kind=kind, **fields, evidenceIds=[evidence_id] if evidence_id else [], firstSeen=time,
                lastSeen=time, createdAt=now(), updatedAt=now(), reviewStatus='unreviewed')


def migrate(data):
    if isinstance(data, dict) and data.get('schemaVersion') == SCHEMA_VERSION and isinstance(data.get('findings'), list) and isinstance(data.get('evidence'), list):
        return data
    if not isinstance(data, list):
        raise ValueError('Unsupported findings file format.')
    doc = empty()
    for old in data:
        try:
            time = timestamp(old.get('createdAt'))
        except ValueError:
            time = now()
        ev = dict(id=uid('evidence'), tool=old.get('source') or 'manual', command='', output=old.get('detail') or '', observedAt=time, importedAt=now(), format='legacy')
        doc['evidence'].append(ev)
        host = next((f for f in doc['findings'] if f['kind'] == 'host' and f['ip'] == old.get('ip')), None)
        if is_ip(old.get('ip')) and not host:
            host = record('host', dict(ip=old['ip'], aliases=[], name=old.get('title', '') if old.get('kind') == 'host' and old.get('title') != old['ip'] else '', state='unknown', local=False, title=old['ip'], detail=''), ev['id'], time)
            doc['findings'].append(host)
        if old.get('kind') != 'host':
            doc['findings'].append(record('observation', dict(title=old.get('title') or 'Imported note', detail=old.get('detail') or '', hostId=host['id'] if host else None, serviceId=None), ev['id'], time))
        elif host:
            host['evidenceIds'] = list(dict.fromkeys(host['evidenceIds'] + [ev['id']]))
            host['detail'] = old.get('detail') or ''
    return doc


def parse_import(data):
    if not isinstance(data, dict):
        raise ValueError('Invalid import request.')
    tool, output = data.get('tool'), data.get('output')
    if tool not in ('nmap', 'ip addr', 'ip neigh', 'ping', 'httpx', 'nuclei'):
        raise ValueError('Choose a supported parser.')
    if not isinstance(output, str) or not output.strip():
        raise ValueError('Command output is required.')
    if len(output.encode()) > 800000:
        raise ValueError('Output exceeds the 800 KB import limit.')
    time = timestamp(data.get('observedAt'))
    fmt = 'jsonl' if tool in ('httpx', 'nuclei') else 'json' if output.lstrip().startswith('[') else 'xml' if '<nmaprun' in output else 'text'
    command = data.get('command') or (re.search(r'<nmaprun\b[^>]*\bargs=["\']([^"\']+)', output).group(1) if tool == 'nmap' and re.search(r'<nmaprun\b[^>]*\bargs=["\']([^"\']+)', output) else tool)
    ev = dict(id=uid('evidence'), tool=tool, command=str(command).strip()[:2000], output=output, observedAt=time, importedAt=now(), format=fmt)
    findings, warnings = [], []

    def host(ip, **fields):
        if not is_ip(ip):
            return None
        h = next((f for f in findings if f['kind'] == 'host' and f['ip'] == ip), None)
        if h:
            h.update(fields)
        else:
            h = record('host', {**dict(ip=ip, aliases=[], name='', state='unknown', local=False, title=ip, detail=''), **fields}, ev['id'], time)
            findings.append(h)
        return h

    def observe(h, title, detail, service=None):
        findings.append(record('observation', dict(hostId=h['id'] if h else None, serviceId=service['id'] if service else None, title=title, detail=detail), ev['id'], time))

    def service(h, **fields):
        port = fields.get('port')
        if not h or not isinstance(port, int) or not 1 <= port <= 65535 or fields.get('protocol') not in ('tcp', 'udp', 'sctp'):
            return None
        s = record('service', {**dict(hostId=h['id'], name='', product='', version='', tunnel='', state='unknown', title=f"{port}/{fields['protocol']}", detail=''), **fields}, ev['id'], time)
        findings.append(s)
        return s

    if tool in ('httpx', 'nuclei'):
        from urllib.parse import urlsplit
        rows = []
        try:
            rows = [json.loads(line) for line in output.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid {tool} JSONL: {exc}')
        if not rows or len(rows) > 1000 or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f'{tool} requires 1–1000 JSONL objects.')
        for row in rows:
            target = row.get('url') or row.get('matched-at') or row.get('matched') or ''
            if not isinstance(target, str):
                raise ValueError(f'{tool} target URL must be text.')
            parsed_url = urlsplit(target)
            ip = row.get('host') if is_ip(row.get('host')) else parsed_url.hostname
            if not is_ip(ip):
                warnings.append(f'{tool} row without a numeric target IP was not linked.')
                continue
            h = host(ip)
            if tool == 'httpx':
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                s = service(h, port=port, protocol='tcp', state='open', name='https' if parsed_url.scheme == 'https' else 'http')
                detail = f"{target} · HTTP {row.get('status_code', '?')} · {row.get('title', '')}"
                observe(h, 'HTTP probe', detail[:4000], s)
                if row.get('tech'):
                    observe(h, 'Web technologies', ', '.join(map(str, row['tech']))[:4000], s)
            else:
                info = row.get('info') if isinstance(row.get('info'), dict) else {}
                title = str(info.get('name') or row.get('template-id') or 'Nuclei match')
                detail = f"{target} · template {row.get('template-id', '?')} · severity {info.get('severity', 'unknown')}"
                observe(h, f'Nuclei: {title}'[:160], detail[:4000])
    elif tool == 'nmap':
        if '<nmaprun' in output:
            if '<!ENTITY' in output.upper():
                raise ValueError('XML entity declarations are not supported.')
            if '</nmaprun>' not in output:
                raise ValueError('Incomplete Nmap XML. Import the completed output.')
            try:
                root = ET.fromstring(output)
            except ET.ParseError as exc:
                raise ValueError(f'Malformed Nmap XML: {exc}')
            for node in root.findall('host'):
                addresses = [a.attrib for a in node.findall('address')]
                address = next((a for a in addresses if a.get('addrtype') == 'ipv4'), None) or next((a for a in addresses if a.get('addrtype') == 'ipv6'), None)
                if not address:
                    continue
                status = node.find('status')
                status = status.attrib if status is not None else {}
                hostname = node.find('./hostnames/hostname')
                name = hostname.get('name', '') if hostname is not None else ''
                h = host(address.get('addr'), state=status.get('state', 'unknown'), name=name, mac=next((a.get('addr') for a in addresses if a.get('addrtype') == 'mac'), ''))
                if not h:
                    continue
                h['aliases'] = [a['addr'] for a in addresses if is_ip(a.get('addr')) and a['addr'] != h['ip']]
                observe(h, 'Nmap host status', status.get('state', 'unknown') + (f" ({status['reason']})" if status.get('reason') else ''))
                for p in node.findall('./ports/port'):
                    st, sv = p.find('state'), p.find('service')
                    st, sv = st.attrib if st is not None else {}, sv.attrib if sv is not None else {}
                    try:
                        port = int(p.get('portid', ''))
                    except ValueError:
                        continue
                    s = service(h, port=port, protocol=p.get('protocol'), state=st.get('state', 'unknown'), name=sv.get('name', ''), product=sv.get('product', ''), version=sv.get('version', ''), tunnel=sv.get('tunnel', ''), detail=sv.get('extrainfo', ''))
                    if s:
                        for script in p.findall('script'):
                            observe(h, script.get('id') or 'Nmap script', script.get('output') or '', s)
                for script in node.findall('./hostscript/script'):
                    observe(h, script.get('id') or 'Nmap host script', script.get('output') or '')
                for match in node.findall('./os/osmatch'):
                    name = match.get('name', '').strip()
                    if name:
                        accuracy = match.get('accuracy', '')
                        observe(h, 'Nmap OS guess', f"{name} ({accuracy}% accuracy)" if accuracy else name)
        else:
            h = current = None
            for line in output.splitlines():
                report = re.match(r'^Nmap scan report for (.+)$', line)
                if report:
                    named = re.match(r'^(.*?)\s+\(([^)]+)\)$', report[1])
                    h = host(named[2] if named else report[1].strip(), name=named[1] if named else '')
                    current = None
                    continue
                if not h:
                    continue
                if line.startswith('Host is up') or line.startswith('Host seems down'):
                    h['state'] = 'up' if line.startswith('Host is up') else 'down'
                    observe(h, 'Nmap host status', line.strip())
                p = re.match(r'^\s*(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$', line)
                if p:
                    current = service(h, port=int(p[1]), protocol=p[2], state=p[3], name='' if p[4] == 'unknown' else p[4], product=p[5] or '')
                    continue
                mac = re.match(r'^MAC Address:\s+(\S+)', line)
                if mac:
                    h['mac'] = mac[1]
                if re.match(r'^(Running:|OS details:|Aggressive OS guesses:|No exact OS matches for host)', line):
                    observe(h, 'Nmap OS guess', line.strip())
                if line.startswith('|'):
                    observe(h, 'Nmap script output', re.sub(r'^\|[_ ]?', '', line).strip(), current)
            if not re.search(r'Nmap scan report for|Nmap done:', output):
                raise ValueError('Output is not recognized as Nmap text or XML.')
    elif tool == 'ip addr':
        if fmt == 'json':
            try:
                rows = json.loads(output)
            except json.JSONDecodeError:
                raise ValueError('Invalid ip addr JSON.')
            for row in rows:
                for a in row.get('addr_info', []):
                    h = host(a.get('local'), local=True, interface=row.get('ifname', ''), prefix=a.get('prefixlen'), state=row.get('operstate', 'unknown').lower())
                    if h:
                        observe(h, 'Local interface address', f"{row.get('ifname', '')}: {a.get('local')}/{a.get('prefixlen')} ({a.get('scope') or 'unknown scope'})")
        else:
            iface, state, recognized = '', 'unknown', False
            for line in output.splitlines():
                header = re.match(r'^\d+:\s+(\S+?):\s+', line)
                if header:
                    iface = header[1].split('@')[0]
                    match = re.search(r'\bstate\s+(\S+)', line)
                    state = match[1].lower() if match else 'unknown'
                    recognized = True
                a = re.search(r'\binet6?\s+([\da-fA-F:.]+)/(\d+)', line)
                if a:
                    h = host(a[1], local=True, interface=iface, prefix=int(a[2]), state=state)
                    if h:
                        observe(h, 'Local interface address', line.strip())
            if not recognized:
                raise ValueError('Output is not recognized as ip addr text or JSON.')
    elif tool == 'ip neigh':
        if fmt == 'json':
            try:
                rows = json.loads(output)
            except json.JSONDecodeError:
                raise ValueError('Invalid ip neigh JSON.')
            for row in rows:
                state = row.get('state') or 'unknown'
                state = ', '.join(state) if isinstance(state, list) else str(state)
                h = host(row.get('dst'), interface=row.get('dev', ''), mac=row.get('lladdr', ''), neighborState=state)
                if h:
                    observe(h, 'Neighbor table entry', f"{row.get('dst')} dev {row.get('dev', '')} {row.get('lladdr', '')} {state}".strip())
        else:
            for line in output.splitlines():
                m = re.match(r'^(\S+)\s+dev\s+(\S+)(.*)$', line.strip())
                if not m:
                    continue
                mac = re.search(r'\blladdr\s+(\S+)', m[3])
                h = host(m[1], interface=m[2], mac=mac[1] if mac else '', neighborState=m[3].strip().split()[-1] if m[3].strip() else 'unknown')
                if h:
                    observe(h, 'Neighbor table entry', line.strip())
            if not findings:
                raise ValueError('Output is not recognized as ip neigh text or JSON; use [] for an empty table.')
    else:
        match = re.search(r'PING\s+[^\n]*?\(([\da-fA-F:.]+)\)|PING\s+([\da-fA-F:.]+)(?:\s|\()|Pinging\s+[^\n]*?\[([\da-fA-F:.]+)\]|Pinging\s+([\d.]+)\s', output, re.I)
        reply = re.search(r'(?:bytes from|Reply from)\s+([\da-fA-F:.]+)(?::|\s)', output, re.I)
        ip = next((x for x in match.groups() if x), None) if match else None
        h = host(ip or (reply[1] if reply else None))
        if not h:
            raise ValueError('Ping output must identify a numeric target address.')
        received = re.search(r'(\d+)\s+(?:packets?\s+)?received|Received\s*=\s*(\d+)', output, re.I)
        good = bool(re.search(r'(?:bytes from .*(?:time[=<]|icmp_seq)|Reply from .*bytes=)', output, re.I))
        state = 'up' if received and int(received[1] or received[2]) > 0 else 'no-response' if received else 'up' if good else 'unknown'
        h['state'] = state
        stats = ' · '.join(line for line in output.splitlines() if re.search(r'transmitted|received|loss|rtt|round-trip|Packets:', line, re.I))
        observe(h, 'ICMP reachability', f"{state}; {stats or 'No complete statistics reported.'}")
        if state == 'no-response':
            warnings.append('No ICMP reply does not prove the host is down.')
    if not findings:
        warnings.append('No hosts or services were found. The source output can still be saved as evidence.')
    return dict(schemaVersion=SCHEMA_VERSION, findings=findings, evidence=[ev], warnings=warnings)


def merge_parsed(doc, parsed):
    remap, added, linked = {}, 0, 0
    for kind in ('host', 'service', 'observation'):
        for original in (f for f in parsed['findings'] if f['kind'] == kind):
            f = copy.deepcopy(original)
            for key in ('hostId', 'serviceId'):
                if f.get(key):
                    f[key] = remap.get(f[key], f[key])
            def same(x):
                if x['kind'] != kind:
                    return False
                if kind == 'host':
                    return f['ip'] in [x['ip']] + x.get('aliases', []) or x['ip'] in f.get('aliases', [])
                if kind == 'service':
                    return all(x.get(k) == f.get(k) for k in ('hostId', 'port', 'protocol'))
                return all(x.get(k) == f.get(k) for k in ('hostId', 'serviceId', 'title', 'detail'))
            existing = next((x for x in doc['findings'] if same(x)), None)
            if existing:
                remap[f['id']] = existing['id']
                latest = f['lastSeen'] >= existing['lastSeen']
                existing['evidenceIds'] = list(dict.fromkeys(existing['evidenceIds'] + f['evidenceIds']))
                if kind == 'host':
                    f['local'] = existing.get('local') or f.get('local')
                if existing['reviewStatus'] != 'reviewed' and latest:
                    for key, value in f.items():
                        if key not in ('id', 'evidenceIds', 'firstSeen', 'lastSeen', 'createdAt', 'updatedAt', 'reviewStatus', 'aliases') and value not in ('', 'unknown'):
                            existing[key] = value
                if kind == 'host':
                    existing['aliases'] = [x for x in dict.fromkeys(existing.get('aliases', []) + f.get('aliases', [])) if x != existing['ip']]
                existing['firstSeen'] = min(existing['firstSeen'], f['firstSeen'])
                existing['lastSeen'] = max(existing['lastSeen'], f['lastSeen'])
                existing['updatedAt'] = now()
                linked += 1
            else:
                doc['findings'].append(f)
                remap[f['id']] = f['id']
                added += 1
    doc['evidence'].extend(parsed['evidence'])
    return dict(added=added, linked=linked)


def edit_finding(doc, finding, patch):
    f = finding.copy()
    for key in ('title', 'detail'):
        if key in patch:
            f[key] = patch[key].strip()[:160 if key == 'title' else 4000] if isinstance(patch[key], str) else ''
    if not f.get('title'):
        raise ValueError('Title is required.')
    if f['kind'] == 'host':
        for key in ('ip', 'name', 'mac', 'interface', 'state', 'neighborState'):
            if key in patch:
                f[key] = patch[key].strip()[:160] if isinstance(patch[key], str) else ''
        if not is_ip(f.get('ip')):
            raise ValueError('A valid host IP is required.')
        if 'prefix' in patch:
            if patch['prefix'] == '':
                f.pop('prefix', None)
            else:
                try:
                    f['prefix'] = int(patch['prefix'])
                except (ValueError, TypeError):
                    raise ValueError('Invalid address prefix length.')
                if not 0 <= f['prefix'] <= (32 if ipaddress.ip_address(f['ip']).version == 4 else 128):
                    raise ValueError('Invalid address prefix length.')
        if 'aliases' in patch:
            if not isinstance(patch['aliases'], list) or any(not is_ip(x) for x in patch['aliases']):
                raise ValueError('Aliases must be valid IP addresses.')
            f['aliases'] = [x for x in dict.fromkeys(patch['aliases']) if x != f['ip']]
        for x in doc['findings']:
            if x['kind'] == 'host' and x['id'] != f['id'] and (f['ip'] in [x['ip']] + x.get('aliases', []) or any(a in [x['ip']] + x.get('aliases', []) for a in f.get('aliases', []))):
                raise ValueError('This host or alias already exists. Merge the duplicates instead.')
        if 'local' in patch:
            f['local'] = patch['local'] is True
    elif f['kind'] == 'service':
        for key in ('name', 'product', 'version', 'state', 'tunnel'):
            if key in patch:
                f[key] = patch[key].strip()[:160] if isinstance(patch[key], str) else ''
        if 'port' in patch:
            try:
                f['port'] = int(patch['port'])
            except (ValueError, TypeError):
                raise ValueError('Use a port from 1–65535 and tcp, udp, or sctp.')
        if 'protocol' in patch:
            f['protocol'] = str(patch['protocol']).strip()[:10]
        if not 1 <= f.get('port', 0) <= 65535 or f.get('protocol') not in ('tcp', 'udp', 'sctp'):
            raise ValueError('Use a port from 1–65535 and tcp, udp, or sctp.')
        if any(x['kind'] == 'service' and x['id'] != f['id'] and all(x.get(k) == f.get(k) for k in ('hostId', 'port', 'protocol')) for x in doc['findings']):
            raise ValueError('This service already exists. Merge the duplicates instead.')
    elif f['kind'] == 'observation':
        for key in ('hostId', 'serviceId'):
            if key in patch:
                f[key] = patch[key] or None
        if f.get('serviceId'):
            service = next((x for x in doc['findings'] if x['kind'] == 'service' and x['id'] == f['serviceId']), None)
            if not service:
                raise ValueError('Service not found.')
            f['hostId'] = service['hostId']
        if f.get('hostId') and not any(x['kind'] == 'host' and x['id'] == f['hostId'] for x in doc['findings']):
            raise ValueError('Host not found.')
    f['reviewStatus'], f['updatedAt'] = 'reviewed', now()
    finding.update(f)
    return finding


def merge_findings(doc, target_id, source_id):
    target = next((f for f in doc['findings'] if f['id'] == target_id), None)
    source = next((f for f in doc['findings'] if f['id'] == source_id), None)
    if not target or not source or target is source or target['kind'] != source['kind']:
        raise ValueError('Choose two different findings of the same kind.')
    if target['kind'] == 'service' and any(target.get(k) != source.get(k) for k in ('hostId', 'port', 'protocol')):
        raise ValueError('Only services on the same host, port, and protocol can be merged.')
    target['evidenceIds'] = list(dict.fromkeys(target['evidenceIds'] + source['evidenceIds']))
    target['firstSeen'], target['lastSeen'] = min(target['firstSeen'], source['firstSeen']), max(target['lastSeen'], source['lastSeen'])
    if source.get('detail') and source['detail'] != target.get('detail'):
        target['detail'] = '\n'.join(x for x in (target.get('detail'), source['detail']) if x)
    if target['kind'] == 'host':
        target['aliases'] = [x for x in dict.fromkeys(target.get('aliases', []) + [source['ip']] + source.get('aliases', [])) if x != target['ip']]
    for f in doc['findings']:
        for key in ('hostId', 'serviceId'):
            if f.get(key) == source_id:
                f[key], f['updatedAt'] = target_id, now()
    doc['findings'] = [f for f in doc['findings'] if f['id'] != source_id]
    target['reviewStatus'], target['updatedAt'] = 'reviewed', now()
    if target['kind'] == 'host':
        seen = {}
        for s in list(doc['findings']):
            if s['kind'] == 'service' and s.get('hostId') == target_id:
                key = (s.get('protocol'), s.get('port'))
                if key in seen:
                    merge_findings(doc, seen[key], s['id'])
                else:
                    seen[key] = s['id']
    return target


def remove_finding(doc, finding_id):
    ids = {finding_id}
    ids.update(f['id'] for f in doc['findings'] if f.get('hostId') == finding_id)
    ids.update(f['id'] for f in doc['findings'] if f.get('serviceId') in ids)
    doc['findings'] = [f for f in doc['findings'] if f['id'] not in ids]
