import ipaddress
import re


def is_local_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        if ip.version != 4:
            return False
        a, b = ip.packed[:2]
        return a == 10 or a == 172 and 16 <= b <= 31 or a == 192 and b == 168 or a == 127 or a == 169 and b == 254
    except ValueError:
        return False


COMMAND_CATALOG = [
    dict(id='interfaces', title='Read local IPv4 interfaces', command='ip -j -4 addr', when='List local interface addresses and scan ranges.'),
    dict(id='neighbors', title='Refresh local neighbors', command='ip -j -4 neigh', when='Refresh neighbor entries seen on the local link.'),
    dict(id='nmap-discovery', title='Discover hosts in a local range', command='nmap -n -sn -oX - {cidr}', when='Discover reachable hosts in an authorized local IPv4 range of at most 1,024 addresses.'),
    dict(id='ping', title='Check host reachability', command='ping -c 3 {host}', when='Check ICMP reachability of a recorded host.'),
    dict(id='nmap-ports', title='Check common TCP ports', command='nmap -n -Pn -sT --top-ports 100 {host}', when='Discover common services when a target has no recorded open TCP ports using a TCP connect scan.'),
    dict(id='nmap-service', title='Identify service versions', command='nmap -n -Pn -sT -sV --version-light -p {ports} {host}', when='Identify versions on recorded open TCP ports using a TCP connect scan.'),
    dict(id='nmap-os', title='Guess host operating system', command='nmap -n -Pn -O {host}', when='Use Nmap OS fingerprinting on a recorded host with an open TCP port. May require elevated privileges.'),
    dict(id='http-headers', title='Inspect HTTP headers', command='curl -I --max-time 5 {scheme}://{host}:{port}/', when='Review headers for a recorded open web service.'),
    dict(id='smb-shares', title='List SMB shares', command='smbclient -L //{host} -N', when='Check advertised shares for a recorded open SMB service.'),
]


def workflow(doc, authorized_cidr=None):
    candidates, targets = [], []
    try:
        authorized_network = ipaddress.ip_network(authorized_cidr, strict=False) if authorized_cidr else None
        if authorized_network and authorized_network.version != 4:
            authorized_network = None
    except ValueError:
        authorized_network = None
    catalog = {c['id']: c for c in COMMAND_CATALOG}
    rows = doc['findings']

    def add(catalog_id, host, services, reason, **values):
        ids = [host['id']] + [s['id'] for s in services]
        evidence_ids = list(dict.fromkeys(e for f in [host] + services for e in f['evidenceIds']))
        if not evidence_ids:
            return
        values = dict(host=host['ip'], **values)
        command = re.sub(r'\{(\w+)\}', lambda m: str(values.get(m[1], m[0])), catalog[catalog_id]['command'])
        candidates.append(dict(id=f"{catalog_id}:{host['id']}:{','.join(s['id'] for s in services)}", catalogId=catalog_id,
                               title=catalog[catalog_id]['title'], command=command, hostId=host['id'],
                               serviceIds=[s['id'] for s in services], findingIds=ids, evidenceIds=evidence_ids, reason=reason))

    for host in (f for f in rows if f['kind'] == 'host'):
        services = [s for s in rows if s['kind'] == 'service' and s.get('hostId') == host['id']]
        observations = [o for o in rows if o['kind'] == 'observation' and o.get('hostId') == host['id']]
        opened = [s for s in services if s.get('state') == 'open']
        eligible = (is_local_ip(host['ip']) and authorized_network is not None and
                    ipaddress.ip_address(host['ip']) in authorized_network and
                    not host.get('local') and host.get('state') != 'down')
        if eligible:
            if host.get('state') != 'up':
                add('ping', host, [], f"Host {host['ip']} is recorded with reachability {host.get('state')}; verify ICMP response.")
            tcp = [s for s in opened if s.get('protocol') == 'tcp']
            if not tcp:
                add('nmap-ports', host, [], f"Host {host['ip']} has no recorded open TCP services; discover common ports.")
            unknown = [s for s in tcp if not s.get('product') and not s.get('version')]
            if unknown:
                ports = ','.join(str(s['port']) for s in sorted(unknown, key=lambda s: s['port']))
                add('nmap-service', host, unknown, f"Open TCP ports {', '.join(str(s['port']) for s in unknown)} lack recorded product/version information.", ports=ports)
            if tcp and not any(o.get('title') == 'Nmap OS guess' for o in observations):
                add('nmap-os', host, tcp, f"Host {host['ip']} has a recorded open TCP port but no Nmap OS guess; fingerprint its operating system.")
            for s in tcp:
                port, name = s['port'], s.get('name', '')
                if re.search('http|www', name, re.I) or port in (80, 443, 8000, 8080, 8443):
                    scheme = 'https' if s.get('tunnel') == 'ssl' or re.search('https', name, re.I) or port in (443, 8443) else 'http'
                    add('http-headers', host, [s], f"Recorded open {port}/tcp ({name or 'web-associated port'}) supports a web header check.", port=port, scheme=scheme)
                if port == 445 or name in ('microsoft-ds', 'netbios-ssn', 'smb'):
                    add('smb-shares', host, [s], f"Recorded open {port}/tcp ({name or 'SMB-associated port'}) supports share enumeration.")
        stage = 'local context' if host.get('local') else 'recon' if not opened else 'service identification' if any(not s.get('product') and not s.get('version') for s in opened) else 'access triage'
        reason = ('' if eligible else 'Local interface address' if host.get('local') else
                  'Imported target outside local IPv4 suggestion scope' if not is_local_ip(host['ip']) else
                  'No authorized check range selected' if authorized_network is None else
                  'Outside selected authorized check range' if ipaddress.ip_address(host['ip']) not in authorized_network else
                  'Last recorded host state is down')
        targets.append(dict(host=host, services=services, observations=observations, stage=stage, eligible=eligible, scopeReason=reason))
    return dict(targets=targets, candidates=candidates)
