import ipaddress
import re

from .web_contacts import website_url


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
    dict(id='web-contacts', title='Inspect published website contacts', command='python3 -m backend.web_contacts --url {url} --ip {host}', when='Review email addresses in page text and mailto links on a recorded web service; inspect up to five same-origin pages.'),
    dict(id='smb-shares', title='List SMB shares', command='smbclient -L //{host} -N', when='Check advertised shares for a recorded open SMB service.'),
    dict(id='dns-ptr', title='Resolve host PTR name', command='getent hosts {host}', when='Record the locally resolved reverse DNS name for a scoped host.'),
    dict(id='web-inventory', title='Inventory web pages and routes', command='python3 -m backend.web_inventory --url {url} --ip {host}', when='Record HTTP status, title, server, and up to 50 same-origin links from five pages.'),
    dict(id='ssh-hostkey', title='Inspect SSH host key', command='nmap -n -Pn -sT -p {port} --script ssh-hostkey -oX - {host}', when='Read the SSH host key on a recorded open SSH service.'),
    dict(id='smb-security', title='Inspect SMB security mode', command='nmap -n -Pn -sT -p {port} --script smb2-security-mode -oX - {host}', when='Read SMB signing configuration on a recorded open SMB service.'),
    dict(id='nfs-exports', title='List NFS exports', command='nmap -n -Pn -sT -p {port} --script nfs-showmount -oX - {host}', when='List exports on a recorded open NFS service.'),
    dict(id='nuclei-git', title='Check exposed Git metadata', command='nuclei -u {scheme}://{host}:{port}/ -t backend/templates/git-head-exposure.yaml -j -silent -rl 1 -c 1 -dr -ni', when='Run one bundled read-only Nuclei template on a recorded web service.'),
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
            if not any(o.get('title') == 'Reverse DNS name' for o in observations):
                add('dns-ptr', host, [], f"Resolve a name for recorded host {host['ip']}.")
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
                    add('web-contacts', host, [s], 'A recorded web service can be reviewed for published contact information.', url=website_url(host, s))
                    add('http-headers', host, [s], f"Recorded open {port}/tcp ({name or 'web-associated port'}) supports a web header check.", port=port, scheme=scheme)
                    if not any(o.get('title') == 'Web inventory' and o.get('serviceId') == s['id'] for o in observations):
                        add('web-inventory', host, [s], f"Inventory pages and routes on recorded web service {port}/tcp.", url=website_url(host, s))
                    if not any(o.get('title') == 'Curated Nuclei exposure check' and o.get('serviceId') == s['id'] for o in observations):
                        add('nuclei-git', host, [s], f"Check a recorded web service for publicly exposed Git metadata with one bundled template.", port=port, scheme=scheme)
                if port == 445 or name in ('microsoft-ds', 'netbios-ssn', 'smb'):
                    add('smb-shares', host, [s], f"Recorded open {port}/tcp ({name or 'SMB-associated port'}) supports share enumeration.")
                    if not any(o.get('title') == 'smb2-security-mode' and o.get('serviceId') == s['id'] for o in observations):
                        add('smb-security', host, [s], f"Inspect SMB security mode on {port}/tcp.", port=port)
                if port == 22 or name == 'ssh':
                    if not any(o.get('title') == 'ssh-hostkey' and o.get('serviceId') == s['id'] for o in observations):
                        add('ssh-hostkey', host, [s], f"Read the host key on recorded SSH service {port}/tcp.", port=port)
                if port == 2049 or name == 'nfs':
                    if not any(o.get('title') == 'nfs-showmount' and o.get('serviceId') == s['id'] for o in observations):
                        add('nfs-exports', host, [s], f"List exports on recorded NFS service {port}/tcp.", port=port)
        stage = 'local context' if host.get('local') else 'recon' if not opened else 'service identification' if any(not s.get('product') and not s.get('version') for s in opened) else 'access triage'
        reason = ('' if eligible else 'Local interface address' if host.get('local') else
                  'Imported target outside local IPv4 suggestion scope' if not is_local_ip(host['ip']) else
                  'No authorized check range selected' if authorized_network is None else
                  'Outside selected authorized check range' if ipaddress.ip_address(host['ip']) not in authorized_network else
                  'Last recorded host state is down')
        targets.append(dict(host=host, services=services, observations=observations, stage=stage, eligible=eligible, scopeReason=reason))
    return dict(targets=targets, candidates=candidates)
