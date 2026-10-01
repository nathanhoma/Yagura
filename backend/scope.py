"""Validated engagement scope shared by discovery, checks, and analysis."""
import ipaddress
import re


LOCAL_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
))
DOMAIN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
MAX_CIDRS, MAX_DOMAINS, MAX_ADDRESSES = 16, 16, 4096


def valid_cidr(value):
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
        return (network.version == 4 and network.prefixlen >= 22 and
                any(network.subnet_of(allowed) for allowed in LOCAL_NETWORKS))
    except (AttributeError, ValueError):
        return False


def normalize_scope(value):
    """Read the current shape and the previous single-CIDR shape."""
    if value is None:
        value = {'cidrs': [], 'domains': []}
    if isinstance(value, str):
        value = {'cidrs': [value] if value.strip() else [], 'domains': []}
    if not isinstance(value, dict):
        raise ValueError('Supply CIDR and domain lists for the target scope.')
    if 'cidr' in value and 'cidrs' not in value:
        if set(value) != {'cidr'} or not isinstance(value['cidr'], str):
            raise ValueError('Supply only cidr, or cidrs and domains lists.')
        value = {'cidrs': [value['cidr']] if value['cidr'] else [], 'domains': []}
    if set(value) != {'cidrs', 'domains'} or not isinstance(value['cidrs'], list) or not isinstance(value['domains'], list):
        raise ValueError('Supply only cidrs and domains lists.')
    if len(value['cidrs']) > MAX_CIDRS or len(value['domains']) > MAX_DOMAINS:
        raise ValueError('Scope supports at most 16 CIDRs and 16 domains.')
    cidrs = []
    for entry in value['cidrs']:
        if not valid_cidr(entry):
            raise ValueError('Use private, shared, loopback, or link-local IPv4 CIDRs of at most 1,024 addresses each.')
        cidr = str(ipaddress.ip_network(entry.strip(), strict=False))
        if cidr not in cidrs:
            cidrs.append(cidr)
    if sum(ipaddress.ip_network(cidr).num_addresses for cidr in cidrs) > MAX_ADDRESSES:
        raise ValueError('Scope supports at most 4,096 addresses in total.')
    domains = []
    for entry in value['domains']:
        if not isinstance(entry, str):
            raise ValueError('Each domain must be a DNS name.')
        domain = entry.strip().lower().rstrip('.')
        labels = domain.split('.')
        if len(domain) > 253 or len(labels) < 2 or not all(DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError('Use DNS names such as crimsonia.net, without wildcards or URLs.')
        if domain not in domains:
            domains.append(domain)
    if domains and not cidrs:
        raise ValueError('Add at least one CIDR when restricting by domain.')
    return {'cidrs': sorted(cidrs, key=lambda item: (int(ipaddress.ip_network(item).network_address), ipaddress.ip_network(item).prefixlen)),
            'domains': sorted(domains)}


def ip_allowed(value, scope):
    try:
        address = ipaddress.ip_address(value)
        return address.version == 4 and any(address in ipaddress.ip_network(cidr) for cidr in normalize_scope(scope)['cidrs'])
    except ValueError:
        return False


def name_allowed(name, scope):
    domains = normalize_scope(scope)['domains']
    if not domains:
        return True
    if not isinstance(name, str):
        return False
    hostname = name.strip().lower().rstrip('.')
    if len(hostname) > 253 or not all(DOMAIN_LABEL.fullmatch(label) for label in hostname.split('.')):
        return False
    return any(hostname == domain or hostname.endswith('.' + domain) for domain in domains)


def host_allowed(host, scope):
    return ip_allowed(host.get('ip'), scope) and name_allowed(host.get('name'), scope)


def approved_host(host, scope):
    """A domain-bound check needs an explicit, current IP/name approval."""
    selected = normalize_scope(scope)
    if not host_allowed(host, selected):
        return False
    approval = host.get('approval')
    if not selected['domains'] and not approval:
        return True  # Preserve explicitly imported legacy IP-only workspaces.
    return bool(approval and approval.get('ip') == host.get('ip') and
                approval.get('name') == str(host.get('name', '')).lower().rstrip('.') and
                approval.get('scope') == selected)


def discovery_allowed(cidr, scope, findings):
    """Only CIDR containment is needed; discovered IPs stay quarantined."""
    if not valid_cidr(cidr):
        return False
    requested = ipaddress.ip_network(cidr.strip(), strict=False)
    saved = normalize_scope(scope)
    if not any(requested.subnet_of(ipaddress.ip_network(item)) for item in saved['cidrs']):
        return False
    return True
