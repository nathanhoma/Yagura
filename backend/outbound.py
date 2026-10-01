"""Single application-level target gate for executable checks.

Host firewall isolation is still required before adding a browser, proxy, or
third-party crawler: subprocesses can create their own sockets.
"""
import ipaddress

from .scope import approved_host, normalize_scope
from .web_contacts import origin
from .workflow import is_local_ip


def require_target(host, scope):
    if not normalize_scope(scope)['cidrs'] or not is_local_ip(host.get('ip')) or not approved_host(host, scope):
        raise ValueError('Target IP/name is not approved in the current saved scope.')
    if host.get('local') or host.get('state') == 'down':
        raise ValueError('Local interface and explicitly down hosts cannot receive checks.')


def require_web_origin(url, host, scope):
    require_target(host, scope)
    scheme, name, port = origin(url)
    expected = str(host.get('name') or host['ip']).lower().rstrip('.')
    if name != expected or scheme not in ('http', 'https') or not 1 <= port <= 65535:
        raise ValueError('Web request must retain the approved host name and pinned IP.')
    return host['ip']


def require_private_pin(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError('A literal local IPv4 pin is required.') from exc
    if address.version != 4 or not is_local_ip(str(address)):
        raise ValueError('Public and IPv6 web pins are blocked.')
    return str(address)
