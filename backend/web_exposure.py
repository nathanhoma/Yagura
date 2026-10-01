"""Fixed, bounded web metadata probes using the existing IP-pinned transport."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urljoin

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.web_contacts import fetch_page, origin
from backend.workflow import is_local_ip

PATHS = ('/.git/HEAD', '/WEB-INF/web.xml', '/WEB-INF/classes/struts.xml', '/WEB-INF/lib/', '/docs', '/yagura-not-found-baseline')


def inspect(url, ip):
    if not is_local_ip(ip) or ipaddress.ip_address(ip).version != 4:
        raise ValueError('Use a recorded private/local IPv4 address.')
    origin(url)
    pages, errors = [], []
    for path in PATHS:
        target = urljoin(url, path)
        try:
            status, headers, body = fetch_page(target, ip, 4)
            pages.append(dict(url=target, status=status, contentType=headers.get('content-type', ''),
                              location=headers.get('location', ''), excerpt=body[:3000], truncated=len(body) > 3000))
        except Exception as exc:
            errors.append(dict(url=target, error=str(exc)[:200]))
    return dict(url=url, ip=ip, pages=pages, errors=errors,
                coverage='Six fixed GET probes including a not-found comparison. No redirects followed. Responses require interpretation; status alone is not exposure proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--ip', required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.url, args.ip)))
