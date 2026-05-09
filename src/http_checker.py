import ipaddress
import re
import socket
import requests
from typing import NamedTuple, Optional
from urllib.parse import urlparse, urljoin

REPO_RE = re.compile(
    r'https?://(?:www\.)?(github\.com|gitlab\.com)'
    r'/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)'
    r'(/[a-zA-Z0-9_./-]*)?'
)
SKIP_SUBPATHS = {'issues', 'pulls', 'wiki', 'discussions', 'blob',
                 'tree', 'commit', 'releases', 'actions', 'tags'}

HEADERS = {'User-Agent': 'listrot/1.0'}
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 10

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_host(host: str) -> bool:
    if not host:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            if any(ipaddress.ip_address(info[4][0]) in net for net in _PRIVATE_NETS):
                return True
        return False
    except (socket.gaierror, ValueError):
        return False


class LivenessResult(NamedTuple):
    status: str        # 'alive', 'dead', 'unreachable'
    code: Optional[int]
    repo_url: Optional[str]


def _find_repo_url(html: str) -> Optional[str]:
    for m in REPO_RE.finditer(html):
        subpath = m.group(4) or ''
        first_subpath_segment = subpath.lstrip('/').split('/')[0] if subpath else ''
        if first_subpath_segment in SKIP_SUBPATHS:
            continue
        host, owner, repo = m.group(1), m.group(2), m.group(3)
        return f"https://{host}/{owner}/{repo}"
    return None


def check_url(url: str, timeout: int = 10) -> LivenessResult:
    try:
        current_url = url
        for _ in range(MAX_REDIRECTS):
            parsed = urlparse(current_url)
            if _is_private_host(parsed.hostname or ''):
                return LivenessResult('dead', None, None)
            resp = requests.get(current_url, timeout=timeout, allow_redirects=False,
                                headers=HEADERS, stream=True)
            if resp.is_redirect:
                location = resp.headers.get('Location', '')
                current_url = urljoin(current_url, location)
                continue
            if resp.status_code in (403, 429):
                # Bot-blocking, not dead — treat as alive but no repo link recoverable
                return LivenessResult('alive', resp.status_code, None)
            if resp.status_code >= 400:
                return LivenessResult('dead', resp.status_code, None)
            body = b""
            for chunk in resp.iter_content(chunk_size=65536):
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    break
            text = body.decode("utf-8", errors="replace")
            return LivenessResult('alive', resp.status_code, _find_repo_url(text))
        return LivenessResult('dead', None, None)
    except requests.RequestException:
        return LivenessResult('unreachable', None, None)
