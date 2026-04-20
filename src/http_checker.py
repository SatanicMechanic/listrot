import re
import requests
from typing import NamedTuple, Optional

REPO_RE = re.compile(
    r'https?://(?:www\.)?(github\.com|gitlab\.com)'
    r'/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)'
    r'(/[a-zA-Z0-9_./-]*)?'
)
SKIP_SUBPATHS = {'issues', 'pulls', 'wiki', 'discussions', 'blob',
                 'tree', 'commit', 'releases', 'actions', 'tags'}

HEADERS = {'User-Agent': 'listrot/1.0'}


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
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers=HEADERS)
        if resp.status_code in (403, 429):
            # Bot-blocking, not dead — treat as alive but no repo link recoverable
            return LivenessResult('alive', resp.status_code, None)
        if resp.status_code >= 400:
            return LivenessResult('dead', resp.status_code, None)
        return LivenessResult('alive', resp.status_code, _find_repo_url(resp.text))
    except requests.RequestException:
        return LivenessResult('unreachable', None, None)
