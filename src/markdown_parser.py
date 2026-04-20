import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

GITHUB_RE = re.compile(r'https?://github\.com/([^/\s\)]+)/([^/\s\)#?]+)')
GITLAB_RE = re.compile(r'https?://gitlab\.com/([^/\s\)]+)/([^/\s\)#?]+)')

GITHUB_NON_REPO_OWNERS = {'marketplace', 'features', 'explore', 'orgs',
                           'sponsors', 'apps', 'topics', 'collections'}
GITLAB_NON_REPO_OWNERS = {'users', 'groups', 'explore', 'dashboard',
                           'admin', 'help', 'profile', '-'}
IMAGE_RE = re.compile(r'!\[')
BADGE_DOMAINS = {'shields.io', 'img.shields.io', 'travis-ci.org', 'travis-ci.com',
                 'circleci.com', 'codecov.io', 'badge.fury.io', 'coveralls.io'}
HEADING_RE = re.compile(r'^(#{1,6})\s+(.+)$')
LINK_RE = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')


@dataclass
class Entry:
    name: str
    url: str
    section: Optional[str]
    is_github: bool
    is_gitlab: bool = False
    owner: Optional[str] = None
    repo: Optional[str] = None


def _is_badge_url(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lstrip('www.')
        return host in BADGE_DOMAINS or url.startswith('https://img.shields.io')
    except Exception:
        return False


def _extract_links_from_line(line: str) -> list[tuple[str, str]]:
    """Return (name, url) pairs from a markdown line, filtering badge/image links."""
    results = []
    for match in LINK_RE.finditer(line):
        name = match.group(1)
        url = match.group(2).strip()
        start = match.start()
        if start > 0 and line[start - 1] == '!':
            continue
        if _is_badge_url(url):
            continue
        if url.startswith('http://') or url.startswith('https://'):
            results.append((name, url))
    return results


def _classify(url: str) -> tuple[bool, bool, Optional[str], Optional[str]]:
    """Return (is_github, is_gitlab, owner, repo)."""
    m = GITHUB_RE.match(url.rstrip('/'))
    if m and m.group(1) not in GITHUB_NON_REPO_OWNERS:
        return True, False, m.group(1), m.group(2)
    m = GITLAB_RE.match(url.rstrip('/'))
    if m and m.group(1) not in GITLAB_NON_REPO_OWNERS:
        return False, True, m.group(1), m.group(2)
    return False, False, None, None


def parse_entries(text: str) -> list[Entry]:
    entries: list[Entry] = []
    current_section: Optional[str] = None

    for line in text.splitlines():
        heading_match = HEADING_RE.match(line.rstrip())
        if heading_match:
            current_section = heading_match.group(2).strip()
            continue

        stripped = re.sub(r'^\s*[-*+]\s+', '', line)
        links = _extract_links_from_line(stripped)
        if not links:
            continue

        # Use the first link's text as the entry name.
        # Prefer the first GitHub/GitLab URL on the line as the audit target;
        # fall back to the first URL. This handles the common awesome list pattern:
        #   [Name](homepage) - Description. ([Source Code](github-url))
        name = links[0][0]
        repo_link = next(
            ((u) for _, u in links if _classify(u)[0] or _classify(u)[1]),
            links[0][1],
        )
        url = repo_link
        is_github, is_gitlab, owner, repo = _classify(url)
        entries.append(Entry(
            name=name,
            url=url,
            section=current_section,
            is_github=is_github,
            is_gitlab=is_gitlab,
            owner=owner,
            repo=repo,
        ))

    return entries
