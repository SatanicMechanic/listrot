import re
from typing import Optional, Tuple
import yaml
from markdown_parser import Entry, _classify

_GITHUB_URL_RE = re.compile(r'github\.com/([^/\s]+)/([^/\s#?]+)')
_GITLAB_URL_RE = re.compile(r'gitlab\.com/([^/\s]+)/([^/\s#?]+)')


def _parse_owner_repo(field: str, host: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from either 'owner/repo' shorthand or a full URL."""
    pattern = _GITHUB_URL_RE if host == "github" else _GITLAB_URL_RE
    m = pattern.search(field)
    if m:
        return m.group(1), m.group(2).rstrip('/')
    if "://" in field:
        return None  # URL that didn't match the host pattern — not a valid repo reference
    parts = field.strip("/").split("/")
    if len(parts) >= 2 and "." not in parts[0]:
        return parts[0], parts[1]
    return None


def _github_url(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}"


def _gitlab_url(owner: str, repo: str) -> str:
    return f"https://gitlab.com/{owner}/{repo}"


def parse_entries(text: str) -> list[Entry]:
    import sys
    data = yaml.safe_load(text)
    if not data or not isinstance(data, dict):
        print("WARNING: YAML file is empty or not a mapping — no entries parsed.", file=sys.stderr)
        return []
    if "categories" not in data:
        print(
            "WARNING: YAML file does not contain a 'categories' key. "
            "listrot's YAML parser expects the awesome-privacy schema "
            "(categories > sections > services). "
            "Use a .md file for standard markdown awesome lists.",
            file=sys.stderr,
        )
        return []

    entries: list[Entry] = []

    for category in data.get("categories") or []:
        cat_name = category.get("name", "")
        for section in category.get("sections") or []:
            sec_name = section.get("name", "")
            section_label = f"{cat_name} / {sec_name}" if cat_name and sec_name else (cat_name or sec_name)

            for service in section.get("services") or []:
                name = service.get("name", "")
                url = service.get("url", "")
                github_field = service.get("github", "")
                gitlab_field = service.get("gitlab", "")

                if github_field:
                    parsed = _parse_owner_repo(github_field, "github")
                    if parsed:
                        owner, repo = parsed
                        entries.append(Entry(
                            name=name,
                            url=_github_url(owner, repo),
                            section=section_label,
                            is_github=True,
                            is_gitlab=False,
                            owner=owner,
                            repo=repo,
                        ))
                        continue

                if gitlab_field:
                    parsed = _parse_owner_repo(gitlab_field, "gitlab")
                    if parsed:
                        owner, repo = parsed
                        entries.append(Entry(
                            name=name,
                            url=_gitlab_url(owner, repo),
                            section=section_label,
                            is_github=False,
                            is_gitlab=True,
                            owner=owner,
                            repo=repo,
                        ))
                        continue

                if not url:
                    continue

                is_github, is_gitlab, owner, repo = _classify(url)
                entries.append(Entry(
                    name=name,
                    url=url,
                    section=section_label,
                    is_github=is_github,
                    is_gitlab=is_gitlab,
                    owner=owner,
                    repo=repo,
                ))

    return entries
