import time
import requests
from typing import Optional
from urllib.parse import quote

GITLAB_API = "https://gitlab.com/api/v4"


class GitLabClient:
    def __init__(self, token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json'})
        if token:
            self.session.headers['PRIVATE-TOKEN'] = token

    def _get(self, url: str, params: dict = None) -> requests.Response:
        backoff = 1
        for attempt in range(5):
            resp = self.session.get(url, params=params, timeout=20)
            if resp.status_code in (429, 403):
                retry_after = int(resp.headers.get('Retry-After', backoff * 2))
                time.sleep(retry_after)
                backoff = min(backoff * 2, 60)
                continue
            return resp
        return resp

    def get_project(self, owner: str, repo: str) -> Optional[dict]:
        encoded = quote(f"{owner}/{repo}", safe='')
        resp = self._get(f"{GITLAB_API}/projects/{encoded}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_file_content(self, project_id: int, path: str) -> Optional[str]:
        encoded_path = quote(path, safe="")
        resp = self._get(
            f"{GITLAB_API}/projects/{project_id}/repository/files/{encoded_path}/raw",
            params={"ref": "HEAD"},
        )
        if not resp.ok:
            return None
        return resp.text

    def get_tree(self, project_id: int) -> list[str]:
        resp = self._get(
            f"{GITLAB_API}/projects/{project_id}/repository/tree",
            params={"per_page": 100},
        )
        if not resp.ok:
            return []
        return [item["name"] for item in resp.json() if item.get("type") == "blob"]

    def get_latest_release(self, project_id: int) -> Optional[dict]:
        resp = self._get(
            f"{GITLAB_API}/projects/{project_id}/releases",
            params={"per_page": 1},
        )
        if not resp.ok:
            return None
        releases = resp.json()
        return releases[0] if releases else None
