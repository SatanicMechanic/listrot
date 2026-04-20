import time
import requests
from typing import Optional

GITHUB_API = "https://api.github.com"


class GitHubClient:
    def __init__(self, token: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _get(self, url: str, params: dict = None) -> requests.Response:
        backoff = 1
        for attempt in range(5):
            resp = self.session.get(url, params=params, timeout=20)
            if resp.status_code in (429, 403):
                retry_after = int(resp.headers.get("Retry-After", backoff * 2))
                time.sleep(retry_after)
                backoff = min(backoff * 2, 60)
                continue
            return resp
        return resp

    def get_repo(self, owner: str, repo: str) -> Optional[dict]:
        resp = self._get(f"{GITHUB_API}/repos/{owner}/{repo}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_dependency_sbom(self, owner: str, repo: str) -> Optional[dict]:
        resp = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/dependency-graph/sbom")
        if not resp.ok:
            return None
        return resp.json().get("sbom")

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        import base64
        resp = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}")
        if not resp.ok:
            return None
        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"].replace("\n", "")).decode("utf-8", errors="replace")
        return None

    def get_tree(self, owner: str, repo: str) -> list[str]:
        resp = self._get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/HEAD",
            params={"recursive": "1"},
        )
        if not resp.ok:
            return []
        data = resp.json()
        return [item["path"] for item in data.get("tree", []) if item.get("type") == "blob"]

    def get_latest_release(self, owner: str, repo: str) -> Optional[dict]:
        resp = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/releases/latest")
        if resp.status_code == 404:
            return None
        if not resp.ok:
            return None
        return resp.json()

    def create_issue(self, owner: str, repo: str, title: str, body: str, labels: list[str]) -> dict:
        resp = self.session.post(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues",
            json={"title": title, "body": body, "labels": labels},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()

    def update_issue(self, owner: str, repo: str, issue_number: int, body: str) -> dict:
        resp = self.session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{issue_number}",
            json={"body": body},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()

    def close_issue(self, owner: str, repo: str, issue_number: int) -> None:
        self.session.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/issues/{issue_number}",
            json={"state": "closed"},
            timeout=20,
        )

    def list_issues(self, owner: str, repo: str, label: str, state: str = "open") -> list[dict]:
        issues = []
        page = 1
        while True:
            resp = self._get(
                f"{GITHUB_API}/repos/{owner}/{repo}/issues",
                params={"labels": label, "state": state, "per_page": 100, "page": page},
            )
            if not resp.ok:
                break
            batch = resp.json()
            if not batch:
                break
            issues.extend(batch)
            page += 1
        return issues

    def ensure_label(self, owner: str, repo: str, label: str, color: str = "e4e669") -> None:
        resp = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/labels/{label}")
        if resp.status_code == 404:
            self.session.post(
                f"{GITHUB_API}/repos/{owner}/{repo}/labels",
                json={"name": label, "color": color},
                timeout=20,
            )
