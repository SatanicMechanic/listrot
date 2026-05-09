from datetime import date
from typing import Optional
from github_client import GitHubClient


def _md_escape(s: str) -> str:
    if not s:
        return s
    return s.replace('|', r'\|').replace('\r', '').replace('\n', ' ')

AUTO_TITLE_PREFIX = "[Auto] List Health Audit"
MANUAL_TITLE = "[Auto] Manual Review Queue"


def _auto_title() -> str:
    return f"{AUTO_TITLE_PREFIX} — {date.today().isoformat()}"


SOFT_RUBRIC = """\
### How to interpret soft candidates

| Score | Signals | Suggested action |
|---|---|---|
| 3 | Push stale only | Check if the project is intentionally "done" — stable software may not need commits. If clearly abandoned, remove. |
| 4–5 | Multiple staleness signals | Strong indication of abandonment. Remove unless you can verify active maintenance (forum, chat, releases). |
| 6+ | All signals firing | Remove. |

**Signal key:** `archived` = repo is archived (+4) · `push_very_stale` = no commit in >{stale_commit_days}d · `push_stale` = no commit in >{half_stale}d · `dep_stale` = dependencies not updated in >{stale_dep_days}d · `release_stale` = no release in >2yr · `dep_cve_upgrade` = dependency CVE with fix available, >30d old (+1) · `dep_cve_no_fix` = dependency CVE with no fix available, >90d old (+2)

> **Note:** CVE/dependency scanning is GitHub-only. GitLab repos are audited for staleness and archival signals only.
"""


def _build_auto_body(hard_flagged: list[dict], soft_flagged: list[dict],
                     skipped: int, passed: int,
                     stale_commit_days: int = 730, stale_dep_days: int = 180,
                     gitlab_count: int = 0) -> str:
    lines = ["# List Health Audit Report\n"]

    lines.append("## Hard Disqualifiers — remove these entries\n")
    lines.append("_These entries have an objective, verifiable problem. No judgment needed._\n")
    if hard_flagged:
        lines.append("| Entry | Section | Reason |")
        lines.append("|---|---|---|")
        for item in hard_flagged:
            lines.append(f"| [{_md_escape(item['name'])}]({item['url']}) | {_md_escape(item['section'] or '—')} | {_md_escape(item['reason'])} |")
    else:
        lines.append("_None found._")

    lines.append("\n## Soft Candidates — review and decide\n")
    if soft_flagged:
        rubric = SOFT_RUBRIC.format(
            stale_commit_days=stale_commit_days,
            half_stale=stale_commit_days // 2,
            stale_dep_days=stale_dep_days,
        )
        lines.append(rubric)
        lines.append("| Entry | Section | Score | Signals |")
        lines.append("|---|---|---|---|")
        for item in soft_flagged:
            signals = ", ".join(item.get("signals", []))
            lines.append(
                f"| [{_md_escape(item['name'])}]({item['url']}) | {_md_escape(item['section'] or '—')} "
                f"| {item['score']} | {signals} |"
            )
    else:
        lines.append("_None above threshold._")

    footer = f"_Entries skipped (no ecosystem data): {skipped} — Entries passed: {passed}_"
    if gitlab_count:
        footer += f"\n\n_Note: {gitlab_count} GitLab repo(s) in this list. CVE/dependency scanning is not supported for GitLab — staleness and archival signals only._"
    lines.append(f"\n---\n{footer}")
    return "\n".join(lines)


def _build_manual_body(dead_urls: list[dict], no_ecosystem: list[dict],
                       carried_forward: list[dict],
                       cve_entries: Optional[list[dict]] = None) -> str:
    lines = ["# Manual Review Queue\n",
             "_Items below require human review. Remove entries from this list once resolved._\n"]

    lines.append("## Dependency CVEs Detected\n")
    lines.append("_These entries have known CVEs in their dependencies. Specific CVE IDs are listed for investigation. listrot checks by package name only — verify affected versions before acting._\n")
    cve_entries = cve_entries or []
    if cve_entries:
        lines.append("| Entry | Section | CVE IDs |")
        lines.append("|---|---|---|")
        for item in cve_entries:
            ids = ", ".join(f"[{v}](https://osv.dev/vulnerability/{v})" for v in item.get("cve_ids", []))
            lines.append(f"| [{_md_escape(item['name'])}]({item['url']}) | {_md_escape(item['section'] or '—')} | {ids} |")
    else:
        lines.append("_None._")

    lines.append("\n## Dead or Unreachable URLs\n")
    if dead_urls:
        lines.append("| Entry | Section | URL | Reason |")
        lines.append("|---|---|---|---|")
        for item in dead_urls:
            lines.append(
                f"| {_md_escape(item['name'])} | {_md_escape(item['section'] or '—')} "
                f"| {item['url']} | {_md_escape(item.get('reason', ''))} |"
            )
    else:
        lines.append("_None._")

    lines.append("\n## Repos — Dependency Data Unavailable\n")
    if no_ecosystem:
        lines.append("| Entry | Section | URL |")
        lines.append("|---|---|---|")
        for item in no_ecosystem:
            lines.append(f"| [{_md_escape(item['name'])}]({item['url']}) | {_md_escape(item['section'] or '—')} | {item['url']} |")
    else:
        lines.append("_None._")

    lines.append("\n## Carried Forward from Prior Runs\n")
    if carried_forward:
        lines.append("| Entry | Section | URL | Note |")
        lines.append("|---|---|---|---|")
        for item in carried_forward:
            lines.append(
                f"| [{_md_escape(item['name'])}]({item['url']}) | {_md_escape(item['section'] or '—')} "
                f"| {item['url']} | {_md_escape(item.get('note', ''))} |"
            )
    else:
        lines.append("_None._")

    return "\n".join(lines)


class IssueManager:
    def __init__(self, client: GitHubClient, owner: str, repo: str, label: str):
        self.client = client
        self.owner = owner
        self.repo = repo
        self.label = label
        self._ensure_labels()

    def _ensure_labels(self):
        self.client.ensure_label(self.owner, self.repo, self.label)
        self.client.ensure_label(self.owner, self.repo, "automated", color="0075ca")
        self.client.ensure_label(self.owner, self.repo, "needs-human-review", color="d93f0b")

    def publish_audit_issue(self, hard_flagged: list[dict], soft_flagged: list[dict],
                            skipped: int, passed: int,
                            stale_commit_days: int = 730, stale_dep_days: int = 180,
                            gitlab_count: int = 0) -> dict:
        existing = [
            i for i in self.client.list_issues(self.owner, self.repo, self.label)
            if i["title"].startswith(AUTO_TITLE_PREFIX)
        ]
        for issue in existing:
            self.client.close_issue(self.owner, self.repo, issue["number"])

        body = _build_auto_body(hard_flagged, soft_flagged, skipped, passed,
                                stale_commit_days, stale_dep_days, gitlab_count)
        return self.client.create_issue(
            self.owner, self.repo,
            title=_auto_title(),
            body=body,
            labels=[self.label, "automated"],
        )

    def publish_manual_issue(self, dead_urls: list[dict], no_ecosystem: list[dict],
                             carried_forward: list[dict],
                             cve_entries: Optional[list[dict]] = None) -> dict:
        existing = [
            i for i in self.client.list_issues(self.owner, self.repo, self.label)
            if i["title"] == MANUAL_TITLE
        ]
        body = _build_manual_body(dead_urls, no_ecosystem, carried_forward, cve_entries)
        if existing:
            issue = existing[0]
            return self.client.update_issue(self.owner, self.repo, issue["number"], body)
        return self.client.create_issue(
            self.owner, self.repo,
            title=MANUAL_TITLE,
            body=body,
            labels=[self.label, "needs-human-review"],
        )
