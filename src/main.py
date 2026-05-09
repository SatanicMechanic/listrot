import json
import os
import sys
import time
from typing import Optional

from github_client import GitHubClient
from gitlab_client import GitLabClient
from markdown_parser import parse_entries as parse_markdown, Entry, _classify
from yaml_parser import parse_entries as parse_yaml
from ecosystem_detector import detect_ecosystem
from dep_scanner import scan_github_deps, DepCveResult
from scorer import score_entry, HardFlag
from issue_manager import IssueManager
from http_checker import check_url


def get_env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _write_github_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{key}={value}\n")


def _sanitize_annotation(s: str) -> str:
    return s.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def _annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub Actions workflow annotation (no-op outside Actions)."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level} title={_sanitize_annotation(title)}::{_sanitize_annotation(message)}")


def parse_only(list_file: str) -> None:
    try:
        with open(list_file, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"ERROR: file not found: {list_file}", file=sys.stderr)
        sys.exit(1)

    ext = os.path.splitext(list_file)[1].lower()
    entries = parse_yaml(text) if ext in (".yml", ".yaml") else parse_markdown(text)

    github_entries = [e for e in entries if e.is_github]
    gitlab_entries = [e for e in entries if e.is_gitlab]
    other_entries = [e for e in entries if not e.is_github and not e.is_gitlab]

    sections = {}
    for e in entries:
        sections.setdefault(e.section, 0)
        sections[e.section] += 1

    print(f"\nFile: {list_file}")
    print(f"Total entries : {len(entries)}")
    print(f"  GitHub repos: {len(github_entries)}")
    print(f"  GitLab repos: {len(gitlab_entries)}")
    print(f"  Other URLs  : {len(other_entries)}")
    print(f"  Sections    : {len(sections)}")
    print("\nSections:")
    for sec, count in sorted(sections.items(), key=lambda x: -x[1]):
        print(f"  {count:4d}  {sec or '(no section)'}")
    print("\nSample entries (first 10):")
    for e in entries[:10]:
        platform = f"[{e.owner}/{e.repo}]" if (e.is_github or e.is_gitlab) else ""
        print(f"  {e.name!r:40s} {e.section or ''} {platform}")


def _audit_github_entry(e: Entry, client: GitHubClient, stale_commit_days: int,
                         stale_dep_days: int) -> tuple[Optional[dict], bool]:
    """Return (entry_record, no_ecosystem). entry_record is None if no signals."""
    repo_data = client.get_repo(e.owner, e.repo)
    if repo_data is None:
        return {"name": e.name, "url": e.url, "section": e.section,
                "hard_flag": "deleted", "reason": "Repo not found (404) — deleted, private, or moved"}, False

    archived = repo_data.get("archived", False)
    pushed_at = repo_data.get("pushed_at")
    cve = scan_github_deps(e.owner, e.repo, client)
    tree_paths = client.get_tree(e.owner, e.repo)
    ecosystem = detect_ecosystem(tree_paths) if tree_paths else None
    release_data = client.get_latest_release(e.owner, e.repo)
    has_releases = release_data is not None
    latest_release_at = release_data.get("published_at") if release_data else None

    result = score_entry(
        archived=archived,
        cve_unfixed_days=cve.oldest_unfixed_days,
        cve_fixable_days=cve.oldest_fixable_days,
        pushed_at=pushed_at, latest_release_at=latest_release_at,
        has_releases=has_releases, stale_commit_days=stale_commit_days,
        stale_dep_days=stale_dep_days,
    )
    record = {
        "name": e.name, "url": e.url, "section": e.section,
        "score": result.score, "signals": result.signals,
        "hard_flag": result.hard_flag.value if result.hard_flag else None,
    }
    if result.hard_flag:
        record["reason"] = _hard_flag_reason(result.hard_flag)
    if cve.cve_ids:
        record["cve_ids"] = cve.cve_ids
    return record, not ecosystem


def _audit_gitlab_entry(e: Entry, client: GitLabClient, stale_commit_days: int,
                          stale_dep_days: int) -> tuple[Optional[dict], bool]:
    project = client.get_project(e.owner, e.repo)
    if project is None:
        return {"name": e.name, "url": e.url, "section": e.section,
                "hard_flag": "deleted", "reason": "Repo not found (404) — deleted, private, or moved"}, False

    archived = project.get("archived", False)
    pushed_at = project.get("last_activity_at")
    project_id = project["id"]
    tree_paths = client.get_tree(project_id)
    ecosystem = detect_ecosystem(tree_paths) if tree_paths else None
    release_data = client.get_latest_release(project_id)
    has_releases = release_data is not None
    latest_release_at = release_data.get("released_at") if release_data else None

    result = score_entry(
        archived=archived, cve_unfixed_days=None,
        pushed_at=pushed_at, latest_release_at=latest_release_at,
        has_releases=has_releases, stale_commit_days=stale_commit_days,
        stale_dep_days=stale_dep_days,
    )
    record = {
        "name": e.name, "url": e.url, "section": e.section,
        "score": result.score, "signals": result.signals,
        "hard_flag": result.hard_flag.value if result.hard_flag else None,
    }
    if result.hard_flag:
        record["reason"] = _hard_flag_reason(result.hard_flag)
    return record, not ecosystem


def _hard_flag_reason(flag: HardFlag) -> str:
    return {
        HardFlag.DELETED: "Repo not found (404) — deleted, private, or moved",
    }.get(flag, str(flag))


def main():
    parse_only_file = get_env("PARSE_ONLY")
    if parse_only_file:
        parse_only(parse_only_file)
        return

    token = get_env("GITHUB_TOKEN") or get_env("INPUT_GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN is required", file=sys.stderr)
        sys.exit(1)

    gitlab_token = get_env("GITLAB_TOKEN") or get_env("INPUT_GITLAB_TOKEN")

    list_file = get_env("MARKDOWN_FILE", "README.md")
    stale_commit_days = int(get_env("STALE_COMMIT_DAYS", "730"))
    stale_dep_days = int(get_env("STALE_DEP_DAYS", "180"))
    score_threshold = int(get_env("SCORE_THRESHOLD", "3"))
    issue_label = get_env("ISSUE_LABEL", "list-health-audit")
    create_issue = get_env("CREATE_ISSUE", "true").lower() == "true"
    output_file = get_env("OUTPUT_FILE", "")

    target_repo = get_env("GITHUB_REPOSITORY")
    if create_issue and (not target_repo or "/" not in target_repo):
        print(
            "ERROR: GITHUB_REPOSITORY must be set when CREATE_ISSUE=true. "
            "This is set automatically in GitHub Actions. "
            "For local runs, set CREATE_ISSUE=false or set GITHUB_REPOSITORY=owner/repo.",
            file=sys.stderr,
        )
        sys.exit(1)
    target_owner, target_repo_name = target_repo.split("/", 1) if target_repo else (None, None)

    try:
        with open(list_file, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"ERROR: file not found: {list_file}", file=sys.stderr)
        sys.exit(1)

    ext = os.path.splitext(list_file)[1].lower()
    entries = parse_yaml(text) if ext in (".yml", ".yaml") else parse_markdown(text)
    if not entries:
        print("ERROR: no entries parsed — check your list file format.", file=sys.stderr)
        sys.exit(1)
    print(f"Parsed {len(entries)} entries from {list_file}")

    gh_client = GitHubClient(token)
    gl_client = GitLabClient(token=gitlab_token or None)

    if not gitlab_token:
        gitlab_entries_count = sum(1 for e in entries if e.is_gitlab)
        if gitlab_entries_count:
            print(f"Note: {gitlab_entries_count} GitLab repo(s) found. "
                  "No GITLAB_TOKEN set — unauthenticated requests may be rate-limited.")

    hard_flagged = []
    soft_flagged = []
    no_ecosystem = []
    dead_urls = []
    passed = 0
    skipped = 0

    seen = set()

    # --- GitHub entries ---
    github_entries = [e for e in entries if e.is_github]
    total_gh = len(github_entries)
    print(f"Auditing {total_gh} GitHub repos...")
    for i, e in enumerate(github_entries, 1):
        key = ("github", e.owner, e.repo)
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        if i % 25 == 0 or i == total_gh:
            print(f"  GitHub: {i}/{total_gh}")
        time.sleep(0.3)

        record, missing_ecosystem = _audit_github_entry(e, gh_client, stale_commit_days, stale_dep_days)
        if missing_ecosystem:
            no_ecosystem.append({"name": e.name, "url": e.url, "section": e.section})

        _route_record(record, hard_flagged, soft_flagged, score_threshold, passed_counter := [0])
        passed += passed_counter[0]

    # --- GitLab entries ---
    gitlab_entries = [e for e in entries if e.is_gitlab]
    total_gl = len(gitlab_entries)
    if total_gl:
        print(f"Auditing {total_gl} GitLab repos... (note: CVE scanning not supported for GitLab)")
    for i, e in enumerate(gitlab_entries, 1):
        key = ("gitlab", e.owner, e.repo)
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        if i % 25 == 0 or i == total_gl:
            print(f"  GitLab: {i}/{total_gl}")
        time.sleep(0.3)

        record, missing_ecosystem = _audit_gitlab_entry(e, gl_client, stale_commit_days, stale_dep_days)
        if missing_ecosystem:
            no_ecosystem.append({"name": e.name, "url": e.url, "section": e.section})

        _route_record(record, hard_flagged, soft_flagged, score_threshold, passed_counter := [0])
        passed += passed_counter[0]

    # --- Other URLs: crawl for repo links, then liveness check ---
    other_entries = [e for e in entries if not e.is_github and not e.is_gitlab]
    total_other = len(other_entries)
    if total_other:
        print(f"Checking {total_other} non-git URLs...")
    for i, e in enumerate(other_entries, 1):
        if i % 25 == 0 or i == total_other:
            print(f"  Other: {i}/{total_other}")
        time.sleep(0.2)
        liveness = check_url(e.url)

        if liveness.status in ('dead', 'unreachable'):
            dead_urls.append({
                "name": e.name, "url": e.url, "section": e.section,
                "reason": f"HTTP {liveness.code}" if liveness.code else "unreachable",
            })
            continue

        if liveness.repo_url:
            is_github, is_gitlab, owner, repo = _classify(liveness.repo_url)
            if not is_github and not is_gitlab:
                passed += 1
                continue
            key = ("github" if is_github else "gitlab", owner, repo)
            if key in seen:
                passed += 1
                continue
            seen.add(key)

            discovered = Entry(
                name=e.name, url=liveness.repo_url, section=e.section,
                is_github=is_github, is_gitlab=is_gitlab, owner=owner, repo=repo,
            )
            time.sleep(0.3)
            if is_github:
                record, missing_ecosystem = _audit_github_entry(
                    discovered, gh_client, stale_commit_days, stale_dep_days)
            else:
                record, missing_ecosystem = _audit_gitlab_entry(
                    discovered, gl_client, stale_commit_days, stale_dep_days)

            if missing_ecosystem:
                no_ecosystem.append({"name": e.name, "url": e.url, "section": e.section})

            _route_record(record, hard_flagged, soft_flagged, score_threshold, passed_counter := [0])
            passed += passed_counter[0]
        else:
            passed += 1

    print(f"Hard flagged: {len(hard_flagged)}, Soft candidates: {len(soft_flagged)}, "
          f"Passed: {passed}, Dead URLs: {len(dead_urls)}, No ecosystem: {len(no_ecosystem)}")

    for item in hard_flagged:
        _annotate("error", f"Hard flag — {item['name']}",
                  f"{item.get('reason', 'deleted')} | {item['url']}")
    for item in dead_urls:
        _annotate("error", f"Dead URL — {item['name']}",
                  f"{item.get('reason', 'unreachable')} | {item['url']}")
    for item in soft_flagged:
        signals = ", ".join(item.get("signals", []))
        _annotate("warning", f"Soft candidate — {item['name']} (score {item['score']})",
                  f"{signals} | {item['url']}")

    _write_github_output("hard-count", str(len(hard_flagged)))
    _write_github_output("soft-count", str(len(soft_flagged)))
    _write_github_output("dead-count", str(len(dead_urls)))

    all_results = {
        "hard_flagged": hard_flagged,
        "soft_flagged": soft_flagged,
        "dead_urls": dead_urls,
        "no_ecosystem": no_ecosystem,
        "passed": passed,
        "skipped": skipped,
    }

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        print(f"Results written to {output_file}")

    if create_issue:
        gitlab_count = len([e for e in entries if e.is_gitlab])
        manager = IssueManager(gh_client, target_owner, target_repo_name, issue_label)
        audit_issue = manager.publish_audit_issue(
            hard_flagged, soft_flagged,
            skipped=skipped + len(no_ecosystem),
            passed=passed,
            stale_commit_days=stale_commit_days,
            stale_dep_days=stale_dep_days,
            gitlab_count=gitlab_count,
        )
        print(f"Audit issue: {audit_issue.get('html_url', audit_issue.get('url', ''))}")

        cve_entries = [r for r in soft_flagged + hard_flagged if r.get("cve_ids")]
        manual_issue = manager.publish_manual_issue(
            dead_urls, no_ecosystem, carried_forward=[], cve_entries=cve_entries)
        print(f"Manual review issue: {manual_issue.get('html_url', manual_issue.get('url', ''))}")


def _route_record(record: dict, hard_flagged: list, soft_flagged: list,
                  threshold: int, passed_counter: list) -> None:
    if record.get("hard_flag"):
        hard_flagged.append(record)
    elif record.get("score", 0) >= threshold:
        soft_flagged.append(record)
    else:
        passed_counter[0] = 1


if __name__ == "__main__":
    main()
