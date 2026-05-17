# listrot

> **Archived** — This action doesn't meet my bar for quality and I'm out of ideas so I'm shutting it down before anyone actually consumes it. 

A GitHub Action that audits curated markdown lists for abandoned, unmaintained, or vulnerable entries.

Awesome lists can be awesomely handy. But the awesomeness quotient can be negatively impacted when they lead you to dead or dying destinations. No need to call Charon when you have this aspirationally awesome little bot to help you cull that massive link farm.

## What it does

1. Parses a markdown or YAML list file and extracts all linked projects
2. For GitHub and GitLab repos: queries the API and OSV.dev for maintenance health signals
3. For other URLs: crawls the page for a repo link, then falls back to a liveness check
4. Scores each entry and opens two GitHub Issues with results

## Supported list formats

**Markdown** — the default and most general format. Works with any list that follows the standard awesome list convention:

```markdown
- [Name](https://github.com/owner/repo) - Description.
- [Name](https://example.com) - Description. ([Source Code](https://github.com/owner/repo))
```

Both patterns are handled correctly. For entries with multiple links on one line, listrot uses the first link's text as the project name and the first GitHub or GitLab URL on the line as the audit target. This covers the common `[Name](homepage) ... ([Source Code](github))` pattern used by lists like [awesome-selfhosted](https://github.com/awesome-selfhosted/awesome-selfhosted).

**Table-format lists** are not currently supported — entries must be in list-item (`-`) form.

**YAML** — supports the [awesome-privacy](https://github.com/Lissy93/awesome-privacy) schema (`categories > sections > services`) with `github`, `gitlab`, and `url` fields. Other YAML schemas are not supported; listrot will warn and exit cleanly if the format is unrecognized.

## Usage

```yaml
- uses: SatanicMechanic/listrot@v0.1.4
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    list-file: README.md
```

See [`sample-workflow/maintenance-audit.yml`](sample-workflow/maintenance-audit.yml) for a full example with quarterly scheduling and output consumption.

## Inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | required | For API access and issue creation |
| `gitlab-token` | — | GitLab personal access token (`read_api` scope). Required for private GitLab repos; public repos work without it but may be rate-limited. |
| `list-file` | `README.md` | Path to the list file to audit (`.md`, `.yml`, `.yaml`) |
| `stale-commit-days` | `730` | Days since last push to flag stale |
| `stale-dep-days` | `180` | Days since last dep update to flag |
| `score-threshold` | `3` | Minimum soft score to surface in report |
| `issue-label` | `list-health-audit` | Label applied to both issue types |
| `create-issue` | `true` | Toggle issue creation; set to `false` for JSON-only output |
| `output-file` | `''` | Optional path to write JSON results |

## Outputs

| Output | Description |
|---|---|
| `hard-count` | Number of hard-flagged entries (deleted repos, dead URLs) |
| `soft-count` | Number of soft-flagged entries above the score threshold |
| `dead-count` | Number of dead or unreachable URLs |

## Scoring rubric

**Hard disqualifiers** — always surface, no threshold applies. Remove these entries.

| Signal | Detection |
|---|---|
| Repo not found | HTTP 404 from API — deleted, private, or moved |
| URL dead or unreachable | HTTP 4xx/5xx or connection failure |

> **Note on 404s:** A 404 means the linked repo does not exist at that URL. The project itself may still be active if it has moved (e.g., migrated to self-hosted git or renamed). Verify before removing.

**Soft scoring** — surface if total ≥ `score-threshold`:

| Signal | Points | Detection |
|---|---|---|
| Repo archived | +4 | `archived: true` in API response |
| No push > `stale-commit-days` | +3 | `pushed_at` / `last_activity_at` |
| No push > `stale-commit-days / 2` | +1 | `pushed_at` / `last_activity_at` |
| No release > 2 years (repos with releases only) | +1 | releases API |
| Dependency CVE with fix available, >30 days old | +1 | OSV.dev (GitHub only) |
| Dependency CVE with no fix available, >90 days old | +2 | OSV.dev (GitHub only) |

The two push staleness signals are mutually exclusive — a repo scores one or the other, not both.

> **Note on archived repos:** Archived ≠ abandoned. Some projects keep repos archived while the service runs normally. Treat `archived` as a prompt to verify, not a mandate to remove.

> **Note on CVEs:** listrot checks dependencies against OSV.dev by package name. It does not verify that your list entries consume affected versions — that requires a full dependency graph. CVE signals should be treated as an indicator, not a definitive finding.

**What to do with soft candidates:**

| Score | Signals | Suggested action |
|---|---|---|
| 3 | Push stale only | Check if intentionally "done" — stable software may not need commits. If clearly abandoned, remove. |
| 4–5 | Multiple staleness signals | Strong indication of abandonment. Remove unless you can verify active maintenance. |
| 6+ | All signals firing | Remove. |

## Issues created

**`[Auto] List Health Audit — YYYY-MM-DD`** — closed and re-opened fresh on each run. Contains:
- Hard disqualifiers
- Soft candidates with decision rubric
- Pass/skip counts

**`[Auto] Manual Review Queue`** — single persistent issue, updated in place. Contains:
- Dead or unreachable URLs
- Repos where dependency data was unavailable
- Items carried forward from prior runs

## Known limitations

**GitLab repos:** Staleness and archival signals work. CVE/dependency scanning is not supported — GitLab has no equivalent to GitHub's dependency graph SBOM API. GitLab repos will never produce `dep_cve_*` signals; this is noted in the audit issue footer when GitLab repos are present.

**GitHub dependency graph:** CVE scanning requires the dependency graph to be enabled on each repo (GitHub Settings → Security → Dependency graph; on by default for public repos). If disabled, the repo appears in the "no ecosystem data" count rather than failing or producing false signals.

**Non-repo URLs:** When an entry links to a project homepage rather than a GitHub or GitLab repo, listrot crawls the page for a repo link and audits that if found. It cannot verify the found link is the canonical source repo rather than a documentation theme, CI badge target, or unrelated dependency. Entries flagged via crawling should be spot-checked.

**Table-format lists:** Not currently supported. Entries must be in list-item (`-`) form.

## Permissions required

```yaml
permissions:
  issues: write
  contents: read
```

## License

CC0 1.0 Universal — see [LICENSE](LICENSE).
