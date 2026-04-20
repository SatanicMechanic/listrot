"""Generate sample-report.html from results.json."""
import json
import sys
from datetime import date

results_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/results.json"
output_path = sys.argv[2] if len(sys.argv) > 2 else "sample-report.html"

with open(results_path) as f:
    r = json.load(f)


def signals_html(signals):
    return "".join(f'<span class="signal">{s}</span>' for s in signals)


def score_class(score):
    if score >= 6:
        return "score-high"
    if score >= 4:
        return "score-mid"
    return "score-low"


hard_rows = "\n".join(
    f'<tr><td><a href="{x["url"]}">{x["name"]}</a></td>'
    f'<td>{x["section"] or "—"}</td>'
    f'<td><span class="badge badge-red">deleted</span> {x.get("reason", "")}</td></tr>'
    for x in r["hard_flagged"]
)

soft_rows = "\n".join(
    f'<tr><td><a href="{x["url"]}">{x["name"]}</a></td>'
    f'<td>{x["section"] or "—"}</td>'
    f'<td class="{score_class(x["score"])}">{x["score"]}</td>'
    f'<td>{signals_html(x.get("signals", []))}</td></tr>'
    for x in sorted(r["soft_flagged"], key=lambda x: -x["score"])
)

dead_rows = "\n".join(
    f'<tr><td>{x["name"]}</td>'
    f'<td><a href="{x["url"]}">{x["url"]}</a></td>'
    f'<td>{x.get("reason", "")}</td></tr>'
    for x in r["dead_urls"]
)

no_eco_count = len(r.get("no_ecosystem", []))
passed = r.get("passed", 0)
skipped = r.get("skipped", 0)
run_date = date.today().isoformat()

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>List Health Audit — {run_date}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; line-height: 1.6; color: #24292f; background: #f6f8fa; padding: 24px; }}
  .container {{ max-width: 960px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 32px; }}
  h1 {{ font-size: 20px; font-weight: 600; border-bottom: 1px solid #d0d7de; padding-bottom: 12px; margin-bottom: 20px; }}
  h2 {{ font-size: 16px; font-weight: 600; margin: 28px 0 10px; }}
  h3 {{ font-size: 14px; font-weight: 600; margin: 20px 0 8px; color: #57606a; }}
  p {{ margin: 8px 0; color: #57606a; font-size: 13px; }}
  hr {{ border: none; border-top: 1px solid #d0d7de; margin: 24px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }}
  th {{ background: #f6f8fa; font-weight: 600; text-align: left; padding: 8px 12px; border: 1px solid #d0d7de; }}
  td {{ padding: 7px 12px; border: 1px solid #d0d7de; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #f6f8fa; }}
  code {{ font-family: ui-monospace, monospace; font-size: 12px; background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 3px; padding: 1px 5px; }}
  .badge {{ display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 10px; white-space: nowrap; }}
  .badge-red {{ background: #ffebe9; color: #cf222e; border: 1px solid #ff8182; }}
  .score-high {{ color: #cf222e; font-weight: 700; }}
  .score-mid {{ color: #9a6700; font-weight: 600; }}
  .score-low {{ color: #57606a; }}
  .signal {{ font-family: ui-monospace, monospace; font-size: 11px; display: inline-block; background: #ddf4ff; color: #0969da; border: 1px solid #54aeff80; border-radius: 3px; padding: 1px 5px; margin: 1px 2px 1px 0; }}
  .meta {{ font-size: 12px; color: #57606a; margin-top: 24px; padding-top: 12px; border-top: 1px solid #d0d7de; }}
  .callout {{ background: #ddf4ff; border: 1px solid #54aeff; border-radius: 6px; padding: 10px 14px; margin: 10px 0; font-size: 13px; color: #0550ae; }}
  a {{ color: #0969da; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .empty {{ color: #57606a; font-style: italic; padding: 10px 0; }}
</style>
</head>
<body>
<div class="container">

  <h1>[Auto] List Health Audit — {run_date}</h1>

  <hr>

  <h2>Hard Disqualifiers — remove these entries</h2>
  <p>These entries have an objective, verifiable problem. No judgment needed.</p>
  {'<table><thead><tr><th>Entry</th><th>Section</th><th>Reason</th></tr></thead><tbody>' + hard_rows + '</tbody></table>' if hard_rows else '<p class="empty">None found.</p>'}

  <hr>

  <h2>Soft Candidates — review and decide</h2>

  <h3>How to interpret</h3>
  <table>
    <thead><tr><th>Score</th><th>Signals</th><th>Suggested action</th></tr></thead>
    <tbody>
      <tr><td>3</td><td>Push stale only</td><td>Check if the project is intentionally "done" — stable software may not need commits. If clearly abandoned, remove.</td></tr>
      <tr><td>4–5</td><td>Multiple staleness signals</td><td>Strong indication of abandonment. Remove unless you can verify active maintenance.</td></tr>
      <tr><td>6+</td><td>All signals firing</td><td>Remove.</td></tr>
    </tbody>
  </table>

  <div class="callout">
    <strong>Signal key:</strong>
    <code>archived</code> repo is archived (+4) ·
    <code>push_very_stale</code> no commit in &gt;730d (+3) ·
    <code>push_stale</code> no commit in &gt;365d (+1) ·
    <code>release_stale</code> no release in &gt;2yr (+1) ·
    <code>dep_cve_no_fix</code> dependency CVE with no fix available, &gt;90d old (+2)
  </div>

  {'<table><thead><tr><th>Entry</th><th>Section</th><th>Score</th><th>Signals</th></tr></thead><tbody>' + soft_rows + '</tbody></table>' if soft_rows else '<p class="empty">None above threshold.</p>'}

  <hr>

  <h2>Manual Review Queue</h2>

  <h3>Dead or Unreachable URLs</h3>
  <p>403/429 responses (bot-blocking) are excluded — those sites are up.</p>
  {'<table><thead><tr><th>Entry</th><th>URL</th><th>Reason</th></tr></thead><tbody>' + dead_rows + '</tbody></table>' if dead_rows else '<p class="empty">None.</p>'}

  <h3>Repos — Dependency Data Unavailable</h3>
  <p>{no_eco_count} entries had no detectable dependency ecosystem. Dependency CVE scanning was skipped; all other signals still applied.</p>

  <div class="meta">Skipped (no ecosystem): {no_eco_count} · Skipped (duplicate): {skipped} · Passed: {passed}</div>

</div>
</body>
</html>"""

with open(output_path, "w") as f:
    f.write(html)

print(f"Written to {output_path}")
print(f"Hard: {len(r['hard_flagged'])} · Soft: {len(r['soft_flagged'])} · Dead: {len(r['dead_urls'])} · Passed: {passed}")
