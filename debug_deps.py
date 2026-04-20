"""Diagnostic: trace dep scanning for a single repo."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import requests as req_lib
from github_client import GitHubClient
from dep_scanner import _sbom_to_queries, _query_deps

token = os.environ.get("GITHUB_TOKEN", "")
if not token:
    print("ERROR: GITHUB_TOKEN not set")
    sys.exit(1)

owner, repo = (sys.argv[1].split("/") if len(sys.argv) > 1 else ("laurent22", "joplin"))

client = GitHubClient(token)

print(f"Fetching SBOM for {owner}/{repo}...")
GITHUB_API = "https://api.github.com"
raw = client._get(f"{GITHUB_API}/repos/{owner}/{repo}/dependency-graph/sbom")
print(f"SBOM HTTP status: {raw.status_code}")
if not raw.ok:
    print(f"SBOM error body: {raw.text[:500]}")
    sys.exit(1)
sbom = raw.json().get("sbom")
if not sbom:
    print("SBOM: parsed ok but 'sbom' key missing in response")
    print(f"Keys present: {list(raw.json().keys())}")
    sys.exit(1)

packages = sbom.get("packages", [])
print(f"SBOM packages: {len(packages)}")

queries = _sbom_to_queries(sbom)
print(f"Recognisable queries (known ecosystem): {len(queries)}")
if queries:
    print("  Sample (first 5):")
    for q in queries[:5]:
        print(f"    {q['package']['ecosystem']}  {q['package']['name']}@{q['version']}")

if not queries:
    sys.exit(0)

print(f"\nQuerying OSV for {len(queries)} packages...")
result = _query_deps(queries)
print(f"Oldest fixable CVE age : {result.oldest_fixable_days} days")
print(f"Oldest unfixed CVE age : {result.oldest_unfixed_days} days")

# Sanity check with known-vulnerable packages.
import requests as _req, json as _json

def _osv_check(pkg_name, ecosystem, version):
    print(f"\nOSV check: {ecosystem}/{pkg_name}@{version}")
    _resp = _req.post("https://api.osv.dev/v1/querybatch", json={"queries": [
        {"package": {"name": pkg_name, "ecosystem": ecosystem}, "version": version}
    ]}, timeout=15)
    _results = _resp.json().get("results", [{}])
    _vulns = _results[0].get("vulns", []) if _results else []
    print(f"  HTTP {_resp.status_code}, vulns returned: {len(_vulns)}")
    if _vulns:
        v = _vulns[0]
        print(f"  First vuln keys: {list(v.keys())}")
        print(f"  id={v.get('id')}  published={v.get('published')!r}  modified={v.get('modified')!r}")

_osv_check("lodash", "npm", "4.17.20")
_osv_check("json5", "npm", "1.0.1")
