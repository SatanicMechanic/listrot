from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote
import re
import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 500

PURL_ECOSYSTEM_MAP = {
    "npm":     "npm",
    "pypi":    "PyPI",
    "golang":  "Go",
    "cargo":   "crates.io",
    "gem":     "RubyGems",
    "maven":   "Maven",
}


def _parse_purl(purl: str) -> Optional[tuple[str, str, str]]:
    """Return (osv_ecosystem, name, version) from a PURL, or None if unrecognised."""
    m = re.match(r'pkg:([^/]+)/(.+?)@([^?#\s]+)', purl)
    if not m:
        return None
    pkg_type, path, version = m.group(1).lower(), unquote(m.group(2)), m.group(3).strip()
    ecosystem = PURL_ECOSYSTEM_MAP.get(pkg_type)
    if not ecosystem:
        return None
    if pkg_type == "maven":
        # "groupId/artifactId" → "groupId:artifactId" for OSV
        parts = path.split("/", 1)
        name = ":".join(parts) if len(parts) == 2 else path
    elif pkg_type == "golang":
        name = path  # full module path, e.g. github.com/gin-gonic/gin
    else:
        name = path.split("/")[-1]
    return ecosystem, name, version


def _sbom_to_queries(sbom: dict) -> list[dict]:
    queries = []
    for pkg in sbom.get("packages", []):
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") != "purl":
                continue
            parsed = _parse_purl(ref.get("referenceLocator", ""))
            if parsed:
                ecosystem, name, version = parsed
                queries.append({"package": {"name": name, "ecosystem": ecosystem},
                                 "version": version})
                break
    return queries


def _has_fix(vuln: dict) -> bool:
    for affected in vuln.get("affected", []):
        for range_ in affected.get("ranges", []):
            for event in range_.get("events", []):
                if "fixed" in event:
                    return True
    return False


def _age_days(date_str: str) -> Optional[int]:
    try:
        if date_str.endswith("Z"):
            date_str = date_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


class DepCveResult:
    __slots__ = ("oldest_unfixed_days", "oldest_fixable_days", "cve_ids")

    def __init__(self, oldest_unfixed_days: Optional[int], oldest_fixable_days: Optional[int],
                 cve_ids: Optional[list] = None):
        self.oldest_unfixed_days = oldest_unfixed_days
        self.oldest_fixable_days = oldest_fixable_days
        self.cve_ids = cve_ids or []


OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"


def _query_deps(queries: list[dict], timeout: int = 30) -> DepCveResult:
    # Step 1: batch query to discover which CVE IDs affect this package set.
    # The batch API only returns id + modified — no affected/fix data.
    vuln_ids: set[str] = set()
    for i in range(0, len(queries), OSV_BATCH_SIZE):
        batch = queries[i:i + OSV_BATCH_SIZE]
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": batch}, timeout=timeout)
            resp.raise_for_status()
            for result in resp.json().get("results", []):
                for vuln in result.get("vulns", []):
                    if vuln.get("id"):
                        vuln_ids.add(vuln["id"])
        except requests.RequestException:
            continue

    if not vuln_ids:
        return DepCveResult(None, None)

    # Step 2: fetch full vuln details for each unique CVE to get published date
    # and fix availability. Per-repo CVE counts are small so this is cheap.
    oldest_unfixed: Optional[int] = None
    oldest_fixable: Optional[int] = None
    for vuln_id in vuln_ids:
        try:
            resp = requests.get(OSV_VULN_URL.format(vuln_id), timeout=timeout)
            if not resp.ok:
                continue
            vuln = resp.json()
        except requests.RequestException:
            continue
        age = _age_days(vuln.get("published") or vuln.get("modified", ""))
        if age is None:
            continue
        if _has_fix(vuln):
            oldest_fixable = max(oldest_fixable or 0, age)
        else:
            oldest_unfixed = max(oldest_unfixed or 0, age)

    return DepCveResult(oldest_unfixed, oldest_fixable, cve_ids=sorted(vuln_ids))


def scan_github_deps(owner: str, repo: str, client) -> DepCveResult:
    """
    Query the GitHub dependency graph SBOM, check each package against OSV.dev.
    Returns a DepCveResult with oldest unfixed and oldest fixable CVE ages in days.
    """
    sbom = client.get_dependency_sbom(owner, repo)
    if not sbom:
        return DepCveResult(None, None)
    queries = _sbom_to_queries(sbom)
    if not queries:
        return DepCveResult(None, None)
    return _query_deps(queries)
