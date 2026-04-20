from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import requests

OSV_URL = "https://api.osv.dev/v1/query"

ECOSYSTEM_PACKAGE_MAP = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Go": "Go",
    "crates.io": "crates.io",
    "RubyGems": "RubyGems",
    "Maven": "Maven",
}


@dataclass
class VulnInfo:
    has_fix: bool
    severity: str       # "critical", "high", "other"
    age_days: Optional[int]


@dataclass
class OsvResult:
    vulns: list[VulnInfo] = field(default_factory=list)

    @property
    def has_fixed(self) -> bool:
        return any(v.has_fix for v in self.vulns)

    @property
    def has_unfixed(self) -> bool:
        return any(not v.has_fix for v in self.vulns)

    @property
    def oldest_unfixed_days(self) -> Optional[int]:
        ages = [v.age_days for v in self.vulns if not v.has_fix and v.age_days is not None]
        return max(ages) if ages else None

    def oldest_unfixed_age(self) -> Optional[int]:
        """Age in days of the oldest CVE with no available fix."""
        return self.oldest_unfixed_days


def _has_fix(vuln: dict) -> bool:
    for affected in vuln.get("affected", []):
        for range_ in affected.get("ranges", []):
            for event in range_.get("events", []):
                if "fixed" in event:
                    return True
    return False


def _get_severity(vuln: dict) -> str:
    for source in (vuln.get("database_specific", {}), vuln.get("ecosystem_specific", {})):
        s = source.get("severity", "").upper()
        if s == "CRITICAL":
            return "critical"
        if s == "HIGH":
            return "high"
        if s:
            return "other"
    return "other"


def _days_since(date_str: str) -> Optional[int]:
    try:
        if date_str.endswith('Z'):
            date_str = date_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def query_osv(package_name: str, ecosystem: str, timeout: int = 15) -> OsvResult:
    osv_ecosystem = ECOSYSTEM_PACKAGE_MAP.get(ecosystem)
    if not osv_ecosystem:
        return OsvResult()

    payload = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
    try:
        resp = requests.post(OSV_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        vulns = resp.json().get("vulns") or []
    except requests.RequestException:
        return OsvResult()

    return OsvResult(vulns=[
        VulnInfo(
            has_fix=_has_fix(v),
            severity=_get_severity(v),
            age_days=_days_since(v.get("published", "")),
        )
        for v in vulns
    ])
