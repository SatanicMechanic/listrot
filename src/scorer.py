from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class HardFlag(Enum):
    DELETED = "deleted"


@dataclass
class ScoreResult:
    hard_flag: Optional[HardFlag] = None
    score: int = 0
    signals: list[str] = field(default_factory=list)

    def meets_threshold(self, threshold: int) -> bool:
        return self.score >= threshold

    def should_surface(self, threshold: int) -> bool:
        return self.hard_flag is not None or self.meets_threshold(threshold)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    if value.endswith('Z'):
        value = value[:-1] + '+00:00'
    return datetime.fromisoformat(value)


def _days_since(dt: Optional[datetime]) -> Optional[float]:
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt).total_seconds() / 86400


def score_entry(
    deleted: bool = False,
    archived: bool = False,
    cve_unfixed_days: Optional[int] = None,
    cve_unfixed_grace_days: int = 90,
    cve_fixable_days: Optional[int] = None,
    cve_fixable_grace_days: int = 30,
    pushed_at: Optional[str] = None,
    dep_updated_at: Optional[str] = None,
    latest_release_at: Optional[str] = None,
    has_releases: bool = False,
    stale_commit_days: int = 730,
    stale_dep_days: int = 180,
) -> ScoreResult:
    result = ScoreResult()

    if deleted:
        result.hard_flag = HardFlag.DELETED
        return result

    if archived:
        result.score += 4
        result.signals.append("archived")

    if cve_unfixed_days is not None and cve_unfixed_days >= cve_unfixed_grace_days:
        result.score += 2
        result.signals.append("dep_cve_no_fix")

    if cve_fixable_days is not None and cve_fixable_days >= cve_fixable_grace_days:
        result.score += 1
        result.signals.append("dep_cve_upgrade")

    push_age = _days_since(_parse_dt(pushed_at))
    if push_age is not None:
        if push_age >= stale_commit_days:
            result.score += 3
            result.signals.append("push_very_stale")
        elif push_age >= stale_commit_days / 2:
            result.score += 1
            result.signals.append("push_stale")

    dep_age = _days_since(_parse_dt(dep_updated_at))
    if dep_age is not None and dep_age > stale_dep_days:
        result.score += 2
        result.signals.append("dep_stale")

    if has_releases:
        release_age = _days_since(_parse_dt(latest_release_at))
        if release_age is not None and release_age > 730:
            result.score += 1
            result.signals.append("release_stale")

    return result
