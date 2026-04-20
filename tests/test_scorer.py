import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from datetime import datetime, timezone, timedelta
from scorer import score_entry, ScoreResult, HardFlag


def now():
    return datetime.now(timezone.utc)


def days_ago(n):
    return (now() - timedelta(days=n)).isoformat()


# --- Hard flag tests ---

def test_deleted_repo_is_hard_flag():
    result = score_entry(deleted=True)
    assert result.hard_flag == HardFlag.DELETED


def test_archived_repo_is_soft_flag():
    result = score_entry(archived=True)
    assert result.hard_flag is None
    assert result.score == 4
    assert "archived" in result.signals


def test_cve_unfixed_old_is_soft_flag():
    result = score_entry(cve_unfixed_days=91, cve_unfixed_grace_days=90)
    assert result.hard_flag is None
    assert result.score == 2
    assert "dep_cve_no_fix" in result.signals


def test_cve_unfixed_new_is_no_flag():
    result = score_entry(cve_unfixed_days=30, cve_unfixed_grace_days=90)
    assert result.hard_flag is None
    assert result.score == 0
    assert "dep_cve_no_fix" not in result.signals


def test_cve_unfixed_at_grace_boundary_is_soft_flag():
    result = score_entry(cve_unfixed_days=90, cve_unfixed_grace_days=90)
    assert result.score == 2
    assert "dep_cve_no_fix" in result.signals


def test_cve_fixable_past_grace_scores_1():
    result = score_entry(cve_fixable_days=31, cve_fixable_grace_days=30)
    assert result.score == 1
    assert "dep_cve_upgrade" in result.signals


def test_cve_fixable_within_grace_scores_0():
    result = score_entry(cve_fixable_days=10, cve_fixable_grace_days=30)
    assert result.score == 0
    assert "dep_cve_upgrade" not in result.signals


def test_cve_fixable_and_unfixed_accumulate():
    result = score_entry(cve_fixable_days=31, cve_unfixed_days=91)
    assert result.score == 3  # 1 + 2
    assert "dep_cve_upgrade" in result.signals
    assert "dep_cve_no_fix" in result.signals


def test_archived_accumulates_with_other_signals():
    result = score_entry(
        archived=True,
        pushed_at=days_ago(800),
        stale_commit_days=730,
    )
    assert result.score == 7  # 4 (archived) + 3 (push_very_stale)
    assert "archived" in result.signals
    assert "push_very_stale" in result.signals


def test_no_hard_flag_by_default():
    result = score_entry(pushed_at=days_ago(10))
    assert result.hard_flag is None


# --- Push staleness soft scoring ---

def test_push_over_stale_commit_days_scores_3(stale_commit_days=730):
    result = score_entry(pushed_at=days_ago(731), stale_commit_days=730)
    assert result.score == 3
    assert "push_very_stale" in result.signals


def test_push_over_half_stale_commit_days_scores_1():
    result = score_entry(pushed_at=days_ago(400), stale_commit_days=730)
    assert result.score == 1
    assert "push_stale" in result.signals


def test_push_under_half_stale_commit_days_scores_0():
    result = score_entry(pushed_at=days_ago(100), stale_commit_days=730)
    assert result.score == 0
    assert "push_stale" not in result.signals
    assert "push_very_stale" not in result.signals


def test_push_staleness_mutually_exclusive():
    result = score_entry(pushed_at=days_ago(800), stale_commit_days=730)
    assert "push_stale" not in result.signals
    assert "push_very_stale" in result.signals


def test_exact_boundary_stale_commit_days():
    result = score_entry(pushed_at=days_ago(730), stale_commit_days=730)
    assert result.score == 3


def test_exact_boundary_half_stale_commit_days():
    result = score_entry(pushed_at=days_ago(365), stale_commit_days=730)
    assert result.score == 1


# --- Dependency staleness ---

def test_stale_dep_scores_2():
    result = score_entry(dep_updated_at=days_ago(200), stale_dep_days=180)
    assert result.score == 2
    assert "dep_stale" in result.signals


def test_fresh_dep_scores_0():
    result = score_entry(dep_updated_at=days_ago(50), stale_dep_days=180)
    assert result.score == 0
    assert "dep_stale" not in result.signals


def test_no_dep_data_scores_0():
    result = score_entry()
    assert result.score == 0


# --- Release staleness ---

def test_stale_release_with_releases_scores_1():
    result = score_entry(
        latest_release_at=days_ago(800),
        has_releases=True,
    )
    assert result.score == 1
    assert "release_stale" in result.signals


def test_stale_release_without_releases_scores_0():
    result = score_entry(
        latest_release_at=days_ago(800),
        has_releases=False,
    )
    assert result.score == 0
    assert "release_stale" not in result.signals


def test_fresh_release_scores_0():
    result = score_entry(
        latest_release_at=days_ago(100),
        has_releases=True,
    )
    assert result.score == 0


def test_no_release_data_scores_0():
    result = score_entry(has_releases=True, latest_release_at=None)
    assert result.score == 0


# --- Combined scoring ---

def test_combined_score_accumulates():
    result = score_entry(
        pushed_at=days_ago(800),
        dep_updated_at=days_ago(200),
        stale_commit_days=730,
        stale_dep_days=180,
        latest_release_at=days_ago(800),
        has_releases=True,
    )
    assert result.score == 6  # 3 + 2 + 1
    assert "push_very_stale" in result.signals
    assert "dep_stale" in result.signals
    assert "release_stale" in result.signals


def test_threshold_check_above():
    result = score_entry(pushed_at=days_ago(800), stale_commit_days=730)
    assert result.meets_threshold(3) is True


def test_threshold_check_below():
    result = score_entry(pushed_at=days_ago(400), stale_commit_days=730)
    assert result.meets_threshold(3) is False


def test_threshold_check_equal():
    result = score_entry(pushed_at=days_ago(800), stale_commit_days=730)
    assert result.meets_threshold(3) is True


# --- Hard flags bypass threshold ---

def test_hard_flag_always_surfaces_regardless_of_threshold():
    result = score_entry(deleted=True)
    assert result.should_surface(threshold=100) is True


def test_low_score_below_threshold_does_not_surface():
    result = score_entry(pushed_at=days_ago(400), stale_commit_days=730)
    assert result.should_surface(threshold=3) is False


def test_score_at_threshold_surfaces():
    result = score_entry(pushed_at=days_ago(800), stale_commit_days=730)
    assert result.should_surface(threshold=3) is True
