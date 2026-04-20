import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
import requests
from osv_client import query_osv, OsvResult, VulnInfo


def days_ago_iso(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime('%Y-%m-%dT%H:%M:%SZ')


def mock_response(vulns):
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"vulns": vulns} if vulns is not None else {}
    r.raise_for_status = MagicMock()
    return r


def make_vuln(fixed=True, severity_str="HIGH", age_days=100):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": "1.2.3"})
    return {
        "id": "GHSA-0001",
        "published": days_ago_iso(age_days),
        "database_specific": {"severity": severity_str},
        "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": events}]}],
    }


# --- No vulnerabilities ---

def test_no_vulns_returns_empty_result():
    with patch('requests.post', return_value=mock_response([])):
        result = query_osv("mypkg", "PyPI")
    assert result.has_fixed is False
    assert result.has_unfixed is False
    assert result.oldest_unfixed_days is None


def test_empty_response_returns_empty_result():
    with patch('requests.post', return_value=mock_response(None)):
        result = query_osv("mypkg", "PyPI")
    assert isinstance(result, OsvResult)


# --- Fix detection ---

def test_vuln_with_fix_sets_has_fixed():
    with patch('requests.post', return_value=mock_response([make_vuln(fixed=True)])):
        result = query_osv("mypkg", "PyPI")
    assert result.has_fixed is True
    assert result.has_unfixed is False


def test_vuln_without_fix_sets_has_unfixed():
    with patch('requests.post', return_value=mock_response([make_vuln(fixed=False)])):
        result = query_osv("mypkg", "PyPI")
    assert result.has_unfixed is True
    assert result.has_fixed is False


# --- Severity parsing ---

def test_critical_severity_parsed():
    with patch('requests.post', return_value=mock_response([make_vuln(severity_str="CRITICAL")])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].severity == "critical"


def test_high_severity_parsed():
    with patch('requests.post', return_value=mock_response([make_vuln(severity_str="HIGH")])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].severity == "high"


def test_moderate_maps_to_other():
    with patch('requests.post', return_value=mock_response([make_vuln(severity_str="MODERATE")])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].severity == "other"


def test_low_maps_to_other():
    with patch('requests.post', return_value=mock_response([make_vuln(severity_str="LOW")])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].severity == "other"


def test_missing_severity_maps_to_other():
    vuln = make_vuln()
    del vuln["database_specific"]
    with patch('requests.post', return_value=mock_response([vuln])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].severity == "other"


# --- Age ---

def test_age_days_populated():
    with patch('requests.post', return_value=mock_response([make_vuln(age_days=50)])):
        result = query_osv("mypkg", "PyPI")
    assert result.vulns[0].age_days is not None
    assert 48 <= result.vulns[0].age_days <= 52


def test_oldest_unfixed_days_uses_oldest():
    vulns = [make_vuln(fixed=False, age_days=300), make_vuln(fixed=False, age_days=50)]
    with patch('requests.post', return_value=mock_response(vulns)):
        result = query_osv("mypkg", "PyPI")
    assert result.oldest_unfixed_days >= 290


# --- oldest_unfixed_age ---

def test_oldest_unfixed_age_returns_none_for_all_fixed():
    result = OsvResult(vulns=[VulnInfo(has_fix=True, severity="high", age_days=100)])
    assert result.oldest_unfixed_age() is None


def test_oldest_unfixed_age_returns_days_for_unfixed():
    result = OsvResult(vulns=[VulnInfo(has_fix=False, severity="other", age_days=150)])
    assert result.oldest_unfixed_age() == 150


def test_oldest_unfixed_age_empty_result():
    result = OsvResult()
    assert result.oldest_unfixed_age() is None


# --- Error handling ---

def test_request_error_returns_empty_result():
    with patch('requests.post', side_effect=requests.RequestException()):
        result = query_osv("mypkg", "PyPI")
    assert result.has_fixed is False


def test_unknown_ecosystem_returns_empty_result():
    result = query_osv("mypkg", "UnknownEco")
    assert result.has_fixed is False
