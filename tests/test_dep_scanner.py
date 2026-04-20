import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import requests

from dep_scanner import _parse_purl, _sbom_to_queries, scan_github_deps, _query_deps, DepCveResult


def days_ago_iso(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime('%Y-%m-%dT%H:%M:%SZ')


def make_sbom(*purls):
    return {"packages": [
        {"externalRefs": [{"referenceType": "purl", "referenceLocator": p}]}
        for p in purls
    ]}


def make_batch_response(vuln_id_lists: list[list[str]]) -> MagicMock:
    """Batch API returns abbreviated results — just ids."""
    r = MagicMock()
    r.ok = True
    r.raise_for_status = MagicMock()
    r.json.return_value = {"results": [
        {"vulns": [{"id": vid} for vid in ids]} if ids else {}
        for ids in vuln_id_lists
    ]}
    return r


def make_vuln(vuln_id: str, has_fix: bool, age_days: int) -> dict:
    """Full vuln object as returned by GET /v1/vulns/{id}."""
    events = [{"introduced": "0"}]
    if has_fix:
        events.append({"fixed": "9.9.9"})
    return {
        "id": vuln_id,
        "published": days_ago_iso(age_days),
        "affected": [{"ranges": [{"type": "SEMVER", "events": events}]}],
    }


def make_get_response(vuln: dict) -> MagicMock:
    r = MagicMock()
    r.ok = True
    r.json.return_value = vuln
    return r


# --- _parse_purl ---

def test_parse_npm():
    assert _parse_purl("pkg:npm/lodash@4.17.4") == ("npm", "lodash", "4.17.4")

def test_parse_pypi():
    assert _parse_purl("pkg:pypi/requests@2.28.0") == ("PyPI", "requests", "2.28.0")

def test_parse_golang():
    assert _parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.8.0") == (
        "Go", "github.com/gin-gonic/gin", "v1.8.0")

def test_parse_cargo():
    assert _parse_purl("pkg:cargo/serde@1.0.0") == ("crates.io", "serde", "1.0.0")

def test_parse_gem():
    assert _parse_purl("pkg:gem/rails@7.0.0") == ("RubyGems", "rails", "7.0.0")

def test_parse_maven():
    result = _parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
    assert result == ("Maven", "org.apache.commons:commons-lang3", "3.12.0")

def test_parse_unknown_type_returns_none():
    assert _parse_purl("pkg:nuget/Newtonsoft.Json@13.0.1") is None

def test_parse_malformed_returns_none():
    assert _parse_purl("not-a-purl") is None

def test_parse_url_encoded_path():
    result = _parse_purl("pkg:golang/github.com%2Fgin-gonic%2Fgin@v1.8.0")
    assert result == ("Go", "github.com/gin-gonic/gin", "v1.8.0")


# --- _sbom_to_queries ---

def test_sbom_to_queries_extracts_packages():
    sbom = make_sbom("pkg:npm/lodash@4.17.4", "pkg:pypi/requests@2.28.0")
    queries = _sbom_to_queries(sbom)
    assert len(queries) == 2
    assert queries[0] == {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.4"}
    assert queries[1] == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.0"}

def test_sbom_to_queries_skips_unknown_ecosystems():
    sbom = make_sbom("pkg:nuget/Foo@1.0", "pkg:npm/bar@2.0")
    queries = _sbom_to_queries(sbom)
    assert len(queries) == 1
    assert queries[0]["package"]["name"] == "bar"

def test_sbom_to_queries_skips_non_purl_refs():
    sbom = {"packages": [{"externalRefs": [
        {"referenceType": "cpe22Type", "referenceLocator": "cpe:/a:foo:bar:1.0"}
    ]}]}
    assert _sbom_to_queries(sbom) == []

def test_sbom_to_queries_empty_sbom():
    assert _sbom_to_queries({}) == []


# --- _query_deps ---

def test_query_separates_fixable_from_unfixed():
    vuln_fix = make_vuln("GHSA-fix", has_fix=True, age_days=200)
    vuln_nofix = make_vuln("GHSA-nofix", has_fix=False, age_days=100)
    batch_resp = make_batch_response([["GHSA-fix", "GHSA-nofix"]])
    get_resps = {"GHSA-fix": make_get_response(vuln_fix),
                 "GHSA-nofix": make_get_response(vuln_nofix)}
    with patch('requests.post', return_value=batch_resp), \
         patch('requests.get', side_effect=lambda url, **kw: get_resps[url.split('/')[-1]]):
        result = _query_deps([{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}])
    assert result.oldest_fixable_days is not None and result.oldest_fixable_days >= 198
    assert result.oldest_unfixed_days is not None and 98 <= result.oldest_unfixed_days <= 102

def test_query_returns_none_both_when_no_vulns():
    batch_resp = make_batch_response([[]])
    with patch('requests.post', return_value=batch_resp):
        result = _query_deps([{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}])
    assert result.oldest_fixable_days is None
    assert result.oldest_unfixed_days is None

def test_query_oldest_across_packages():
    vuln_a = make_vuln("GHSA-a", has_fix=True, age_days=50)
    vuln_b = make_vuln("GHSA-b", has_fix=True, age_days=300)
    batch_resp = make_batch_response([["GHSA-a"], ["GHSA-b"]])
    get_resps = {"GHSA-a": make_get_response(vuln_a), "GHSA-b": make_get_response(vuln_b)}
    with patch('requests.post', return_value=batch_resp), \
         patch('requests.get', side_effect=lambda url, **kw: get_resps[url.split('/')[-1]]):
        result = _query_deps([
            {"package": {"name": "a", "ecosystem": "npm"}, "version": "1"},
            {"package": {"name": "b", "ecosystem": "npm"}, "version": "1"},
        ])
    assert result.oldest_fixable_days >= 290

def test_query_tolerates_request_error():
    with patch('requests.post', side_effect=requests.RequestException()):
        result = _query_deps([{"package": {"name": "x", "ecosystem": "npm"}, "version": "1"}])
    assert result.oldest_fixable_days is None
    assert result.oldest_unfixed_days is None


# --- scan_github_deps ---

def test_scan_returns_empty_result_when_sbom_unavailable():
    client = MagicMock()
    client.get_dependency_sbom.return_value = None
    result = scan_github_deps("owner", "repo", client)
    assert result.oldest_unfixed_days is None
    assert result.oldest_fixable_days is None

def test_scan_returns_empty_result_when_no_recognised_packages():
    client = MagicMock()
    client.get_dependency_sbom.return_value = make_sbom("pkg:nuget/Foo@1.0")
    result = scan_github_deps("owner", "repo", client)
    assert result.oldest_unfixed_days is None
    assert result.oldest_fixable_days is None

def test_scan_returns_fixable_days():
    client = MagicMock()
    client.get_dependency_sbom.return_value = make_sbom("pkg:npm/lodash@4.17.4")
    vuln = make_vuln("GHSA-fix", has_fix=True, age_days=100)
    batch_resp = make_batch_response([["GHSA-fix"]])
    with patch('requests.post', return_value=batch_resp), \
         patch('requests.get', return_value=make_get_response(vuln)):
        result = scan_github_deps("owner", "repo", client)
    assert result.oldest_fixable_days is not None and 98 <= result.oldest_fixable_days <= 102
    assert result.oldest_unfixed_days is None

def test_scan_returns_unfixed_days():
    client = MagicMock()
    client.get_dependency_sbom.return_value = make_sbom("pkg:npm/lodash@4.17.4")
    vuln = make_vuln("GHSA-nofix", has_fix=False, age_days=100)
    batch_resp = make_batch_response([["GHSA-nofix"]])
    with patch('requests.post', return_value=batch_resp), \
         patch('requests.get', return_value=make_get_response(vuln)):
        result = scan_github_deps("owner", "repo", client)
    assert result.oldest_unfixed_days is not None and 98 <= result.oldest_unfixed_days <= 102
    assert result.oldest_fixable_days is None
