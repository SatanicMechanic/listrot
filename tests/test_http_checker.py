import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import patch, MagicMock
import requests
from http_checker import check_url, LivenessResult


def mock_response(status_code, text=''):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


# --- Liveness ---

def test_404_is_dead():
    with patch('requests.get', return_value=mock_response(404)):
        result = check_url('https://example.com')
    assert result.status == 'dead'
    assert result.code == 404


def test_403_is_alive():
    with patch('requests.get', return_value=mock_response(403)):
        result = check_url('https://example.com')
    assert result.status == 'alive'
    assert result.code == 403
    assert result.repo_url is None


def test_429_is_alive():
    with patch('requests.get', return_value=mock_response(429)):
        result = check_url('https://example.com')
    assert result.status == 'alive'
    assert result.repo_url is None


def test_500_is_dead():
    with patch('requests.get', return_value=mock_response(500)):
        result = check_url('https://example.com')
    assert result.status == 'dead'
    assert result.code == 500


def test_connection_error_is_unreachable():
    with patch('requests.get', side_effect=requests.ConnectionError()):
        result = check_url('https://example.com')
    assert result.status == 'unreachable'
    assert result.code is None


def test_timeout_is_unreachable():
    with patch('requests.get', side_effect=requests.Timeout()):
        result = check_url('https://example.com')
    assert result.status == 'unreachable'


def test_200_is_alive():
    with patch('requests.get', return_value=mock_response(200, '<html></html>')):
        result = check_url('https://example.com')
    assert result.status == 'alive'
    assert result.code == 200


def test_301_redirect_alive():
    with patch('requests.get', return_value=mock_response(200, '<html></html>')):
        result = check_url('https://example.com')
    assert result.status == 'alive'


# --- Repo link discovery ---

def test_github_link_in_html_returned():
    html = '<a href="https://github.com/owner/repo">Source</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url == 'https://github.com/owner/repo'


def test_gitlab_link_in_html_returned():
    html = '<a href="https://gitlab.com/owner/repo">Code</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url == 'https://gitlab.com/owner/repo'


def test_no_repo_link_returns_none():
    html = '<html><body><a href="https://twitter.com/foo">Follow us</a></body></html>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url is None


def test_issues_link_skipped():
    html = '<a href="https://github.com/owner/repo/issues">Bugs</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url is None


def test_wiki_link_skipped():
    html = '<a href="https://github.com/owner/repo/wiki">Docs</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url is None


def test_org_only_link_skipped():
    html = '<a href="https://github.com/owner">GitHub</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url is None


def test_dead_url_has_no_repo_url():
    with patch('requests.get', return_value=mock_response(404)):
        result = check_url('https://example.com')
    assert result.repo_url is None


def test_result_is_named_tuple():
    with patch('requests.get', return_value=mock_response(200, '')):
        result = check_url('https://example.com')
    assert hasattr(result, 'status')
    assert hasattr(result, 'code')
    assert hasattr(result, 'repo_url')


def test_trailing_slash_stripped_from_repo_url():
    html = '<a href="https://github.com/owner/repo/">Source</a>'
    with patch('requests.get', return_value=mock_response(200, html)):
        result = check_url('https://example.com')
    assert result.repo_url == 'https://github.com/owner/repo'
