import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import yaml
from yaml_parser import parse_entries

# Helpers to build minimal YAML strings

def make_yaml(categories):
    return yaml.dump({"categories": categories})


SIMPLE = make_yaml([{
    "name": "Essentials",
    "sections": [{
        "name": "Password Managers",
        "services": [
            {"name": "Bitwarden", "url": "https://bitwarden.com", "github": "bitwarden/server"},
            {"name": "KeePass", "url": "https://keepass.info"},
        ]
    }]
}])

MULTI_CATEGORY = make_yaml([
    {
        "name": "Essentials",
        "sections": [{
            "name": "Password Managers",
            "services": [{"name": "Alpha", "url": "https://alpha.io", "github": "org/alpha"}]
        }]
    },
    {
        "name": "Communication",
        "sections": [{
            "name": "Messaging",
            "services": [{"name": "Signal", "url": "https://signal.org", "github": "signalapp/Signal-Android"}]
        }]
    }
])

MULTI_SECTION = make_yaml([{
    "name": "Cat",
    "sections": [
        {
            "name": "SectionA",
            "services": [{"name": "A", "url": "https://a.com", "github": "owner/a"}]
        },
        {
            "name": "SectionB",
            "services": [{"name": "B", "url": "https://b.com", "github": "owner/b"}]
        }
    ]
}])

GITHUB_URL_NO_FIELD = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [{"name": "Tool", "url": "https://github.com/owner/tool"}]
    }]
}])

NO_GITHUB = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [{"name": "Site", "url": "https://example.com"}]
    }]
}])

MISSING_URL = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [
            {"name": "HasURL", "url": "https://example.com"},
            {"name": "NoURL", "github": "owner/repo"},
        ]
    }]
}])

GITHUB_FULL_URL_FIELD = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [{"name": "Linguist", "url": "https://linguister.io",
                      "github": "https://github.com/translate-tools/linguist"}]
    }]
}])

GITHUB_ORG_URL_FIELD = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [{"name": "nostr", "url": "https://github.com/nostr-protocol/nostr",
                      "github": "https://github.com/nostr-protocol"}]
    }]
}])

GITLAB_FIELD = make_yaml([{
    "name": "Cat",
    "sections": [{
        "name": "Sec",
        "services": [{"name": "GLProject", "url": "https://example.com",
                      "gitlab": "rluna-gitlab/gitlab-ce"}]
    }]
}])

EMPTY = make_yaml([])


# --- Basic extraction ---

def test_simple_extracts_entries():
    entries = parse_entries(SIMPLE)
    assert len(entries) == 2


def test_entry_names():
    entries = parse_entries(SIMPLE)
    names = {e.name for e in entries}
    assert "Bitwarden" in names
    assert "KeePass" in names


def test_entry_urls():
    entries = parse_entries(SIMPLE)
    bw = next(e for e in entries if e.name == "Bitwarden")
    kp = next(e for e in entries if e.name == "KeePass")
    # github field → repo URL is the link, not the project homepage
    assert bw.url == "https://github.com/bitwarden/server"
    assert kp.url == "https://keepass.info"


# --- Section / category hierarchy ---

def test_section_includes_category_and_section():
    entries = parse_entries(SIMPLE)
    bw = next(e for e in entries if e.name == "Bitwarden")
    assert "Essentials" in bw.section
    assert "Password Managers" in bw.section


def test_multi_category_sections_distinct():
    entries = parse_entries(MULTI_CATEGORY)
    alpha = next(e for e in entries if e.name == "Alpha")
    signal = next(e for e in entries if e.name == "Signal")
    assert "Essentials" in alpha.section
    assert "Communication" in signal.section


def test_multi_section_within_category():
    entries = parse_entries(MULTI_SECTION)
    a = next(e for e in entries if e.name == "A")
    b = next(e for e in entries if e.name == "B")
    assert "SectionA" in a.section
    assert "SectionB" in b.section


# --- GitHub field ---

def test_github_field_sets_is_github():
    entries = parse_entries(SIMPLE)
    bw = next(e for e in entries if e.name == "Bitwarden")
    assert bw.is_github is True


def test_github_field_parses_owner_repo():
    entries = parse_entries(SIMPLE)
    bw = next(e for e in entries if e.name == "Bitwarden")
    assert bw.owner == "bitwarden"
    assert bw.repo == "server"


def test_github_url_without_field_detected():
    entries = parse_entries(GITHUB_URL_NO_FIELD)
    assert len(entries) == 1
    assert entries[0].is_github is True
    assert entries[0].owner == "owner"
    assert entries[0].repo == "tool"


def test_non_github_entry():
    entries = parse_entries(NO_GITHUB)
    assert entries[0].is_github is False
    assert entries[0].owner is None
    assert entries[0].repo is None


def test_no_github_field_non_github_url():
    entries = parse_entries(SIMPLE)
    kp = next(e for e in entries if e.name == "KeePass")
    assert kp.is_github is False


# --- Edge cases ---

def test_service_without_url_uses_github_url():
    entries = parse_entries(MISSING_URL)
    no_url = next(e for e in entries if e.name == "NoURL")
    assert no_url.url == "https://github.com/owner/repo"
    assert no_url.is_github is True


def test_github_full_url_in_field_parsed():
    entries = parse_entries(GITHUB_FULL_URL_FIELD)
    assert len(entries) == 1
    e = entries[0]
    assert e.is_github is True
    assert e.owner == "translate-tools"
    assert e.repo == "linguist"
    assert e.url == "https://github.com/translate-tools/linguist"


def test_github_org_url_falls_back_to_url_field():
    """github: field that's an org URL (no repo) should fall back to url: field."""
    entries = parse_entries(GITHUB_ORG_URL_FIELD)
    assert len(entries) == 1
    e = entries[0]
    assert e.is_github is True
    assert e.owner == "nostr-protocol"
    assert e.repo == "nostr"
    assert e.url == "https://github.com/nostr-protocol/nostr"


def test_gitlab_field_shorthand():
    entries = parse_entries(GITLAB_FIELD)
    assert len(entries) == 1
    e = entries[0]
    assert e.is_gitlab is True
    assert e.owner == "rluna-gitlab"
    assert e.repo == "gitlab-ce"
    assert e.url == "https://gitlab.com/rluna-gitlab/gitlab-ce"


def test_empty_categories_returns_no_entries():
    entries = parse_entries(EMPTY)
    assert entries == []


def test_all_entries_have_required_fields():
    entries = parse_entries(MULTI_CATEGORY)
    for e in entries:
        assert hasattr(e, 'name')
        assert hasattr(e, 'url')
        assert hasattr(e, 'section')
        assert hasattr(e, 'is_github')
        assert hasattr(e, 'owner')
        assert hasattr(e, 'repo')
