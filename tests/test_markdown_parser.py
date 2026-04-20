import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from markdown_parser import parse_entries, Entry


SIMPLE_LIST = """\
## Tools

- [Alpha](https://github.com/owner/alpha) - A great tool
- [Beta](https://github.com/owner/beta)

## Libraries

- [Gamma](https://github.com/owner/gamma) - Another tool
"""

BADGE_MIXED = """\
## Section

- [![Build](https://img.shields.io/badge/build-passing-green)](https://travis-ci.org/x) [MyTool](https://github.com/owner/mytool) - Has badges
- [OnlyBadge](https://img.shields.io/badge/foo-bar-blue)
- [RealTool](https://github.com/owner/realtool)
"""

NESTED_LIST = """\
## Category

- Parent item
  - [Child](https://github.com/owner/child) - nested entry
  - [Child2](https://github.com/owner/child2)
"""

MULTI_LINK = """\
## Multi

- [Tool](https://github.com/owner/tool) - see also [mirror](https://github.com/mirror/tool)
"""

HOMEPAGE_PLUS_SOURCE = """\
## Apps

- [Aptabase](https://aptabase.com/) - Privacy first analytics. ([Source Code](https://github.com/aptabase/aptabase)) `AGPL-3.0`
- [GoAccess](http://goaccess.io/) - Web log analyzer. ([Source Code](https://github.com/allinurl/goaccess)) `GPL-2.0`
- [DirectGitHub](https://github.com/direct/repo) - Listed directly.
"""

NON_GITHUB = """\
## External

- [Site](https://example.com) - not a github link
- [GitLab](https://gitlab.com/owner/repo) - also not github
"""

NO_SECTION = """\
- [Orphan](https://github.com/owner/orphan) - no heading
"""

EMPTY = ""

HEADING_NESTING = """\
# Top Level

## Sub Section

- [Tool](https://github.com/owner/tool)

### Sub Sub

- [Tool2](https://github.com/owner/tool2)
"""


def test_simple_list_extracts_entries():
    entries = parse_entries(SIMPLE_LIST)
    assert len(entries) == 3
    urls = [e.url for e in entries]
    assert "https://github.com/owner/alpha" in urls
    assert "https://github.com/owner/beta" in urls
    assert "https://github.com/owner/gamma" in urls


def test_section_preserved():
    entries = parse_entries(SIMPLE_LIST)
    alpha = next(e for e in entries if "alpha" in e.url)
    gamma = next(e for e in entries if "gamma" in e.url)
    assert alpha.section == "Tools"
    assert gamma.section == "Libraries"


def test_entry_name_extracted():
    entries = parse_entries(SIMPLE_LIST)
    alpha = next(e for e in entries if "alpha" in e.url)
    assert alpha.name == "Alpha"


def test_badge_links_filtered_out():
    entries = parse_entries(BADGE_MIXED)
    urls = [e.url for e in entries]
    assert not any("shields.io" in u for u in urls)
    assert not any("travis-ci.org" in u for u in urls)
    assert any("mytool" in u for u in urls)
    assert any("realtool" in u for u in urls)


def test_only_badge_line_skipped():
    entries = parse_entries(BADGE_MIXED)
    urls = [e.url for e in entries]
    assert "https://img.shields.io/badge/foo-bar-blue" not in urls


def test_nested_list_entries_extracted():
    entries = parse_entries(NESTED_LIST)
    urls = [e.url for e in entries]
    assert "https://github.com/owner/child" in urls
    assert "https://github.com/owner/child2" in urls


def test_nested_entries_inherit_section():
    entries = parse_entries(NESTED_LIST)
    for e in entries:
        assert e.section == "Category"


def test_multi_link_uses_first_link_name_and_first_github_url():
    entries = parse_entries(MULTI_LINK)
    assert len(entries) == 1
    assert entries[0].name == "Tool"
    assert entries[0].url == "https://github.com/owner/tool"


def test_homepage_plus_source_code_pattern():
    """The common awesome-selfhosted pattern: [Name](homepage) ... ([Source Code](github))."""
    entries = parse_entries(HOMEPAGE_PLUS_SOURCE)
    assert len(entries) == 3

    aptabase = next(e for e in entries if e.name == "Aptabase")
    assert aptabase.url == "https://github.com/aptabase/aptabase"
    assert aptabase.is_github is True

    goaccess = next(e for e in entries if e.name == "GoAccess")
    assert goaccess.url == "https://github.com/allinurl/goaccess"
    assert goaccess.is_github is True

    direct = next(e for e in entries if e.name == "DirectGitHub")
    assert direct.url == "https://github.com/direct/repo"
    assert direct.is_github is True


def test_non_github_urls_included():
    entries = parse_entries(NON_GITHUB)
    urls = [e.url for e in entries]
    assert "https://example.com" in urls
    assert "https://gitlab.com/owner/repo" in urls


def test_is_github_flag():
    entries = parse_entries(SIMPLE_LIST)
    for e in entries:
        assert e.is_github is True

    ext_entries = parse_entries(NON_GITHUB)
    for e in ext_entries:
        assert e.is_github is False


def test_is_gitlab_false_for_github_entries():
    entries = parse_entries(SIMPLE_LIST)
    for e in entries:
        assert e.is_gitlab is False


def test_no_section_uses_none_or_empty():
    entries = parse_entries(NO_SECTION)
    assert len(entries) == 1
    assert entries[0].section is None or entries[0].section == ""


def test_empty_markdown_returns_no_entries():
    entries = parse_entries(EMPTY)
    assert entries == []


def test_heading_nesting_uses_nearest_heading():
    entries = parse_entries(HEADING_NESTING)
    tool = next(e for e in entries if "owner/tool" in e.url)
    tool2 = next(e for e in entries if "owner/tool2" in e.url)
    assert tool.section == "Sub Section"
    assert tool2.section == "Sub Sub"


def test_entry_has_required_fields():
    entries = parse_entries(SIMPLE_LIST)
    for e in entries:
        assert hasattr(e, 'name')
        assert hasattr(e, 'url')
        assert hasattr(e, 'section')
        assert hasattr(e, 'is_github')


def test_github_owner_repo_parsed():
    entries = parse_entries(SIMPLE_LIST)
    alpha = next(e for e in entries if "alpha" in e.url)
    assert alpha.owner == "owner"
    assert alpha.repo == "alpha"


def test_non_github_owner_repo_none():
    entries = parse_entries(NON_GITHUB)
    site = next(e for e in entries if "example.com" in e.url)
    assert site.owner is None
    assert site.repo is None


GITLAB_LIST = """\
## Tools

- [MyTool](https://gitlab.com/org/mytool) - hosted on GitLab
- [Other](https://example.com) - not a git host
"""


def test_gitlab_url_detected():
    entries = parse_entries(GITLAB_LIST)
    gl = next(e for e in entries if "gitlab.com" in e.url)
    assert gl.is_gitlab is True
    assert gl.is_github is False


def test_gitlab_owner_repo_parsed():
    entries = parse_entries(GITLAB_LIST)
    gl = next(e for e in entries if "gitlab.com" in e.url)
    assert gl.owner == "org"
    assert gl.repo == "mytool"


def test_non_git_host_is_not_gitlab():
    entries = parse_entries(GITLAB_LIST)
    other = next(e for e in entries if "example.com" in e.url)
    assert other.is_gitlab is False


NON_REPO_PATHS = """\
## Section

- [GitLab Login](https://gitlab.com/users/sign_in)
- [GitLab Groups](https://gitlab.com/groups/mygroup)
- [GitHub Marketplace](https://github.com/marketplace/some-app)
- [GitHub Explore](https://github.com/explore)
- [Real GitLab Repo](https://gitlab.com/org/repo)
- [Real GitHub Repo](https://github.com/owner/repo)
"""


def test_gitlab_system_paths_not_classified_as_repos():
    entries = parse_entries(NON_REPO_PATHS)
    login = next(e for e in entries if "sign_in" in e.url)
    groups = next(e for e in entries if "groups" in e.url)
    assert login.is_gitlab is False
    assert groups.is_gitlab is False


def test_github_system_paths_not_classified_as_repos():
    entries = parse_entries(NON_REPO_PATHS)
    marketplace = next(e for e in entries if "marketplace" in e.url)
    assert marketplace.is_github is False


def test_real_repos_still_classified_after_filtering():
    entries = parse_entries(NON_REPO_PATHS)
    gl = next(e for e in entries if "gitlab.com/org/repo" in e.url)
    gh = next(e for e in entries if "github.com/owner/repo" in e.url)
    assert gl.is_gitlab is True
    assert gh.is_github is True
