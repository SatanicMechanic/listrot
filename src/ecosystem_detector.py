from typing import Optional

MANIFEST_PRIORITY = [
    ("package.json", "npm"),
    ("requirements.txt", "PyPI"),
    ("pyproject.toml", "PyPI"),
    ("go.mod", "Go"),
    ("Cargo.toml", "crates.io"),
    ("Gemfile", "RubyGems"),
    ("pom.xml", "Maven"),
    ("build.gradle", "Maven"),
]


def detect_ecosystem(tree_paths: list[str]) -> Optional[str]:
    """Return the ecosystem name for the first recognised manifest found."""
    path_set = set(p.lstrip('/') for p in tree_paths)
    for manifest, ecosystem in MANIFEST_PRIORITY:
        if any(p == manifest or p.endswith('/' + manifest) for p in path_set):
            return ecosystem
    return None
