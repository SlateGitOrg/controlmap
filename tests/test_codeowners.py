"""CODEOWNERS parsing and gitignore-style matching (example-based and property-based)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from controlmap.collectors.codeowners import compile_pattern, parse_codeowners

CASES = [
    # pattern, path, matches
    ("*", "a/b/c.py", True),
    ("*.js", "src/app.js", True),
    ("*.js", "src/app.jsx", False),
    ("/build/", "build/out/x", True),
    ("/build/", "src/build/x", False),
    ("build/", "src/build/x", True),
    ("docs/*", "docs/a.md", True),
    ("docs/*", "docs/sub/a.md", False),
    ("/docs", "docs/sub/a.md", True),
    ("apps/", "apps/x", True),
    ("**/logs", "deep/nested/logs/x.log", True),
    ("/a/**/z.txt", "a/b/c/z.txt", True),
    ("/a/**/z.txt", "a/z.txt", True),
    ("README.md", "pkg/README.md", True),
    ("/README.md", "pkg/README.md", False),
    ("file?.txt", "file1.txt", True),
    ("file?.txt", "file10.txt", False),
    ("src/*.py", "src/a.py", True),
    ("src/*.py", "x/src/a.py", False),
]


@pytest.mark.parametrize(("pattern", "path", "expected"), CASES)
def test_pattern_semantics(pattern: str, path: str, expected: bool) -> None:
    assert (compile_pattern(pattern).fullmatch(path) is not None) is expected


def test_last_matching_rule_wins_and_empty_owner_unowns() -> None:
    owners = parse_codeowners(
        "# comment\n*  @o/all  # trailing comment\n/src/ @o/src dev@x.io\n/src/generated/\n"
    )
    assert owners.owners_for("README") == ("@o/all",)
    assert owners.owners_for("/src/main.py") == ("@o/src", "dev@x.io")
    assert owners.owners_for("src/generated/x.py") == ()
    assert owners.has_catch_all
    assert owners.issues == ()


def test_no_rule_matches_returns_none() -> None:
    owners = parse_codeowners("/docs/ @o/docs\n")
    assert owners.owners_for("src/a.py") is None
    assert not owners.has_catch_all


def test_escaped_characters_and_invalid_owner_reporting() -> None:
    owners = parse_codeowners("\\#notes @o/x\n[ab].py @o/y\n/app @bad!owner @o/ok\n")
    assert owners.owners_for("#notes") == ("@o/x",)
    assert [i.line for i in owners.issues] == [2, 3]
    assert owners.owners_for("app/x") == ("@o/ok",)


_SEGMENT = st.text(alphabet="abcdefxyz019_-", min_size=1, max_size=6)
_PATHS = st.lists(_SEGMENT, min_size=1, max_size=5).map("/".join)


@given(_PATHS)
def test_catch_all_matches_any_path(path: str) -> None:
    assert parse_codeowners("* @o/all\n").owners_for(path) == ("@o/all",)


@given(_PATHS, _SEGMENT)
def test_anchored_directory_owns_exactly_its_subtree(path: str, directory: str) -> None:
    owners = parse_codeowners(f"/{directory}/ @o/dir\n")
    inside = owners.owners_for(f"{directory}/{path}")
    assert inside == ("@o/dir",)
    if not path.startswith(f"{directory}/") and path != directory:
        assert owners.owners_for(path) is None


@given(_PATHS)
def test_literal_full_path_rule_matches_itself(path: str) -> None:
    owners = parse_codeowners(f"/{path} @o/exact\n")
    assert owners.owners_for(path) == ("@o/exact",)
