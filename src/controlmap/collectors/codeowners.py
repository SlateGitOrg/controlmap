"""CODEOWNERS parsing and path matching.

Implements the subset of GitHub's CODEOWNERS semantics that matters for an ownership
control:

* one rule per line: ``<pattern> <owner> [<owner> ...]``; ``#`` starts a comment;
* owners are ``@user``, ``@org/team`` or an e-mail address;
* patterns use gitignore-style globs: ``*`` and ``?`` stay within one path segment,
  ``**`` crosses segments, a leading ``/`` (or any interior ``/``) anchors the pattern to the
  repository root, otherwise it may match at any depth, and a trailing ``/`` matches
  everything inside a directory;
* ``dir/*`` matches only direct children of ``dir`` (as GitHub documents), while ``dir`` or
  ``dir/`` matches the whole subtree;
* the **last** matching rule wins, and a rule with no owners makes matching paths unowned.

Negation (``!``) and character classes (``[...]``) are not supported by GitHub either; they
are reported as errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any

_OWNER = re.compile(
    r"^(?:@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?"
    r"|[^@\s]+@[^@\s]+\.[^@\s]+)$"
)
_INLINE_COMMENT = re.compile(r"(?<!\\)\s#.*$")


@dataclass(frozen=True)
class OwnerRule:
    line: int
    pattern: str
    owners: tuple[str, ...]

    @cached_property
    def regex(self) -> re.Pattern[str]:
        return compile_pattern(self.pattern)

    def matches(self, path: str) -> bool:
        return self.regex.fullmatch(path.lstrip("/")) is not None

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "pattern": self.pattern, "owners": list(self.owners)}


@dataclass(frozen=True)
class ParseIssue:
    line: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "message": self.message}


@dataclass(frozen=True)
class CodeOwners:
    rules: tuple[OwnerRule, ...]
    issues: tuple[ParseIssue, ...]

    def owners_for(self, path: str) -> tuple[str, ...] | None:
        """Owners of ``path`` (last matching rule wins); ``None`` when no rule matches."""
        for rule in reversed(self.rules):
            if rule.matches(path):
                return rule.owners
        return None

    @property
    def has_catch_all(self) -> bool:
        return any(rule.pattern in ("*", "/*", "**", "/**") and rule.owners for rule in self.rules)


def _glob_to_regex(glob: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(glob):
        char = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "\\" and i + 1 < len(glob):
            out.append(re.escape(glob[i + 1]))
            i += 2
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Translate one CODEOWNERS pattern into an anchored regular expression over
    repository-relative POSIX paths (no leading slash)."""
    directory_only = pattern.endswith("/")
    body = pattern.rstrip("/")
    anchored = body.startswith("/") or "/" in body
    body = body.lstrip("/")
    if body in ("", "**"):
        return re.compile(".*")
    prefix = "" if anchored else "(?:.*/)?"
    regex = prefix + _glob_to_regex(body)
    last_segment = body.rsplit("/", 1)[-1]
    if directory_only:
        regex += "/.*"
    elif last_segment != "*":
        regex += "(?:/.*)?"
    return re.compile(regex)


def parse_codeowners(text: str) -> CodeOwners:
    rules: list[OwnerRule] = []
    issues: list[ParseIssue] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _INLINE_COMMENT.sub("", raw).strip()
        if not line or line.startswith("#"):
            continue
        pattern, *owners = line.split()
        if pattern.startswith("!"):
            issues.append(ParseIssue(number, f"negated pattern {pattern!r} is not supported"))
            continue
        if "[" in pattern or "]" in pattern:
            issues.append(ParseIssue(number, f"character class in {pattern!r} is not supported"))
            continue
        bad = [owner for owner in owners if not _OWNER.match(owner)]
        if bad:
            issues.append(ParseIssue(number, f"invalid owner(s): {', '.join(bad)}"))
            owners = [owner for owner in owners if owner not in bad]
        rules.append(OwnerRule(number, pattern, tuple(owners)))
    return CodeOwners(tuple(rules), tuple(issues))


def codeowners_from_evidence(data: dict[str, Any]) -> CodeOwners:
    """Rebuild a :class:`CodeOwners` from the normalized evidence representation."""
    rules = tuple(
        OwnerRule(int(r["line"]), str(r["pattern"]), tuple(str(o) for o in r["owners"]))
        for r in data.get("rules", [])
    )
    issues = tuple(ParseIssue(int(i["line"]), str(i["message"])) for i in data.get("issues", []))
    return CodeOwners(rules, issues)
