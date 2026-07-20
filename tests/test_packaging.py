"""Packaging / tooling configuration pins.

These guard the static config that has no runtime surface but protects the
declared support range.
"""

from __future__ import annotations

import ast
from pathlib import Path

try:
    import tomllib  # stdlib on 3.11+
except ModuleNotFoundError:  # Python 3.10: no stdlib TOML reader
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Lowest interpreter the package claims to support (python = ">=3.10").
FLOOR = (3, 10)


def _python_sources() -> list[Path]:
    # src-layout: the shipped package lives under src/vulners, not REPO_ROOT/vulners.
    roots = [REPO_ROOT / "src" / "vulners", REPO_ROOT / "samples"]
    files: list[Path] = []
    for root in roots:
        files.extend(sorted(root.rglob("*.py")))
    return files


class TestRuffTarget:
    """ruff target-version must not exceed the declared python floor.

    A py313 target let pyupgrade rules modernize the code into 3.11-3.13-only
    idioms that break on 3.10; the fix pins target-version to py310.
    """

    def test_ruff_target_version_matches_floor(self):
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        assert data["tool"]["ruff"]["target-version"] == "py310"

    def test_all_sources_parse_under_floor(self):
        # Every shipped/sample module must parse as 3.10 syntax, i.e. contain no
        # newer-only syntax the linter (now targeting py310) would flag.
        files = _python_sources()
        # Guard against the scan silently matching nothing (e.g. a layout move):
        # the shipped package must actually be covered.
        assert any(p.match("src/vulners/*.py") or "src/vulners" in str(p) for p in files), (
            "src/vulners was not scanned"
        )
        offenders = []
        for path in files:
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path), feature_version=FLOOR)
            except SyntaxError as err:  # pragma: no cover - failure detail
                offenders.append(f"{path}: {err}")
        assert not offenders, "sources use syntax newer than the declared floor:\n" + "\n".join(
            offenders
        )
