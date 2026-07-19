"""Import smoke, constructor validation, ResultSet pins and packaging metadata.

Covers the legacy v3 surface (kept as backward-compatible shims in v4) and the
v4 packaging contract (PEP 621 metadata, MIT license, uv_build backend).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

import vulners
from vulners.base import ResultSet

# vulners.__file__ is src/vulners/__init__.py → parents[2] is the repo root.
REPO_ROOT = Path(vulners.__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _load_pyproject():
    tomllib = pytest.importorskip("tomllib")  # stdlib on 3.11+
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _project() -> dict:
    return _load_pyproject()["project"]


def _dep_names() -> set[str]:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    return {canonicalize_name(Requirement(dep).name) for dep in _project()["dependencies"]}


class TestImportSmoke:
    def test_import_exposes_public_classes(self):
        assert vulners.VulnersApi is not None
        assert vulners.VScannerApi is not None
        assert issubclass(vulners.VulnersApiError, Exception)

    def test_base_version_is_nonempty_string(self):
        assert isinstance(vulners.base.__version__, str)
        assert vulners.base.__version__


class TestPublicSurface:
    """__all__ pins the public export surface and keeps star-import from leaking
    warnings/submodules; the private import paths must keep working."""

    def test_all_declared_and_resolves(self):
        assert vulners.__all__ == [
            "VScannerApi",
            "VulnersApi",
            "VulnersApiError",
            "VulnersDeprecationWarning",
        ]
        for name in vulners.__all__:
            assert hasattr(vulners, name)

    def test_star_import_surface_is_public_names(self):
        ns: dict = {}
        exec("from vulners import *", ns)
        names = {k for k in ns if not k.startswith("__")}
        assert names == {
            "VulnersApi",
            "VScannerApi",
            "VulnersApiError",
            "VulnersDeprecationWarning",
        }

    def test_reexport_identity(self):
        assert vulners.VulnersApiError is vulners.base.VulnersApiError
        assert vulners.VScannerApi is vulners.vscanner.VScannerApi
        assert vulners.VulnersApi is vulners.vulners.VulnersApi

    def test_private_paths_not_broken(self):
        # explicit imports of private paths must keep working
        from vulners.base import ResultSet, Unset  # noqa: F401
        from vulners.vulners.audit import AuditApi  # noqa: F401

    def test_submodule_attribute_access_alive(self):
        assert vulners.base is not None
        assert vulners.vscanner is not None
        assert vulners.vulners is not None

    def test_subpackage_all(self):
        assert vulners.vulners.__all__ == ["VulnersApi"]

    def test_construct_smoke(self):
        api = vulners.VulnersApi("SYNTHETIC-KEY")
        try:
            assert isinstance(api, vulners.VulnersApi)
        finally:
            api._client.close()


class TestVersion:
    """import vulners must not crash without dist-info, and __version__ must be
    reexported from the package root."""

    def test_top_level_version_reexported(self):
        assert vulners.__version__ == vulners.base.__version__

    def test_happy_path_matches_importlib_metadata(self):
        try:
            expected = version("vulners")
        except PackageNotFoundError:
            expected = "unknown"
        assert vulners.base.__version__ == expected

    def test_static_version_matches_pyproject(self):
        # _version.py is the single source of truth; it must match pyproject.
        from vulners import _version

        assert _version.__version__ == _project()["version"]

    def test_import_survives_missing_distribution(self):
        # Subprocess so import state stays isolated: with the "vulners"
        # distribution metadata absent (a checkout / PYTHONPATH / vendored /
        # frozen run), `import vulners` must exit 0 and __version__ must fall
        # back to "unknown".
        code = textwrap.dedent(
            """
            import importlib.metadata as m

            _orig = m.version

            def _fake(name, *a, **k):
                if name == "vulners":
                    raise m.PackageNotFoundError(name)
                return _orig(name, *a, **k)

            m.version = _fake

            import vulners

            assert vulners.base.__version__ == "unknown", vulners.base.__version__
            assert vulners.__version__ == "unknown", vulners.__version__
            # User-Agent must still build with the fallback version.
            api = vulners.VulnersApi("SYNTHETIC-KEY")
            assert api._client.headers["user-agent"] == "Vulners Python API unknown"
            api._client.close()
            print("unknown")
            """
        )
        env = dict(os.environ)
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().endswith("unknown"), result.stdout


class TestConstructorValidation:
    @pytest.mark.parametrize("cls", [vulners.VulnersApi, vulners.VScannerApi])
    @pytest.mark.parametrize("key", ["", None, 0, []])
    def test_falsy_api_key_raises_value_error(self, cls, key):
        with pytest.raises(ValueError):
            cls(key)

    @pytest.mark.parametrize("cls", [vulners.VulnersApi, vulners.VScannerApi])
    @pytest.mark.parametrize("key", [123, 4.5, b"SYNTHETIC-KEY", ["SYNTHETIC-KEY"]])
    def test_truthy_non_string_api_key_raises_type_error(self, cls, key):
        with pytest.raises(TypeError):
            cls(key)


class TestResultSet:
    def test_from_dataset_sets_total(self):
        rs = ResultSet.from_dataset([{"id": "CVE-2099-0001"}, {"id": "CVE-2099-0002"}], 42)
        assert isinstance(rs, ResultSet)
        assert list(rs) == [{"id": "CVE-2099-0001"}, {"id": "CVE-2099-0002"}]
        assert rs.total == 42

    def test_default_total_is_none(self):
        assert ResultSet.total is None
        assert ResultSet(["x"]).total is None

    def test_slice_returns_plain_list_without_total(self):
        # pin: slicing loses the ResultSet type and .total
        rs = ResultSet.from_dataset([1, 2, 3], 3)
        sliced = rs[:2]
        assert type(sliced) is list


class TestDependencies:
    """Directly-imported runtime dependencies must be declared, not reached only
    transitively through pydantic."""

    def test_typing_helpers_declared(self):
        declared = _dep_names()
        assert "typing-extensions" in declared
        assert "typing-inspection" in declared

    def test_core_runtime_deps_declared(self):
        declared = _dep_names()
        assert {"httpx", "pydantic", "orjson"} <= declared

    def test_typing_helpers_importable(self):
        # These are imported at `import vulners`; make the runtime need explicit.
        import typing_extensions  # noqa: F401
        import typing_inspection  # noqa: F401


class TestPyTyped:
    """PEP 561 py.typed marker so consumers' type checkers read the inline
    annotations. It lives inside the package, so uv_build ships it automatically
    in both wheel and sdist (asserted end-to-end by the CI package job)."""

    def test_marker_exists_and_is_empty(self):
        marker = REPO_ROOT / "src" / "vulners" / "py.typed"
        assert marker.is_file()
        # Must be truly empty (guards against a stray "partial\n").
        assert marker.read_bytes() == b""


class TestPackageMetadata:
    """PEP 621 metadata must be accurate. The exact built-wheel METADATA
    (License, Project-URLs) is asserted by the CI package job; here we pin the
    pyproject source that drives it."""

    def test_license_is_spdx_mit(self):
        # PEP 639 SPDX license expression.
        assert _project()["license"] == "MIT"

    def test_build_backend_is_uv_build(self):
        assert _load_pyproject()["build-system"]["build-backend"] == "uv_build"

    def test_description_drops_nonexistent_cli_claim(self):
        description = _project()["description"].lower()
        # There is no console_scripts / entry point; the old "command-line
        # utility" claim was false.
        assert "command-line" not in description
        assert "command line" not in description

    def test_project_urls_present(self):
        urls = _project()["urls"]
        assert urls["Homepage"] == "https://vulners.com"
        assert urls["Repository"] == "https://github.com/vulnersCom/api"
        assert urls["Documentation"]

    def test_typed_classifier_present(self):
        assert "Typing :: Typed" in _project()["classifiers"]

    def test_stray_classifier_removed(self):
        classifiers = _project()["classifiers"]
        # copy-paste classifier that never applied to this library
        assert "Topic :: Software Development :: Version Control" not in classifiers


class TestChangelog:
    """A Keep a Changelog / SemVer CHANGELOG, linked from package metadata."""

    CHANGELOG = REPO_ROOT / "CHANGELOG.md"

    def test_changelog_exists_with_unreleased_section(self):
        text = self.CHANGELOG.read_text(encoding="utf-8")
        assert "# Changelog" in text
        assert "keepachangelog.com" in text
        assert "## [Unreleased]" in text

    def test_headers_follow_keep_a_changelog(self):
        import re

        text = self.CHANGELOG.read_text(encoding="utf-8")
        # every versioned section is "## [x.y.z] - yyyy-mm-dd"
        versions = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$", text, re.M)
        assert versions, "no versioned sections found"
        # retrospective anchors: the v3 baseline releases are present
        found = {v for v, _ in versions}
        assert "3.0.0" in found
        assert "3.1.0" in found
        assert "3.1.11" in found
        assert "3.2.0" in found

    def test_top_versioned_section_tracks_a_release(self):
        import re

        text = self.CHANGELOG.read_text(encoding="utf-8")
        first = re.search(r"^## \[(\d+\.\d+\.\d+)\]", text, re.M)
        assert first is not None
        pkg_version = _project()["version"]
        is_prerelease = any(tag in pkg_version for tag in (".dev", "a", "b", "rc"))
        if is_prerelease:
            # During v4 pre-release, [Unreleased] holds the new work and the top
            # versioned entry is still the last shipped release (3.2.0).
            assert first.group(1) == "3.2.0"
        else:
            assert first.group(1) == pkg_version

    def test_changelog_linked_in_pyproject_urls(self):
        urls = _project()["urls"]
        assert "Changelog" in urls
        assert urls["Changelog"].startswith("https://")
