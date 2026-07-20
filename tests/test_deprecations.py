"""Pins for deprecation warnings.

The declared endpoints of the package emit warnings either through
@deprecated proxy shims (VulnersApi.find, ...) or through the
endpoint(deprecated=...) parameter; a synthetic endpoint pins the latter
mechanism without depending on package declarations.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

import vulners
from vulners.base import (
    VulnersApiProxy,
    VulnersDeprecationWarning,
    _shim_guard,
    deprecated,
    endpoint,
)

_REPO_ROOT = Path(vulners.__file__).resolve().parent.parent


def _run_python(code: str, warn_args: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    """Run `code` in a fresh interpreter (isolated warning-filter state).

    Optional ``warn_args`` are passed as ``-W`` options so a test can pin the
    host application's warning policy and prove `import vulners` no longer
    clobbers it.
    """
    args = [sys.executable]
    for w in warn_args:
        args += ["-W", w]
    args += ["-c", textwrap.dedent(code)]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_REPO_ROOT), env.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=60)


class _SyntheticApi(VulnersApiProxy):
    fetch = endpoint(
        "_SyntheticApi.fetch",
        method="GET",
        url="/synthetic/deprecated/",
        deprecated="_SyntheticApi.fetch() is deprecated.",
    )
    plain = endpoint(
        "_SyntheticApi.plain",
        method="GET",
        url="/synthetic/plain/",
    )


@deprecated("_raising_shim() is deprecated.")
def _raising_shim() -> None:
    raise RuntimeError("boom")


class TestEndpointDeprecatedParam:
    def test_synthetic_endpoint_warns_with_exact_format(self, api, server):
        proxy = _SyntheticApi(api)
        with pytest.warns(DeprecationWarning) as record:
            proxy.fetch()
        messages = [str(w.message) for w in record]
        assert messages == [
            "\n[!] DEPRECATION WARNING\n[!] _SyntheticApi.fetch() is deprecated."
            "\n[!] Migration guide: https://vulnersCom.github.io/api/explanation/migration/"
        ]
        # the request itself still goes out
        assert server.last.url.path == "/synthetic/deprecated/"


class TestAttribution:
    """Deprecation warnings must point at the user's call site and use the
    dedicated VulnersDeprecationWarning category."""

    def test_endpoint_deprecated_attributes_to_caller(self, api, server):
        proxy = _SyntheticApi(api)
        with pytest.warns(DeprecationWarning) as record:
            proxy.fetch()
        # stacklevel=3 -> this test file, not vulners/base.py
        assert record[0].filename.endswith("test_deprecations.py")
        assert "base.py" not in record[0].filename
        assert record[0].category is VulnersDeprecationWarning

    def test_shim_attributes_to_caller(self, api, server):
        server.enqueue_envelope({"documents": {"CVE-2099-99999": {"id": "CVE-2099-99999"}}})
        with pytest.warns(DeprecationWarning) as record:
            api.get_bulletin("CVE-2099-99999")
        assert record[0].filename.endswith("test_deprecations.py")
        assert "base.py" not in record[0].filename
        assert record[0].category is VulnersDeprecationWarning

    def test_category_is_deprecationwarning_subclass(self):
        # issubclass keeps `except DeprecationWarning` / -W rules / pytest.warns
        # working while allowing a scoped filter
        assert issubclass(VulnersDeprecationWarning, DeprecationWarning)

    def test_category_is_a_clean_public_export(self):
        # The category is advertised as public (callers scope their warning
        # filters to it), so it must be reachable from the package root and
        # listed in __all__ (a clean re-export under py.typed / no-implicit-
        # reexport).
        assert vulners.VulnersDeprecationWarning is VulnersDeprecationWarning
        assert "VulnersDeprecationWarning" in vulners.__all__


class TestDeprecatedMarker:
    """PEP 702-style __deprecated__ runtime marker."""

    def test_endpoint_deprecated_has_marker(self):
        assert _SyntheticApi.fetch.__deprecated__ == "_SyntheticApi.fetch() is deprecated."

    def test_non_deprecated_endpoint_has_no_marker(self):
        assert "__deprecated__" not in _SyntheticApi.plain.__dict__

    def test_flat_proxy_shim_has_marker(self):
        marker = vulners.VulnersApi.get_subscriptions.__deprecated__
        assert "get_subscriptions" in marker

    def test_getsploit_shim_names_itself_and_migration_target(self):
        # the shim message must name the deprecated method (getsploit), not a
        # copy-pasted sibling, and point at the replacement
        marker = vulners.VulnersApi.getsploit.__deprecated__
        assert "VulnersApi.getsploit()" in marker
        assert "get_distributive" not in marker
        assert "VulnersApi.archive.getsploit()" in marker

    def test_wraps_metadata_intact(self):
        assert _SyntheticApi.fetch.__name__ == "fetch"
        assert _SyntheticApi.fetch.__qualname__ == "_SyntheticApi.fetch"
        assert vulners.VulnersApi.get_subscriptions.__name__ == "get_subscriptions"


class TestDeprecatedShims:
    def test_flat_proxy_shim_warns_once_and_delegates(self, api, server):
        server.enqueue_envelope({"documents": {"CVE-2099-99999": {"id": "CVE-2099-99999"}}})
        with pytest.warns(DeprecationWarning) as record:
            doc = api.get_bulletin("CVE-2099-99999")
        messages = [str(w.message) for w in record]
        assert len(messages) == 1
        assert "VulnersApi.get_bulletin() is deprecated" in messages[0]
        assert doc == {"id": "CVE-2099-99999"}
        assert server.last.url.path == "/api/v3/search/id/"

    def test_shim_over_deprecated_endpoint_warns_once(self, api, server):
        # a @deprecated shim delegating to an endpoint(deprecated=...)
        # declaration emits exactly one warning (the shim's own); the inner
        # endpoint warning is suppressed
        server.enqueue_envelope({"subscriptions": []})
        with pytest.warns(DeprecationWarning) as record:
            subs = api.get_subscriptions()
        assert len(record) == 1
        assert "get_subscriptions" in str(record[0].message)
        assert subs == []


class TestWarningCount:
    """Exactly one deprecation warning per call; the guard is thread-local and
    reset on exceptions."""

    def test_direct_deprecated_endpoint_still_warns(self, api, server):
        # a direct call to a deprecated endpoint keeps its own warning (guard
        # only suppresses the *inner* warning when reached through a shim)
        server.enqueue_envelope({"subscriptions": []})
        with pytest.warns(DeprecationWarning) as record:
            api.subscription.list()
        assert len(record) == 1
        assert "SubscriptionApi.list" in str(record[0].message)

    def test_synthetic_shim_over_deprecated_endpoint_warns_once(self, api, server):
        @deprecated("outer shim is deprecated")
        def outer(a):
            return _SyntheticApi(a).fetch()

        with pytest.warns(DeprecationWarning) as record:
            outer(api)
        assert len(record) == 1
        assert "outer shim" in str(record[0].message)

    def test_guard_reset_after_exception(self):
        with pytest.warns(DeprecationWarning):
            with pytest.raises(RuntimeError):
                _raising_shim()
        # the finally clause restored the guard even though the call raised
        assert getattr(_shim_guard, "active", False) is False

    def test_guard_is_thread_local(self):
        seen: dict[str, bool] = {}

        def worker() -> None:
            seen["active"] = getattr(_shim_guard, "active", False)

        _shim_guard.active = True
        try:
            t = threading.Thread(target=worker)
            t.start()
            t.join()
        finally:
            _shim_guard.active = False
        # a fresh thread never inherits another thread's active guard
        assert seen["active"] is False


class TestWarningFilterScope:
    """`import vulners` must no longer mutate the process-global warning filters.
    It registers a scoped filter for its own VulnersDeprecationWarning subclass
    instead, leaving the host application's DeprecationWarning policy intact.
    These run in subprocesses so filter state is clean."""

    def test_import_registers_scoped_filter_not_global(self):
        result = _run_python(
            """
            import vulners, warnings
            unscoped = [
                f for f in warnings.filters
                if f[0] == "always" and f[2] is DeprecationWarning
            ]
            scoped = [
                f for f in warnings.filters
                if f[0] == "always" and f[2].__name__ == "VulnersDeprecationWarning"
            ]
            assert not unscoped, unscoped
            assert scoped, warnings.filters
            print("OK")
            """
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().endswith("OK")

    def test_host_error_gate_survives_import(self):
        # -W error::DeprecationWarning must still turn a non-Vulners
        # DeprecationWarning into an error after importing vulners. The old
        # global simplefilter downgraded this gate to "always" (exit 0).
        result = _run_python(
            "import vulners, warnings; warnings.warn('boom', DeprecationWarning)",
            warn_args=("error::DeprecationWarning",),
        )
        assert result.returncode != 0
        assert "DeprecationWarning" in result.stderr

    def test_host_ignore_survives_import(self):
        # -W ignore::DeprecationWarning must still suppress a non-Vulners
        # DeprecationWarning; the old global "always" would have shown it.
        result = _run_python(
            "import vulners, warnings; warnings.warn('boom', DeprecationWarning)",
            warn_args=("ignore::DeprecationWarning",),
        )
        assert result.returncode == 0, result.stderr
        assert "boom" not in result.stderr

    def test_own_deprecation_shown_on_every_call(self):
        # the SDK's own notices still fire on every call (not once-per-location).
        # Both calls share a line so the "default" policy would dedup to one;
        # "always" keeps both.
        result = _run_python(
            """
            import vulners
            from vulners.base import deprecation_warning
            for _ in range(2):
                deprecation_warning("dep-msg")
            """
        )
        assert result.returncode == 0, result.stderr
        assert result.stderr.count("DEPRECATION WARNING") == 2, result.stderr
