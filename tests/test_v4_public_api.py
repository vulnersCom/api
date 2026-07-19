"""The v4 public surface is importable from the package root and coexists with v3.

Locks the WP6 backward-compat wiring: `from vulners import Vulners` works, the
exception hierarchy is coherent, and the v3 names are untouched alongside it.
"""

from __future__ import annotations

import vulners


class TestV4Importable:
    def test_clients_importable_from_root(self):
        from vulners import AsyncVulners, Vulners

        assert Vulners.__name__ == "Vulners"
        assert AsyncVulners.__name__ == "AsyncVulners"

    def test_lazy_load_identity(self):
        # The root re-export is the same object as the private module's.
        from vulners._client import Vulners as PrivateVulners

        assert vulners.Vulners is PrivateVulners

    def test_sentinels_importable(self):
        from vulners import NotGiven, Omit, not_given, omit

        assert bool(omit) is False
        assert bool(not_given) is False
        assert isinstance(omit, Omit)
        assert isinstance(not_given, NotGiven)

    def test_unknown_attribute_raises(self):
        import pytest

        with pytest.raises(AttributeError):
            _ = vulners.DoesNotExist


class TestExceptionHierarchy:
    def test_hierarchy_is_coherent(self):
        from vulners import (
            APIConnectionError,
            APIError,
            APIStatusError,
            AuthenticationError,
            NotFoundError,
            RateLimitError,
            VulnersError,
        )

        assert issubclass(APIError, VulnersError)
        assert issubclass(APIStatusError, APIError)
        assert issubclass(APIConnectionError, APIError)
        for cls in (AuthenticationError, NotFoundError, RateLimitError):
            assert issubclass(cls, APIStatusError)


class TestV3StillPresent:
    def test_v3_names_untouched(self):
        from vulners import VScannerApi, VulnersApi, VulnersApiError, VulnersDeprecationWarning

        assert issubclass(VulnersApiError, Exception)
        assert issubclass(VulnersDeprecationWarning, DeprecationWarning)
        assert VulnersApi is not None and VScannerApi is not None

    def test_v3_and_v4_are_distinct_error_types(self):
        # v3 raises VulnersApiError (legacy); v4 raises the VulnersError hierarchy.
        # They are intentionally separate contracts (documented migration note).
        from vulners import APIError, VulnersApiError

        assert APIError is not VulnersApiError


class TestPublicClientWorks:
    def test_construct_and_close_from_root(self):
        client = vulners.Vulners(api_key="SYNTHETIC-KEY")
        try:
            assert client.is_closed is False
            assert client.search is not None
            assert client.audit is not None
        finally:
            client.close()
        assert client.is_closed is True
