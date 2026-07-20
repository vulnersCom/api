"""The v4 public surface is importable from the package root and coexists with v3.

Locks the backward-compat wiring: `from vulners import Vulners` works, the public
types and exception hierarchy are reachable from the root, and the v3 names are
untouched alongside it.
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
        from vulners import NotGiven, not_given

        assert bool(not_given) is False
        assert isinstance(not_given, NotGiven)

    def test_omit_not_public(self):
        # `omit`/`Omit` are internal (no public method accepts them); they must
        # not be part of the package-root surface.
        import pytest

        assert "omit" not in vulners.__all__
        assert "Omit" not in vulners.__all__
        with pytest.raises(AttributeError):
            _ = vulners.omit
        with pytest.raises(AttributeError):
            _ = vulners.Omit

    def test_public_types_reexported(self):
        # Annotation-worthy return/input types are reachable from the root, lazily.
        from vulners import AsyncSearchPage, Bulletin, SearchPage

        assert Bulletin.__name__ == "Bulletin"
        assert SearchPage.__name__ == "SearchPage"
        assert AsyncSearchPage.__name__ == "AsyncSearchPage"
        # Same object as the private module's (lazy re-export identity).
        from vulners._models.bulletin import Bulletin as PrivateBulletin
        from vulners._pagination import SearchPage as PrivateSearchPage

        assert Bulletin is PrivateBulletin
        assert SearchPage is PrivateSearchPage

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
        from vulners.base import VulnersApiError

        assert issubclass(APIError, VulnersError)
        assert issubclass(APIStatusError, APIError)
        # Server-reported errors stay catchable by legacy v3 handlers.
        assert issubclass(APIError, VulnersApiError)
        # Transport-side failures are siblings of APIError (v3 surfaced those as
        # raw httpx errors, never VulnersApiError) — deliberately NOT APIError.
        assert issubclass(APIConnectionError, VulnersError)
        assert not issubclass(APIConnectionError, APIError)
        assert not issubclass(APIConnectionError, VulnersApiError)
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


class TestRootModuleSurface:
    def test_dir_lists_lazy_and_eager_names(self):
        import vulners

        names = dir(vulners)
        for expected in (
            "Vulners",
            "AsyncVulners",
            "VulnersApi",
            "ValidationError",
            "__version__",
        ):
            assert expected in names

    def test_plan_alias_exports_resolve(self):
        import vulners

        assert vulners.ValidationError is vulners.UnprocessableEntityError
        assert vulners.ServerError is vulners.InternalServerError

    def test_legacy_type_reexports(self):
        from vulners import (
            DEFAULT_BULLETIN_FIELDS,
            DEFAULT_FIELDS,
            AuditFields,
            BulletinField,
            NotificationObj,
        )

        assert isinstance(DEFAULT_FIELDS, tuple) and DEFAULT_FIELDS
        assert isinstance(DEFAULT_BULLETIN_FIELDS, list) and DEFAULT_BULLETIN_FIELDS
        assert AuditFields is not None and BulletinField is not None
        assert NotificationObj is not None

    def test_version_is_static(self):
        import vulners
        from vulners._version import __version__ as static_version

        assert vulners.__version__ == static_version
