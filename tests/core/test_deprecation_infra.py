"""The deprecation escalation tier and the server-retirement registry."""

from __future__ import annotations

import vulners
from vulners._deprecation import (
    MIGRATION_GUIDE_URL,
    SERVER_RETIRED_ENDPOINTS,
    RemovedInVulners5Warning,
    retired_endpoint_message,
)


class TestWarningTiers:
    def test_removed_in_5_is_a_deprecation_warning(self):
        assert issubclass(RemovedInVulners5Warning, vulners.VulnersDeprecationWarning)
        assert issubclass(RemovedInVulners5Warning, DeprecationWarning)

    def test_exported_from_root(self):
        assert vulners.RemovedInVulners5Warning is RemovedInVulners5Warning
        assert "RemovedInVulners5Warning" in vulners.__all__

    def test_migration_url_is_shared_single_source(self):
        # The base warning helper and the deprecation module quote the same URL.
        from vulners.base import MIGRATION_GUIDE_URL as base_url

        assert base_url == MIGRATION_GUIDE_URL
        assert MIGRATION_GUIDE_URL.startswith("https://")


class TestServerRetiredRegistry:
    def test_ships_empty(self):
        assert SERVER_RETIRED_ENDPOINTS == {}

    def test_no_message_for_live_endpoint(self):
        assert retired_endpoint_message("/api/v3/search/id/") is None

    def test_message_is_actionable_when_registered(self, monkeypatch):
        monkeypatch.setitem(
            SERVER_RETIRED_ENDPOINTS,
            "/api/v3/burp/",
            "The Burp integration endpoints were retired by the server.",
        )
        msg = retired_endpoint_message("/api/v3/burp/rules/")
        assert msg is not None
        assert "retired" in msg and MIGRATION_GUIDE_URL in msg

    def test_non_matching_registered_prefix_is_skipped(self, monkeypatch):
        # A registered entry whose prefix does not match the path is passed over
        # (the loop continues) and an unrelated path still yields None.
        monkeypatch.setitem(SERVER_RETIRED_ENDPOINTS, "/api/v3/burp/", "retired.")
        assert retired_endpoint_message("/api/v3/search/id/") is None


def test_every_legacy_warning_links_the_guide(recwarn):
    # A deprecated flat proxy warns, and the message carries the guide URL.
    api = vulners.VulnersApi("SYNTHETIC-KEY")
    try:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("always")
            from vulners.base import deprecation_warning

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                deprecation_warning("X.y() is deprecated.")
        assert any(MIGRATION_GUIDE_URL in str(w.message) for w in caught)
    finally:
        api._client.close()
