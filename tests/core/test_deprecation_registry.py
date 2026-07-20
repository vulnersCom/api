"""The server-retired-endpoint registry lookup (``vulners._deprecation``)."""

from __future__ import annotations

from vulners._deprecation import (
    MIGRATION_GUIDE_URL,
    retired_endpoint_message,
)


class TestRetiredEndpointMessage:
    def test_unknown_path_returns_none(self):
        # The registry ships empty, so any path misses.
        assert retired_endpoint_message("/api/v3/search/lucene/") is None

    def test_registered_prefix_returns_actionable_message(self, monkeypatch):
        monkeypatch.setattr(
            "vulners._deprecation.SERVER_RETIRED_ENDPOINTS",
            {"/api/v3/burp/": "The burp rules endpoint was retired."},
        )
        message = retired_endpoint_message("/api/v3/burp/rules/")
        assert message is not None
        assert message.startswith("The burp rules endpoint was retired.")
        assert MIGRATION_GUIDE_URL in message

    def test_non_matching_entry_falls_through_to_none(self, monkeypatch):
        monkeypatch.setattr(
            "vulners._deprecation.SERVER_RETIRED_ENDPOINTS",
            {"/api/v3/burp/": "retired"},
        )
        assert retired_endpoint_message("/api/v3/search/lucene/") is None
