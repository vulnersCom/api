"""SearchApi pagination-boundary tests."""

from __future__ import annotations

import orjson
import pytest


class TestOffsetGuard:
    """search_bulletins(offset >= 10000) raises a clear ValueError, not a crash.

    The backend caps the search window at 10000 (Elasticsearch
    max_result_window), so an offset >= 10000 cannot be served. The guard fails
    loudly with a message before any request is sent, instead of the confusing
    pydantic ValidationError about ``size`` the ``min(limit, 10000 - offset)``
    clamp would otherwise produce.
    """

    @pytest.mark.parametrize("offset", [10000, 10001, 1_000_000])
    def test_offset_at_or_past_cap_raises_without_request(self, api, server, offset):
        with pytest.raises(ValueError, match="10000"):
            api.search.search_bulletins("type:synthetic", limit=20, offset=offset)
        # never touched the network
        assert server.requests == []

    def test_boundary_offset_9999_still_queries(self, api, server):
        server.enqueue_envelope({"search": [], "total": 12345})
        api.search.search_bulletins("type:synthetic", limit=20, offset=9999)
        req = server.last
        body = orjson.loads(req.content)
        # size clamped to the one remaining slot, skip is the offset
        assert body["size"] == 1
        assert body["skip"] == 9999

    def test_normal_path_regression(self, api, server):
        server.enqueue_envelope({"search": [{"_source": {"id": "CVE-2099-0001"}}], "total": 1})
        result = api.search.search_bulletins("type:synthetic", limit=5, offset=0)
        body = orjson.loads(server.last.content)
        assert body["size"] == 5
        assert body["skip"] == 0
        assert list(result) == [{"id": "CVE-2099-0001"}]
        assert result.total == 1

    def test_search_exploits_inherits_guard(self, api, server):
        with pytest.raises(ValueError, match="10000"):
            api.search.search_exploits("wordpress", offset=10000)
        assert server.requests == []

    def test_invalid_limit_at_valid_offset_still_validates(self, api, server):
        with pytest.raises(Exception) as excinfo:
            api.search.search_bulletins("type:synthetic", limit=-5, offset=0)
        assert excinfo.type.__name__ == "ValidationError"
        assert server.requests == []

    def test_negative_offset_still_validates(self, api, server):
        # the guard is offset >= 10000 only; a negative offset must still raise
        with pytest.raises(Exception) as excinfo:
            api.search.search_bulletins("type:synthetic", limit=20, offset=-1)
        assert excinfo.type.__name__ == "ValidationError"
        assert server.requests == []
