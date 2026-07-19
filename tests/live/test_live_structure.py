"""Live structural-invariant tests against the real Vulners API (opt-in).

Rules (the live database is dynamic, so tests pin structure, not data):
- assert STRUCTURE only (envelope keys, types, statuses, content-type) —
  never concrete vulnerabilities, documents or counts;
- keep the API key and echoed request input out of assertion messages:
  boolean-style asserts are used wherever a failure message could otherwise
  dump a response payload (v4 validation errors echo the request input).
"""

from __future__ import annotations

import orjson
import pytest

from vulners.base import ResultSet

pytestmark = pytest.mark.live


def test_v3_success_envelope_shape(live_api):
    resp = live_api._client.post(
        "/api/v3/search/lucene/", json={"query": "type:cve", "size": 1, "fields": ["id"]}
    )
    assert resp.status_code == 200
    # exact media type, no charset (server fact, pinned)
    assert resp.headers.get("content-type") == "application/json"
    body = orjson.loads(resp.content)
    assert isinstance(body, dict) is True
    assert set(body) >= {"result", "data"}
    assert body.get("result") == "OK"
    data = body.get("data")
    assert isinstance(data, dict) is True
    # success envelopes carry no "error" key at all
    assert ("error" in data) is False


def test_v3_error_arrives_in_http_200_with_error_code(live_api):
    # malformed parameter type: v3 answers HTTP 200 with an error envelope
    resp = live_api._client.post(
        "/api/v3/search/lucene/", json={"query": "type:cve", "size": "not-a-number"}
    )
    assert resp.status_code == 200
    assert resp.headers.get("content-type") == "application/json"
    body = orjson.loads(resp.content)
    assert isinstance(body, dict) is True
    assert body.get("result") == "error"
    data = body.get("data")
    assert isinstance(data, dict) is True
    # do not assert on the error text (may echo input); types/keys only
    assert isinstance(data.get("error"), str) is True
    assert isinstance(data.get("errorCode"), int) is True


def test_v4_validation_error_is_http_400_with_errors_list(live_api):
    resp = live_api._client.post(
        "/api/v4/audit/software/", json={"software": "SYNTHETIC-not-a-list"}
    )
    assert resp.status_code == 400
    assert resp.headers.get("content-type") == "application/json"
    body = orjson.loads(resp.content)
    assert isinstance(body, dict) is True
    errors = body.get("errors")
    assert isinstance(errors, list) is True
    assert len(errors) > 0
    first = errors[0]
    assert isinstance(first, dict) is True
    # keys only; never inspect first["input"] — it echoes the request
    assert set(first) >= {"type", "loc", "msg"}


def test_sdk_search_roundtrip_returns_resultset(live_api):
    result = live_api.search.search_bulletins("type:cve", limit=1)
    assert isinstance(result, ResultSet)
    assert isinstance(result.total, int) is True
    assert result.total >= 0
    assert len(result) <= 1
