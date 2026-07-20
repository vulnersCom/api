"""Live structural tests for the v4 client against the real Vulners API (opt-in).

These would have caught the archive-format and bulletin-family bugs the mocked
tests missed. Structural only (the DB is dynamic); the key is never asserted or
logged. Archive streaming is bounded so nothing downloads gigabytes.
"""

from __future__ import annotations

import itertools

import pytest

from vulners import AsyncVulners, CveBulletin
from vulners._pagination import SearchPage

pytestmark = pytest.mark.live


def test_search_query_returns_typed_page(live_v4):
    page = live_v4.search.query(
        "type:cve order:published", limit=5, fields=["id", "bulletinFamily"]
    )
    assert isinstance(page, SearchPage)
    assert page.total > 0
    assert page.data, "expected at least one bulletin"
    # A CVE must discriminate to the typed CveBulletin, not fall back to Generic.
    assert isinstance(page.data[0], CveBulletin)
    assert page.data[0].id


def test_get_bulletin_cve_is_cve_bulletin(live_v4):
    bulletin = live_v4.search.get_bulletin("CVE-2021-44228")
    assert bulletin is not None
    assert isinstance(bulletin, CveBulletin)
    assert bulletin.id == "CVE-2021-44228"


def test_iter_collection_streams_dicts_lazily(live_v4):
    # The archive is a gzip-compressed JSON array; iter_collection must stream its
    # elements (dicts), not choke on a wrong NDJSON assumption. Bounded to 3.
    records = list(itertools.islice(live_v4.archive.iter_collection("cve"), 3))
    assert len(records) == 3
    assert all(isinstance(r, dict) and r.get("id") for r in records)


def test_escape_hatch_post(live_v4):
    # The escape hatch reaches an arbitrary endpoint through the full core
    # pipeline (auth, retries, error mapping) and returns the parsed body.
    out = live_v4.post("/api/v3/search/lucene/", json={"query": "type:cve", "size": 1})
    assert isinstance(out, dict)
    assert out.get("result") == "OK"


async def test_async_search_and_stream(live_config):
    key, server_url = live_config
    async with AsyncVulners(api_key=key, base_url=server_url) as v:
        page = await v.search.query("type:cve", limit=3, fields=["id", "bulletinFamily"])
        assert page.data and isinstance(page.data[0], CveBulletin)
        records = []
        async for rec in v.archive.aiter_collection("cve"):
            records.append(rec)
            if len(records) >= 3:
                break
        assert len(records) == 3 and all(isinstance(r, dict) for r in records)
