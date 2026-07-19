"""Micro-benchmarks for the v4 core hot paths (pytest-codspeed).

These cover the four operations that run on every request or per streamed record:

* ``construct_type`` — validation-free model construction from a bulletin payload;
* ``_build_request`` — turning a :class:`RequestSpec` + body into an httpx request;
* ``_extract_error`` — normalizing a server error envelope into an ``ErrorInfo``;
* NDJSON line decode — the per-chunk archive-stream decoder.

They are marked ``benchmark`` and are **excluded from the default test run** by the
``-m "not benchmark"`` default in ``pyproject.toml`` (so ``uv run pytest -n auto``
never runs them). Run them explicitly with::

    uv run pytest tests/benchmarks --codspeed -m benchmark

The ``benchmark`` fixture is provided by pytest-codspeed; without ``--codspeed`` it
falls back to a single walltime call, so this file also imports and runs cleanly
under a plain pytest invocation (it just does not measure).
"""

from __future__ import annotations

from typing import Any

import pytest

from vulners._base_client import BaseClient, RequestSpec
from vulners._config import resolve_config
from vulners._exceptions import _extract_error
from vulners._models._base import construct_type
from vulners._models.bulletin import Bulletin, bulletin_class_for
from vulners._streaming import PlainNdjsonDecoder

pytestmark = pytest.mark.benchmark


# A representative CVE bulletin payload (synthetic; shape mirrors a real
# ``/search/id`` ``_source`` document, nested CVSS blocks and list fields).
_BULLETIN_PAYLOAD: dict[str, Any] = {
    "id": "CVE-2099-0001",
    "title": "Synthetic remote code execution in libsynthetic",
    "description": "A crafted packet triggers a heap overflow. " * 8,
    "type": "cve",
    "bulletinFamily": "NVD",
    "published": "2099-01-01T00:00:00",
    "modified": "2099-02-01T00:00:00",
    "lastseen": "2099-03-01T00:00:00",
    "href": "https://vulners.com/cve/CVE-2099-0001",
    "cvss": {"version": "3.1", "score": 9.8, "vector": "AV:N/AC:L/PR:N", "severity": "CRITICAL"},
    "cvss2": {"version": "2.0", "score": 10.0, "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
    "cvss3": {"version": "3.1", "score": 9.8, "vector": "AV:N/AC:L/PR:N"},
    "cpe": [f"cpe:/a:synthetic:lib:{n}" for n in range(20)],
    "cwe": ["CWE-787", "CWE-122"],
    "cvelist": ["CVE-2099-0001"],
    "epss": [{"cve": "CVE-2099-0001", "epss": 0.97, "percentile": 0.999}],
    "references": [f"https://example.test/ref/{n}" for n in range(15)],
}

_ERROR_ENVELOPE: dict[str, Any] = {
    "result": "error",
    "data": {"error": "Wrong parameter value for 'query'", "errorCode": 104},
}

_NDJSON_CHUNK: bytes = (
    b"\n".join(
        b'{"id": "CVE-2099-%04d", "cvss": {"score": 7.5}, "type": "cve"}' % n for n in range(50)
    )
    + b"\n"
)


@pytest.fixture(scope="module")
def _client() -> BaseClient:
    # BaseClient carries only the sans-IO helpers (no network); enough for
    # _build_request. A synthetic key keeps it self-contained.
    return BaseClient(resolve_config(api_key="SYNTHETIC-BENCH-KEY", version="bench"))


def test_construct_type_bulletin(benchmark: Any) -> None:
    model = bulletin_class_for(_BULLETIN_PAYLOAD)

    def run() -> Bulletin:
        return construct_type(_BULLETIN_PAYLOAD, model)

    result = benchmark(run)
    assert result.id == "CVE-2099-0001"


def test_build_request(benchmark: Any, _client: BaseClient) -> None:
    spec = RequestSpec("POST", "/api/v3/search/lucene/", body_mode="json", unwrap=("data",))
    body = {"query": "type:cve order:published", "size": 20, "skip": 0}

    def run() -> Any:
        return _client._build_request(spec, body=body)

    request = benchmark(run)
    assert request.method == "POST"


def test_extract_error(benchmark: Any) -> None:
    def run() -> Any:
        return _extract_error(200, None, _ERROR_ENVELOPE, secret="SYNTHETIC-BENCH-KEY")

    info = benchmark(run)
    assert info is not None
    assert info.error_code == 104


def test_ndjson_line_decode(benchmark: Any) -> None:
    def run() -> int:
        decoder = PlainNdjsonDecoder()
        count = sum(1 for _ in decoder.feed(_NDJSON_CHUNK))
        count += sum(1 for _ in decoder.flush())
        return count

    total = benchmark(run)
    assert total == 50
