"""Client lifecycle tests: close() and context-manager support."""

from __future__ import annotations

import httpx
import pytest

import vulners
from vulners.base import VulnersApiBase, VulnersApiTransport


class _SpyTransport(httpx.BaseTransport):
    """Records whether close() reached it (through the real wrapper chain)."""

    def __init__(self) -> None:
        self.closed = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"result": "OK", "data": {}})

    def close(self) -> None:
        self.closed = True


def _api_with_spy(cls=vulners.VulnersApi):
    api = cls("SYNTHETIC-KEY")
    spy = _SpyTransport()
    # keep the real wrapper in the chain — a bare Client would mask the bug
    api._client._transport = VulnersApiTransport(spy)
    return api, spy


class TestClose:
    def test_transport_close_delegates(self):
        spy = _SpyTransport()
        VulnersApiTransport(spy).close()
        assert spy.closed

    def test_close_reaches_inner_transport(self):
        api, spy = _api_with_spy()
        api.close()
        assert spy.closed

    def test_double_close_is_idempotent(self):
        api, spy = _api_with_spy()
        api.close()
        api.close()
        assert spy.closed

    def test_context_manager_returns_self_and_closes(self):
        api, spy = _api_with_spy()
        with api as ctx:
            assert ctx is api
        assert spy.closed

    def test_exception_in_with_block_not_suppressed(self):
        api, spy = _api_with_spy()
        with pytest.raises(ValueError):
            with api:
                raise ValueError("boom")
        # still closed on the way out
        assert spy.closed

    def test_request_inside_with_then_closed(self, server):
        api = vulners.VulnersApi("SYNTHETIC-KEY")
        api._client._transport = VulnersApiTransport(httpx.MockTransport(server.handler))
        with api:
            server.enqueue_envelope({"result": [{"x": 1}]})
            api.search.get_bulletin_history(id="CVE-2099-0001")
        # after close, a further request fails
        with pytest.raises(RuntimeError):
            api.search.get_bulletin_history(id="CVE-2099-0002")

    @pytest.mark.parametrize("cls", [vulners.VulnersApi, vulners.VScannerApi])
    def test_close_available_on_both_apis(self, cls):
        api, spy = _api_with_spy(cls)
        api.close()
        assert spy.closed

    def test_close_not_shadowed_by_endpoint_generation(self):
        assert vulners.VulnersApi.close is VulnersApiBase.close
        assert vulners.VScannerApi.close is VulnersApiBase.close
        assert vulners.VulnersApi.__enter__ is VulnersApiBase.__enter__
        assert vulners.VulnersApi.__exit__ is VulnersApiBase.__exit__

    def test_enter_return_annotation_is_self(self):
        # __enter__ must be annotated Self (not the base class) so a typed
        # `with VulnersApi(...) as api:` keeps the concrete subclass and its
        # sub-API attributes type-check.
        assert VulnersApiBase.__enter__.__annotations__["return"] == "Self"
