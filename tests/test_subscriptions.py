"""Subscription / webhook endpoint fixes: the key-in-query leak, the dead
SubscriptionV4Api.get wire param, and the full-replace update() docstring warning.

All IDs are synthetic (SYNTHETIC*); mock data mirrors only the shape of the real
server envelopes.
"""

from __future__ import annotations

import inspect

import orjson
import pytest

from vulners.vulners.subscription_v4 import SubscriptionV4Api


class TestKeyNotInQuery:
    """Header-only GET endpoints no longer duplicate the API key
    into the query string; the one endpoint that requires it keeps it."""

    def test_subscription_list_no_api_key_in_query(self, api, server):
        server.enqueue_envelope({"subscriptions": []})
        with pytest.warns(DeprecationWarning):
            api.subscription.list()
        req = server.last
        assert req.method == "GET"
        assert req.url.path == "/api/v3/subscriptions/listEmailSubscriptions/"
        assert "apiKey" not in dict(req.url.params)
        # auth still travels in the header
        assert req.headers["x-api-key"] == api._api_key

    def test_webhook_list_no_api_key_in_query(self, api, server):
        server.enqueue_envelope({"subscriptions": []})
        api.webhook.list()
        req = server.last
        assert req.method == "GET"
        assert req.url.path == "/api/v3/subscriptions/listWebhookSubscriptions/"
        assert "apiKey" not in dict(req.url.params)
        assert req.headers["x-api-key"] == api._api_key

    def test_webhook_read_keeps_api_key_in_query(self, api, server):
        # pin the selective decision: this endpoint ignores X-Api-Key and
        # requires apiKey in the query (server errorCode 103 otherwise), so the
        # key MUST stay in the query here (the server requires it).
        server.enqueue_envelope({"webhook": {}})
        api.webhook.read(id="SYNTHETIC00-WH-0001")
        req = server.last
        assert req.method == "GET"
        assert req.url.path == "/api/v3/subscriptions/webhook"
        params = dict(req.url.params)
        assert params.get("apiKey") == api._api_key
        assert params["subscriptionid"] == "SYNTHETIC00-WH-0001"
        assert req.headers["x-api-key"] == api._api_key


class TestGetWireParam:
    """SubscriptionV4Api.get accepts either `id` or `subscription_id` and sends
    the `subscription_id` query parameter the server requires (it rejects `id`
    with 400)."""

    def test_python_signature_takes_both_names(self):
        # public arguments are (self, id, subscription_id) — either may be given
        params = list(inspect.signature(SubscriptionV4Api.get).parameters)
        assert params == ["self", "id", "subscription_id"]

    def test_get_id_keyword_sends_subscription_id_on_wire(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0001"}})
        api.subscription_v4.get(id="SYNTHETIC00-SUB-0001")
        req = server.last
        assert req.method == "GET"
        assert req.url.path == "/api/v4/subscriptions/get/"
        # exactly one id-bearing param, and it is the working name
        assert dict(req.url.params) == {"subscription_id": "SYNTHETIC00-SUB-0001"}
        assert "id" not in dict(req.url.params)

    def test_get_subscription_id_keyword_sends_subscription_id_on_wire(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0009"}})
        api.subscription_v4.get(subscription_id="SYNTHETIC00-SUB-0009")
        assert dict(server.last.url.params) == {"subscription_id": "SYNTHETIC00-SUB-0009"}

    def test_get_without_any_id_raises(self, api, server):
        with pytest.raises(TypeError, match="id"):
            api.subscription_v4.get()
        assert server.requests == []

    def test_get_positional_sends_subscription_id_on_wire(self, api, server):
        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0002"}})
        api.subscription_v4.get("SYNTHETIC00-SUB-0002")
        assert dict(server.last.url.params) == {"subscription_id": "SYNTHETIC00-SUB-0002"}

    def test_delete_and_update_still_use_id_on_wire(self, api, server):
        # neighbours are untouched: DELETE keeps ?id, PUT keeps id in the body
        server.enqueue_json({"result": "OK"})
        api.subscription_v4.delete(id="SYNTHETIC00-SUB-0003")
        assert dict(server.last.url.params) == {"id": "SYNTHETIC00-SUB-0003"}

        server.enqueue_json({"result": {"id": "SYNTHETIC00-SUB-0004"}})
        api.subscription_v4.update(
            id="SYNTHETIC00-SUB-0004",
            name="synthetic",
            query={"type": "synthetic"},
            delivery={"kind": "webhook"},
        )
        body = orjson.loads(server.last.content)
        assert body["id"] == "SYNTHETIC00-SUB-0004"
        assert "subscription_id" not in body


class TestUpdateFullReplaceDocstring:
    """update() carries a loud full-replace warning in its docstring (the
    server does not support partial PUT; partial merge is deferred to the v4 API)."""

    def test_update_docstring_warns_about_full_replace(self):
        doc = SubscriptionV4Api.update.__doc__
        assert doc is not None
        lowered = doc.lower()
        assert "full-replace" in lowered
        assert "overwrite" in lowered
        # names the SDK-default fields that get silently reset
        assert "bulletin_fields" in doc
        assert "send_empty_result" in doc

    def test_update_docstring_visible_on_bound_method(self, api):
        # help()/hover on the bound method shows the same warning
        assert api.subscription_v4.update.__doc__ == SubscriptionV4Api.update.__doc__

    def test_create_has_no_full_replace_warning(self):
        # the warning is scoped to update(); create() legitimately uses defaults
        assert not (SubscriptionV4Api.create.__doc__ or "")

