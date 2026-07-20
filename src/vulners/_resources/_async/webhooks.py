"""Async ``webhooks`` resource (unasyncd source for the sync ``webhooks`` resource).

Webhook subscriptions over the v3 polling endpoints. These endpoints carry the
API key in the request *body* (``apiKey``) in addition to the ``X-Api-Key``
header: ``addWebhookSubscription`` requires it, ``edit`` / ``remove`` consume it
when present. The body key names the *owner* of the subscription, which is why
every mutating method takes an ``api_key`` argument — it defaults to the client's
own key, but a privileged key (sent in the header) can pass a different owner key
to manage that key's subscriptions.

``read`` is special: the server ignores the ``X-Api-Key`` header there and
requires the key in the query string, so this one endpoint echoes the api key as
a query parameter.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from . import _base

_LIST = RequestSpec(
    "GET",
    "/api/v3/subscriptions/listWebhookSubscriptions/",
    body_mode="query",
    unwrap=("data", "subscriptions"),
)
_ADD = RequestSpec(
    "POST", "/api/v3/subscriptions/addWebhookSubscription/", body_mode="json", unwrap=("data",)
)
_EDIT = RequestSpec(
    "POST", "/api/v3/subscriptions/editWebhookSubscription/", body_mode="json", unwrap=("data",)
)
_DELETE = RequestSpec(
    "POST", "/api/v3/subscriptions/removeWebhookSubscription/", body_mode="json", unwrap=("data",)
)
_READ = RequestSpec("GET", "/api/v3/subscriptions/webhook", body_mode="query", unwrap=("data",))


class AsyncWebhooks(_base.AsyncBaseResource):
    """Manage webhook subscriptions.

    The ``api_key`` argument on the mutating methods is the *owner* of the
    subscription and defaults to the client's own key. To manage another key's
    subscriptions, authenticate the client with a privileged key and pass that
    other key as ``api_key``.
    """

    async def list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the account's webhook subscriptions.

        Scoped to the client's own key: the server reads this endpoint from the
        ``X-Api-Key`` header only, so there is no owner-key override here.
        """
        return await self._request(_LIST, timeout=timeout)

    async def add(
        self,
        query: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create a webhook subscription for a query.

        Args:
            query: The Lucene query that defines matches.
            api_key: Owner key for the subscription. Defaults to the client's
                own key; pass another key (with a privileged key on the client)
                to create the subscription under that key.
        """
        body = {"query": query, "apiKey": api_key or self._api_key}
        return await self._request(_ADD, body=body, timeout=timeout)

    async def create(
        self,
        query: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Alias of :meth:`add` (the primary CRUD-style name)."""
        return await self.add(query, api_key=api_key, timeout=timeout)

    async def enable(
        self,
        id: str,
        active: bool,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Enable or disable a webhook subscription.

        Args:
            id: The subscription to toggle.
            active: New active state.
            api_key: Owner key for the subscription (see :meth:`add`).
        """
        body = {
            "subscriptionid": id,
            "active": "true" if active else "false",
            "apiKey": api_key or self._api_key,
        }
        return await self._request(_EDIT, body=body, timeout=timeout)

    async def set_enabled(
        self,
        id: str,
        active: bool,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Alias of :meth:`enable` (the explicit setter-style name)."""
        return await self.enable(id, active, api_key=api_key, timeout=timeout)

    async def read(
        self,
        id: str,
        *,
        newest_only: bool = True,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Read pending webhook payloads for a subscription.

        This endpoint requires the api key in the query string (the ``X-Api-Key``
        header alone is rejected), so the key is echoed as a query parameter here.

        Args:
            id: The subscription to read.
            newest_only: Return only the newest stored payload.
            api_key: Owner key for the subscription (see :meth:`add`).
        """
        body = {
            "subscriptionid": id,
            "newest_only": "true" if newest_only else "false",
            "apiKey": api_key or self._api_key,
        }
        return await self._request(_READ, body=body, timeout=timeout)

    async def delete(
        self,
        id: str,
        *,
        api_key: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a webhook subscription.

        Args:
            id: The subscription to delete.
            api_key: Owner key for the subscription (see :meth:`add`).
        """
        body = {"subscriptionid": id, "apiKey": api_key or self._api_key}
        return await self._request(_DELETE, body=body, timeout=timeout)


__all__ = ["AsyncWebhooks"]
