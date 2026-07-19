"""Async ``webhooks`` resource (unasyncd source for the sync ``webhooks`` resource).

Webhook subscriptions over the v3 endpoints. ``read`` is special: the server
ignores the ``X-Api-Key`` header there and requires the key in the query string,
so this one endpoint echoes the api key as a query parameter.
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
    """Manage webhook subscriptions."""

    async def list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the account's webhook subscriptions."""
        return await self._request(_LIST, timeout=timeout)

    async def add(
        self,
        query: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create a webhook subscription for a query."""
        body = {"query": query, "apiKey": self._api_key}
        return await self._request(_ADD, body=body, timeout=timeout)

    async def enable(
        self,
        id: str,
        active: bool,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Enable or disable a webhook subscription."""
        body = {
            "subscriptionid": id,
            "active": "true" if active else "false",
            "apiKey": self._api_key,
        }
        return await self._request(_EDIT, body=body, timeout=timeout)

    async def read(
        self,
        id: str,
        *,
        newest_only: bool = True,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Read pending webhook payloads for a subscription.

        This endpoint requires the api key in the query string (the ``X-Api-Key``
        header alone is rejected), so the key is echoed as a query parameter here.
        """
        body = {
            "subscriptionid": id,
            "newest_only": "true" if newest_only else "false",
            "apiKey": self._api_key,
        }
        return await self._request(_READ, body=body, timeout=timeout)

    async def delete(
        self,
        id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a webhook subscription."""
        body = {"subscriptionid": id, "apiKey": self._api_key}
        return await self._request(_DELETE, body=body, timeout=timeout)


__all__ = ["AsyncWebhooks"]
