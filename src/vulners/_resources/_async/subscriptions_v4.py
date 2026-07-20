"""Async v4 ``subscriptions`` resource (unasyncd source for the sync mirror).

The v4 subscription API with JSON delivery, reachable as ``client.subscriptions``
(``client.subscriptions_v4`` remains a temporary alias of the same resource).
``create`` sends the full subscription definition; ``update`` is a partial
update — only the fields you pass are sent, everything else keeps its stored
value.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from ..._types.subscriptions import SubscriptionDelivery, SubscriptionQuery
from . import _base

_LIST = RequestSpec("GET", "/api/v4/subscriptions/list/", body_mode="query", unwrap=("result",))
_GET = RequestSpec("GET", "/api/v4/subscriptions/get/", body_mode="query", unwrap=("result",))
_CREATE = RequestSpec(
    "POST", "/api/v4/subscriptions/create/", body_mode="json", unwrap=("result",)
)
_UPDATE = RequestSpec(
    "PUT", "/api/v4/subscriptions/update/", body_mode="json", unwrap=("result",)
)
_DELETE = RequestSpec(
    "DELETE", "/api/v4/subscriptions/delete/", body_mode="query", unwrap=("result",)
)

TimestampSource = Literal[
    "modified",
    "published",
    "timestamps.created",
    "timestamps.updated",
    "timestamps.enriched",
    "timestamps.reviewed",
    "timestamps.metricsUpdated",
    "timestamps.webApplicabilityUpdated",
]

DEFAULT_BULLETIN_FIELDS: tuple[str, ...] = (
    "title",
    "short_description",
    "type",
    "href",
    "published",
    "modified",
    "ai_score",
)


class AsyncSubscriptionsV4(_base.AsyncBaseResource):
    """Manage v4 subscriptions."""

    async def list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List every subscription on the account."""
        return await self._request(_LIST, timeout=timeout)

    async def get_list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Alias of :meth:`list`, kept for the pre-release naming window."""
        return await self.list(timeout=timeout)

    async def get(
        self,
        id: str | None = None,
        *,
        subscription_id: str | None = None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Fetch a single subscription by id.

        Args:
            id: The subscription id. Interchangeable with ``subscription_id``;
                pass exactly one of the two.
            subscription_id: The subscription id under the server's query
                parameter name; interchangeable with ``id``.

        Raises:
            TypeError: Neither or both of ``id`` and ``subscription_id`` were
                given.
        """
        if (id is None) == (subscription_id is None):
            raise TypeError("get() requires exactly one of id= or subscription_id=")
        value = id if id is not None else subscription_id
        return await self._request(_GET, body={"subscription_id": value}, timeout=timeout)

    async def create(
        self,
        *,
        name: str,
        query: SubscriptionQuery | Mapping[str, Any],
        delivery: SubscriptionDelivery | Mapping[str, Any],
        license_id: str | None = None,
        bulletin_fields: Sequence[str] | None = None,
        is_active: bool = True,
        timestamp_source: TimestampSource = "modified",
        send_empty_result: bool = False,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create a subscription.

        Args:
            name: Human-readable subscription name.
            query: Query definition, discriminated by ``type`` — a typed dict
                such as :class:`~vulners._types.subscriptions.SubscriptionQueryLucene`
                or a plain mapping.
            delivery: Delivery definition, discriminated by ``type`` — a typed
                dict such as
                :class:`~vulners._types.subscriptions.SubscriptionDeliveryWebhook`
                or a plain mapping.
            license_id: License to bill against, if any.
            bulletin_fields: Bulletin fields to include in results.
            is_active: Whether the subscription starts active.
            timestamp_source: Which timestamp drives incremental delivery.
            send_empty_result: Deliver even when there are no new results.
        """
        fields = (
            list(bulletin_fields)
            if bulletin_fields is not None
            else list(DEFAULT_BULLETIN_FIELDS)
        )
        body: dict[str, Any] = {
            "name": name,
            "query": dict(query),
            "delivery": dict(delivery),
            "licenseId": license_id,
            "bulletin_fields": fields,
            "is_active": is_active,
            "timestamp_source": timestamp_source,
            "send_empty_result": send_empty_result,
        }
        return await self._request(_CREATE, body=body, timeout=timeout)

    async def update(
        self,
        id: str,
        *,
        name: str | NotGiven = not_given,
        query: SubscriptionQuery | Mapping[str, Any] | NotGiven = not_given,
        delivery: SubscriptionDelivery | Mapping[str, Any] | NotGiven = not_given,
        license_id: str | None | NotGiven = not_given,
        bulletin_fields: Sequence[str] | NotGiven = not_given,
        is_active: bool | NotGiven = not_given,
        timestamp_source: TimestampSource | NotGiven = not_given,
        send_empty_result: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Update a subscription, sending only the fields you pass.

        This is a partial update: an argument you omit is left out of the
        request entirely, so the stored value is kept. Pass a field explicitly
        to change it.

        Args:
            id: The subscription to update.
            name: New subscription name.
            query: New query definition (discriminated by ``type``).
            delivery: New delivery definition (discriminated by ``type``).
            license_id: License to bill against (``None`` clears it).
            bulletin_fields: Bulletin fields to include in results.
            is_active: Enable or disable the subscription.
            timestamp_source: Which timestamp drives incremental delivery.
            send_empty_result: Deliver even when there are no new results.
        """
        body: dict[str, Any] = {"id": id}
        self._set(body, "name", name)
        self._set(body, "query", query, dict)
        self._set(body, "delivery", delivery, dict)
        self._set(body, "licenseId", license_id)
        self._set(body, "bulletin_fields", bulletin_fields, list)
        self._set(body, "is_active", is_active)
        self._set(body, "timestamp_source", timestamp_source)
        self._set(body, "send_empty_result", send_empty_result)
        return await self._request(_UPDATE, body=body, timeout=timeout)

    async def delete(
        self,
        id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a subscription by id."""
        return await self._request(_DELETE, body={"id": id}, timeout=timeout)


__all__ = ["AsyncSubscriptionsV4"]
