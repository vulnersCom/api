"""Async ``subscriptions_v4`` resource (unasyncd source for the sync mirror).

The v4 subscription API with JSON delivery. ``update`` is a full replace: every
optional field you omit is sent with its default and overwrites the stored value,
so read the current subscription first if you want to keep fields.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
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

    async def get_list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List every subscription on the account."""
        return await self._request(_LIST, timeout=timeout)

    async def get(
        self,
        id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Fetch a single subscription by id.

        Args:
            id: The subscription id (sent to the server as its
                ``subscription_id`` query parameter).
        """
        return await self._request(_GET, body={"subscription_id": id}, timeout=timeout)

    async def create(
        self,
        *,
        name: str,
        query: dict[str, Any],
        delivery: dict[str, Any],
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
            query: Query definition (discriminated by ``type``).
            delivery: Delivery definition (discriminated by ``type``).
            license_id: License to bill against, if any.
            bulletin_fields: Bulletin fields to include in results.
            is_active: Whether the subscription starts active.
            timestamp_source: Which timestamp drives incremental delivery.
            send_empty_result: Deliver even when there are no new results.
        """
        body = self._body(
            name=name,
            query=query,
            delivery=delivery,
            license_id=license_id,
            bulletin_fields=bulletin_fields,
            is_active=is_active,
            timestamp_source=timestamp_source,
            send_empty_result=send_empty_result,
        )
        return await self._request(_CREATE, body=body, timeout=timeout)

    async def update(
        self,
        id: str,
        *,
        name: str,
        query: dict[str, Any],
        delivery: dict[str, Any],
        license_id: str | None = None,
        bulletin_fields: Sequence[str] | None = None,
        is_active: bool = True,
        timestamp_source: TimestampSource = "modified",
        send_empty_result: bool = False,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Replace a subscription in full.

        This is a full replace, not a patch: any optional argument you omit is
        sent with its default and overwrites the stored value. Read the current
        subscription with :meth:`get` and pass every field you want to keep.
        """
        body = self._body(
            name=name,
            query=query,
            delivery=delivery,
            license_id=license_id,
            bulletin_fields=bulletin_fields,
            is_active=is_active,
            timestamp_source=timestamp_source,
            send_empty_result=send_empty_result,
        )
        body = {"id": id, **body}
        return await self._request(_UPDATE, body=body, timeout=timeout)

    async def delete(
        self,
        id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a subscription by id."""
        return await self._request(_DELETE, body={"id": id}, timeout=timeout)

    @staticmethod
    def _body(
        *,
        name: str,
        query: dict[str, Any],
        delivery: dict[str, Any],
        license_id: str | None,
        bulletin_fields: Sequence[str] | None,
        is_active: bool,
        timestamp_source: str,
        send_empty_result: bool,
    ) -> dict[str, Any]:
        fields = (
            list(bulletin_fields)
            if bulletin_fields is not None
            else list(DEFAULT_BULLETIN_FIELDS)
        )
        return {
            "name": name,
            "query": query,
            "delivery": delivery,
            "licenseId": license_id,
            "bulletin_fields": fields,
            "is_active": is_active,
            "timestamp_source": timestamp_source,
            "send_empty_result": send_empty_result,
        }


__all__ = ["AsyncSubscriptionsV4"]
