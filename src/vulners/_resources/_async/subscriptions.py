"""Async ``subscriptions`` resource (v3 email subscriptions).

Unasyncd source for the sync ``subscriptions`` resource. These are the legacy v3
email-subscription endpoints; the newer JSON-delivery subscriptions live on the
``subscriptions_v4`` resource.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from . import _base

_LIST = RequestSpec(
    "GET",
    "/api/v3/subscriptions/listEmailSubscriptions/",
    body_mode="query",
    unwrap=("data", "subscriptions"),
)
_ADD = RequestSpec(
    "POST", "/api/v3/subscriptions/addEmailSubscription/", body_mode="json", unwrap=("data",)
)
_EDIT = RequestSpec(
    "POST", "/api/v3/subscriptions/editEmailSubscription/", body_mode="json", unwrap=("data",)
)
_DELETE = RequestSpec(
    "POST", "/api/v3/subscriptions/removeEmailSubscription/", body_mode="json", unwrap=("data",)
)


class AsyncSubscriptions(_base.AsyncBaseResource):
    """Manage v3 email subscriptions."""

    async def list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the account's email subscriptions."""
        return await self._request(_LIST, timeout=timeout)

    async def add(
        self,
        *,
        query: str,
        email: str,
        format: Literal["html", "json", "pdf"] = "html",
        crontab: str | NotGiven = not_given,
        query_type: str = "lucene",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create an email subscription for a query.

        Args:
            query: The search query to subscribe to.
            email: Destination email address.
            format: Report format, ``"html"``, ``"json"`` or ``"pdf"``.
            crontab: Optional crontab schedule.
            query_type: Query language, defaults to ``"lucene"``.
        """
        body: dict[str, Any] = {
            "query": query,
            "email": email,
            "format": format,
            "query_type": query_type,
        }
        if not isinstance(crontab, NotGiven):
            body["crontab"] = crontab
        body["apiKey"] = self._api_key
        return await self._request(_ADD, body=body, timeout=timeout)

    async def edit(
        self,
        subscription_id: str,
        *,
        format: Literal["html", "json", "pdf"] | NotGiven = not_given,
        crontab: str | NotGiven = not_given,
        active: Literal["yes", "no", "true", "false"] | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Edit an existing email subscription.

        Args:
            subscription_id: The subscription to edit.
            format: New report format, if changing.
            crontab: New crontab schedule, if changing.
            active: New active state, if changing.
        """
        body: dict[str, Any] = {"subscriptionid": subscription_id}
        if not isinstance(format, NotGiven):
            body["format"] = format
        if not isinstance(crontab, NotGiven):
            body["crontab"] = crontab
        if not isinstance(active, NotGiven):
            body["active"] = active
        body["apiKey"] = self._api_key
        return await self._request(_EDIT, body=body, timeout=timeout)

    async def delete(
        self,
        subscription_id: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete an email subscription."""
        body = {"subscriptionid": subscription_id, "apiKey": self._api_key}
        return await self._request(_DELETE, body=body, timeout=timeout)


__all__ = ["AsyncSubscriptions"]
