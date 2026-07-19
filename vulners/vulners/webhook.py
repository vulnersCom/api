from typing import Any, Literal

from ..base import VulnersApiProxy, endpoint


class WebhookApi(VulnersApiProxy):
    list = endpoint(
        "WebhookApi.list",
        method="GET",
        url="/api/v3/subscriptions/listWebhookSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        # No add_api_key: authenticated header-only (X-Api-Key), confirmed on the
        # success path. Keeps the key out of the query string / access logs
        # (CWE-598). Note: __read below intentionally keeps add_api_key.
    )

    add = endpoint(
        "WebhookApi.add",
        method="POST",
        url="/api/v3/subscriptions/addWebhookSubscription/",
        params={
            "query": str,
        },
        add_api_key=True,
    )

    __enable = endpoint(
        "WebhookApi.enable",
        method="POST",
        url="/api/v3/subscriptions/editWebhookSubscription/",
        params={
            "subscriptionid": str,
            "active": Literal["true", "false"],
        },
        add_api_key=True,
    )

    def enable(self, id: str, active: bool) -> dict[str, Any]:
        return self.__enable(id, "true" if active else "false")

    delete = endpoint(
        "WebhookApi.delete",
        method="POST",
        url="/api/v3/subscriptions/removeWebhookSubscription/",
        params={
            "subscriptionid": str,
        },
        add_api_key=True,
    )

    __read = endpoint(
        "WebhookApi.read",
        method="GET",
        url="/api/v3/subscriptions/webhook",
        params={
            "subscriptionid": str,
            "newest_only": Literal["true", "false"],
        },
        # DO NOT remove add_api_key here: unlike list/add above, this endpoint
        # ignores the X-Api-Key header and requires apiKey in the query string
        # (header-only -> errorCode 103 "Missing parameters"). Dropping it would
        # break read(). The residual key-in-query exposure is a known
        # server-side limitation.
        add_api_key=True,
    )

    def read(self, id: str, newest_only: bool = True) -> dict[str, Any]:
        return self.__read(id, "true" if newest_only else "false")
