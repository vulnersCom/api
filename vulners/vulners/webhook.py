from typing import Any, Literal

from ..base import VulnersApiProxy, endpoint


class WebhookApi(VulnersApiProxy):
    list = endpoint(
        "WebhookApi.list",
        method="GET",
        url="/api/v3/subscriptions/listWebhookSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        add_api_key=True,
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
        add_api_key=True,
    )

    def read(self, id: str, newest_only: bool = True) -> dict[str, Any]:
        return self.__read(id, "true" if newest_only else "false")
