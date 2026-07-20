from typing import Annotated, Any, Literal

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint

# The v3 polling ("webhook") endpoints carry the key in the request body as
# `apiKey`, naming the *owner* of the subscription. It defaults to the client's
# own key (injected by add_api_key), but a privileged key sent in the header can
# pass a different owner key to manage that key's subscriptions. The public
# parameter is `api_key`; it is aliased to the `apiKey` wire field.
_OwnerApiKey = Annotated[str, Field(default=Unset, alias="apiKey")]


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
            "api_key": _OwnerApiKey,
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
            "api_key": _OwnerApiKey,
        },
        add_api_key=True,
    )

    def enable(self, id: str, active: bool, api_key: str | None = None) -> dict[str, Any]:
        active_str: Literal["true", "false"] = "true" if active else "false"
        if api_key is None:
            return self.__enable(id, active_str)
        return self.__enable(id, active_str, api_key=api_key)

    delete = endpoint(
        "WebhookApi.delete",
        method="POST",
        url="/api/v3/subscriptions/removeWebhookSubscription/",
        params={
            "subscriptionid": str,
            "api_key": _OwnerApiKey,
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
            "api_key": _OwnerApiKey,
        },
        # DO NOT remove add_api_key here: unlike list/add above, this endpoint
        # ignores the X-Api-Key header and requires apiKey in the query string
        # (header-only -> errorCode 103 "Missing parameters"). Dropping it would
        # break read(). The residual key-in-query exposure is a known
        # server-side limitation.
        add_api_key=True,
    )

    def read(
        self, id: str, newest_only: bool = True, api_key: str | None = None
    ) -> dict[str, Any]:
        newest: Literal["true", "false"] = "true" if newest_only else "false"
        if api_key is None:
            return self.__read(id, newest)
        return self.__read(id, newest, api_key=api_key)
