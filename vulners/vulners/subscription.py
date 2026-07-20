from typing import Annotated, Literal

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint

# Optional owner key, sent in the body as `apiKey` (aliased). Defaults to the
# client's own key via add_api_key; a privileged header key can pass a different
# owner key to manage that key's subscriptions.
_OwnerApiKey = Annotated[str, Field(default=Unset, alias="apiKey")]


class SubscriptionApi(VulnersApiProxy):
    list = endpoint(
        "SubscriptionApi.list",
        method="GET",
        url="/api/v3/subscriptions/listEmailSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        # No add_api_key: this GET is authenticated header-only (X-Api-Key). The
        # server accepts header-only auth on this endpoint (confirmed on the
        # success path), so the key must not be duplicated into the query string
        # where it would leak into access logs / proxies / APM (CWE-598).
        deprecated=(
            "SubscriptionApi.list() is deprecated and will be removed in future releases.\n"
        ),
    )

    add = endpoint(
        "SubscriptionApi.add",
        method="POST",
        url="/api/v3/subscriptions/addEmailSubscription/",
        params={
            "query": str,
            "email": str,
            "format": Annotated[Literal["html", "json", "pdf"], Field(default="html")],
            "crontab": Annotated[str, Field(default=Unset)],
            "query_type": Annotated[str, Field(default="lucene")],
            "api_key": _OwnerApiKey,
        },
        add_api_key=True,
        deprecated=(
            "SubscriptionApi.add() is deprecated and will be removed in future releases.\n"
        ),
    )

    edit = endpoint(
        "SubscriptionApi.edit",
        method="POST",
        url="/api/v3/subscriptions/editEmailSubscription/",
        params={
            "subscriptionid": str,
            "format": Annotated[Literal["html", "json", "pdf"], Field(default=Unset)],
            "crontab": Annotated[str, Field(default=Unset)],
            "active": Annotated[Literal["yes", "no", "true", "false"], Field(default=Unset)],
            "api_key": _OwnerApiKey,
        },
        add_api_key=True,
        deprecated=(
            "SubscriptionApi.edit() is deprecated and will be removed in future releases.\n"
        ),
    )

    delete = endpoint(
        "SubscriptionApi.delete",
        method="POST",
        url="/api/v3/subscriptions/removeEmailSubscription/",
        params={
            "subscriptionid": str,
            "api_key": _OwnerApiKey,
        },
        add_api_key=True,
        deprecated=(
            "SubscriptionApi.delete() is deprecated and will be removed in future releases.\n"
        ),
    )
