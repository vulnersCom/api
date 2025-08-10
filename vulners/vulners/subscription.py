from typing import Annotated, Literal

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint


class SubscriptionApi(VulnersApiProxy):
    list = endpoint(
        "SubscriptionApi.list",
        method="GET",
        url="/api/v3/subscriptions/listEmailSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        add_api_key=True,
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
        },
        add_api_key=True,
        deprecated=(
            "SubscriptionApi.delete() is deprecated and will be removed in future releases.\n"
        ),
    )
