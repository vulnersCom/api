from typing import Annotated, Literal

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint


class SubscriptionV4Api(VulnersApiProxy):
    list = endpoint(
        "SubscriptionV4Api.list",
        method="GET",
        url="/api/v4/subscriptions/list/",
    )

    get = endpoint(
        "SubscriptionV4Api.get",
        method="GET",
        url="/api/v4/subscriptions/get/",
        params={"id": str},
    )

    create = endpoint(
        "SubscriptionV4Api.create",
        method="POST",
        url="/api/v4/subscriptions/create/",
        params={
            "name": str,
            "query": dict,
            "delivery": dict,
            "licenseId": Annotated[str | None, Field(default=None)],
        },
    )

    update = endpoint(
        "SubscriptionV4Api.update",
        method="PUT",
        url="/api/v4/subscriptions/update/",
        params={
            "id": str,
            "name": str,
            "query": dict,
            "delivery": dict,
            "licenseId": Annotated[str | None, Field(default=None)],
        },
    )

    delete = endpoint(
        "SubscriptionV4Api.delete",
        method="DELETE",
        url="/api/v4/subscriptions/delete/",
        params={
            "id": str,
        },
    )
