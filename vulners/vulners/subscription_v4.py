from typing import Annotated, Any, Literal

from pydantic import Field

from ..base import VulnersApiProxy, endpoint

BulletinField = Literal[
    "title",
    "short_description",
    "type",
    "published",
    "modified",
    "href",
    "metrics",
    "exploitation",
    "cvelist",
    "ai_score",
    "epss",
    "description",
    "enchantments",
    "webApplicability",
    "cvelistMetrics",
    # Extra fields accepted by the server. The enum is
    # only IDE guidance; the `| str` union on the parameters carries validation,
    # so any other server-side field name passes through too.
    "cvss",
    "bulletinFamily",
    "lastseen",
]

DEFAULT_BULLETIN_FIELDS: list[BulletinField] = [
    "title",
    "short_description",
    "type",
    "href",
    "published",
    "modified",
    "ai_score",
]


class SubscriptionV4Api(VulnersApiProxy):
    get_list = endpoint(
        "SubscriptionV4Api.list",
        method="GET",
        url="/api/v4/subscriptions/list/",
    )

    __get = endpoint(
        "SubscriptionV4Api.get",
        method="GET",
        url="/api/v4/subscriptions/get/",
        # The server requires the `subscription_id` query parameter here; `?id=`
        # returns 400. PUT update / DELETE delete keep `id` (accepted there).
        params={"subscription_id": str},
    )

    def get(self, id: str | None = None, subscription_id: str | None = None) -> dict[str, Any]:
        """Fetch a single subscription.

        Accepts either ``id`` or ``subscription_id`` for convenience; both are
        sent to the server as the ``subscription_id`` query parameter it
        requires. ``get("...")``, ``get(id=...)`` and ``get(subscription_id=...)``
        are equivalent.
        """
        value = subscription_id if subscription_id is not None else id
        if value is None:
            raise TypeError("get() requires either 'id' or 'subscription_id'")
        return self.__get(subscription_id=value)

    create = endpoint(
        "SubscriptionV4Api.create",
        method="POST",
        url="/api/v4/subscriptions/create/",
        params={
            "name": str,
            "query": dict,
            "delivery": dict,
            "licenseId": Annotated[str | None, Field(default=None)],
            "bulletin_fields": Annotated[
                list[BulletinField | str], Field(default=DEFAULT_BULLETIN_FIELDS)
            ],
            "is_active": Annotated[bool, Field(default=True)],
            "timestamp_source": Annotated[
                Literal[
                    "modified",
                    "published",
                    "timestamps.created",
                    "timestamps.updated",
                    "timestamps.enriched",
                    "timestamps.reviewed",
                    "timestamps.metricsUpdated",
                    "timestamps.webApplicabilityUpdated",
                ],
                Field(default="modified"),
            ],
            "send_empty_result": Annotated[bool, Field(default=False)],
        },
    )

    update = endpoint(
        "SubscriptionV4Api.update",
        method="PUT",
        url="/api/v4/subscriptions/update/",
        description=(
            "WARNING: this is a FULL-REPLACE update, not a partial patch. The "
            "server requires the complete subscription body, so any optional "
            "argument you omit (licenseId, bulletin_fields, is_active, "
            "timestamp_source, send_empty_result) is sent with its SDK DEFAULT "
            "and OVERWRITES the subscription's current value on the server. To "
            "avoid silently resetting fields, read the current subscription with "
            "get() and pass every field you want to keep explicitly. Partial "
            "(merge) updates are only available in the v4 client API; the "
            "server does not support partial PUT on this endpoint."
        ),
        params={
            "id": str,
            "name": str,
            "query": dict,
            "delivery": dict,
            "licenseId": Annotated[str | None, Field(default=None)],
            "bulletin_fields": Annotated[
                list[BulletinField | str], Field(default=DEFAULT_BULLETIN_FIELDS)
            ],
            "is_active": Annotated[bool, Field(default=True)],
            "timestamp_source": Annotated[
                Literal[
                    "modified",
                    "published",
                    "timestamps.created",
                    "timestamps.updated",
                    "timestamps.enriched",
                    "timestamps.reviewed",
                    "timestamps.metricsUpdated",
                    "timestamps.webApplicabilityUpdated",
                ],
                Field(default="modified"),
            ],
            "send_empty_result": Annotated[bool, Field(default=False)],
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
