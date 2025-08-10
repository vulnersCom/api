from typing import Annotated, Literal

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
            "bulletin_fields": Annotated[
                list[BulletinField], Field(default=DEFAULT_BULLETIN_FIELDS)
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
        params={
            "id": str,
            "name": str,
            "query": dict,
            "delivery": dict,
            "licenseId": Annotated[str | None, Field(default=None)],
            "bulletin_fields": Annotated[
                list[BulletinField], Field(default=DEFAULT_BULLETIN_FIELDS)
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
