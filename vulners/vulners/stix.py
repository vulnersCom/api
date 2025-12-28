from typing import Annotated

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint


class StixApi(VulnersApiProxy):
    make_bundle_by_id = endpoint(
        "StixApi.bundle",
        description="Make bundle of STIX objects for the given bulletin ID",
        method="GET",
        url="/api/v4/stix/bundle",
        params={
            "id": Annotated[str, Field(description="Bulletin ID")],
            "opencti_id": Annotated[
                str | None,
                Field(default=None, description="Existing OpenCTI object ID"),
            ],
        },
        response_handler=lambda resp: resp["result"],
    )
