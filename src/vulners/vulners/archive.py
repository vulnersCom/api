from datetime import datetime
from typing import Annotated

from pydantic import Field

from ..base import VulnersApiProxy, endpoint


class ArchiveApi(VulnersApiProxy):
    fetch_collection = endpoint(
        "ArchiveApi.fetch_collection",
        method="GET",
        url="/api/v4/archive/collection",
        description="Get entire collection data",
        params={"type": str},
    )

    fetch_collection_update = endpoint(
        "ArchiveApi.fetch_collection_update",
        method="GET",
        url="/api/v4/archive/collection-update",
        description="Get collection updates only",
        params={"type": str, "after": datetime},
    )

    get_collection = endpoint(
        "ArchiveApi.get_collection",
        method="GET",
        url="/api/v3/archive/collection/",
        params={
            "type": str,
            "datefrom": Annotated[str, Field(default="1976-01-01")],
            "dateto": Annotated[str, Field(default="2199-01-01")],
        },
        deprecated=(
            "ArchiveApi.get_collection() is deprecated and will be removed in future releases.\n"
        ),
    )

    get_distributive = endpoint(
        "ArchiveApi.get_distributive",
        method="GET",
        url="/api/v3/archive/distributive/",
        params={"os": str, "version": str},
        deprecated=(
            "ArchiveApi.get_distributive() is deprecated and will be removed in future releases."
        ),
        response_handler=lambda c: [o["_source"] for o in c],
        timeout=120,
    )

    getsploit = endpoint(
        "ArchiveApi.getsploit",
        method="GET",
        url="/api/v3/archive/getsploit/",
        deprecated=(
            "ArchiveApi.getsploit() is deprecated and will be removed in future releases."
        ),
        parse_response=False,
    )
