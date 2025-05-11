from typing import Annotated, Literal

from pydantic import Field

from ..base import Unset, VulnersApiProxy, endpoint


class MiscApi(VulnersApiProxy):
    get_suggestion = endpoint(
        "MiscApi.get_suggestion",
        method="POST",
        url="/api/v3/search/suggest/",
        params={
            "field_name": Annotated[str, Field(alias="fieldName")],
            "type": Annotated[Literal["distinct"], Field(default="distinct")],
        },
        response_handler=lambda c: c["suggest"],
    )

    get_ai_score = endpoint(
        "MiscApi.get_ai_score",
        method="POST",
        url="/api/v3/ai/scoretext/",
        params={"text": str},
        response_handler=lambda c: c.get("score", 0),
    )

    search_cpe = endpoint(
        "MiscApi.search_cpe",
        method="GET",
        url="/api/v4/search/cpe",
        description="Search CPE",
        params={
            "product": Annotated[str, Field(description="Product string to search CPE for")],
            "vendor": Annotated[
                str, Field(default=Unset, description="Optional vendor to include in CPE")
            ],
        },
        response_handler=lambda c: c["result"],
    )

    query_autocomplete = endpoint(
        "MiscApi.query_autocomplete",
        method="POST",
        url="/api/v3/search/autocomplete/",
        description="Ask Vulners for possible suggestions to complete your query",
        params={"query": str},
        response_handler=lambda c: [q[0] for q in c["suggestions"]],
    )

    get_web_application_rules = endpoint(
        "MiscApi.get_web_application_rules",
        method="GET",
        url="/api/v3/burp/rules/",
        deprecated=(
            "MiscApi.get_web_application_rules() is deprecated "
            "and will be removed in future releases."
        ),
    )
