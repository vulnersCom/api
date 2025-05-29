import re
from typing import Annotated, Any, Sequence

from pydantic import Field

from ..base import ResultSet, VulnersApiProxy, endpoint

DEFAULT_FIELDS = (
    "id",
    "title",
    "description",
    "type",
    "bulletinFamily",
    "cvss",
    "published",
    "modified",
    "lastseen",
    "href",
    "sourceHref",
    "sourceData",
    "cvelist",
    "vulnStatus",
    "assigned",
)


class SearchApi(VulnersApiProxy):
    __search = endpoint(
        "SearchApi.search",
        method="POST",
        url="/api/v3/search/lucene/",
        params={
            "query": str,
            "size": Annotated[int, Field(gt=0, le=10000)],
            "skip": Annotated[int, Field(ge=0, le=10000)],
            "fields": Sequence[str],
        },
    )

    def search_bulletins(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_FIELDS,
    ) -> ResultSet:
        """
        Search in Vulners database.

        query: Vulners query. See https://vulners.com/help for the details.
        limit: The maximum number of documents to return.
        offset: The number of documents to skip in the result set.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        limit = min(limit, 10000 - offset)  # real limit is unknown
        search = self.__search(query, limit, offset, fields)
        return ResultSet.from_dataset([e["_source"] for e in search["search"]], search["total"])

    def search_bulletins_all(
        self,
        query: str,
        limit: int = 100,  # default limit is 100
        fields: Sequence[str] = DEFAULT_FIELDS,
    ) -> ResultSet:
        offset = 0
        limit = min(limit, 10000)
        chunk = self.__search(query, limit, offset, fields)
        total = min(limit, chunk["total"])
        max_chunk_size = chunk["maxSearchSize"]
        result = ResultSet.from_dataset([e["_source"] for e in chunk["search"]], chunk["total"])
        offset += len(result)
        while offset < total:
            chunk_size = min(max_chunk_size, total - offset)
            chunk = self.__search(query, chunk_size, offset, fields)
            data = chunk["search"]
            result += [e["_source"] for e in data]
            if len(data) < chunk_size:
                break
            offset += len(data)
        return result

    @staticmethod
    def __get_exploit_query(query: str, lookup_fields: Sequence[str] | None = None) -> str:
        if re.match(r"^CVE-\d{4}-\d+$", (query := query.strip()), re.IGNORECASE):
            query = f'"{query}"'
        if lookup_fields:
            return "bulletinFamily:exploit AND (%s)" % (
                " OR ".join('%s:"%s"' % (field, query) for field in lookup_fields)
            )
        else:
            return "bulletinFamily:exploit AND (%s)" % query

    def search_exploits(
        self,
        query: str,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = DEFAULT_FIELDS,
    ) -> ResultSet:
        """
        Search in Vulners database for the exploits.

        query: Software name and criteria.
        lookup_fields: Make a strict search using lookup fields. Like ["title"]
        limit: The maximum number of documents to return.
        offset: The number of documents to skip in the result set.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        return self.search_bulletins(
            self.__get_exploit_query(query, lookup_fields),
            limit=limit,
            offset=offset,
            fields=fields,
        )

    def search_exploits_all(
        self,
        query: str,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 100,  # default limit
        fields: Sequence[str] = DEFAULT_FIELDS,
    ) -> ResultSet:
        return self.search_bulletins_all(
            self.__get_exploit_query(query, lookup_fields), limit=limit, fields=fields
        )

    __get_bulletins = endpoint(
        "SearchApi.__get_bulletins",
        method="POST",
        url="/api/v3/search/id/",
        description="Fetch multiple bulletins by ids.",
        params={
            "id": Annotated[
                Sequence[str],
                Field(min_length=1, description="List of ID's. E.g., ['CVE-2017-14174']"),
            ],
            "fields": Annotated[Sequence[str], Field(default=DEFAULT_FIELDS)],
            "references": Annotated[bool, Field(default=False)],
        },
    )

    def get_multiple_bulletins(
        self, id: Sequence[str], fields: Sequence[str] = DEFAULT_FIELDS
    ) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=fields)["documents"]

    def get_bulletin(self, id: str, fields: Sequence[str] = DEFAULT_FIELDS) -> dict[str, Any]:
        return self.get_multiple_bulletins([id], fields).get(id, {})

    def get_multiple_bulletin_references(self, id: Sequence[str]) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=[], references=True)["references"]

    def get_bulletin_references(self, id: str) -> dict[str, Any]:
        return self.get_multiple_bulletin_references([id]).get(id, {})

    def get_multiple_bulletins_with_references(
        self, id: Sequence[str], fields: Sequence[str] = DEFAULT_FIELDS
    ) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=fields, references=True)

    def get_bulletin_with_references(
        self, id: str, fields: Sequence[str] = DEFAULT_FIELDS
    ) -> dict[str, Any]:
        return self.get_multiple_bulletins_with_references([id], fields=fields)

    def get_kb_seeds(self, kbid: str) -> dict[str, Any]:
        """
        Returns superseeds and parentseeds for the given KB.
        Superseeds means "KB which are covered by this KB".
        Parentseeds means "KB which are covering this KB".

        superseeds --> KB --> parentseeds

        kbid: Microsoft KB identificator
        """
        candidate = self.get_bulletin(id=kbid, fields=["superseeds", "parentseeds"])
        if candidate:
            return {
                "superseeds": candidate.get("superseeds", []),
                "parentseeds": candidate.get("parentseeds", []),
            }
        return {}

    def get_kb_updates(self, kbid: str, fields: Sequence[str] = DEFAULT_FIELDS):
        """
        Returns list of updates for KB.

        kbid: Microsoft KB identificator.
        """
        query = "type:msupdate AND kb:(%s)" % kbid
        return self.search_bulletins(query, limit=1000, fields=fields)

    get_bulletin_history = endpoint(
        "SearchApi.get_bulletin_history",
        method="GET",
        url="/api/v3/search/history/",
        description="Bulletin history list",
        params={
            "id": str,
        },
        response_handler=lambda c: c["result"],
    )
