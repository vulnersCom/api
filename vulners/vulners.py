import datetime
import re
from typing import Annotated, Any, Literal, Required, Sequence

from pydantic import Field
from typing_extensions import TypedDict

from .base import ResultSet, Unset, VulnersApiBase, endpoint


class AuditItem(TypedDict, total=False):
    part: Literal["a", "o", "h"]
    vendor: str
    product: Required[str]
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


class WinAuditItem(TypedDict):
    software: str
    version: str


AuditFields = Literal[
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
]


class VulnersApi(VulnersApiBase):
    default_fields = (
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

    __search = endpoint(
        "VulnersApi.__search",
        method="POST",
        url="/api/v3/search/lucene/",
        params={
            "query": str,
            "size": Annotated[int, Field(gt=0, lt=10000)],
            "skip": Annotated[int, Field(ge=0, lt=10000)],
            "fields": Sequence[str],
        },
    )

    def find(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = default_fields,
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
        limit = min(limit, 10000 - offset)
        search = self.__search(query, limit, offset, fields)
        return ResultSet.from_dataset([e["_source"] for e in search["search"]], search["total"])

    def find_all(
        self,
        query: str,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = default_fields,
    ) -> ResultSet:
        """
        Search in Vulners database and returns up to 10000 documents.

        query: Vulners query. See https://vulners.com/help for the details.
        limit: The maximum number of documents to return.
        offset: The number of documents to skip in the result set.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        limit = min(limit, 10000 - offset)
        end = offset + limit
        batch_size = min(1000, limit)
        result = ResultSet()
        while len(result) < limit:
            chunk = self.__search(query, min(batch_size, end - offset), offset, fields)
            data = chunk["search"]
            result += [e["_source"] for e in data]
            result.total = chunk["total"]
            if not data:
                break
            if result.total <= len(data):  # type:ignore[operator]
                break
            offset += len(data)
        return result

    @staticmethod
    def __find_exploit_query(query: str, lookup_fields: Sequence[str] | None) -> str:
        if re.match(r"^CVE-\d{4}-\d+$", (query := query.strip()), re.IGNORECASE):
            query = f'"{query}"'
        if lookup_fields:
            search_query = "bulletinFamily:exploit AND (%s)" % (
                " OR ".join('%s:"%s"' % (field, query) for field in lookup_fields)
            )
        else:
            search_query = "bulletinFamily:exploit AND %s" % query
        return search_query

    def find_exploit(
        self,
        query: str,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = default_fields,
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
        return self.find(self.__find_exploit_query(query, lookup_fields), limit, offset, fields)

    def find_exploit_all(
        self,
        query: str,
        lookup_fields: Sequence[str] | None = None,
        limit: int = 20,
        offset: int = 0,
        fields: Sequence[str] = default_fields,
    ) -> ResultSet:
        """
        Search in Vulners database for the exploits and returns up to 10000 documents.

        query: Software name and criteria.
        lookup_fields: Make a strict search using lookup fields. Like ["title"]
        limit: The maximum number of documents to return.
        offset: The number of documents to skip in the result set.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        return self.find_all(
            self.__find_exploit_query(query, lookup_fields), limit, offset, fields
        )

    get_web_application_rules = endpoint(
        "VulnersApi.get_web_application_rules",
        method="GET",
        url="/api/v3/burp/rules/",
    )

    audit_software = endpoint(
        "VulnersApi.audit_software",
        method="POST",
        url="/api/v4/audit/software/",
        params={
            "software": Annotated[
                list[AuditItem | str],
                Field(
                    min_length=1,
                    description="List of dicts. E.g., [{'product': 'curl', 'version': '8.11.1', ...}, ...]",
                ),
            ],
            "match": Annotated[Literal["partial", "full"], Field(default="partial")],
            "fields": Annotated[
                Sequence[AuditFields],
                Field(
                    default=Unset,
                    description="List of fields to retrieve about each vulnerability",
                ),
            ],
        },
        response_handler=lambda c: c["result"],
    )

    audit_host = endpoint(
        "VulnersApi.audit_host",
        method="POST",
        url="/api/v4/audit/host/",
        params={
            "software": Annotated[
                list[AuditItem | str],
                Field(
                    min_length=1,
                    description="List of dicts. E.g., [{'product': 'curl', 'version': '8.11.1', ...}, ...]",
                ),
            ],
            "application": Annotated[AuditItem | str, Field(default=Unset)],
            "operating_system": Annotated[AuditItem | str, Field(default=Unset)],
            "hardware": Annotated[AuditItem | str, Field(default=Unset)],
            "match": Annotated[Literal["partial", "full"], Field(default="partial")],
            "fields": Annotated[
                Sequence[AuditFields],
                Field(
                    default=Unset,
                    description="List of fields to retrieve about each vulnerability",
                ),
            ],
        },
        response_handler=lambda c: c["result"],
    )

    search_cpe = endpoint(
        "VulnersApi.search_cpe",
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

    __get_bulletins = endpoint(
        "VulnersApi.get_multiple_bulletins",
        method="POST",
        url="/api/v3/search/id/",
        description="Fetch multiple bulletins by ids.",
        params={
            "id": Annotated[
                Sequence[str],
                Field(min_length=1, description="List of ID's. E.g., ['CVE-2017-14174']"),
            ],
            "fields": Annotated[Sequence[str], Field(default=default_fields)],
            "references": Annotated[bool, Field(default=False)],
        },
    )

    def get_multiple_bulletins(
        self, id: Sequence[str], fields: Sequence[str] = default_fields
    ) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=fields)["documents"]

    def get_bulletin(self, id: str, fields: Sequence[str] = default_fields) -> dict[str, Any]:
        return self.get_multiple_bulletins([id], fields).get(id, {})

    def get_multiple_bulletin_references(self, id: Sequence[str]) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=[], references=True)["references"]

    def get_bulletin_references(self, id: str) -> dict[str, Any]:
        return self.get_multiple_bulletin_references([id]).get(id, {})

    def get_multiple_documents_with_references(
        self, id: Sequence[str], fields: Sequence[str] = default_fields
    ) -> dict[str, Any]:
        return self.__get_bulletins(id, fields=fields, references=True)

    def get_document_with_references(
        self, id: str, fields: Sequence[str] = default_fields
    ) -> dict[str, Any]:
        return self.get_multiple_documents_with_references([id], fields=fields)

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

    def get_kb_updates(self, kbid: str, fields: Sequence[str] = default_fields):
        """
        Returns list of updates for KB.

        kbid: Microsoft KB identificator.
        """
        query = "type:msupdate AND kb:(%s)" % kbid
        return self.find_all(query, limit=1000, fields=fields)

    os_audit = endpoint(
        "VulnersApi.os_audit",
        method="POST",
        url="/api/v3/audit/audit/",
        description=(
            "Linux Audit API for analyzing package vulnerabilities.\n"
            "Accepts RPM and DEB based package lists.\n"
            "For collecting RPM use command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\\\n'\n"
            "For collecting DEB use command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\\\n'\n"
        ),
        params={
            "os": Annotated[
                str,
                Field(description="Full name of the OS. Like Ubuntu, Debian, rhel, oraclelinux"),
            ],
            "version": Annotated[str, Field(description="OS version")],
            "packages": Annotated[
                list[str],
                Field(
                    min_length=1,
                    alias="package",
                    description="List of the installed packages",
                ),
            ],
        },
    )

    kb_audit = endpoint(
        "VulnersApi.kb_audit",
        method="POST",
        url="/api/v3/audit/kb/",
        description="Windows KB audit function",
        params={
            "os": Annotated[
                str, Field(description="Windows OS name, like 'Windows Server 2012 R2'")
            ],
            "kb_list": Annotated[
                list[str],
                Field(
                    alias="kbList",
                    min_length=1,
                    description="List of installed KB's, ['KB2918614', 'KB2918616']",
                ),
            ],
        },
    )

    winaudit = endpoint(
        "VulnersApi.winaudit",
        method="POST",
        url="/api/v3/audit/winaudit/",
        description="Windows KB and software audit function",
        params={
            "os": Annotated[
                str, Field(description="Windows OS name, like 'Windows Server 2012 R2'")
            ],
            "os_version": Annotated[
                str, Field(description="Windows OS version, like '10.0.19045'")
            ],
            "kb_list": Annotated[
                list[str],
                Field(
                    description="List of installed KB's, ['KB2918614', 'KB2918616']",
                ),
            ],
            "software": Annotated[
                list[WinAuditItem],
                Field(
                    description="List of the software dicts, {'software': 'Microsoft Edge', 'version': '107.0.1418.56'}",
                ),
            ],
            "platform": Annotated[str, Field(default=Unset, description="OS platform like x86")],
        },
        add_api_key=True,
    )

    get_suggestion = endpoint(
        "VulnersApi.get_suggestion",
        method="POST",
        url="/api/v3/search/suggest/",
        params={
            "field_name": Annotated[str, Field(alias="fieldName")],
            "type": Annotated[Literal["distinct"], Field(default="distinct")],
        },
        response_handler=lambda c: c["suggest"],
    )

    get_ai_score = endpoint(
        "VulnersApi.get_ai_score",
        method="POST",
        url="/api/v3/ai/scoretext/",
        params={"text": str},
        response_handler=lambda c: c.get("score", 0),
    )

    query_autocomplete = endpoint(
        "VulnersApi.query_autocomplete",
        method="POST",
        url="/api/v3/search/autocomplete/",
        description="Ask Vulners for possible suggestions to complete your query",
        params={"query": str},
        response_handler=lambda c: [q[0] for q in c["suggestions"]],
    )

    fetch_collection = endpoint(
        "VulnersApi.fetch_collection",
        method="GET",
        url="/api/v4/archive/collection",
        description="Get entire collection data",
        params={"type": str},
    )

    fetch_collection_update = endpoint(
        "VulnersApi.fetch_collection_update",
        method="GET",
        url="/api/v4/archive/collection-update",
        description="Get collection updates only",
        params={"type": str, "after": datetime.datetime},
    )

    __report = endpoint(
        "VulnersApi.__report",
        method="POST",
        url="/api/v3/reports/vulnsreport",
        params={
            "reporttype": Literal[
                "vulnssummary", "vulnslist", "ipsummary", "scanlist", "hostvulns"
            ],
            "skip": Annotated[
                int,
                Field(
                    ge=0,
                    lt=10000,
                    description="Skip this amount of items. 10000 is the hard limit",
                ),
            ],
            "size": Annotated[
                int,
                Field(
                    gt=0,
                    le=10000,
                    description="The maximum number of items to return. 10000 is the hard limit",
                ),
            ],
            "filter": Annotated[
                dict[str, Any],
                Field(
                    description="Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}",
                ),
            ],
            "sort": Annotated[
                str, Field(description="Field to sort, eg 'severity' or '-severity' to sort desc")
            ],
        },
        response_handler=lambda c: c["report"],
    )

    def vulnssummary_report(
        self,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
    ) -> Any:
        """
        Get Linux Audit results. Return summary for all found vulnerabilities - id, title, score, severity etc

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'severity' or '-severity' to sort desc
        """

        return self.__report("vulnssummary", offset, limit, filter or {}, sort)

    def vulnslist_report(
        self,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
    ) -> Any:
        """
        Get Linux Audit results. Return list of vulnerabilities found on hosts:
            vulnerability id, vulnerability title, vulnerability severity, host information,  etc

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'severity' or '-severity' to sort desc
        """

        return self.__report("vulnslist", offset, limit, filter or {}, sort)

    def ipsummary_report(
        self,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
    ) -> Any:
        """
        Get Linux Audit results. Return summary for hosts:
            agent id, host ip, host fqdn, os name and version, found vulnerabilities count and severity

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'total' or '-total' to sort desc
        """

        return self.__report("ipsummary", offset, limit, filter or {}, sort)

    def scanlist_report(
        self,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
    ) -> Any:
        """
        Get Linux Audit results. Return list of scans:
           host ip and fqdn, os name and version, scan date, cvss score

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'modified' or '-modified' to sort desc
        """

        return self.__report("scanlist", offset, limit, filter or {}, sort)

    def hostvulns_report(
        self,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
    ) -> Any:
        """
        Get Linux Audit results. Return list of hosts and host vulnerabilities:
           host ip and fqdn, os name and version, cumulative fix, vulnerability ids

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'modified' or '-modified' to sort desc
        """

        return self.__report("hostvulns", offset, limit, filter or {}, sort)

    get_subscriptions = endpoint(
        "VulnersApi.get_subscriptions",
        method="GET",
        url="/api/v3/subscriptions/listEmailSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        add_api_key=True,
    )

    add_subscription = endpoint(
        "VulnersApi.add_subscription",
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
    )

    edit_subscription = endpoint(
        "VulnersApi.edit_subscription",
        method="POST",
        url="/api/v3/subscriptions/editEmailSubscription/",
        params={
            "subscriptionid": str,
            "format": Annotated[Literal["html", "json", "pdf"], Field(default=Unset)],
            "crontab": Annotated[str, Field(default=Unset)],
            "active": Annotated[Literal["yes", "no", "true", "false"], Field(default=Unset)],
        },
        add_api_key=True,
    )

    delete_subscription = endpoint(
        "VulnersApi.delete_subscription",
        method="POST",
        url="/api/v3/subscriptions/removeEmailSubscription/",
        params={
            "subscriptionid": str,
        },
        add_api_key=True,
    )

    get_webhooks = endpoint(
        "VulnersApi.get_webhooks",
        method="GET",
        url="/api/v3/subscriptions/listWebhookSubscriptions/",
        response_handler=lambda c: c["subscriptions"],
        add_api_key=True,
    )

    add_webhook = endpoint(
        "VulnersApi.__add_webhook",
        method="POST",
        url="/api/v3/subscriptions/addWebhookSubscription/",
        params={
            "query": str,
        },
        add_api_key=True,
    )

    __edit_webhook = endpoint(
        "VulnersApi.__edit_webhook",
        method="POST",
        url="/api/v3/subscriptions/editWebhookSubscription/",
        params={
            "subscriptionid": str,
            "active": Literal["true", "false"],
        },
        add_api_key=True,
    )

    def enable_webhook(self, id: str, active: bool) -> dict[str, Any]:
        return self.__edit_webhook(id, "true" if active else "false")

    delete_webhook = endpoint(
        "VulnersApi.delete_webhook",
        method="POST",
        url="/api/v3/subscriptions/removeWebhookSubscription/",
        params={
            "subscriptionid": str,
        },
        add_api_key=True,
    )

    __read_webhook = endpoint(
        "VulnersApi.read_webhook",
        method="GET",
        url="/api/v3/subscriptions/webhook",
        params={
            "subscriptionid": str,
            "newest_only": Literal["true", "false"],
        },
        add_api_key=True,
    )

    def read_webhook(self, id: str, newest_only: bool = True) -> dict[str, Any]:
        return self.__read_webhook(id, "true" if newest_only else "false")

    get_bulletin_history = endpoint(
        "VulnersApi.get_bulletin_history",
        method="GET",
        url="/api/v3/search/history/",
        description="Bulletin history list",
        params={
            "id": str,
        },
        response_handler=lambda c: c["result"],
    )
