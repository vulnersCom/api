from typing import Annotated, Any, Literal

from pydantic import Field

from ..base import VulnersApiProxy, endpoint


class ReportApi(VulnersApiProxy):
    __report = endpoint(
        "Report.__report",
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

    def vulns_summary(
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

    def vulns_list(
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

    def ip_summary(
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

    def scan_list(
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

    def host_vulns(
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
