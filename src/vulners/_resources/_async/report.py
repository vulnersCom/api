"""Async ``report`` resource (unasyncd source for the sync ``report`` resource).

Linux-audit reporting: summaries and lists of vulnerabilities, hosts and scans.
All five methods hit the same ``/api/v3/reports/vulnsreport`` endpoint with a
different ``reporttype`` and unwrap the ``report`` payload.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from . import _base

_REPORT = RequestSpec(
    "POST", "/api/v3/reports/vulnsreport", body_mode="json", unwrap=("data", "report")
)


class AsyncReport(_base.AsyncBaseResource):
    """Reports over Linux-audit results."""

    async def _report(
        self,
        reporttype: str,
        limit: int,
        offset: int,
        filter: dict[str, Any] | None,
        sort: str,
        timeout: float | httpx.Timeout | NotGiven,
    ) -> Any:
        body: dict[str, Any] = {
            "reporttype": reporttype,
            "skip": offset,
            "size": limit,
            "filter": filter or {},
            "sort": sort,
        }
        return await self._request(_REPORT, body=body, timeout=timeout)

    async def vulns_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Summarise every found vulnerability (id, title, score, severity...).

        Args:
            limit: Maximum number of rows to return in this page.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.

        Returns:
            The vulnerability-summary report payload: one row per distinct vulnerability.
        """
        return await self._report("vulnssummary", limit, offset, filter, sort, timeout)

    async def vulns_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List vulnerabilities found on hosts, with host information.

        Args:
            limit: Maximum number of rows to return in this page.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.

        Returns:
            The vulnerability-list report payload: one row per vulnerability occurrence on a host.
        """
        return await self._report("vulnslist", limit, offset, filter, sort, timeout)

    async def ip_summary(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Summarise results per host (agent id, ip, fqdn, os, vulnerability counts).

        Args:
            limit: Maximum number of rows to return in this page.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.

        Returns:
            The per-host summary report payload: one row per host.
        """
        return await self._report("ipsummary", limit, offset, filter, sort, timeout)

    async def scan_list(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List scans (host ip/fqdn, os, scan date, cvss score).

        Args:
            limit: Maximum number of rows to return in this page.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.

        Returns:
            The scan-list report payload: one row per scan.
        """
        return await self._report("scanlist", limit, offset, filter, sort, timeout)

    async def host_vulns(
        self,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List hosts with their cumulative fix and vulnerability ids.

        Args:
            limit: Maximum number of rows to return in this page.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.

        Returns:
            The host-vulnerabilities report payload: one row per host with its
            fix and vulnerability ids.
        """
        return await self._report("hostvulns", limit, offset, filter, sort, timeout)

    async def vuln_info(
        self,
        ip_address: str,
        bulletin_id: str,
        *,
        limit: int = 30,
        offset: int = 0,
        filter: dict[str, Any] | None = None,
        sort: str = "",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Detail of one vulnerability on one host.

        Args:
            ip_address: The host ip the vulnerability was found on.
            bulletin_id: The vulnerability bulletin id (e.g. a CVE id).
            limit: Maximum number of rows to return.
            offset: Number of rows to skip.
            filter: Additional report filter, if any.
            sort: Sort field; prefix with ``-`` for descending.
        """
        body: dict[str, Any] = {
            "reporttype": "vulninfo",
            "ipaddress": ip_address,
            "bulletinID": bulletin_id,
            "skip": offset,
            "size": limit,
            "filter": filter or {},
            "sort": sort,
        }
        return await self._request(_REPORT, body=body, timeout=timeout)


__all__ = ["AsyncReport"]
