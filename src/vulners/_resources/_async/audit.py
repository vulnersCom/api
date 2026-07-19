"""Async ``audit`` resource (unasyncd source for the sync ``audit`` resource).

Vulnerability audit of software inventories, package lists, SBOMs, KBs and CVEs.
Each method issues the same real endpoint the v3 SDK used, with a clean
keyword-only signature and the v3/v4 response envelope unwrapped.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from ..._types.audit import AuditItem, WinAuditItem
from . import _base

# v4 audit endpoints answer with ``{"result": <payload>}``; v3 ones with the
# ``{"result": "OK", "data": <payload>}`` envelope.
_SOFTWARE = RequestSpec("POST", "/api/v4/audit/software/", body_mode="json", unwrap=("result",))
_HOST = RequestSpec("POST", "/api/v4/audit/host/", body_mode="json", unwrap=("result",))
_OS_AUDIT = RequestSpec("POST", "/api/v3/audit/audit/", body_mode="json", unwrap=("data",))
_LINUX = RequestSpec("POST", "/api/v4/audit/linux", body_mode="json", unwrap=("result",))
_LIBRARY = RequestSpec("POST", "/api/v4/audit/library", body_mode="json", unwrap=("result",))
_SBOM = RequestSpec("POST", "/api/v4/audit/sbom", body_mode="multipart", unwrap=("result",))
_CVE = RequestSpec("POST", "/api/v4/audit/cve", body_mode="json", unwrap=("result",))
_CVES = RequestSpec("POST", "/api/v4/audit/cves", body_mode="json", unwrap=("result",))
_KB = RequestSpec("POST", "/api/v3/audit/kb/", body_mode="json", unwrap=("data",))
_WINAUDIT = RequestSpec("POST", "/api/v3/audit/winaudit/", body_mode="json", unwrap=("data",))
_SMART = RequestSpec("POST", "/api/v4/audit/smart", body_mode="json", unwrap=("result",))

_SMART_MAX_ITEMS = 500
_SMART_MAX_LEN = 512


class AsyncAudit(_base.AsyncBaseResource):
    """Audit software inventories and identifiers against Vulners intelligence."""

    async def software(
        self,
        software: Sequence[AuditItem | str],
        *,
        match: Literal["partial", "full"] = "partial",
        fields: Sequence[str] | NotGiven = not_given,
        config: Sequence[str] | NotGiven = not_given,
        catalog: Literal["official", "extended"] = "official",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[dict[str, Any]]:
        """Audit a list of software (CPE dicts or strings) for vulnerabilities.

        Args:
            software: Entries as :class:`AuditItem` dicts (``{"product": ...}``)
                or plain CPE-like strings.
            match: ``"partial"`` or ``"full"`` CPE matching.
            fields: Vulnerability fields to include; server default when omitted.
            config: Optional configuration entries.
            catalog: ``"official"`` or ``"extended"`` product catalog.
        """
        body: dict[str, Any] = {
            "software": list(software),
            "match": match,
            "catalog": catalog,
        }
        if not isinstance(fields, NotGiven):
            body["fields"] = list(fields)
        if not isinstance(config, NotGiven):
            body["config"] = list(config)
        return await self._request(_SOFTWARE, body=body, timeout=timeout)

    async def host(
        self,
        software: Sequence[AuditItem | str],
        *,
        application: AuditItem | str | NotGiven = not_given,
        operating_system: AuditItem | str | NotGiven = not_given,
        hardware: AuditItem | str | NotGiven = not_given,
        match: Literal["partial", "full"] = "partial",
        fields: Sequence[str] | NotGiven = not_given,
        config: Sequence[str] | NotGiven = not_given,
        catalog: Literal["official", "extended"] = "official",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[dict[str, Any]]:
        """Audit a host: its software plus optional application/OS/hardware CPEs."""
        body: dict[str, Any] = {
            "software": list(software),
            "match": match,
            "catalog": catalog,
        }
        if not isinstance(application, NotGiven):
            body["application"] = application
        if not isinstance(operating_system, NotGiven):
            body["operating_system"] = operating_system
        if not isinstance(hardware, NotGiven):
            body["hardware"] = hardware
        if not isinstance(fields, NotGiven):
            body["fields"] = list(fields)
        if not isinstance(config, NotGiven):
            body["config"] = list(config)
        return await self._request(_HOST, body=body, timeout=timeout)

    async def os_audit(
        self,
        *,
        os: str,
        version: str,
        packages: Sequence[str],
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit an OS package list (legacy v3 endpoint; prefer :meth:`linux_audit`).

        Args:
            os: OS name, e.g. ``"ubuntu"``, ``"debian"``, ``"rhel"``.
            version: OS version.
            packages: Installed packages, one per entry.
        """
        body = {"os": os, "version": version, "package": list(packages)}
        return await self._request(_OS_AUDIT, body=body, timeout=timeout)

    async def linux_audit(
        self,
        *,
        os_name: str,
        os_version: str,
        packages: Sequence[str],
        os_arch: str | None = None,
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit RPM/DEB/APK package lists for a Linux host.

        Args:
            os_name: OS name or id (``ubuntu``, ``debian``, ``rhel``, ``alpine``...).
            os_version: OS version.
            packages: Installed packages (1..2500 entries).
            os_arch: Default architecture for packages.
            include_unofficial: Include unofficial packages.
            include_candidates: Include ``candidate`` vulnerabilities.
            include_any_version: Include ``any`` version vulnerabilities.
            cvelist_metrics: Add cvelist metrics (non-free licenses only).
        """
        body = {
            "osName": os_name,
            "osVersion": os_version,
            "packages": list(packages),
            "osArch": os_arch,
            "includeUnofficial": include_unofficial,
            "includeCandidates": include_candidates,
            "includeAnyVersion": include_any_version,
            "cvelistMetrics": cvelist_metrics,
        }
        return await self._request(_LINUX, body=body, timeout=timeout)

    async def library_audit(
        self,
        *,
        packages: Sequence[str],
        include_unofficial: bool = False,
        include_candidates: bool = False,
        include_any_version: bool = False,
        cvelist_metrics: bool = False,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a list of packages in PURL format.

        Args:
            packages: Packages in PURL format (1..2500 entries).
            include_unofficial: Include unofficial packages.
            include_candidates: Include ``candidate`` vulnerabilities.
            include_any_version: Include ``any`` version vulnerabilities.
            cvelist_metrics: Add cvelist metrics (non-free licenses only).
        """
        body = {
            "packages": list(packages),
            "includeUnofficial": include_unofficial,
            "includeCandidates": include_candidates,
            "includeAnyVersion": include_any_version,
            "cvelistMetrics": cvelist_metrics,
        }
        return await self._request(_LIBRARY, body=body, timeout=timeout)

    async def sbom_audit(
        self,
        file: str | os.PathLike[str],
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit an SBOM file (SPDX or CycloneDX) for vulnerabilities.

        Args:
            file: Path to the SBOM file to upload.
        """
        path = os.fspath(file)
        with open(path, "rb") as handle:
            content = handle.read()
        files = {"file": (os.path.basename(path), content, "application/json")}
        return await self._request(_SBOM, files=files, timeout=timeout)

    async def cve_audit(
        self,
        cve: str,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a single CVE identifier."""
        return await self._request(_CVE, body={"cve": cve}, timeout=timeout)

    async def cve_batch_audit(
        self,
        cve: Sequence[str],
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[dict[str, Any]]:
        """Audit a batch of CVE identifiers (at least one)."""
        return await self._request(_CVES, body={"cve": list(cve)}, timeout=timeout)

    async def kb_audit(
        self,
        *,
        os: str,
        kb_list: Sequence[str],
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a Windows host by its installed KB list.

        Args:
            os: Windows OS name, e.g. ``"Windows Server 2012 R2"``.
            kb_list: Installed KBs, e.g. ``["KB2918614", "KB2918616"]``.
        """
        body = {"os": os, "kbList": list(kb_list)}
        return await self._request(_KB, body=body, timeout=timeout)

    async def win_audit(
        self,
        *,
        os: str,
        os_version: str,
        kb_list: Sequence[str],
        software: Sequence[WinAuditItem],
        platform: str | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a Windows host by installed KBs and software.

        Args:
            os: Windows OS name, e.g. ``"Windows Server 2012 R2"``.
            os_version: Windows OS version, e.g. ``"10.0.19045"``.
            kb_list: Installed KBs.
            software: Installed software, ``{"software": ..., "version": ...}``.
            platform: OS platform, e.g. ``"x86"``.
        """
        body: dict[str, Any] = {
            "os": os,
            "os_version": os_version,
            "kb_list": list(kb_list),
            "software": list(software),
        }
        if not isinstance(platform, NotGiven):
            body["platform"] = platform
        # This endpoint requires the api key echoed in the request body.
        body["apiKey"] = self._api_key
        return await self._request(_WINAUDIT, body=body, timeout=timeout)

    async def smart(
        self,
        software: Sequence[str],
        *,
        catalog: Literal["official", "extended"] = "official",
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> list[dict[str, Any]]:
        """Resolve free-form software strings to CPE/PURLs and their vulnerabilities.

        Each input string is matched heuristically to a CPE and/or PURLs, returning
        ``{"input", "cpe"?, "purls", "confidence", "vulnerabilities"}`` per entry.

        Note:
            This is a preview endpoint. **Billing is per submitted string** (every
            entry in ``software`` is charged), so keep the batch to what you need.

        Args:
            software: 1..500 strings, each at most 512 characters.
            catalog: ``"official"`` or ``"extended"`` product catalog.

        Raises:
            ValueError: ``software`` is empty, has more than 500 entries, or any
                entry exceeds 512 characters.
        """
        items = list(software)
        if not 1 <= len(items) <= _SMART_MAX_ITEMS:
            raise ValueError(
                f"software must have between 1 and {_SMART_MAX_ITEMS} entries "
                f"(got {len(items)}); billing is per submitted string."
            )
        for item in items:
            if len(item) > _SMART_MAX_LEN:
                raise ValueError(
                    f"each software entry must be at most {_SMART_MAX_LEN} characters"
                )
        body: dict[str, Any] = {"software": items, "catalog": catalog}
        return await self._request(_SMART, body=body, timeout=timeout)


__all__ = ["AsyncAudit"]
