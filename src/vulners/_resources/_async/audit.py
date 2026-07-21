"""Async ``audit`` resource (unasyncd source for the sync ``audit`` resource).

Vulnerability audit of software inventories, package lists, SBOMs, KBs and CVEs.
Each method issues the same real endpoint the v3 SDK used, with a clean
keyword-only signature and the v3/v4 response envelope unwrapped.
"""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import Sequence
from functools import cached_property
from typing import IO, Any, Literal

import httpx

from ..._base_client import RequestSpec
from ..._types import NotGiven, not_given
from ..._types.audit import AuditItem, WinAuditItem
from . import _base


def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        # Validate the descriptor actually opened, not the path examined
        # earlier: between any prior check and this open the path could be
        # swapped for a device, FIFO or directory, so rejecting a non-regular
        # target closes that TOCTOU window (CWE-367). A regular file (including
        # a symlink to one) has S_ISREG set and is uploaded exactly as before.
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("upload path is not a regular file")
        return handle.read()


def _read_package_manifest(file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes) -> bytes:
    """Coerce a package-audit input (path / open file / raw bytes) to bytes."""
    if isinstance(file, bytes):
        return file
    if isinstance(file, (str, os.PathLike)):
        return _read_file_bytes(os.fspath(file))
    data = file.read()
    return data.encode("utf-8") if isinstance(data, str) else bytes(data)


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
_SUPPORTED_OS = RequestSpec(
    "GET", "/api/v3/audit/getSupportedOS/", body_mode="query", unwrap=("data", "supportedOS")
)

_SMART_MAX_ITEMS = 500
_SMART_MAX_LEN = 512
# Documented upper bound for the package/library audit endpoints.
_AUDIT_MAX_PACKAGES = 2500


def _require_count(
    items: Sequence[Any], name: str, *, hi: int | None = None, strings: bool = False
) -> list[Any]:
    """Validate a batch before a request: non-empty, within ``hi``, no empty strings.

    Enforces the documented limits client-side so an empty or oversized batch (or a
    negative-size payload derived from it) fails fast with a clear message instead
    of a confusing server error — important for the per-string-billed endpoints.
    """
    seq = list(items)
    if not seq:
        raise ValueError(f"{name} must not be empty")
    if hi is not None and len(seq) > hi:
        raise ValueError(f"{name} must have at most {hi} entries, got {len(seq)}")
    if strings:
        for i, entry in enumerate(seq):
            if not isinstance(entry, str) or not entry.strip():
                raise ValueError(f"{name}[{i}] must be a non-empty string")
    return seq


PackageEcosystem = Literal["maven", "pip", "poetry", "uv", "npm", "golang"]

# The package-audit endpoints take the raw manifest as a text/plain body.
_PACKAGE_SPECS: dict[str, RequestSpec] = {
    ecosystem: RequestSpec(
        "POST", f"/api/v4/audit/package/{ecosystem}", body_mode="text", unwrap=("result",)
    )
    for ecosystem in ("maven", "pip", "poetry", "uv", "npm", "golang")
}


# Deliberately not Async-prefixed: the class name is shared with the generated
# sync mirror (the namespace is reached through ``client.audit.packages``, so
# the module path — _async vs _sync — is what distinguishes the two).
class AuditPackages(_base.AsyncBaseResource):
    """Audit raw package-manager manifests (``client.audit.packages``).

    Each method posts the manifest text as-is and returns the audit result
    (an ``issues`` list, one entry per vulnerable package). The ``include_*``
    filters are sent only when given, so the server defaults apply otherwise.
    """

    async def _audit(
        self,
        spec: RequestSpec,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        include_any_version: bool | NotGiven,
        include_candidates: bool | NotGiven,
        include_unofficial: bool | NotGiven,
        include_transitives: bool | NotGiven,
        timeout: float | httpx.Timeout | NotGiven,
    ) -> dict[str, Any]:
        content = await asyncio.to_thread(_read_package_manifest, file)
        params: dict[str, Any] = {}
        self._set(params, "includeAnyVersion", include_any_version)
        self._set(params, "includeCandidates", include_candidates)
        self._set(params, "includeUnofficial", include_unofficial)
        self._set(params, "includeTransitives", include_transitives)
        return await self._request(spec, body=content, params=params, timeout=timeout)

    async def maven(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit ``mvn dependency:list`` output.

        Args:
            file: The manifest — a file path, an open file object, or the raw
                bytes of the ``mvn dependency:list`` output.
            include_any_version: Include advisories matching the package name
                regardless of version (server default: on).
            include_candidates: Include candidate advisories awaiting vendor
                confirmation (server default: off).
            include_unofficial: Include advisories from unofficial feeds
                (server default: off).
            include_transitives: Include transitively-introduced packages
                (server default: off).
        """
        return await self._audit(
            _PACKAGE_SPECS["maven"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def pip(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit ``pip freeze`` output; arguments as in :meth:`maven`."""
        return await self._audit(
            _PACKAGE_SPECS["pip"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def poetry(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a ``poetry.lock`` file; arguments as in :meth:`maven`."""
        return await self._audit(
            _PACKAGE_SPECS["poetry"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def uv(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a ``uv.lock`` file; arguments as in :meth:`maven`."""
        return await self._audit(
            _PACKAGE_SPECS["uv"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def npm(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a ``package-lock.json`` file; arguments as in :meth:`maven`."""
        return await self._audit(
            _PACKAGE_SPECS["npm"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def golang(
        self,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit ``go list -m all`` output; arguments as in :meth:`maven`."""
        return await self._audit(
            _PACKAGE_SPECS["golang"],
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )

    async def scan(
        self,
        ecosystem: PackageEcosystem,
        file: str | os.PathLike[str] | IO[bytes] | IO[str] | bytes,
        *,
        include_any_version: bool | NotGiven = not_given,
        include_candidates: bool | NotGiven = not_given,
        include_unofficial: bool | NotGiven = not_given,
        include_transitives: bool | NotGiven = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, Any]:
        """Audit a manifest for the given ``ecosystem``; arguments as in :meth:`maven`.

        Args:
            ecosystem: One of ``"maven"``, ``"pip"``, ``"poetry"``, ``"uv"``,
                ``"npm"``, ``"golang"``.
            file: The manifest — a file path, an open file object, or raw bytes.

        Raises:
            ValueError: ``ecosystem`` is not a supported value.
        """
        spec = _PACKAGE_SPECS.get(ecosystem)
        if spec is None:
            supported = ", ".join(sorted(_PACKAGE_SPECS))
            raise ValueError(f"unsupported ecosystem {ecosystem!r}; expected one of {supported}")
        return await self._audit(
            spec,
            file,
            include_any_version,
            include_candidates,
            include_unofficial,
            include_transitives,
            timeout,
        )


class AsyncAudit(_base.AsyncBaseResource):
    """Audit software inventories and identifiers against Vulners intelligence."""

    @cached_property
    def packages(self) -> AuditPackages:
        """Package-manager manifest audits (``pip``/``npm``/``maven``/...)."""
        return AuditPackages(self._client)

    async def supported_os(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> dict[str, str]:
        """List the operating systems accepted by the Linux-package audits.

        Returns:
            A mapping of OS short name (e.g. ``"ubuntu"``, ``"rhel"``) to the
            shell command Vulners recommends for enumerating that OS's
            installed packages.
        """
        return await self._request(_SUPPORTED_OS, timeout=timeout)

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
            "software": _require_count(software, "software"),
            "match": match,
            "catalog": catalog,
        }
        self._set(body, "fields", fields, list)
        self._set(body, "config", config, list)
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
            "software": _require_count(software, "software"),
            "match": match,
            "catalog": catalog,
        }
        self._set(body, "application", application)
        self._set(body, "operating_system", operating_system)
        self._set(body, "hardware", hardware)
        self._set(body, "fields", fields, list)
        self._set(body, "config", config, list)
        return await self._request(_HOST, body=body, timeout=timeout)

    async def os_audit(
        self,
        os: str,
        version: str,
        packages: Sequence[str],
        *,
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
        os_name: str,
        os_version: str,
        packages: Sequence[str],
        *,
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
            "packages": _require_count(
                packages, "packages", hi=_AUDIT_MAX_PACKAGES, strings=True
            ),
            "osArch": os_arch,
            "includeUnofficial": include_unofficial,
            "includeCandidates": include_candidates,
            "includeAnyVersion": include_any_version,
            "cvelistMetrics": cvelist_metrics,
        }
        return await self._request(_LINUX, body=body, timeout=timeout)

    async def library_audit(
        self,
        packages: Sequence[str],
        *,
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
            "packages": _require_count(
                packages, "packages", hi=_AUDIT_MAX_PACKAGES, strings=True
            ),
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
        content = await asyncio.to_thread(_read_file_bytes, path)
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
        return await self._request(
            _CVES, body={"cve": _require_count(cve, "cve", strings=True)}, timeout=timeout
        )

    async def kb_audit(
        self,
        os: str,
        kb_list: Sequence[str],
        *,
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
        os: str,
        os_version: str,
        kb_list: Sequence[str],
        software: Sequence[WinAuditItem],
        *,
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
        self._set(body, "platform", platform)
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


__all__ = ["AsyncAudit", "AuditPackages"]
