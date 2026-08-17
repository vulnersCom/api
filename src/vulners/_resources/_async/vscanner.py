"""Async ``vscanner`` resource (unasyncd source for the sync ``vscanner`` resource).

VScanner is a separate Vulners product surfaced here as a namespaced resource:
``vscanner.licenses``, ``vscanner.projects``, ``vscanner.projects.tasks`` and
``vscanner.projects.results``. Id parameters are typed as :class:`uuid.UUID` in
signatures (accepting the canonical string form at runtime).
"""

from __future__ import annotations

import base64
import posixpath
import uuid
from collections.abc import Mapping, Sequence
from functools import cached_property
from typing import Any, Literal
from urllib.parse import quote, unquote, urlsplit

import httpx

from ..._base_client import BodyMode, RequestSpec, ResponseMode
from ..._types import NotGiven, not_given
from . import _base

# All VScanner calls share one rate-limit bucket, matching the v3 client.
_GROUP = "vscanner"
_ROOT = "/api/v3/proxy/vscanner/v2/projects"
# Upper bound on percent-decode passes when validating a screenshot uri; a real
# uri stabilises in one or two passes, the cap stops pathological nesting.
_MAX_DECODE_PASSES = 40

_LICENSES = RequestSpec(
    "GET",
    "/api/v3/useraction/licenseids",
    body_mode="query",
    unwrap=("data",),
    ratelimit_group=_GROUP,
)


def _seg(value: Any) -> str:
    """Percent-quote a single path segment so an id cannot retarget the URL."""
    return quote(str(value), safe="")


def _spec(
    method: str, path: str, *, body_mode: BodyMode = "query", response_mode: ResponseMode = "json"
) -> RequestSpec:
    return RequestSpec(
        method,
        path,
        body_mode=body_mode,
        response_mode=response_mode,
        unwrap=() if response_mode == "bytes" else ("data",),
        ratelimit_group=_GROUP,
    )


def _guard_screenshot_path(url_path: str) -> None:
    """Reject a screenshot uri whose normalized path escapes /vscanner/screen/."""
    decoded = urlsplit(url_path).path
    for _ in range(_MAX_DECODE_PASSES):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once
    else:
        raise ValueError("Invalid image_uri: excessive percent-encoding")
    decoded = decoded.replace("\\", "/")
    if not posixpath.normpath(decoded).startswith("/vscanner/screen/"):
        raise ValueError("Invalid image_uri: path must stay under /vscanner/screen/")


class AsyncVscannerLicenses(_base.AsyncBaseResource):
    """VScanner license ids."""

    async def list(
        self,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the account's VScanner license ids.

        Returns:
            The license ids available to the account; pass one as ``license_id``
            when creating a project (see :meth:`AsyncVscannerProjects.create`).
        """
        return await self._request(_LICENSES, timeout=timeout)


class AsyncVscannerTasks(_base.AsyncBaseResource):
    """Scan tasks within a VScanner project."""

    async def list(
        self,
        project_id: uuid.UUID,
        *,
        offset: int = 0,
        limit: int = 50,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the scan tasks defined in a project.

        Args:
            project_id: The owning project.
            offset: Number of tasks to skip.
            limit: Maximum number of tasks to return in this page.

        Returns:
            A page of task records for the project.
        """
        spec = _spec("GET", f"{_ROOT}/{_seg(project_id)}/tasks")
        return await self._request(spec, body={"offset": offset, "limit": limit}, timeout=timeout)

    async def create(
        self,
        project_id: uuid.UUID,
        *,
        name: str,
        networks: Sequence[str],
        ports: Sequence[str],
        schedule: str,
        timing: str,
        enabled: bool,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create a scan task in a project.

        Args:
            project_id: The owning project.
            name: Task name.
            networks: Networks to scan (ips or domains).
            ports: Ports or port ranges.
            schedule: Crontab schedule string.
            timing: Scan timing profile.
            enabled: Whether the task is enabled.

        Returns:
            The created task record, including its assigned task id.
        """
        body = {
            "name": name,
            "networks": list(networks),
            "ports": list(ports),
            "schedule": schedule,
            "timing": timing,
            "enabled": enabled,
        }
        spec = _spec("POST", f"{_ROOT}/{_seg(project_id)}/tasks", body_mode="json")
        return await self._request(spec, body=body, timeout=timeout)

    async def update(
        self,
        project_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        name: str,
        networks: Sequence[str],
        ports: Sequence[str],
        schedule: str,
        timing: str,
        enabled: bool,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Replace a scan task's configuration in full.

        Every field is required: unset fields overwrite the stored values rather
        than leaving them untouched.

        Args:
            project_id: The owning project.
            task_id: The task to update.
            name: Task name.
            networks: Networks to scan (ips or domains).
            ports: Ports or port ranges.
            schedule: Crontab schedule string.
            timing: Scan timing profile.
            enabled: Whether the task is enabled.

        Returns:
            The updated task record.
        """
        body = {
            "name": name,
            "networks": list(networks),
            "ports": list(ports),
            "schedule": schedule,
            "timing": timing,
            "enabled": enabled,
        }
        spec = _spec("PUT", f"{_ROOT}/{_seg(project_id)}/tasks/{_seg(task_id)}", body_mode="json")
        return await self._request(spec, body=body, timeout=timeout)

    async def start(
        self,
        project_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Queue a task to run as soon as possible, ignoring its schedule.

        Args:
            project_id: The owning project.
            task_id: The task to start.

        Returns:
            The API acknowledgement that the task was queued.
        """
        spec = _spec(
            "POST", f"{_ROOT}/{_seg(project_id)}/tasks/{_seg(task_id)}/start", body_mode="json"
        )
        return await self._request(spec, timeout=timeout)

    async def delete(
        self,
        project_id: uuid.UUID,
        task_id: uuid.UUID,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a scan task from a project.

        Args:
            project_id: The owning project.
            task_id: The task to delete.

        Returns:
            The API acknowledgement of the deletion.
        """
        spec = _spec("DELETE", f"{_ROOT}/{_seg(project_id)}/tasks/{_seg(task_id)}")
        return await self._request(spec, timeout=timeout)


class AsyncVscannerResults(_base.AsyncBaseResource):
    """Scan results and screenshots within a VScanner project."""

    async def list(
        self,
        project_id: uuid.UUID,
        *,
        search: str | NotGiven = not_given,
        in_port: Sequence[str] | NotGiven = not_given,
        ex_port: Sequence[str] | NotGiven = not_given,
        min_cvss: float | NotGiven = not_given,
        max_cvss: float | NotGiven = not_given,
        last_seen: int | NotGiven = not_given,
        first_seen: int | NotGiven = not_given,
        last_seen_port: int | NotGiven = not_given,
        first_seen_port: int | NotGiven = not_given,
        sort: Literal[
            "ip", "name", "last_seen", "first_seen", "resolved", "min_cvss", "max_cvss"
        ] = "last_seen",
        sort_dir: Literal["asc", "desc"] = "asc",
        offset: int = 0,
        limit: int = 50,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List a project's scan results, with optional filtering and sorting.

        Args:
            project_id: The owning project.
            search: Free-text query to match against results.
            in_port: Keep only results on these ports.
            ex_port: Drop results on these ports.
            min_cvss: Keep only results with a CVSS score at or above this value.
            max_cvss: Keep only results with a CVSS score at or below this value.
            last_seen: Filter by the result's last-seen time (Unix timestamp).
            first_seen: Filter by the result's first-seen time (Unix timestamp).
            last_seen_port: Filter by a port's last-seen time (Unix timestamp).
            first_seen_port: Filter by a port's first-seen time (Unix timestamp).
            sort: Field to sort by.
            sort_dir: Sort direction, ascending or descending.
            offset: Number of results to skip.
            limit: Maximum number of results to return in this page.

        Returns:
            A page of scan-result records matching the filters.
        """
        body: dict[str, Any] = {
            "sort": sort,
            "sort_dir": sort_dir,
            "offset": offset,
            "limit": limit,
        }
        self._set(body, "search", search)
        self._set(body, "in_port", in_port, list)
        self._set(body, "ex_port", ex_port, list)
        self._set(body, "min_cvss", min_cvss)
        self._set(body, "max_cvss", max_cvss)
        self._set(body, "last_seen", last_seen)
        self._set(body, "first_seen", first_seen)
        self._set(body, "last_seen_port", last_seen_port)
        self._set(body, "first_seen_port", first_seen_port)
        spec = _spec("GET", f"{_ROOT}/{_seg(project_id)}/results")
        return await self._request(spec, body=body, timeout=timeout)

    async def delete(
        self,
        project_id: uuid.UUID,
        result_id: uuid.UUID,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a single scan result from a project.

        Args:
            project_id: The owning project.
            result_id: The scan result to delete.

        Returns:
            The API acknowledgement of the deletion.
        """
        spec = _spec("DELETE", f"{_ROOT}/{_seg(project_id)}/results/{_seg(result_id)}")
        return await self._request(spec, timeout=timeout)

    async def screenshot(
        self,
        image_uri: str,
        *,
        as_base64: bool = False,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> bytes:
        """Download a result screenshot as bytes.

        Args:
            image_uri: The server-provided screenshot uri (from a result's
                ``screens``). It is validated to stay under ``/vscanner/screen/``.
            as_base64: Return base64-encoded bytes instead of raw bytes.

        Returns:
            The screenshot image bytes, base64-encoded when ``as_base64`` is set.

        Raises:
            ValueError: If ``image_uri`` resolves outside ``/vscanner/screen/``
                or uses excessive percent-encoding.
        """
        url = "/vscanner/screen/" + image_uri
        _guard_screenshot_path(url)
        spec = _spec("GET", url, response_mode="bytes")
        content: bytes = await self._request(spec, timeout=timeout)
        return base64.b64encode(content) if as_base64 else content


class AsyncVscannerProjects(_base.AsyncBaseResource):
    """VScanner projects, plus their tasks and results namespaces."""

    @cached_property
    def tasks(self) -> AsyncVscannerTasks:
        """Scan-task operations scoped to a project."""
        return AsyncVscannerTasks(self._client)

    @cached_property
    def results(self) -> AsyncVscannerResults:
        """Scan-result and screenshot operations scoped to a project."""
        return AsyncVscannerResults(self._client)

    async def list(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """List the account's VScanner projects.

        Args:
            offset: Number of projects to skip.
            limit: Maximum number of projects to return in this page.

        Returns:
            A page of project records.
        """
        spec = _spec("GET", f"{_ROOT}/")
        return await self._request(spec, body={"offset": offset, "limit": limit}, timeout=timeout)

    async def create(
        self,
        *,
        name: str,
        license_id: uuid.UUID,
        notification: Mapping[str, Any],
        result_expire_in: int | NotGiven | None = not_given,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Create a project.

        Args:
            name: New project name.
            license_id: The license id to use.
            notification: A notification object (see
                :meth:`AsyncVscanner.notification`).
            result_expire_in: Expire results after N days; ``None`` never expires.

        Returns:
            The created project record, including its assigned project id.
        """
        body: dict[str, Any] = {
            "name": name,
            "license_id": str(license_id),
            "notification": dict(notification),
        }
        self._set(body, "result_expire_in", result_expire_in)
        spec = _spec("POST", f"{_ROOT}/", body_mode="json")
        return await self._request(spec, body=body, timeout=timeout)

    async def update(
        self,
        project_id: uuid.UUID,
        *,
        name: str,
        license_id: uuid.UUID,
        notification: Mapping[str, Any],
        result_expire_in: int | None,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Replace a project's configuration in full.

        Every field is required: unset fields overwrite the stored values rather
        than leaving them untouched.

        Args:
            project_id: The project to update.
            name: Project name.
            license_id: The license id to use.
            notification: A notification object (see
                :meth:`AsyncVscanner.notification`).
            result_expire_in: Expire results after N days; ``None`` never expires.

        Returns:
            The updated project record.
        """
        body = {
            "name": name,
            "license_id": str(license_id),
            "notification": dict(notification),
            "result_expire_in": result_expire_in,
        }
        spec = _spec("PUT", f"{_ROOT}/{_seg(project_id)}", body_mode="json")
        return await self._request(spec, body=body, timeout=timeout)

    async def delete(
        self,
        project_id: uuid.UUID,
        *,
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Delete a project and its scan data.

        Args:
            project_id: The project to delete.

        Returns:
            The API acknowledgement of the deletion.
        """
        spec = _spec("DELETE", f"{_ROOT}/{_seg(project_id)}")
        return await self._request(spec, timeout=timeout)

    async def statistics(
        self,
        project_id: uuid.UUID,
        *,
        stat: Sequence[
            Literal[
                "total_hosts",
                "vulnerable_hosts",
                "unique_cve",
                "min_max_cvss",
                "vulnerabilities_rank",
                "vulnerable_hosts_rank",
            ]
        ],
        timeout: float | httpx.Timeout | NotGiven = not_given,
    ) -> Any:
        """Return project statistics for the requested aggregations.

        Args:
            project_id: The project to summarize.
            stat: Which aggregations to compute (e.g. ``"total_hosts"``,
                ``"unique_cve"``, ``"min_max_cvss"``).

        Returns:
            A mapping keyed by the requested aggregation names, each holding its
            computed value.
        """
        spec = _spec("GET", f"{_ROOT}/{_seg(project_id)}/statistic")
        return await self._request(spec, body={"stat": list(stat)}, timeout=timeout)


class AsyncVscanner(_base.AsyncBaseResource):
    """VScanner product namespace on the client."""

    @cached_property
    def licenses(self) -> AsyncVscannerLicenses:
        """Access to the account's VScanner license ids."""
        return AsyncVscannerLicenses(self._client)

    @cached_property
    def projects(self) -> AsyncVscannerProjects:
        """VScanner projects, plus their nested tasks and results."""
        return AsyncVscannerProjects(self._client)

    @staticmethod
    def notification(
        period: Literal["disabled", "asap", "hourly", "daily"],
        emails: Sequence[str] | None = None,
        slack_webhooks: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Build a notification object for a project.

        Args:
            period: One of ``"disabled"``, ``"asap"``, ``"hourly"``, ``"daily"``.
            emails: Email destinations.
            slack_webhooks: Slack webhook destinations.

        Returns:
            A notification object suitable for the ``notification`` argument of
            :meth:`AsyncVscannerProjects.create` and
            :meth:`AsyncVscannerProjects.update`.

        Raises:
            ValueError: If ``period`` is not one of the four accepted values.
        """
        if period not in ("disabled", "asap", "hourly", "daily"):
            raise ValueError(
                'period expected to be one of "disabled", "asap", "hourly" or "daily"'
            )
        return {
            "period": period,
            "email": list(emails or []),
            "slack": list(slack_webhooks or []),
        }

    @staticmethod
    def disabled_notification() -> dict[str, Any]:
        """Build a notification object with delivery turned off.

        Returns:
            A notification object with ``"disabled"`` period and no
            destinations, for a project that should send no alerts.
        """
        return {"period": "disabled", "email": [], "slack": []}


__all__ = [
    "AsyncVscanner",
    "AsyncVscannerLicenses",
    "AsyncVscannerProjects",
    "AsyncVscannerResults",
    "AsyncVscannerTasks",
]
