from __future__ import annotations

import base64
import uuid
from typing import Annotated, Any, Iterable, Iterator, Literal, Mapping

from pydantic import Field
from typing_extensions import TypedDict

from .base import Unset, VulnersApiBase, endpoint


class NotificationObj(TypedDict):
    period: Literal["disabled", "asap", "hourly", "daily"]
    email: list[str]
    slack: list[str]


class ApiObject(Mapping[str, Any]):
    __slots__ = ("_api", "__dict__")

    def __init__(self, api: VScannerApi, data: dict[str, Any]):
        self._api = api
        self.__dict__ = data

    def __len__(self):
        return len(self.__dict__)

    def __getitem__(self, k):
        return self.__dict__[k]

    def __iter__(self) -> Iterator[Any]:
        return iter(self.__dict__)

    def __repr__(self) -> str:
        return repr(self.__dict__)


class ProjectList(list):
    def __init__(self, api: VScannerApi, value: Iterable[dict[str, Any]]) -> None:
        super().__init__(Project(api, c) for c in value)


class Project(ApiObject):
    _id: uuid.UUID
    name: str
    license_id: str
    notification: NotificationObj
    result_expire_in: int | None

    def update(self, **kwargs):
        kwargs.setdefault("name", self.name)
        kwargs.setdefault("license_id", self.license_id)
        kwargs.setdefault("notification", self.notification)
        kwargs.setdefault("result_expire_in", self.result_expire_in)
        self.__dict__ = self._api.update_project(self._id, **kwargs).__dict__

    def delete(self):
        self._api.delete_project(self._id)

    def get_tasks(self, *args, **kwargs):
        return self._api.get_tasks(self._id, *args, **kwargs)

    def create_task(self, *args, **kwargs):
        return self._api.create_task(self._id, *args, **kwargs)

    def get_results(self, *args, **kwargs):
        return self._api.get_results(self._id, *args, **kwargs)

    def get_statistics(self, *args, **kwargs):
        return self._api.get_statistics(self._id, *args, **kwargs)


class TaskList(list):
    def __init__(self, api: VScannerApi, value: Iterable[dict[str, Any]]) -> None:
        super().__init__(Task(api, c) for c in value)


class Task(ApiObject):
    _id: uuid.UUID
    name: str
    project_id: uuid.UUID
    networks: list[str]
    ports: list[str]
    timing: str
    schedule: str
    enabled: bool
    context_id: uuid.UUID

    def update(self, **kwargs):
        kwargs.setdefault("name", self.name)
        kwargs.setdefault("networks", self.networks)
        kwargs.setdefault("ports", self.ports)
        kwargs.setdefault("timing", self.timing)
        kwargs.setdefault("schedule", self.schedule)
        kwargs.setdefault("enabled", self.enabled)
        self.__dict__ = self._api.update_task(self.project_id, self._id, **kwargs).__dict__

    def delete(self):
        self._api.delete_task(self.project_id, self._id)

    def start_task(self):
        self.__dict__ = self._api.start_task(self.project_id, self._id).__dict__


class ResultList(list):
    def __init__(self, api: VScannerApi, value: Iterable[dict[str, Any]]) -> None:
        super().__init__(Result(api, c) for c in value)


class Result(ApiObject):
    _id: uuid.UUID
    project_id: uuid.UUID
    screens: Mapping[str, Any]

    def delete(self):
        self._api.delete_result(self.project_id, self._id)

    def get_screenshot(self, port, as_base64=False):
        try:
            screen = self.screens[str(port)]["screen"]
        except (AttributeError, KeyError):
            return None
        if not screen:
            return None
        return self._api.get_image_binary(screen, as_base64)


class VScannerApi(VulnersApiBase):
    _ratelimit_key = "vscanner"

    get_licenses = endpoint(
        "VScannerApi.get_licenses",
        method="GET",
        url="/api/v3/useraction/licenseids",
        description="Get user's license ids.",
        wrapper=ApiObject,
    )
    get_projects = endpoint(
        "VScannerApi.get_projects",
        method="GET",
        url="/api/v3/proxy/vscanner/v2/projects/",
        description="Get existing projects.",
        params={
            "offset": Annotated[int, Field(default=0, ge=0)],
            "limit": Annotated[int, Field(default=50, le=1000)],
        },
        wrapper=ProjectList,
    )
    create_project = endpoint(
        "VScannerApi.create_project",
        method="POST",
        url="/api/v3/proxy/vscanner/v2/projects/",
        description="Create new project.",
        params={
            "name": Annotated[str, Field(description="New project name")],
            "license_id": Annotated[uuid.UUID, Field(description="User's license id")],
            "notification": Annotated[
                NotificationObj,
                Field(
                    description=(
                        "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                        "to create notification object."
                    ),
                ),
            ],
            "result_expire_in": Annotated[
                int | None,
                Field(
                    default=Unset,
                    gt=0,
                    description="Result expire in N days. Null means it will never expire",
                ),
            ],
        },
        wrapper=Project,
    )
    update_project = endpoint(
        "VScannerApi.update_project",
        method="PUT",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}",
        description="Update existing project.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "name": Annotated[str, Field(description="Project name")],
            "license_id": Annotated[uuid.UUID, Field(description="User's license id")],
            "notification": Annotated[
                NotificationObj,
                Field(
                    description=(
                        "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                        "to create notification object."
                    ),
                ),
            ],
            "result_expire_in": Annotated[
                int | None,
                Field(
                    gt=0,
                    description="Result expire in N days. Null means it will never expire",
                ),
            ],
        },
        wrapper=Project,
    )
    delete_project = endpoint(
        "VScannerApi.delete_project",
        method="DELETE",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}",
        description="Delete existing project.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
        },
    )
    get_tasks = endpoint(
        "VScannerApi.get_tasks",
        method="GET",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks",
        description="Get project tasks",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "offset": Annotated[int, Field(default=0, ge=0)],
            "limit": Annotated[int, Field(default=50, le=1000)],
        },
        wrapper=TaskList,
    )
    create_task = endpoint(
        "VScannerApi.create_task",
        method="POST",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks",
        description="Create new task.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "name": Annotated[str, Field(description="Task name")],
            "networks": Annotated[
                list[str], Field(description="List of networks (ip or domains)")
            ],
            "ports": Annotated[list[str], Field(description="List of ports or port ranges")],
            "schedule": Annotated[str, Field(description="Crontab string")],
            "timing": Annotated[str, Field(description="Scan timing")],
            "enabled": Annotated[bool, Field(description="Enable/disable task")],
        },
        wrapper=Task,
    )
    update_task = endpoint(
        "VScannerApi.update_task",
        method="PUT",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}",
        description="Update task.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "task_id": Annotated[uuid.UUID, Field(description="Task ID")],
            "name": Annotated[str, Field(description="Task name")],
            "networks": Annotated[
                list[str], Field(description="List of networks (ip or domains)")
            ],
            "ports": Annotated[list[str], Field(description="List of ports or port ranges")],
            "schedule": Annotated[str, Field(description="Crontab string")],
            "timing": Annotated[str, Field(description="Scan timing")],
            "enabled": Annotated[bool, Field(description="Enable/disable task")],
        },
        wrapper=Task,
    )
    start_task = endpoint(
        "VScannerApi.start_task",
        method="POST",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}/start",
        description="Start task asap.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "task_id": Annotated[uuid.UUID, Field(description="Task ID")],
        },
        wrapper=Task,
    )
    delete_task = endpoint(
        "VScannerApi.delete_task",
        method="DELETE",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/tasks/{task_id}",
        description="Delete task.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "task_id": Annotated[uuid.UUID, Field(description="Task ID")],
        },
    )
    get_results = endpoint(
        "VScannerApi.get_results",
        method="GET",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/results",
        description="Get results.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "search": Annotated[
                str, Field(default=Unset, description="Search by ip, network, name or vuln_id.")
            ],
            "in_port": Annotated[list[str], Field(default=Unset, description="Include ports")],
            "ex_port": Annotated[list[str], Field(default=Unset, description="Exclude ports")],
            "min_cvss": Annotated[float, Field(default=Unset, description="Minimum CVSS value")],
            "max_cvss": Annotated[float, Field(default=Unset, description="Maximum CVSS value")],
            "last_seen": Annotated[
                int, Field(default=Unset, description="last_seen >= given value")
            ],
            "first_seen": Annotated[
                int, Field(default=Unset, description="first_seen >= given value")
            ],
            "last_seen_port": Annotated[
                int, Field(default=Unset, description="last_seen_port >= given value")
            ],
            "first_seen_port": Annotated[
                int, Field(default=Unset, description="first_seen_port >= given value")
            ],
            "sort": Annotated[
                Literal[
                    "ip",
                    "name",
                    "last_seen",
                    "first_seen",
                    "resolved",
                    "min_cvss",
                    "max_cvss",
                ],
                Field(default="last_seen", description="Sort by field"),
            ],
            "sort_dir": Annotated[
                Literal["asc", "desc"], Field(default="asc", description="Sort direction")
            ],
            "offset": Annotated[int, Field(default=0, ge=0)],
            "limit": Annotated[int, Field(default=50, le=1000)],
        },
        wrapper=ResultList,
    )
    delete_result = endpoint(
        "VScannerApi.delete_result",
        method="DELETE",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/results/{result_id}",
        description="Delete result by id.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "result_id": Annotated[uuid.UUID, Field(description="Result ID")],
        },
    )
    get_statistics = endpoint(
        "VScannerApi.get_statistics",
        method="GET",
        url="/api/v3/proxy/vscanner/v2/projects/{project_id}/statistic",
        description="Get project statistics.",
        params={
            "project_id": Annotated[uuid.UUID, Field(description="Project ID")],
            "stat": Annotated[
                list[
                    Literal[
                        "total_hosts",
                        "vulnerable_hosts",
                        "unique_cve",
                        "min_max_cvss",
                        "vulnerabilities_rank",
                        "vulnerable_hosts_rank",
                    ]
                ],
                Field(min_length=1, description="List of required aggregations"),
            ],
        },
    )

    def get_image_binary(self, image_uri: str, as_base64: bool = False):
        content = self._invoke(
            "GET", "/vscanner/screen/" + image_uri, {}, (), parse_content=False
        )
        if as_base64:
            return base64.b64encode(content)
        return content

    @staticmethod
    def Notification(
        period: Literal["disabled", "asap", "hourly", "daily"],
        emails: list[str] | None = None,
        slack_webhooks: list[str] | None = None,
    ) -> NotificationObj:
        """
        Create notification project

        period: one of "disabled", "asap", "hourly" or "daily"
        emails: list of emails
        slack_webhooks: list of slack webhooks
        """
        if period not in ("disabled", "asap", "hourly", "daily"):
            raise ValueError(
                'period expected to be one of "disabled", "asap", "hourly" or "daily"'
            )
        return {
            "period": period,
            "email": emails or [],
            "slack": slack_webhooks or [],
        }

    @staticmethod
    def DisabledNotification():
        """
        Create stub notification object with "disabled" period and empty methods
        """
        return {
            "period": "disabled",
            "email": [],
            "slack": [],
        }
