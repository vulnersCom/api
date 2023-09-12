import base64

from .base import UUID, Boolean, Dict, Endpoint, Float, Integer, List, String, VulnersApiBase

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping


class MappingObject(Mapping):
    __slots__ = ("_api",)

    def __init__(self, api, data):
        self._api = api
        self.__dict__ = data

    def __len__(self):
        return len(self.__dict__)

    def __getitem__(self, k):
        return self.__dict__[k]

    def __iter__(self):
        return iter(self.__dict__)

    def __repr__(self):
        return repr(self.__dict__)


class Project(MappingObject):
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


class Task(MappingObject):
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

    def get_log(self):
        return self._api.get_task_log(self.context_id)


class Result(MappingObject):
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
    ratelimit_key = "vscanner"

    get_licenses = Endpoint(
        method="get",
        url="/api/v3/useraction/licenseids",
        description="Get user's license ids.",
    )
    get_projects = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/v2/projects/",
        description="Get existing projects.",
        params=[
            ("offset", Integer(default=0)),
            ("limit", Integer(default=50)),
        ],
        wrapper=lambda api, c: [Project(api, x) for x in c],
    )
    create_project = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/v2/projects/",
        description="Create new project.",
        params=[
            ("name", String(description="New project name")),
            ("license_id", UUID(description="User's license id")),
            (
                "notification",
                Dict(
                    description=(
                        "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                        "to create notification object."
                    ),
                ),
            ),
            (
                "result_expire_in",
                Integer(
                    description="Result expire in N days. Null means it will never expire",
                    required=False,
                    minimum=1,
                ),
            ),
        ],
        wrapper=Project,
    )
    update_project = Endpoint(
        method="put",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}",
        description="Update existing project.",
        params=[
            ("name", String(description="Project name")),
            ("license_id", UUID(description="User's license id")),
            (
                "notification",
                Dict(
                    description=(
                        "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                        "to create notification object."
                    ),
                ),
            ),
            (
                "result_expire_in",
                Integer(
                    description="Result expire in N days. Null means it will never expire",
                    minimum=1,
                    allow_null=True,
                ),
            ),
        ],
        wrapper=Project,
    )
    delete_project = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}",
        description="Delete existing project.",
    )
    get_tasks = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/tasks",
        description="Get project tasks",
        params=[("offset", Integer(default=0)), ("limit", Integer(default=50))],
        wrapper=lambda api, c: [Task(api, x) for x in c],
    )
    create_task = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/tasks",
        description="Create new task.",
        params=[
            ("name", String(description="Task name")),
            ("networks", List(description="List of networks (ip or domains)", item=String())),
            ("ports", List(description="List of ports or port ranges", item=String())),
            ("schedule", String(description="Crontab string")),
            ("timing", String(description="Scan timing")),
            ("enabled", Boolean(description="Enable/disable task")),
        ],
        wrapper=Task,
    )
    update_task = Endpoint(
        method="put",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}",
        description="Update task.",
        params=[
            ("name", String(description="Task name")),
            ("networks", List(description="List of networks (ip or domains)", item=String())),
            ("ports", List(description="List of ports or port ranges", item=String())),
            ("schedule", String(description="Crontab string")),
            ("timing", String(description="Scan timing")),
            ("enabled", Boolean(description="Enable/disable task")),
        ],
        wrapper=Task,
    )
    start_task = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}/start",
        description="Start task asap.",
        wrapper=Task,
    )
    delete_task = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}",
        description="Delete task.",
    )
    get_results = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/results",
        description="Get results.",
        params=[
            (
                "search",
                String(required=False, description="Search by ip, network, name or vuln_id."),
            ),
            ("in_port", List(required=False, description="Include ports")),
            ("ex_port", List(required=False, description="Exclude ports")),
            ("min_cvss", Float(required=False, description="Minimum CVSS value.")),
            ("max_cvss", Float(required=False, description="Maximum CVSS value.")),
            ("last_seen", Integer(required=False, description="last_seen >= given value.")),
            ("first_seen", Integer(required=False, description="first_seen >= given value.")),
            (
                "last_seen_port",
                Integer(required=False, description="last_seen_port >= given value."),
            ),
            (
                "first_seen_port",
                Integer(required=False, description="first_seen_port >= given value."),
            ),
            (
                "sort",
                String(
                    required=False,
                    description=(
                        "Sort by field. Allowable values are 'ip', 'name', 'last_seen', 'first_seen', "
                        "'resolved', 'min_cvss' and 'max_cvss'. Default: last_seen"
                    ),
                ),
            ),
            (
                "sort_dir",
                String(required=False, description="Sort direction: asc or desc. Default: asc"),
            ),
            ("offset", Integer(default=0)),
            ("limit", Integer(default=50)),
        ],
        wrapper=lambda api, c: [Result(api, x) for x in c],
    )
    delete_result = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/results/{uuid:result_id|Result id}",
        description="Delete result by id.",
    )
    get_statistics = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/v2/projects/{uuid:project_id|Project id}/statistic",
        description="Get project statistics.",
        params=[
            (
                "stat",
                List(
                    required=True,
                    description=(
                        "List of required aggregations:"
                        "total_hosts, vulnerable_hosts, unique_cve, min_max_cvss, "
                        "vulnerabilities_rank, vulnerable_hosts_rank"
                    ),
                    item=String(),
                ),
            )
        ],
    )

    def get_image_binary(self, image_uri, as_base64=False):
        result, headers = self._send_request(
            "get", "/vscanner/screen/" + image_uri, {}, {}, self.ratelimit_key, "binary"
        )
        if as_base64:
            return base64.b64encode(result)
        return result

    @staticmethod
    def Notification(period, emails=None, slack_webhooks=None):
        """
        Create notification project

        period: one of "disabled", "asap", "hourly" or "daily"
        emails: list of emails
        slack_webhooks: list of slack webhooks
        """
        if period not in ("disabled", "asap", "hourly", "daily"):
            raise ValueError('period expected to be one of "disabled", "asap", "hourly" or "daily"')
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
