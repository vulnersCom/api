from . base import VulnersApiBase, Endpoint, String, Integer, Float, Dict, List, UUID, Boolean
from . base import ResultSet


def make_result_set(content, headers):
    return ResultSet.from_dataset(content, int(headers["X-Total-Count"]))


class VScannerApi(VulnersApiBase):
    ratelimit_key = "vscanner"

    get_licenses = Endpoint(
        method="get",
        url="/api/v3/useraction/licenseids",
        description="Get user's license ids."
    )
    get_projects = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/projects",
        description="Get existing projects.",
        params=[
            ("offset", Integer(default=0)),
            ("limit", Integer(default=50)),
        ]
    )
    get_quota = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/quota/{uuid:license_id|License id}",
        description="Get api quota left."
    )
    create_project = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/projects",
        description="Create new project.",
        params=[
            ("name", String(description="New project name")),
            ("license_id", UUID(description="User's license id")),
            ("notification", Dict(description=(
                "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                "to create notification object.")))
        ]
    )
    update_project = Endpoint(
        method="put",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}",
        description="Update existing project.",
        params=[
            ("name", String(description="Project name")),
            ("license_id", UUID(description="User's license id")),
            ("notification", Dict(description=(
                "Use VScannerApi.Notification or VScannerApi.DisabledNotification helpers "
                "to create notification object.")))
        ]
    )
    delete_project = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}",
        description="Delete existing project."
    )
    get_tasks = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/tasks",
        description="Get project tasks",
        params=[
            ("offset", Integer(default=0)),
            ("limit", Integer(default=50))
        ]
    )
    create_task = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/tasks",
        description="Create new task.",
        params=[
            ("name", String(description="Task name")),
            ("networks", List(description="List of networks (ip or domains)")),
            ("schedule", String(description="Crontab string")),
            ("enabled", Boolean(description="Enable/disable task")),
        ]
    )
    update_task = Endpoint(
        method="put",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}",
        description="Update task.",
        params=[
            ("name", String(description="Task name")),
            ("networks", List(description="List of networks (ip or domains)")),
            ("schedule", String(description="Crontab string")),
            ("enabled", Boolean(description="Enable/disable task")),
        ]
    )
    start_task = Endpoint(
        method="post",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}/start",
        description="Start task asap.",
    )
    delete_task = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/tasks/{uuid:task_id|Task id}",
        description="Delete task.",
    )
    get_results = Endpoint(
        method="get",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/results",
        description="Get results.",
        params=[
            ("search", String(required=False,
                              description="Search text occurrence in fields: name, ip or resolved.")),
            ("ip_address", String(required=False,
                                  description="Comma-separated list of ip-addresses, networks. "
                                              "Example: '91.218.85.0/24,91.218.86.99'")),
            ("include_ports", String(required=False,
                                     description="Comma-separated list of ports. Example: '80,8080'.")),
            ("exclude_ports", String(required=False,
                                     description="Comma-separated list of ports. Example: '80,8080'.")),
            ("min_cvss", Float(required=False, description="Minimum CVSS value.")),
            ("highlight", Boolean(default=False)),
            ("offset", Integer(default=0)),
            ("limit", Integer(default=50))
        ],
        content_handler=make_result_set
    )
    delete_result = Endpoint(
        method="delete",
        url="/api/v3/proxy/vscanner/projects/{uuid:project_id|Project id}/results/{uuid:result_id|Result id}",
        description="Delete result by id."
    )

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
