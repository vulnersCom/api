from typing import Annotated, Literal, Sequence

from pydantic import Field
from typing_extensions import Required, TypedDict

from ..base import Unset, VulnersApiProxy, endpoint


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
    "cvelistMetrics",
]


class AuditApi(VulnersApiProxy):
    software = endpoint(
        "AuditApi.software",
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
            "config": Annotated[Sequence[str], Field(default=Unset)],
            "catalog": Annotated[Literal["official", "extended"], Field(default="official")],
        },
        response_handler=lambda c: c["result"],
    )

    host = endpoint(
        "AuditApi.host",
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
            "config": Annotated[Sequence[str], Field(default=Unset)],
            "catalog": Annotated[Literal["official", "extended"], Field(default="official")],
        },
        response_handler=lambda c: c["result"],
    )

    os_audit = endpoint(
        "AuditApi.os_audit",
        method="POST",
        url="/api/v3/audit/audit/",
        description=(
            "Linux Audit API for analyzing package vulnerabilities.\n"
            "Accepts RPM and DEB based package lists.\n"
            "For collecting RPM use command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\\\n'\n"
            "For collecting DEB use command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\\\n'\n"
        ),
        deprecated=(
            "AuditApi.os_audit() is deprecated and will be removed in future releases. "
            "Use AuditApi.linux_audit() instead."
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

    linux_audit = endpoint(
        "AuditApi.linux_audit",
        method="POST",
        url="/api/v4/audit/linux",
        description=(
            "Linux Audit API for analyzing package vulnerabilities.\n"
            "Accepts RPM, DEB and APK based package lists.\n"
            "For collecting RPM use command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\\\n'\n"
            "For collecting DEB use command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\\\n'\n"
        ),
        params={
            "os_name": Annotated[
                str,
                Field(
                    alias="osName",
                    description="Full name of the OS or OS ID. Like ubuntu, debian, rhel, ol, alpine and etc",
                ),
            ],
            "os_version": Annotated[str, Field(alias="osVersion", description="OS version")],
            "packages": Annotated[
                list[str],
                Field(
                    min_length=1,
                    max_length=2500,
                    description="List of the installed packages",
                ),
            ],
            "os_arch": Annotated[
                str | None,
                Field(
                    default=None,
                    alias="osArch",
                    description="OS architecture, default arch for packages",
                ),
            ],
            "include_unofficial": Annotated[
                bool,
                Field(
                    default=False,
                    alias="includeUnofficial",
                    description="Include unofficial packages",
                ),
            ],
            "include_candidates": Annotated[
                bool,
                Field(
                    default=False,
                    alias="includeCandidates",
                    description="Include 'candidate' vulnerabilities",
                ),
            ],
            "include_any_version": Annotated[
                bool,
                Field(
                    default=False,
                    alias="includeAnyVersion",
                    description="Include 'any' version vulnerabilities",
                ),
            ],
            "cvelist_metrics": Annotated[
                bool,
                Field(
                    default=False,
                    alias="cvelistMetrics",
                    description="Add cvelist metrics to the response, only for non free, trial licenses",
                ),
            ],
        },
    )

    kb_audit = endpoint(
        "AuditApi.kb_audit",
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

    win_audit = endpoint(
        "AuditApi.win_audit",
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
