"""A lean ``Bulletin`` response model for the search slice.

Every field is optional and unknown server fields are retained (``extra="allow"``
inherited from :class:`VulnersModel`). This is the 4.0.0 core slice, not the full
``bulletinFamily`` hierarchy (that lands over 4.x minors).
"""

from __future__ import annotations

from pydantic import Field

from ._base import VulnersModel


class Cvss(VulnersModel):
    """CVSS score block, as embedded in a bulletin's ``cvss`` field."""

    score: float | None = None
    vector: str | None = None


class Bulletin(VulnersModel):
    """A single Vulners document (CVE, exploit, advisory, ...)."""

    id: str | None = None
    title: str | None = None
    description: str | None = None
    type: str | None = None
    bulletin_family: str | None = Field(default=None, alias="bulletinFamily")
    cvss: Cvss | None = None
    published: str | None = None
    modified: str | None = None
    last_seen: str | None = Field(default=None, alias="lastseen")
    href: str | None = None
    source_href: str | None = Field(default=None, alias="sourceHref")
    source_data: str | None = Field(default=None, alias="sourceData")
    cvelist: list[str] | None = None


__all__ = ["Bulletin", "Cvss"]
