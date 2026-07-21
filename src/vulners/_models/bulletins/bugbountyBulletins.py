"""GENERATED — the `bugbounty` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class BugbountyBulletin(Bulletin):
    """`bulletinFamily: bugbounty` — adds the fields shared across this family."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class HackeroneBulletin(BugbountyBulletin):
    """`type: hackerone` — HackerOne collection includes vulnerability reports and advisories from various vendors, focusing on security issues discovered through bug bounty programs."""

    bounty: float | None = None
    """Bounty amount/details paid for the report."""
    bounty_state: str | None = Field(default=None, alias="bountyState")
    """State of the bounty (awarded, pending, …)."""
    h1reporter: Any = None
    """HackerOne reporter profile."""
    h1team: Any = None
    """HackerOne team/program the report belongs to."""


class HuntrBulletin(BugbountyBulletin):
    """`type: huntr` — Huntr is a vulnerability database that aggregates security advisories, CVEs, and exploits primarily focused on open-source software projects."""

    cwe_id: str | None = None
    """Single associated CWE identifier."""
    language: str | None = None
    """Language of the report."""
    patch_commit_sha: str | None = None
    """Commit SHA of the fixing patch."""
    repository: str | None = None
    """Source code repository associated with the report."""
    status: str | None = None
    """Workflow status of the record."""


class OpenbugbountyBulletin(BugbountyBulletin):
    """`type: openbugbounty` — OpenBugBounty is a community-driven platform that catalogs security advisories and vulnerabilities reported by researchers across various vendors and products."""

    openbugbounty: Any = None
    """Open Bug Bounty metadata (mirror, patch status)."""


class XssedBulletin(BugbountyBulletin):
    """`type: xssed` — XSSed is a vulnerability database focused on cross-site scripting (XSS) vulnerabilities, providing advisories and exploit details for various web applications."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""
