"""Deprecation infrastructure for the 4.x line.

Two warning tiers:

* :class:`~vulners.base.VulnersDeprecationWarning` — the general SDK deprecation
  category (a :class:`DeprecationWarning` subclass, defined by the legacy layer
  and shared with it);
* :class:`RemovedInVulners5Warning` — the escalation tier: the construct works
  through every 4.x release but is scheduled for removal in 5.0.

:data:`SERVER_RETIRED_ENDPOINTS` is a runtime registry of legacy API paths the
server has retired. It ships empty; when Vulners retires an endpoint during the
4.x lifetime, a patch release adds an entry here and callers get an actionable
error message (what was retired, what to use instead, where the guide is) instead
of a bare 404 — no breaking SDK change required.
"""

from __future__ import annotations

from .base import MIGRATION_GUIDE_URL as MIGRATION_GUIDE_URL
from .base import VulnersDeprecationWarning


class RemovedInVulners5Warning(VulnersDeprecationWarning):
    """Deprecated now; will be removed in vulners 5.0.

    Emitted once per legacy client instantiation (``VulnersApi``/``VScannerApi``)
    — the compatibility surface keeps working through all of 4.x.
    """


#: Legacy API path -> actionable explanation, populated via patch releases when
#: the server retires an endpoint (candidates: burp rules, getsploit distributive
#: downloads, e-mail subscriptions). Keys are matched against the request path.
SERVER_RETIRED_ENDPOINTS: dict[str, str] = {}


def retired_endpoint_message(path: str) -> str | None:
    """Actionable message when *path* is a known server-retired endpoint."""
    for prefix, message in SERVER_RETIRED_ENDPOINTS.items():
        if path.startswith(prefix):
            return f"{message} See the migration guide: {MIGRATION_GUIDE_URL}"
    return None


__all__ = [
    "MIGRATION_GUIDE_URL",
    "SERVER_RETIRED_ENDPOINTS",
    "RemovedInVulners5Warning",
    "retired_endpoint_message",
]
