"""Deprecation warning categories for the v4 core.

A dedicated :class:`DeprecationWarning` subclass so the package can scope its own
``warnings.filterwarnings`` rules without touching the process-global
``DeprecationWarning`` policy, while ``except DeprecationWarning`` and ``-W``
rules keep matching by ``issubclass``.

This is intentionally independent of the legacy ``vulners.base`` warning class:
the v4 core does not import from the legacy layer.
"""

from __future__ import annotations

import warnings

MIGRATION_GUIDE_URL = "https://github.com/vulnersCom/api/blob/master/MIGRATION.md"


class VulnersDeprecationWarning(DeprecationWarning):
    """Base category for the SDK's own deprecation notices."""


class RemovedInVulners5Warning(VulnersDeprecationWarning):
    """Emitted for API that keeps working through 4.x but is removed in 5.0."""


def warn_deprecated(
    message: str,
    *,
    category: type[VulnersDeprecationWarning] = RemovedInVulners5Warning,
    stacklevel: int = 2,
) -> None:
    """Emit *message* as a deprecation notice attributed to the caller's caller.

    ``stacklevel`` defaults to 2 so the warning points at the code that invoked
    the deprecated wrapper rather than at this module.
    """
    warnings.warn(f"{message} See {MIGRATION_GUIDE_URL}", category, stacklevel=stacklevel + 1)


__all__ = [
    "MIGRATION_GUIDE_URL",
    "RemovedInVulners5Warning",
    "VulnersDeprecationWarning",
    "warn_deprecated",
]
