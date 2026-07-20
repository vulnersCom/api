"""Vulners SDK — Python client for the Vulners vulnerability intelligence API.

Two APIs live in this package:

* **v4 (recommended)** — modern, fully typed sync and async clients with resource
  namespaces, response models, pagination and streaming::

      from vulners import Vulners, AsyncVulners

      with Vulners(api_key="...") as v:
          page = v.search.query("type:exploit", limit=20)

* **v3 (legacy, kept for 100% backward compatibility)** — the original
  ``VulnersApi`` / ``VScannerApi`` classes. Existing code keeps working
  unchanged; new code should prefer the v4 clients above.

The v4 names are imported lazily (PEP 562 ``__getattr__``): a bare
``import vulners`` stays lightweight and safe in restricted/frozen environments
(it does not eagerly build the v4 pydantic models, which introspect the call
stack at definition time). ``from vulners import Vulners`` triggers the import on
demand. Type checkers see the names through the ``TYPE_CHECKING`` block below.
"""

import warnings
from typing import TYPE_CHECKING, Any

# --- v3 API (legacy, backward-compatible): eager and import-safe ---
from .base import VulnersApiError, VulnersDeprecationWarning
from .base import __version__ as __version__
from .vscanner import VScannerApi
from .vulners import VulnersApi

if TYPE_CHECKING:
    # Static view of the lazily-loaded v4 surface (runtime resolves via __getattr__).
    from ._client import AsyncVulners as AsyncVulners
    from ._client import Vulners as Vulners
    from ._exceptions import APIConnectionError as APIConnectionError
    from ._exceptions import APIError as APIError
    from ._exceptions import APIResponseValidationError as APIResponseValidationError
    from ._exceptions import APIStatusError as APIStatusError
    from ._exceptions import APITimeoutError as APITimeoutError
    from ._exceptions import AuthenticationError as AuthenticationError
    from ._exceptions import BadRequestError as BadRequestError
    from ._exceptions import ConflictError as ConflictError
    from ._exceptions import InternalServerError as InternalServerError
    from ._exceptions import NotFoundError as NotFoundError
    from ._exceptions import PermissionDeniedError as PermissionDeniedError
    from ._exceptions import RateLimitError as RateLimitError
    from ._exceptions import SearchWindowExceeded as SearchWindowExceeded
    from ._exceptions import UnprocessableEntityError as UnprocessableEntityError
    from ._exceptions import VulnersError as VulnersError
    from ._models.bulletin import AdvisoryBulletin as AdvisoryBulletin
    from ._models.bulletin import BugBountyBulletin as BugBountyBulletin
    from ._models.bulletin import Bulletin as Bulletin
    from ._models.bulletin import CveBulletin as CveBulletin
    from ._models.bulletin import Cvss as Cvss
    from ._models.bulletin import Cvss2 as Cvss2
    from ._models.bulletin import Cvss3 as Cvss3
    from ._models.bulletin import Cvss4 as Cvss4
    from ._models.bulletin import Enchantments as Enchantments
    from ._models.bulletin import EpssScore as EpssScore
    from ._models.bulletin import ExploitBulletin as ExploitBulletin
    from ._models.bulletin import GenericBulletin as GenericBulletin
    from ._models.bulletin import InfoBulletin as InfoBulletin
    from ._models.bulletin import LibraryBulletin as LibraryBulletin
    from ._models.bulletin import MicrosoftBulletin as MicrosoftBulletin
    from ._models.bulletin import ScannerBulletin as ScannerBulletin
    from ._models.bulletin import SoftwareBulletin as SoftwareBulletin
    from ._models.bulletin import Timestamps as Timestamps
    from ._models.bulletin import UnixBulletin as UnixBulletin
    from ._pagination import AsyncSearchPage as AsyncSearchPage
    from ._pagination import SearchPage as SearchPage
    from ._response import APIResponse as APIResponse
    from ._response import AsyncStreamedAPIResponse as AsyncStreamedAPIResponse
    from ._response import StreamedAPIResponse as StreamedAPIResponse
    from ._types import NotGiven as NotGiven
    from ._types import not_given as not_given
    from ._types.audit import AuditItem as AuditItem
    from ._types.audit import WinAuditItem as WinAuditItem

# name -> submodule it lives in (relative to this package). Resolved lazily by
# __getattr__ so a bare `import vulners` never eagerly builds the v4 pydantic
# models (which introspect the call stack at class-definition time).
_LAZY_ATTRS = {
    "Vulners": "._client",
    "AsyncVulners": "._client",
    "VulnersError": "._exceptions",
    "APIError": "._exceptions",
    "APIStatusError": "._exceptions",
    "APIConnectionError": "._exceptions",
    "APITimeoutError": "._exceptions",
    "APIResponseValidationError": "._exceptions",
    "AuthenticationError": "._exceptions",
    "BadRequestError": "._exceptions",
    "PermissionDeniedError": "._exceptions",
    "NotFoundError": "._exceptions",
    "ConflictError": "._exceptions",
    "UnprocessableEntityError": "._exceptions",
    "RateLimitError": "._exceptions",
    "InternalServerError": "._exceptions",
    "SearchWindowExceeded": "._exceptions",
    "not_given": "._types",
    "NotGiven": "._types",
    # v4 return/input types users annotate with (lazy: the pydantic core loads
    # only on first access, keeping `import vulners` lightweight).
    "Bulletin": "._models.bulletin",
    "CveBulletin": "._models.bulletin",
    "ExploitBulletin": "._models.bulletin",
    "ScannerBulletin": "._models.bulletin",
    "SoftwareBulletin": "._models.bulletin",
    "UnixBulletin": "._models.bulletin",
    "InfoBulletin": "._models.bulletin",
    "LibraryBulletin": "._models.bulletin",
    "MicrosoftBulletin": "._models.bulletin",
    "BugBountyBulletin": "._models.bulletin",
    "AdvisoryBulletin": "._models.bulletin",
    "GenericBulletin": "._models.bulletin",
    "Cvss": "._models.bulletin",
    "Cvss2": "._models.bulletin",
    "Cvss3": "._models.bulletin",
    "Cvss4": "._models.bulletin",
    "Timestamps": "._models.bulletin",
    "Enchantments": "._models.bulletin",
    "EpssScore": "._models.bulletin",
    "SearchPage": "._pagination",
    "AsyncSearchPage": "._pagination",
    "APIResponse": "._response",
    "StreamedAPIResponse": "._response",
    "AsyncStreamedAPIResponse": "._response",
    "AuditItem": "._types.audit",
    "WinAuditItem": "._types.audit",
}

# Public surface: v4 names first (recommended), v3 legacy names last. Grouped
# deliberately rather than alphabetically.
__all__ = [  # noqa: RUF022
    # v4 clients
    "Vulners",
    "AsyncVulners",
    # v4 exception hierarchy
    "VulnersError",
    "APIError",
    "APIStatusError",
    "APIConnectionError",
    "APITimeoutError",
    "APIResponseValidationError",
    "AuthenticationError",
    "BadRequestError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "UnprocessableEntityError",
    "RateLimitError",
    "InternalServerError",
    "SearchWindowExceeded",
    # v4 sentinels
    "not_given",
    "NotGiven",
    # v4 return / input types (for annotations)
    "Bulletin",
    "CveBulletin",
    "ExploitBulletin",
    "ScannerBulletin",
    "SoftwareBulletin",
    "UnixBulletin",
    "InfoBulletin",
    "LibraryBulletin",
    "MicrosoftBulletin",
    "BugBountyBulletin",
    "AdvisoryBulletin",
    "GenericBulletin",
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "Timestamps",
    "Enchantments",
    "EpssScore",
    "SearchPage",
    "AsyncSearchPage",
    "APIResponse",
    "StreamedAPIResponse",
    "AsyncStreamedAPIResponse",
    "AuditItem",
    "WinAuditItem",
    # v3 legacy
    "VScannerApi",
    "VulnersApi",
    "VulnersApiError",
    "VulnersDeprecationWarning",
]


def __getattr__(name: str) -> Any:
    module = _LAZY_ATTRS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value  # cache so later access skips __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_ATTRS))


# Scope the always-filter to our own subclass so we don't override the host
# app's global DeprecationWarning / -W policy.
warnings.filterwarnings("always", category=VulnersDeprecationWarning)
