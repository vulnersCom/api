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

The v4 names are imported lazily (PEP 562 ``__getattr__``): a bare ``import
vulners`` stays lightweight and safe in restricted/frozen environments (it does
not eagerly build the v4 pydantic models, which call ``sys._getframe`` at class
definition). ``from vulners import Vulners`` / ``CveBulletin`` triggers the import
on demand. Type checkers and IDEs see the full surface — including every generated
``…Bulletin`` class — through the ``TYPE_CHECKING`` block below.
"""

import warnings
from typing import TYPE_CHECKING, Any

# --- v3 API (legacy, backward-compatible): eager and import-safe ---
# __version__ comes from the static _version.py (single source, CI-checked
# against pyproject) — not from a runtime importlib.metadata scan, so frozen /
# vendored deployments report the shipped code's version and `import vulners`
# does no filesystem metadata lookup on this attribute's behalf.
from ._version import __version__ as __version__
from .base import VulnersApiError, VulnersDeprecationWarning
from .vscanner import NotificationObj, VScannerApi
from .vulners import VulnersApi
from .vulners.audit import AuditFields
from .vulners.search import DEFAULT_FIELDS
from .vulners.subscription_v4 import DEFAULT_BULLETIN_FIELDS, BulletinField

if TYPE_CHECKING:
    # Static view of the lazily-loaded v4 surface (runtime resolves via __getattr__).
    from ._client import AsyncVulners as AsyncVulners
    from ._client import Vulners as Vulners
    from ._deprecation import RemovedInVulners5Warning as RemovedInVulners5Warning
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
    from ._exceptions import ServerError as ServerError
    from ._exceptions import UnprocessableEntityError as UnprocessableEntityError
    from ._exceptions import ValidationError as ValidationError
    from ._exceptions import VulnersError as VulnersError

    # The full generated response-model surface (base -> family -> type) plus the
    # nested value objects — static view; the runtime resolves them lazily in
    # __getattr__ so `import vulners` never eagerly builds the pydantic models.
    from ._models._nested import *  # noqa: F403
    from ._models.bulletins import *  # noqa: F403
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
    "ServerError": "._exceptions",
    "ValidationError": "._exceptions",
    "not_given": "._types",
    "NotGiven": "._types",
    "RemovedInVulners5Warning": "._deprecation",
    # v4 response models + nested value objects resolve via the __getattr__ fallback.
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
    "ServerError",
    "SearchWindowExceeded",
    "ValidationError",
    # v4 sentinels
    "not_given",
    "NotGiven",
    # v4 return / input types (for annotations)
    "SearchPage",
    "AsyncSearchPage",
    "APIResponse",
    "StreamedAPIResponse",
    "AsyncStreamedAPIResponse",
    "AuditItem",
    "WinAuditItem",
    # deprecation tiers
    "RemovedInVulners5Warning",
    # v3 legacy
    "AuditFields",
    "BulletinField",
    "DEFAULT_BULLETIN_FIELDS",
    "DEFAULT_FIELDS",
    "NotificationObj",
    "VScannerApi",
    "VulnersApi",
    "VulnersApiError",
    "VulnersDeprecationWarning",
]


# The nested value objects (framework, hand-written in `_models/_nested.py`) are the
# only non-…Bulletin names the model layer exports; naming them lets a top-level miss
# on an unrelated name stay cheap instead of importing (and eagerly building) the model
# package. Kept in sync with `_nested.__all__` (both hand-edited, rarely).
_NESTED_NAMES = frozenset(
    {"Cvss", "Cvss2", "Cvss3", "Cvss4", "Enchantments", "EpssScore", "Timestamps"}
)


def __getattr__(name: str) -> Any:
    import importlib

    module = _LAZY_ATTRS.get(name)
    if module is not None:
        value = getattr(importlib.import_module(module, __name__), name)
        globals()[name] = value  # cache so later access skips __getattr__
        return value
    # Generated response models (…Bulletin) and nested value objects (Cvss, …) resolve
    # lazily, so a bare `import vulners` never eagerly builds the pydantic models (which
    # call sys._getframe at class definition). ONLY these names touch the model layer —
    # an unrelated miss (a typo, a `getattr(vulners, x, default)` probe) stays cheap.
    if name.endswith("Bulletin"):
        mod = "._models.bulletins"
    elif name in _NESTED_NAMES:
        mod = "._models._nested"
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    # import OUTSIDE the getattr guard, so an error while building the model layer
    # surfaces instead of being masked as a bogus "no attribute".
    member = importlib.import_module(mod, __name__)
    try:
        value = getattr(member, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    globals()[name] = value  # cache so later access skips __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_ATTRS))


# Scope the always-filter to our own subclass so we don't override the host
# app's global DeprecationWarning / -W policy.
warnings.filterwarnings("always", category=VulnersDeprecationWarning)
