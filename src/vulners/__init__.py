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
    from ._types import NotGiven as NotGiven
    from ._types import Omit as Omit
    from ._types import not_given as not_given
    from ._types import omit as omit

# name -> submodule it lives in (relative to this package).
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
    "omit": "._types",
    "not_given": "._types",
    "Omit": "._types",
    "NotGiven": "._types",
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
    "omit",
    "not_given",
    "Omit",
    "NotGiven",
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
