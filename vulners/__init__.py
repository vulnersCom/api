import warnings

from .base import VulnersApiError, VulnersDeprecationWarning
from .base import __version__ as __version__
from .vscanner import VScannerApi
from .vulners import VulnersApi

# Explicit public surface; needed for mypy --strict no-implicit-reexport under
# py.typed. VulnersDeprecationWarning is public (callers scope filters to it).
__all__ = [
    "VScannerApi",
    "VulnersApi",
    "VulnersApiError",
    "VulnersDeprecationWarning",
]

# Scope the always-filter to our own subclass so we don't override the host
# app's global DeprecationWarning / -W policy.
warnings.filterwarnings("always", category=VulnersDeprecationWarning)
