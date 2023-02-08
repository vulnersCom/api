# -*- coding: utf-8 -*-

__version__ = "2.0.8"

import warnings
from .vulners import VulnersApi, Vulners
from .vscanner import VScannerApi
from .base import VulnersApiError


warnings.simplefilter("always", DeprecationWarning)
