# -*- coding: utf-8 -*-

__version__ = "2.0.0"

import warnings
from . vulners import VulnersApi, Vulners
from . vscanner import VScannerApi


warnings.simplefilter("always", DeprecationWarning)

