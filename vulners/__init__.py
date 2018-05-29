# -*- coding: utf-8 -*-

__version__ = "1.1.1"

from vulners.api import Vulners
import sys

if sys.version_info > (3, 5):
    from vulners.aioapi import AioVulners


