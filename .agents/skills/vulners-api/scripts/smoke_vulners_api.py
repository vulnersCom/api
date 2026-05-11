#!/usr/bin/env python3
"""Safe smoke-check helper for the Vulners Python SDK.

This script intentionally avoids embedding API keys. It imports the installed
`vulners` package, exercises the offline client construction path, and reports
whether VULNERS_API_KEY is present. It can also run an opt-in malformed-key API
error check, but remains read-only by default.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType


def import_package(package_name: str) -> ModuleType:
    """Import a package and raise a clear error if it is unavailable."""
    try:
        return importlib.import_module(package_name)
    except ImportError as exc:
        raise SystemExit(
            f"Could not import {package_name!r}. Install the project first, "
            "for example with `poetry install` or `pip install -e .`."
        ) from exc


def main() -> int:
    module = import_package("vulners")
    version = getattr(module, "__version__", "unknown")
    has_api_key = bool(os.getenv("VULNERS_API_KEY"))

    print(f"Imported vulners package: {module!r}")
    print(f"Detected version: {version}")

    api_cls = getattr(module, "VulnersApi")
    error_cls = getattr(module, "VulnersApiError")
    api = api_cls(api_key="offline-smoke-check")
    if api.__class__.__name__ != "VulnersApi":
        raise SystemExit("Unexpected VulnersApi construction result")
    if not issubclass(error_cls, Exception):
        raise SystemExit("Unexpected VulnersApiError export")
    try:
        api_cls(api_key="")
    except ValueError:
        pass
    else:
        raise SystemExit("VulnersApi accepted an empty API key")

    print("Constructed VulnersApi without making a network request")
    print(f"VULNERS_API_KEY present: {has_api_key}")

    if os.getenv("VULNERS_SMOKE_CHECK_MALFORMED_KEY"):
        try:
            api_cls(api_key="malformed-smoke-check").search.get_bulletin("CVE-2017-0144")
        except error_cls:
            print("Malformed-key live check raised VulnersApiError as expected")
        else:
            raise SystemExit("Malformed-key live check did not raise VulnersApiError")

    if not has_api_key:
        print(
            "No API key found. This is OK for an import smoke check. "
            "Set VULNERS_API_KEY only for opt-in live API examples."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
