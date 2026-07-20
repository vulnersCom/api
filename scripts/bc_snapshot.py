"""Snapshot the public surface of the installed ``vulners`` package to JSON.

Foundation of the v3 backward-compatibility oracle (``tests/bc``): the v4
deprecated shims must preserve this surface. The baseline tracks the v3 (3.2.x)
compatibility lineage — originally recorded from real ``vulners==3.2.0`` and
maintained forward as that line evolves. Run it against the working tree to diff.
Deterministic: everything is sorted, and the version string is recorded
separately.

Expected deltas between the baseline and the v4 tree are backward-compatible
supersets only: the version string, plus intentional additive extensions that
also ship in the 3.2.x line. One such extension is already baked into
``surface.json``: the optional ``api_key`` (owner-key) argument on
``WebhookApi.add/enable/delete/read`` and ``SubscriptionApi.add/edit/delete``.
When regenerating, regenerate against the current 3.2.x source (the ``v3.2``
branch), NOT the frozen ``vulners==3.2.0`` point release, or these intentional
additions will be lost.

Usage:
    python -m scripts.bc_snapshot            # print snapshot JSON to stdout
    python -m scripts.bc_snapshot --out X    # write to file X
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import pkgutil
import sys
from functools import cached_property
from typing import Any

PACKAGE = "vulners"


def _is_public(name: str) -> bool:
    return not name.startswith("_")


def _signature(obj: Any) -> str | None:
    try:
        return str(inspect.signature(obj))
    except (ValueError, TypeError):
        return None


def _describe_member(member: Any) -> dict[str, Any]:
    if isinstance(member, property):
        return {"kind": "property"}
    if isinstance(member, cached_property):
        return {"kind": "cached_property"}
    if inspect.isclass(member):
        return {"kind": "class", "qualname": f"{member.__module__}.{member.__qualname__}"}
    if callable(member):
        return {
            "kind": "method",
            "signature": _signature(member),
            "deprecated": hasattr(member, "__deprecated__"),
        }
    return {"kind": "attribute", "type": type(member).__name__}


def _defining_module(cls: type, name: str) -> str:
    for base in cls.__mro__:
        if name in base.__dict__:
            return getattr(base, "__module__", "") or ""
    return ""


def _describe_class(cls: type) -> dict[str, Any]:
    members: dict[str, Any] = {}
    # Only members DEFINED within the vulners package are part of our surface.
    # Members inherited from a builtin base (BaseException.add_note, dict.keys on a
    # TypedDict, object/type methods) are skipped: they appear/disappear and their
    # signature reprs shift across Python versions, which is not a BC change of
    # ours. Members from vulners base classes are kept (real inherited surface).
    for name in sorted(dir(cls)):
        if not _is_public(name):
            continue
        if not _defining_module(cls, name).startswith(PACKAGE):
            continue
        try:
            member = getattr(cls, name)
        except Exception:  # pragma: no cover - defensive
            continue
        members[name] = _describe_member(member)
    return {
        "bases": [f"{b.__module__}.{b.__qualname__}" for b in cls.__bases__],
        "members": members,
    }


def snapshot() -> dict[str, Any]:
    root = importlib.import_module(PACKAGE)
    modules: dict[str, Any] = {}
    classes: dict[str, Any] = {}

    module_names = [PACKAGE]
    for info in pkgutil.walk_packages(root.__path__, prefix=f"{PACKAGE}."):
        # Only public modules are part of the compatibility surface; skip private
        # ones (any dotted component past the root starting with "_", e.g.
        # vulners._version or the v4 core vulners._base_client).
        parts = info.name.split(".")[1:]
        if any(part.startswith("_") for part in parts):
            continue
        module_names.append(info.name)

    # Public entrypoints gated behind an optional extra: they raise ImportError
    # unless the extra is installed. They are not part of the frozen v3 surface,
    # so skip them when the extra is absent rather than crashing the snapshot; a
    # non-optional module that fails to import is still a real error and re-raises.
    optional_modules = {"vulners.mcp"}
    for mod_name in sorted(module_names):
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            if mod_name in optional_modules:
                continue
            raise
        public = sorted(n for n in dir(mod) if _is_public(n))
        modules[mod_name] = {
            "all": sorted(mod.__all__) if hasattr(mod, "__all__") else None,
            "public_names": public,
        }
        for name in public:
            obj = getattr(mod, name)
            if inspect.isclass(obj) and getattr(obj, "__module__", "").startswith(PACKAGE):
                qualname = f"{obj.__module__}.{obj.__qualname__}"
                if qualname not in classes:
                    classes[qualname] = _describe_class(obj)

    return {
        "version": getattr(root, "__version__", None),
        "python": f"{sys.version_info[0]}.{sys.version_info[1]}",
        "package_all": sorted(root.__all__) if hasattr(root, "__all__") else None,
        "modules": modules,
        "classes": dict(sorted(classes.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="write JSON here instead of stdout")
    args = parser.parse_args()
    data = json.dumps(snapshot(), indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(data + "\n")
    else:
        print(data)


if __name__ == "__main__":
    main()
