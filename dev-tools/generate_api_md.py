#!/usr/bin/env python3
"""Generate ``api.md`` — a machine-readable index of the public client API.

Introspects the ``Vulners`` client's resource namespaces at runtime (public
methods, signatures, docstring summaries) and maps each method to its HTTP
route by parsing the ``RequestSpec`` declarations in the async resource
sources (``src/vulners/_resources/_async/``) with ``ast``. Routes built from
runtime values (e.g. dynamic redirect targets) that cannot be resolved
statically are shown as ``-``; path segments filled from arguments are shown
as ``{placeholder}`` segments.

Run from a checkout (no API key needed, nothing goes over the network):

    python dev-tools/generate_api_md.py

The output is written to ``api.md`` at the repository root.
"""

from __future__ import annotations

import ast
import inspect
import sys
from functools import cached_property
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from vulners import Vulners  # noqa: E402

ASYNC_DIR = REPO / "src" / "vulners" / "_resources" / "_async"
OUTPUT = REPO / "api.md"

HEADER = """\
# Vulners Python SDK — API index

<!-- Generated file: do not edit by hand.
     Regenerate with `python dev-tools/generate_api_md.py`. -->

Machine-readable index of the public API of the [`Vulners`](src/vulners/_client.py)
client. Every method exists identically on `AsyncVulners` (awaited; lazy iterators
are named `aiter_*` and iterated with `async for`). Rows: method signature,
return annotation, and the HTTP route the method calls (`-` when the route is
resolved at runtime; `{name}` marks a path segment filled from an argument).

The client itself also exposes untyped escape hatches for any API path —
`get`, `post`, `put`, `delete` — plus `with_options(timeout=..., max_retries=...,
max_response_bytes=...)` for per-call-site overrides on a shared connection pool.
"""


# --------------------------------------------------------------------------- #
# Route extraction (static analysis of the async resource sources)
# --------------------------------------------------------------------------- #


class ModuleRoutes:
    """Best-effort ``(class, method) -> "METHOD /path"`` map for one module."""

    def __init__(self, source_path: Path) -> None:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        self._consts: dict[str, str] = {}
        self._specs: dict[str, str] = {}
        for node in tree.body:
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                continue
            name = node.targets[0].id
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self._consts[name] = node.value.value
            else:
                route = self._spec_route(node.value, {})
                if route is not None:
                    self._specs[name] = route
        self._methods: dict[tuple[str, str], str | None] = {}
        deferred: list[tuple[str, ast.AST]] = []
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            for fn in cls.body:
                if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                    route = self._route_of(fn)
                    self._methods[(cls.name, fn.name)] = route
                    if route is None:
                        deferred.append((cls.name, fn))
        # Second pass: a method with no direct spec may delegate to a sibling
        # (e.g. ``aiter_query`` calls ``self.query``); inherit that route.
        for cls_name, fn in deferred:
            for call in ast.walk(fn):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "self"
                ):
                    route = self._methods.get((cls_name, call.func.attr))
                    if route is not None:
                        self._methods[(cls_name, fn.name)] = route
                        break

    def lookup(self, class_name: str, method: str) -> str | None:
        """Route for a sync-mirror method (tries the ``a``-prefixed async name too)."""
        route = self._methods.get((class_name, method))
        if route is None:
            route = self._methods.get((class_name, "a" + method))
        return route

    def _spec_route(self, node: ast.AST, local_strs: dict[str, str]) -> str | None:
        """``RequestSpec("GET", <path>, ...)`` / ``_spec(...)`` -> ``"GET /path"``."""
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"RequestSpec", "_spec"}
            and len(node.args) >= 2
        ):
            return None
        method_node = node.args[0]
        if not (isinstance(method_node, ast.Constant) and isinstance(method_node.value, str)):
            return None
        path = self._render(node.args[1], local_strs)
        return f"{method_node.value} {path}" if path is not None else None

    def _render(self, node: ast.AST, local_strs: dict[str, str]) -> str | None:
        """Render a path expression to a string, with ``{name}`` placeholders."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self._consts.get(node.id) or local_strs.get(node.id)
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for piece in node.values:
                if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                    parts.append(piece.value)
                elif isinstance(piece, ast.FormattedValue):
                    placeholder = self._placeholder(piece.value, local_strs)
                    if placeholder is None:
                        return None
                    parts.append(placeholder)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            sides = []
            for side in (node.left, node.right):
                rendered = self._render(side, local_strs)
                if rendered is None:
                    rendered = self._placeholder(side, local_strs)
                if rendered is None:
                    return None
                sides.append(rendered)
            return "".join(sides)
        return None

    def _placeholder(self, node: ast.AST, local_strs: dict[str, str]) -> str | None:
        """An interpolated value: a known constant, else a ``{name}`` placeholder."""
        rendered = self._render(node, local_strs)
        if rendered is not None:
            return rendered
        if isinstance(node, ast.Name):
            return "{" + node.id + "}"
        # `_seg(x)` percent-quotes one path segment; render it as `{x}`.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_seg"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
        ):
            return "{" + node.args[0].id + "}"
        return None

    def _route_of(self, fn: ast.AST) -> str | None:
        """The single route a method requests, or ``None`` when ambiguous/dynamic."""
        local_strs: dict[str, str] = {}
        local_specs: dict[str, str] = {}
        for node in ast.walk(fn):
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                continue
            name = node.targets[0].id
            rendered = self._render(node.value, local_strs)
            if rendered is not None:
                local_strs[name] = rendered
            else:
                route = self._spec_route(node.value, local_strs)
                if route is not None:
                    local_specs[name] = route
        # A request call is any call whose first argument is a known RequestSpec
        # name; this covers ``self._request(SPEC, ...)`` as well as pipeline
        # entry points like ``self._client.stream_records(SPEC, ...)``.
        routes: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Name):
                spec_name = node.args[0].id
                route = local_specs.get(spec_name) or self._specs.get(spec_name)
                if route is not None:
                    routes.add(route)
        return routes.pop() if len(routes) == 1 else None


# --------------------------------------------------------------------------- #
# Runtime introspection of the client's resources
# --------------------------------------------------------------------------- #


def _format_signature(name: str, bound: Any) -> str:
    """``name(param: ann = default, ...)`` keeping source-text annotations."""
    sig = inspect.signature(bound)
    parts: list[str] = []
    saw_star = False
    for param in sig.parameters.values():
        if param.kind is param.KEYWORD_ONLY and not saw_star:
            parts.append("*")
            saw_star = True
        text = param.name
        if param.kind is param.VAR_POSITIONAL:
            text = "*" + text
            saw_star = True
        elif param.kind is param.VAR_KEYWORD:
            text = "**" + text
        annotation = param.annotation
        if annotation is not param.empty:
            if not isinstance(annotation, str):
                annotation = inspect.formatannotation(annotation)
            text += f": {annotation}"
            if param.default is not param.empty:
                text += f" = {param.default!r}"
        elif param.default is not param.empty:
            text += f"={param.default!r}"
        parts.append(text)
    return f"{name}({', '.join(parts)})"


def _cell(text: str) -> str:
    """Wrap a table cell in backticks, escaping pipes for the table parser."""
    return "`" + text.replace("|", "\\|") + "`" if text else "-"


def _summary(obj: Any) -> str:
    doc = inspect.getdoc(obj) or ""
    return doc.strip().splitlines()[0].rstrip(".") if doc.strip() else ""


def _emit_resource(name_path: str, resource: Any, routes_cache: dict[Path, ModuleRoutes]) -> str:
    cls = type(resource)
    source = ASYNC_DIR / (cls.__module__.rsplit(".", 1)[1] + ".py")
    if source not in routes_cache:
        routes_cache[source] = ModuleRoutes(source)
    routes = routes_cache[source]
    async_cls = "Async" + cls.__name__

    lines = [f"## `client.{name_path}`", ""]
    summary = _summary(cls)
    if summary:
        lines += [summary + ".", ""]
    lines += ["| Method | Returns | HTTP route | Summary |", "|---|---|---|---|"]

    nested: list[tuple[str, Any]] = []
    for attr, member in vars(cls).items():
        if attr.startswith("_"):
            continue
        if isinstance(member, cached_property):
            nested.append((attr, getattr(resource, attr)))
            continue
        func = member.__func__ if isinstance(member, staticmethod) else member
        if not inspect.isfunction(func):
            continue
        bound = getattr(resource, attr)
        returns = func.__annotations__.get("return", "")
        if not isinstance(returns, str):
            returns = inspect.formatannotation(returns)
        route = routes.lookup(async_cls, attr) or ""
        summary_cell = _summary(func).replace("|", "\\|")
        row = (
            f"| {_cell(_format_signature(attr, bound))} "
            f"| {_cell(returns)} | {_cell(route)} | {summary_cell} |"
        )
        lines.append(row)
    lines.append("")

    for attr, sub in nested:
        lines.append(_emit_resource(f"{name_path}.{attr}", sub, routes_cache))
    return "\n".join(lines)


def main() -> None:
    # Offline introspection only: the placeholder key never leaves the process.
    client = Vulners(api_key="offline-introspection-placeholder")
    routes_cache: dict[Path, ModuleRoutes] = {}
    sections = [HEADER]
    try:
        for attr, member in vars(Vulners).items():
            if isinstance(member, cached_property):
                sections.append(_emit_resource(attr, getattr(client, attr), routes_cache))
    finally:
        client.close()
    OUTPUT.write_text("\n".join(sections), encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
