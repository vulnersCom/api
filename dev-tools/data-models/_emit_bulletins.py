"""Emit the ``vulners._models.bulletins`` package as real Python code.

The generator is the source of truth for the whole ``base -> family -> type``
model hierarchy. From the sampled field layers (:func:`derive_layers`) this writes:

* ``bulletins/base.py`` — ``Bulletin`` (the base fields) and ``GenericBulletin``;
* ``bulletins/<family>Bulletins.py`` — one file per ``bulletinFamily``, holding the
  family model ``<Fam>Bulletin(Bulletin)`` and every one of its collection ``type``
  descendants ``<Type>Bulletin(<Fam>Bulletin)`` (one concrete class per type);
* ``bulletins/__init__.py`` — re-exports plus the ``FAMILY_MODELS`` / ``TYPE_MODELS``
  registries the runtime resolves through.

Output is deterministic (sorted) and ``ruff format``-ed, so re-running the sampler
yields a byte-identical tree — an idempotency check the test suite can enforce.
The nested value objects (``Cvss`` & versions, ``Timestamps``, ``Enchantments``,
``EpssScore``) stay hand-written in :mod:`vulners._models._nested`; the rich-type
map below wires those types onto the fields that carry them.
"""

from __future__ import annotations

import keyword
import re
import shutil
import subprocess
import sys
from collections import defaultdict

from _emit_models import derive_layers
from _paths import REPO

BULLETINS_DIR = REPO / "src" / "vulners" / "_models" / "bulletins"

# wire field -> rich annotation (nested value objects from _nested). These keep
# their proper types wherever the field is modelled (all base fields today).
_RICH: dict[str, str] = {
    "cvss": "Cvss | None",
    "cvss2": "Cvss | None",
    "cvss3": "Cvss | None",
    "cvss4": "Cvss | None",
    "timestamps": "Timestamps | None",
    "enchantments": "Enchantments | None",
    "epss": "list[EpssScore] | None",
}
# rich field -> the _nested symbol(s) its annotation needs imported.
_RICH_IMPORTS: dict[str, str] = {
    "cvss": "Cvss",
    "cvss2": "Cvss",
    "cvss3": "Cvss",
    "cvss4": "Cvss",
    "timestamps": "Timestamps",
    "enchantments": "Enchantments",
    "epss": "EpssScore",
}


def _token(types: list[str]) -> str:
    """Compact type token from sampled JSON types (keeps a scalar list item type)."""
    non_null = [t for t in types if t != "null"]
    if len(non_null) == 1:
        t = non_null[0]
        if t in ("str", "int", "float", "bool"):
            return t
        if t.startswith("list["):
            inner = t[5:-1]
            return f"list[{inner}]" if inner in ("str", "int", "float", "bool") else "list"
    return "any"


def _annotation(wire: str, types: list[str]) -> tuple[str, bool, str | None]:
    """(annotation, uses_Any, nested_symbol) for a field."""
    if wire in _RICH:
        return _RICH[wire], False, _RICH_IMPORTS[wire]
    tok = _token(types)
    if tok == "any":
        return "Any", True, None
    return f"{tok} | None", False, None


def _pyname(wire: str, taken: set[str]) -> str:
    """snake_case identifier for a wire field, unique against *taken* (mirrors the
    old runtime factory so field names/aliases are unchanged)."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", wire).lower()
    snake = re.sub(r"__+", "_", snake.replace("-", "_")).lstrip("_")
    if not snake or snake[0].isdigit():
        snake = f"f_{snake}"
    if keyword.iskeyword(snake) or not snake.isidentifier():
        snake = f"{snake}_"
    while snake in taken:
        snake = f"{snake}_"
    return snake


def _pascal(s: str) -> str:
    return "".join(p[:1].upper() + p[1:] for p in re.split(r"[^0-9A-Za-z]+", s) if p)


def _fam_class(fam: str) -> str:
    return f"{_pascal(fam)}Bulletin"


def _type_class(ctype: str, reserved: set[str], taken: set[str]) -> str:
    name = f"{_pascal(ctype)}Bulletin"
    if name[:1].isdigit():  # e.g. `0daydb` -> keep a valid identifier
        name = f"C{name}"
    if name in reserved:  # e.g. the `cve` type vs the CveBulletin family model
        name = name.replace("Bulletin", "CollectionBulletin")
    n, i = name, 2
    while n in taken:  # last-resort disambiguation (two types -> same PascalCase)
        n = f"{name}{i}"
        i += 1
    return n


def _docstring(text: str) -> str:
    """Single-line body for a triple-quoted attribute/​class docstring literal."""
    t = " ".join(text.split()).replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    if t.endswith('"'):
        t = t[:-1] + '\\"'
    return t


def _field_lines(
    wires: list[str],
    schema_fields: dict[str, dict],
    taken: set[str],
    descriptions: dict[str, str],
) -> tuple[list[str], bool, bool, set[str]]:
    """Body lines for a class's OWN fields; flags for the imports the file needs."""
    lines: list[str] = []
    uses_any = uses_field = False
    nested: set[str] = set()
    for wire in sorted(wires):
        types = schema_fields.get(wire, {}).get("types", [])
        name = _pyname(wire, taken)
        taken.add(name)
        ann, na, ns = _annotation(wire, types)
        uses_any |= na
        if ns:
            nested.add(ns)
        if name == wire:
            lines.append(f"    {name}: {ann} = None")
        else:
            uses_field = True
            lines.append(f"    {name}: {ann} = Field(default=None, alias={wire!r})")
        desc = descriptions.get(wire)
        if desc:
            lines.append(f'    """{_docstring(desc)}"""')
    return lines, uses_any, uses_field, nested


def _class_block(name: str, parent: str, doc: str, field_lines: list[str]) -> list[str]:
    # blank-line spacing between classes is added by callers and normalised by
    # ruff format, so this returns just the class's own lines.
    out = [f"class {name}({parent}):", f'    """{_docstring(doc)}"""']
    out += field_lines if field_lines else ["    pass"]
    return out


def _module_header(doc: str, uses_any: bool, uses_field: bool, nested: set[str], base_import: str
                   ) -> list[str]:
    head = [f'"""{doc}"""', "", "from __future__ import annotations", ""]
    if uses_any:
        head += ["from typing import Any", ""]
    if uses_field:
        head.append("from pydantic import Field")
    head.append(base_import)
    if nested:
        head.append(f"from .._nested import {', '.join(sorted(nested))}")
    head.append("")
    return head


def emit_bulletins(type_schemas: dict, collection_map: dict, descriptions: dict) -> int:
    """Generate the whole ``bulletins`` package; returns the number of type models."""
    base_fields, family_fields = derive_layers(type_schemas)

    fam_types: dict[str, list[str]] = defaultdict(list)
    for t, info in collection_map.items():
        fam = info.get("bulletinFamily")
        if fam:
            fam_types[fam].append(t)

    fam_class = {fam: _fam_class(fam) for fam in fam_types}
    reserved = set(fam_class.values()) | {"Bulletin", "GenericBulletin"}
    type_class: dict[str, str] = {}
    taken_classes = set(reserved)
    for fam in sorted(fam_types):
        for t in sorted(fam_types[fam]):
            type_class[t] = _type_class(t, reserved, taken_classes)
            taken_classes.add(type_class[t])

    # aggregate a base field's sampled types across every collection that carries it,
    # so the base annotation reflects the whole corpus (rich fields ignore this).
    base_types: dict[str, list[str]] = {}
    for w in base_fields:
        seen: set[str] = set()
        for ts in type_schemas.values():
            fm = ts.get("fields", {}).get(w)
            if fm:
                seen |= set(fm.get("types", []))
        base_types[w] = sorted(seen)
    # python names of inherited fields, so a subclass never shadows an alias.
    base_taken: set[str] = set()
    for w in sorted(base_fields):
        base_taken.add(_pyname(w, base_taken))

    if BULLETINS_DIR.exists():
        shutil.rmtree(BULLETINS_DIR)
    BULLETINS_DIR.mkdir(parents=True)

    # --- base.py -------------------------------------------------------------
    base_schema = {w: {"types": base_types[w]} for w in base_fields}
    blines, any_b, field_b, nested_b = _field_lines(
        sorted(base_fields), base_schema, set(), descriptions
    )
    out = _module_header(
        "GENERATED base bulletin model — do not edit (see dev-tools/data-models).",
        any_b, field_b, nested_b, "from .._base import VulnersModel",
    )
    out += _class_block(
        "Bulletin", "VulnersModel",
        "A single Vulners document; base for every bulletinFamily. Carries the fields "
        'present in every document. Family/type subclasses add their own; extra="allow" '
        "keeps any unmodelled field accessible.", blines,
    )
    out += ["", ""]
    out += _class_block(
        "GenericBulletin", "Bulletin",
        "Fallback for any bulletinFamily without a dedicated model (forward-compat).", [],
    )
    (BULLETINS_DIR / "base.py").write_text("\n".join(out) + "\n")

    # --- one <family>Bulletins.py per family ---------------------------------
    for fam in sorted(fam_types):
        fam_wires = sorted(family_fields.get(fam, set()))
        fam_taken = set(base_taken)
        fam_agg: dict[str, dict] = {}
        for w in fam_wires:  # aggregate a family field's types across the family's types
            seen = set()
            for t in fam_types[fam]:
                fm = type_schemas.get(t, {}).get("fields", {}).get(w)
                if fm:
                    seen |= set(fm.get("types", []))
            fam_agg[w] = {"types": sorted(seen)}
        flines, any_f, field_f, nested_f = _field_lines(
            fam_wires, fam_agg, fam_taken, descriptions
        )

        classes = _class_block(
            fam_class[fam], "Bulletin",
            f"`bulletinFamily: {fam}` — adds the fields shared across this family.", flines,
        )
        uses_any, uses_field, nested = any_f, field_f, set(nested_f)
        for t in sorted(fam_types[fam]):
            fields = type_schemas.get(t, {}).get("fields", {})
            spec = set(fields) - base_fields - family_fields.get(fam, set())
            # seed with base+family python names so a type field never shadows one
            type_taken = set(base_taken)
            for w in fam_wires:
                type_taken.add(_pyname(w, type_taken))
            tlines, na, nf, nn = _field_lines(sorted(spec), fields, type_taken, descriptions)
            uses_any |= na
            uses_field |= nf
            nested |= nn
            desc = (collection_map.get(t, {}).get("description") or "").strip()
            doc = f"`type: {t}`" + (f" — {desc}" if desc else "")
            classes += ["", "", *_class_block(type_class[t], fam_class[fam], doc, tlines)]

        head = _module_header(
            f"GENERATED — the `{fam}` bulletin family and its collection models.",
            uses_any, uses_field, nested, "from .base import Bulletin",
        )
        (BULLETINS_DIR / f"{fam}Bulletins.py").write_text("\n".join(head + classes) + "\n")

    # --- __init__.py: explicit static re-exports + registries ----------------
    # Real `from .<fam>Bulletins import (...)` statements (not __getattr__), so IDEs
    # and type checkers resolve every class directly. The whole package is eager:
    # building all models costs ~350 ms, paid once on first import of the package.
    init: list[str] = [
        '"""GENERATED bulletin models — do not edit.',
        "",
        "The base -> family -> type hierarchy, one file per bulletinFamily. Every class",
        "is imported here explicitly (so static analysis and IDEs see the whole surface),",
        "and mapped in FAMILY_MODELS / TYPE_MODELS for runtime type -> class resolution.",
        "Regenerate from live data with::",
        "",
        "    python dev-tools/data-models/sample_collections.py",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from .base import Bulletin, GenericBulletin",
    ]
    for fam in sorted(fam_types):
        names = [fam_class[fam]] + [type_class[t] for t in sorted(fam_types[fam])]
        init.append(f"from .{fam}Bulletins import (")
        init += [f"    {n}," for n in names]
        init.append(")")
    init += ["", "FAMILY_MODELS: dict[str, type[Bulletin]] = {"]
    init += [f"    {fam!r}: {fam_class[fam]}," for fam in sorted(fam_types)]
    init += ["}", "", "TYPE_MODELS: dict[str, type[Bulletin]] = {"]
    init += [f"    {t!r}: {type_class[t]}," for t in sorted(type_class)]
    init.append("}")
    all_names = ["Bulletin", "GenericBulletin", *fam_class.values(), *type_class.values()]
    init += ["", "__all__ = ["] + [f"    {n!r}," for n in sorted(all_names)] + ["]", ""]
    (BULLETINS_DIR / "__init__.py").write_text("\n".join(init))

    _format(BULLETINS_DIR)
    return len(type_class)


def _format(path) -> None:
    """ruff-format + import-sort the generated tree so re-runs are byte-identical."""
    for args in (["format"], ["check", "--select", "I,F401", "--fix", "--quiet"]):
        try:
            subprocess.run(["ruff", *args, str(path)], check=False, capture_output=True)
        except FileNotFoundError:  # pragma: no cover
            print("note: `ruff` not found; run `make format` on the generated package",
                  file=sys.stderr)
            return
