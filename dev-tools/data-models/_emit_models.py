"""Codegen the compact per-collection field data (``_collections_data.py``).

Only the data is generated (one line per collection ``type``: its family and the
fields it adds beyond the family model, each with a type token). The hand-written
factory in ``collections.py`` builds the base -> family -> type model on first use.
"""

from __future__ import annotations

import json
import sys

from _paths import MODELS_DATA, TYPE_OUT

_PYTYPE = {"str": "str", "int": "int", "float": "float", "bool": "bool"}


def _field_pytype(types: list[str]) -> str:
    non_null = [t for t in types if t != "null"]
    if len(non_null) == 1:
        t = non_null[0]
        if t in _PYTYPE:
            return _PYTYPE[t]
        if t.startswith("list["):
            return "list[Any]"
    return "Any"


def _token(types: list[str]) -> str:
    """Compact type token for a field, from its sampled JSON types."""
    pt = _field_pytype(types)
    if pt.startswith("list"):
        return "list"
    return pt if pt in ("str", "int", "float", "bool") else "any"


def emit_models() -> int:
    """Write ``src/vulners/_models/_collections_data.py`` from the sampled schemas."""
    if not TYPE_OUT.exists():
        print("run the sampler first (produces type_schemas.json)", file=sys.stderr)
        return 2

    from vulners._models import bulletin as bmod

    type_schemas = json.loads(TYPE_OUT.read_text())
    fam_names = {f: m.__name__ for f, m in bmod._FAMILY_MODELS.items()}
    # wire fields each family model already declares (so we only record the delta)
    fam_declared = {
        m.__name__: {fi.alias or n for n, fi in m.model_fields.items()}
        for m in set(bmod._FAMILY_MODELS.values())
    }

    rows: list[str] = []
    for t in sorted(type_schemas):
        tinfo = type_schemas[t]
        fam = tinfo.get("bulletinFamily")
        if not fam:
            continue
        declared = fam_declared.get(fam_names.get(fam, "GenericBulletin"), set())
        extra = {
            w: _token(meta["types"])
            for w, meta in sorted(tinfo["fields"].items())
            if w not in declared
        }
        fields = "{" + ", ".join(f'"{w}": "{tok}"' for w, tok in extra.items()) + "}"
        rows.append(f'    "{t}": {{"family": "{fam}", "fields": {fields}}},')

    out = [
        '"""Per-collection field data — GENERATED, do not edit.',
        "",
        'Maps a collection ``type`` to ``{"family": <bulletinFamily>, "fields": {<wire>:',
        "<type token>}}`` — the fields it adds beyond its family model. Consumed by the",
        "lazy model factory in :mod:`.collections`. Regenerate from live data with::",
        "",
        "    python dev-tools/data-models/sample_collections.py            # sample",
        "    python dev-tools/data-models/sample_collections.py --emit-models",
        '"""',
        "",
        "# fmt: off",
        "# ruff: noqa: E501 - one compact line per collection by design",
        "",
        "COLLECTIONS: dict[str, dict] = {",
        *rows,
        "}",
        "",
    ]
    MODELS_DATA.write_text("\n".join(out))
    print(f"wrote {MODELS_DATA} ({len(rows)} collections)", file=sys.stderr)
    return 0
