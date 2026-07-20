"""Build and write the compact per-collection field data (``_collections_data.py``).

Only data is generated (one line per collection ``type``: its family and the fields
it adds beyond the family model, each with a type token). The hand-written factory
in ``collections.py`` builds the base -> family -> type model on first use.
"""

from __future__ import annotations

import json
import sys

from _paths import MODELS_DATA

# The token vocabulary is owned by the runtime factory; emitting a token it does
# not know would silently type fields as Any, so the generator refuses.
from vulners._models.collections import _ANN


def _token(types: list[str]) -> str:
    """Compact type token for a field, from its sampled JSON types."""
    non_null = [t for t in types if t != "null"]
    if len(non_null) == 1:
        t = non_null[0]
        if t in ("str", "int", "float", "bool"):
            return t
        if t.startswith("list["):
            return "list"
    return "any"


def build_collections(type_schemas: dict, bmod: object) -> dict:
    """Return ``type -> {"family": <fam>, "fields": {wire: token}}`` for the fields
    each collection adds beyond its family model (the shape of ``COLLECTIONS``)."""
    fam_names = {f: m.__name__ for f, m in bmod._FAMILY_MODELS.items()}
    # Wire fields each family model already declares (so we only record the
    # delta). Includes the base Bulletin fields via inheritance; the base set is
    # also the floor for an UNMAPPED (new) family — otherwise a new family's
    # collections would re-record every base field (id, cvss, …) as type-added
    # and the factory would degrade their typing (cvss -> Any, id_ duplicates).
    base_declared = {fi.alias or n for n, fi in bmod.Bulletin.model_fields.items()}
    fam_declared = {
        m.__name__: {fi.alias or n for n, fi in m.model_fields.items()}
        for m in set(bmod._FAMILY_MODELS.values())
    }
    out: dict[str, dict] = {}
    for t in sorted(type_schemas):
        fam = type_schemas[t].get("bulletinFamily")
        if not fam:
            continue
        declared = fam_declared.get(fam_names.get(fam, ""), base_declared)
        fields = {
            w: _token(meta["types"])
            for w, meta in sorted(type_schemas[t]["fields"].items())
            if w not in declared
        }
        out[t] = {"family": fam, "fields": fields}
    return out


def write_collections_data(collections: dict) -> int:
    """Write ``src/vulners/_models/_collections_data.py``; returns the row count.

    All keys/values go through ``json.dumps`` — valid Python string literals — so
    a server-supplied type or field name containing quotes/backslashes can never
    break or inject code into the generated (and committed) module.
    """
    unknown = {tok for spec in collections.values() for tok in spec["fields"].values()} - set(
        _ANN
    )
    if unknown:
        raise SystemExit(f"generator produced tokens the factory doesn't know: {unknown}")

    rows = []
    for t, spec in collections.items():
        fields = ", ".join(
            f"{json.dumps(w)}: {json.dumps(tok)}" for w, tok in spec["fields"].items()
        )
        rows.append(
            f'    {json.dumps(t)}: {{"family": {json.dumps(spec["family"])}, '
            f'"fields": {{{fields}}}}},'
        )
    out = [
        '"""Per-collection field data — GENERATED, do not edit.',
        "",
        'Maps a collection ``type`` to ``{"family": <bulletinFamily>, "fields": {<wire>:',
        "<type token>}}`` — the fields it adds beyond its family model. Consumed by the",
        "lazy model factory in :mod:`.collections`. Regenerate from live data with::",
        "",
        "    python dev-tools/data-models/sample_collections.py",
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
    return len(rows)
