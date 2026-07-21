"""Codegen the committed data-model reference docs — grouped by family, mirroring
the generated code (``_models/bulletins``).

The generator writes both from the same sampled data, so docs and models never
drift. Under ``documentation/reference/bulletins/``:

* ``index.md``      — the base -> family -> type story and a family catalog;
* ``base.md``       — the base ``Bulletin`` fields every document carries;
* ``<family>.md``   — one page per ``bulletinFamily``: the family model's fields
  and, below it, each collection ``type`` in that family with the fields it adds.
"""

from __future__ import annotations

import shutil
from collections import defaultdict

from _emit_bulletins import _annotation, _fam_class, _type_class
from _emit_models import derive_layers
from _paths import DOC_DIR

BULLETINS_DOC = DOC_DIR / "bulletins"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _md_code(text: str) -> str:
    """Wrap *text* in a table-safe code span (``[..]`` etc. stay literal)."""
    text = text.replace("`", "").replace("\n", " ").replace("|", "\\|").strip()
    return f"`{text}`" if text else ""


def _prose(text: str) -> str:
    return " ".join(text.split()).replace("[", "\\[").replace("]", "\\]")


def _approx(n: object) -> str:
    """Approximate document count (sizes change ~every 2h): 2 sig figs, k/M suffix."""
    if not isinstance(n, int) or n < 100:
        return f"~{n}" if isinstance(n, int) else ""
    factor = 10 ** (len(str(n)) - 2)
    r = round(n / factor) * factor
    if r >= 1_000_000:
        return f"~{r / 1_000_000:g}M"
    if r >= 1000:
        return f"~{r / 1000:g}k"
    return f"~{r}"


def _class_names(collection_map: dict) -> tuple[dict[str, str], dict[str, str], dict[str, list]]:
    """(fam -> class, type -> class, fam -> [types]) — the SAME naming the code
    emitter uses, so the docs reference the exact generated class names."""
    fam_types: dict[str, list[str]] = defaultdict(list)
    for t, info in collection_map.items():
        if info.get("bulletinFamily"):
            fam_types[info["bulletinFamily"]].append(t)
    fam_class = {fam: _fam_class(fam) for fam in fam_types}
    reserved = set(fam_class.values()) | {"Bulletin", "GenericBulletin"}
    type_class: dict[str, str] = {}
    taken = set(reserved)
    for fam in sorted(fam_types):
        for t in sorted(fam_types[fam]):
            type_class[t] = _type_class(t, reserved, taken)
            taken.add(type_class[t])
    return fam_class, type_class, fam_types


def _field_table(wires: set[str], meta_of, descriptions: dict) -> list[str]:
    """A ``| field | type | description | example |`` table for *wires*, sorted."""
    if not wires:
        return ["_No fields beyond the layers above._"]
    rows = ["| field | type | description | example |", "|---|---|---|---|"]
    for w in sorted(wires):
        meta = meta_of(w)
        ann, _, _ = _annotation(w, meta.get("types", []))
        desc = _md_escape(descriptions.get(w, ""))
        ex = meta.get("example") or ""
        if len(ex) > 48:
            ex = ex[:45] + "…"
        rows.append(f"| `{w}` | `{ann}` | {desc} | {_md_code(ex)} |")
    return rows


def _agg_meta(type_schemas: dict, wire: str, types: list[str]) -> dict:
    """Aggregate a field's sampled types across *types* + a first example."""
    seen: set[str] = set()
    example = None
    for t in types:
        fm = type_schemas.get(t, {}).get("fields", {}).get(wire)
        if fm:
            seen |= set(fm.get("types", []))
            example = example or fm.get("example")
    return {"types": sorted(seen), "example": example}


def emit_docs(type_schemas: dict, collection_map: dict, descriptions: dict) -> None:
    """Regenerate ``documentation/reference/bulletins/`` from the sampled layers."""
    base_fields, family_fields = derive_layers(type_schemas)
    fam_class, type_class, fam_types = _class_names(collection_map)
    all_types = [t for fam in fam_types for t in fam_types[fam]]

    # Fresh tree (drop pages for collections/families that no longer exist), plus
    # retire the previous flat layout.
    for stale in (DOC_DIR / "collections", DOC_DIR / "data-models.md"):
        if stale.is_dir():
            shutil.rmtree(stale)
        elif stale.exists():
            stale.unlink()
    if BULLETINS_DOC.exists():
        shutil.rmtree(BULLETINS_DOC)
    BULLETINS_DOC.mkdir(parents=True)

    # --- index.md ------------------------------------------------------------
    idx = [
        "# Data models",
        "",
        "Every document Vulners returns is a **bulletin**, modelled in three layers so "
        "you get typed fields and IDE hints at whatever level of detail you need:",
        "",
        "1. **[`Bulletin`](base.md)** — the base: the fields every document carries.",
        "2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per "
        "`bulletinFamily`, adding that family's shared fields.",
        "3. **Collection models** — one per collection `type`, adding the fields specific "
        "to that collection.",
        "",
        "`search`/`archive`/`audit` return the most specific model that matches a "
        "document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model keeps "
        '`extra="allow"`, so a field Vulners adds before the SDK models it is still there '
        "on the object, just untyped — nothing is ever dropped.",
        "",
        "> The models **and** these pages are generated from live samples by "
        "`dev-tools/data-models/sample_collections.py`; a field belongs to a layer when the "
        "server sends it in *every* sampled document at that level.",
        "",
        f"## Families ({len(fam_types)})",
        "",
        "| family | model | collections |",
        "|---|---|---|",
    ]
    for fam in sorted(fam_types):
        idx.append(
            f"| [`{fam}`]({fam}.md) | `{fam_class[fam]}` | {len(fam_types[fam])} |"
        )
    idx.append("")
    (BULLETINS_DOC / "index.md").write_text("\n".join(idx) + "\n")

    # --- base.md -------------------------------------------------------------
    base = [
        "# `Bulletin` — base fields",
        "",
        "Fields the server sends in **every** document, across all collections. Every "
        "family and collection model inherits them. Nested value objects — `Cvss` (with "
        "`Cvss2`/`Cvss3`/`Cvss4` by version), `Timestamps`, `Enchantments`, `EpssScore` — "
        "are hand-written and shared.",
        "",
        *_field_table(
            base_fields, lambda w: _agg_meta(type_schemas, w, all_types), descriptions
        ),
        "",
    ]
    (BULLETINS_DOC / "base.md").write_text("\n".join(base) + "\n")

    # --- one <family>.md per family ------------------------------------------
    for fam in sorted(fam_types):
        types = sorted(fam_types[fam])
        fam_wires = family_fields.get(fam, set())
        lines = [
            f"# `{fam}` family",
            "",
            f"**Model:** `{fam_class[fam]}` — extends [`Bulletin`](base.md); "
            f"`bulletinFamily: {fam}`. {len(types)} collection"
            f"{'s' if len(types) != 1 else ''}.",
            "",
            "## Family fields",
            "",
            f"Present in every `{fam}` document, beyond the [common base](base.md).",
            "",
            *_field_table(
                fam_wires, lambda w, _t=types: _agg_meta(type_schemas, w, _t), descriptions
            ),
            "",
            "## Collections",
            "",
        ]
        for t in types:
            info = collection_map.get(t, {})
            fields = type_schemas.get(t, {}).get("fields", {})
            spec = set(fields) - base_fields - fam_wires
            cnt = _approx(info.get("count"))
            desc = _prose(info.get("description") or "")
            lines += [
                f"### `{t}`" + (f" · {cnt} documents" if cnt else "") + f" → `{type_class[t]}`",
                "",
                desc or "_(no description)_",
                "",
                *_field_table(spec, lambda w, _f=fields: _f.get(w, {}), descriptions),
                "",
            ]
        (BULLETINS_DOC / f"{fam}.md").write_text("\n".join(lines) + "\n")

    print(
        f"wrote {BULLETINS_DOC}/ (index + base + {len(fam_types)} family pages)",
        file=__import__("sys").stderr,
    )
