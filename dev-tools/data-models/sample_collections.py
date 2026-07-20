#!/usr/bin/env python3
"""Maintainer toolset — study, generate & verify the Vulners bulletin data model.

Samples EVERY collection from ``/api/v4/search/collections`` (a few docs each,
one collection at a time, discarding the raw docs after extracting their shape),
derives the per-``type`` and per-``bulletinFamily`` field schema, generates the
per-collection models and reference docs, and keeps everything honest.

Committed under ``dev-tools/`` so the SDK maintainers (and contributors) can
refresh the models when Vulners adds collections or fields. It NEVER writes or
prints the API key — the key is read from an untracked file / env and redacted
out of every saved example. Saved artifacts hold only public vulnerability
metadata (field names, one truncated example value).

Usage (run from the repo root):
  python dev-tools/data-models/sample_collections.py               # sample -> schemas + snapshot
  python dev-tools/data-models/sample_collections.py --limit 3     # fewer samples per collection
  python dev-tools/data-models/sample_collections.py --emit-models # (re)generate the type models
  python dev-tools/data-models/sample_collections.py --emit-docs   # (re)generate the docs
  python dev-tools/data-models/sample_collections.py --verify      # OFFLINE: models/descriptions
                                                                   #   vs the committed snapshot
Key source: VULNERS_API_KEY env, else tests/live.local.toml ([live] api_key=...).

The large sampled JSONs (``type_schemas.json`` etc.) are regenerable and stay
git-ignored (see ``.gitignore`` here); only ``schema_snapshot.json`` — a compact
``type -> {family, fields}`` baseline — is committed, so ``--verify`` runs offline
in CI without a key.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import tomllib

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
TYPE_OUT = HERE / "type_schemas.json"
SCHEMA_OUT = HERE / "family_schemas.json"
COLLECTION_OUT = HERE / "collection_map.json"
REPORT_OUT = HERE / "coverage_report.md"
# The one committed artifact: a compact type -> {family, fields} baseline so
# --verify runs offline (no key) in CI. The JSONs above are regenerable/ignored.
SNAPSHOT_OUT = HERE / "schema_snapshot.json"


def _load_key() -> tuple[str, str]:
    import os

    k = os.environ.get("VULNERS_API_KEY")
    if k:
        return k, os.environ.get("VULNERS_SERVER_URL", "https://vulners.com")
    data = tomllib.loads((REPO / "tests" / "live.local.toml").read_text())
    sec = data.get("live", data)
    return sec["api_key"], sec.get("server_url", "https://vulners.com")


def _typedesc(value: Any) -> str:
    """Compact JSON type descriptor, one level deep for objects/arrays."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        inner = _typedesc(value[0]) if value else "?"
        return f"list[{inner}]"
    if isinstance(value, dict):
        keys = sorted(value.keys())[:12]
        return "object{" + ",".join(keys) + "}"
    return type(value).__name__


def _new_field() -> dict[str, Any]:
    return {"count": 0, "types": set(), "example": None}


def sample(limit_per: int) -> tuple[dict, dict, dict]:
    """Return (type_schemas, family_schemas, collection_map).

    Fields are aggregated per collection ``type`` (the primary analysis, since the
    field set differs per collection), and the per-``bulletinFamily`` schema is the
    union across the types that share a family. One collection at a time; raw docs
    are dropped after their shape is extracted.
    """
    from vulners import Vulners

    key, server = _load_key()
    redact = key
    client = Vulners(api_key=key, base_url=server)

    collections = client.get("/api/v4/search/collections")["result"]
    collection_map: dict[str, Any] = {}
    # type -> field -> {count, types:set, example}
    type_fields: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(_new_field)
    )
    type_docn: dict[str, int] = defaultdict(int)

    def _record(bucket: dict[str, dict[str, Any]], field: str, val: Any) -> None:
        slot = bucket[field]
        slot["count"] += 1
        slot["types"].add(_typedesc(val))
        if slot["example"] is None and val not in (None, "", [], {}):
            slot["example"] = json.dumps(val)[:160].replace(redact, "[REDACTED]")

    try:
        for i, col in enumerate(sorted(collections, key=lambda c: c["type"]), 1):
            ctype = col["type"]
            try:
                # fields=["*"] returns the FULL document (search otherwise trims to
                # a default subset), so the per-type field schema is complete.
                page = client.search.query(f"type:{ctype}", limit=limit_per, fields=["*"])
                docs = [b.model_dump(by_alias=True, exclude_none=False) for b in page.data]
            except Exception as exc:
                collection_map[ctype] = {
                    "error": type(exc).__name__,
                    "description": col.get("description"),
                }
                continue
            fam = None
            for doc in docs:
                fam = doc.get("bulletinFamily") or fam
                type_docn[ctype] += 1
                for field, val in doc.items():
                    _record(type_fields[ctype], field, val)
            collection_map[ctype] = {
                "bulletinFamily": fam,
                "count": col.get("count"),
                "last_updated": col.get("last_updated"),
                "description": col.get("description"),
                "sampled": len(docs),
            }
            if i % 20 == 0:
                print(f"  ...{i}/{len(collections)} collections", file=sys.stderr)
            time.sleep(0.05)  # gentle; the client also paces via the rate-limit bucket
    finally:
        client.close()

    def _finish_fields(fields: dict[str, dict[str, Any]], docn: int) -> dict[str, Any]:
        # ``fields=["*"]`` returns a GLOBAL field template: fields that don't apply
        # to a collection still come back empty ({} / "" / [] / null). Such a field
        # is noise (e.g. exploit-tool `appercut` on an `android` doc) — a field
        # only belongs to a type if it carried a real value in at least one sample
        # (``example`` is set only for non-empty values), so drop the empty-only ones.
        return {
            name: {
                "presence": round(f["count"] / max(docn, 1), 2),
                "types": sorted(f["types"]),
                "example": f["example"],
            }
            for name, f in sorted(fields.items())
            if f["example"] is not None
        }

    type_schemas = {
        t: {
            "bulletinFamily": collection_map[t].get("bulletinFamily"),
            "doc_count": type_docn[t],
            "description": collection_map[t].get("description"),
            "fields": _finish_fields(type_fields[t], type_docn[t]),
        }
        for t in sorted(type_fields)
    }

    # Derive per-family union across the types sharing that family.
    fam_fields: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(_new_field)
    )
    fam_docn: dict[str, int] = defaultdict(int)
    fam_types: dict[str, set[str]] = defaultdict(set)
    for t, tinfo in type_schemas.items():
        fam = tinfo["bulletinFamily"] or "?"
        fam_docn[fam] += tinfo["doc_count"]
        fam_types[fam].add(t)
        finished = tinfo["fields"]  # already filtered of empty-only fields
        for name, meta in type_fields[t].items():
            if name not in finished:
                continue
            slot = fam_fields[fam][name]
            slot["count"] += meta["count"]
            slot["types"].update(meta["types"])
            if slot["example"] is None:
                slot["example"] = finished[name]["example"]
    family_schemas = {
        fam: {
            "doc_count": fam_docn[fam],
            "collections": sorted(fam_types[fam]),
            "fields": _finish_fields(fam_fields[fam], fam_docn[fam]),
        }
        for fam in sorted(fam_fields)
    }
    return type_schemas, family_schemas, dict(sorted(collection_map.items()))


def _build_snapshot(type_schemas: dict) -> dict[str, Any]:
    """Compact, committed baseline: type -> {bulletinFamily, sorted field names}.

    Small enough to commit and diff; drives the offline --verify. No examples, no
    presence stats (those live in the regenerable type_schemas.json)."""
    return {
        t: {
            "bulletinFamily": info.get("bulletinFamily"),
            "description": (info.get("description") or "").strip()[:160] or None,
            "fields": sorted(info.get("fields", {})),
        }
        for t, info in sorted(type_schemas.items())
    }


def _load_snapshot() -> dict[str, Any]:
    if not SNAPSHOT_OUT.exists():
        raise SystemExit(
            "no schema_snapshot.json — run the sampler first "
            "(python dev-tools/data-models/sample_collections.py)"
        )
    return json.loads(SNAPSHOT_OUT.read_text())


def _fields_missing_description(bmod: Any, type_models: dict) -> list[str]:
    """Declared model fields (family + generated type models, incl. inherited)
    whose ``description`` is empty — a field that lacks an authored docstring."""
    models = set(bmod._FAMILY_MODELS.values()) | {bmod.Bulletin} | set(type_models.values())
    missing = {
        f"{m.__name__}.{name}"
        for m in models
        for name, fi in m.model_fields.items()
        if not (fi.description or "").strip()
    }
    return sorted(missing)


def verify() -> int:
    """OFFLINE consistency check (no API key) against the committed snapshot.

    Fails (exit 1) if a collection/family/field the snapshot recorded is not
    covered by the code models, or a model field lacks a description. This is what
    a maintainer runs after --emit-models to confirm the generated models and the
    authored field descriptions still cover every collection Vulners serves.
    """
    from vulners._models import bulletin as bmod
    from vulners._models._field_descriptions import FIELD_DESCRIPTIONS
    from vulners._models.collections import COLLECTIONS, collection_model

    snap = _load_snapshot()
    families = {t["bulletinFamily"] for t in snap.values() if t.get("bulletinFamily")}
    types = set(snap)
    fields = {f for t in snap.values() for f in t.get("fields", [])}

    def _trunc(items: list[str]) -> str:
        return f"{items[:10]}{'…' if len(items) > 10 else ''}"

    problems: list[str] = []
    unmapped_fam = sorted(families - set(bmod._FAMILY_MODELS))
    if unmapped_fam:
        problems.append(f"bulletinFamily not in _FAMILY_MODELS: {unmapped_fam}")
    unmapped_type = sorted(types - set(COLLECTIONS))
    if unmapped_type:
        problems.append(
            f"{len(unmapped_type)} collection type(s) missing from _collections_data.py "
            f"(run --emit-models): {_trunc(unmapped_type)}"
        )
    undescribed = sorted(fields - set(FIELD_DESCRIPTIONS))
    if undescribed:
        problems.append(
            f"{len(undescribed)} field(s) with no description in _field_descriptions.py "
            f"(author one): {undescribed}"
        )
    # Build EVERY collection model (offline) and confirm no field lacks a
    # description — this exercises the whole base -> family -> type factory.
    built = [collection_model(t) for t in COLLECTIONS]
    missing_doc = _fields_missing_description(bmod, {m.__name__: m for m in built if m})
    if missing_doc:
        problems.append(
            f"{len(missing_doc)} model field(s) without a description: {_trunc(missing_doc)}"
        )

    if problems:
        print("DRIFT — the data model is out of sync with live collections:")
        for p in problems:
            print("  -", p)
        return 1
    print(
        f"OK: {len(types)} collections, {len(families)} families, {len(fields)} fields — "
        "all mapped to models and described."
    )
    return 0


def _family_model_names() -> dict[str, str]:
    """Live ``bulletinFamily`` -> family model class name, read from the code."""
    from vulners._models import bulletin as bmod

    return {fam: model.__name__ for fam, model in bmod._FAMILY_MODELS.items()}


DOC_DIR = REPO / "documentation" / "reference"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _md_code(text: str) -> str:
    """Wrap *text* in a table-safe code span (so ``[..]`` etc. stay literal and
    don't trip mkdocs-autorefs / markdown link parsing)."""
    text = text.replace("`", "").replace("\n", " ").replace("|", "\\|").strip()
    return f"`{text}`" if text else ""


def _model_field_rows(model: Any, base: Any) -> list[tuple[str, str, str]]:
    """(wire_name, python_name, description) for the fields *model* adds over *base*."""
    base_names = set(base.model_fields) if base is not None else set()
    rows = []
    for name, fi in model.model_fields.items():
        if name in base_names:
            continue
        wire = fi.alias or name
        rows.append((wire, name, (fi.description or "").strip()))
    return sorted(rows)


def emit_docs() -> int:
    """Generate the committed data-model reference (no API key; reads the JSONs
    this script wrote plus the code models for the authored field descriptions)."""
    if not (TYPE_OUT.exists() and COLLECTION_OUT.exists()):
        print("run the sampler first (produces type_schemas.json etc.)", file=sys.stderr)
        return 2
    from vulners._models import bulletin as bmod
    from vulners._models._field_descriptions import FIELD_DESCRIPTIONS

    type_schemas = json.loads(TYPE_OUT.read_text())
    collection_map = json.loads(COLLECTION_OUT.read_text())
    fam_names = _family_model_names()
    DOC_DIR.mkdir(parents=True, exist_ok=True)

    _emit_data_models_narrative(bmod)
    _emit_collections_reference(type_schemas, collection_map, fam_names, FIELD_DESCRIPTIONS)
    print(f"wrote {DOC_DIR / 'data-models.md'} and {DOC_DIR / 'collections.md'}", file=sys.stderr)
    return 0


def _emit_data_models_narrative(bmod: Any) -> None:
    """documentation/reference/data-models.md — the base -> family -> type story,
    generated from the actual models so the descriptions always match the code."""
    base = bmod.Bulletin
    lines = [
        "# Data models",
        "",
        "Every document Vulners returns is a **bulletin**. The SDK models them in "
        "three layers, so you get typed fields and IDE hints at whatever level of "
        "detail you need:",
        "",
        "1. **`Bulletin`** — the base: the fields every document carries.",
        "2. **Family models** (`CveBulletin`, `ExploitBulletin`, …) — one per "
        "`bulletinFamily`, each adding that family's fields.",
        "3. **Collection models** — one per collection `type` (see "
        "[Collections reference](collections.md)), adding the fields specific to "
        "that collection.",
        "",
        "`search`/`archive`/`audit` return the most specific model that matches a "
        "document's `type`, then its `bulletinFamily`, then `Bulletin`. Every model "
        'keeps `extra="allow"`: a field Vulners adds before the SDK models it is '
        "still there on the object, just untyped — nothing is ever dropped.",
        "",
        "> These tables are generated from the models themselves "
        "(`dev-tools/data-models/sample_collections.py --emit-docs`); the field "
        "descriptions are the same ones your IDE shows on hover.",
        "",
        "## `Bulletin` — base fields",
        "",
        "| field | wire name | type | description |",
        "|---|---|---|---|",
    ]
    for name, fi in base.model_fields.items():
        wire = fi.alias or name
        lines.append(
            f"| `{name}` | `{wire}` | `{_md_escape(_annot(fi))}` | "
            f"{_md_escape((fi.description or '').strip())} |"
        )
    lines.append("")

    # families, in a stable order (base CVE/exploit/... first, advisory group last),
    # each unique model once even when several families share it (AdvisoryBulletin)
    lines += ["## Family models", ""]
    for model in dict.fromkeys(bmod._FAMILY_MODELS.values()):
        rows = _model_field_rows(model, base)
        parent = model.__mro__[1]
        extends = parent.__name__ if parent is not base else "Bulletin"
        fams = [f for f, m in bmod._FAMILY_MODELS.items() if m is model]
        lines += [
            f"### `{model.__name__}`  (extends `{extends}`)",
            "",
            (model.__doc__ or "").strip().split("\n")[0],
            "",
            f"`bulletinFamily`: {', '.join(f'`{f}`' for f in fams)}",
            "",
        ]
        if rows:
            lines += ["| field | wire name | description |", "|---|---|---|"]
            lines += [f"| `{n}` | `{w}` | {_md_escape(d)} |" for w, n, d in rows]
        else:
            lines.append("_Adds no fields beyond the base._")
        lines.append("")
    (DOC_DIR / "data-models.md").write_text("\n".join(lines) + "\n")


def _annot(fi: Any) -> str:
    """Readable annotation for a pydantic FieldInfo (e.g. ``str | None``), with
    module qualifiers stripped so nested models read as ``Timestamps``, not
    ``vulners._models.bulletin.Timestamps``."""
    import re

    ann = fi.annotation
    text = getattr(ann, "__name__", None) or str(ann).replace("typing.", "")
    text = re.sub(r"\b[a-zA-Z_]\w*\.", "", text)  # drop module qualifiers
    return text.replace("NoneType", "None")


def _emit_collections_reference(
    type_schemas: dict, collection_map: dict, fam_names: dict, descriptions: dict
) -> None:
    """documentation/reference/collections.md — every collection type and its
    fields, grouped by family, with the authored per-field description."""
    by_family: dict[str, list[str]] = defaultdict(list)
    for t, info in collection_map.items():
        if info.get("bulletinFamily"):
            by_family[info["bulletinFamily"]].append(t)
    n_fam = len({fam_names.get(f, "GenericBulletin") for f in by_family})
    lines = [
        "# Collections reference",
        "",
        "Every Vulners **collection** (`type`) and the exact fields its documents "
        "carry, sampled from `/api/v4/search/collections`. Regenerate with "
        "`python dev-tools/data-models/sample_collections.py` then `--emit-docs`.",
        "",
        f"**{len(collection_map)} collections** across **{n_fam} family models** "
        "(see [Data models](data-models.md)). Fields beyond a model's declared set "
        'stay accessible because every model keeps `extra="allow"`. The *in samples* '
        "column is how often the field appeared in the sampled documents.",
        "",
    ]
    for fam in sorted(by_family):
        model = fam_names.get(fam, "GenericBulletin")
        lines += [f"## `{fam}` family → `{model}`", ""]
        for t in sorted(by_family[fam]):
            tinfo = type_schemas.get(t, {})
            desc = (collection_map[t].get("description") or "").strip()
            desc = desc.replace("[", "\\[").replace("]", "\\]")  # prose: not a md link
            cnt = collection_map[t].get("count")
            lines += [
                f"### `{t}`" + (f"  ·  {cnt:,} documents" if isinstance(cnt, int) else ""),
                "",
                desc or "_(no description)_",
                "",
                "| field | type | in samples | description | example |",
                "|---|---|---|---|---|",
            ]
            for name, meta in tinfo.get("fields", {}).items():
                types = ", ".join(meta["types"])
                fdesc = _md_escape(descriptions.get(name, ""))
                raw = meta.get("example") or ""
                if len(raw) > 48:
                    raw = raw[:45] + "…"
                ex = _md_code(raw)
                lines.append(
                    f"| `{name}` | `{types}` | {int(meta['presence'] * 100)}% | {fdesc} | {ex} |"
                )
            lines.append("")
    (DOC_DIR / "collections.md").write_text("\n".join(lines) + "\n")


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
    """Codegen the compact per-collection field DATA into
    ``src/vulners/_models/_collections_data.py``.

    Only the data is generated (one line per collection ``type``: its family and
    the fields it adds beyond the family model, each with a type token). The
    hand-written factory in ``collections.py`` builds the base -> family -> type
    model for a ``type`` on first use — no wall of 238 generated classes."""
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
    dest = REPO / "src" / "vulners" / "_models" / "_collections_data.py"
    dest.write_text("\n".join(out))
    print(f"wrote {dest} ({len(rows)} collections)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=5, help="samples per collection (default 5)")
    ap.add_argument("--verify", action="store_true", help="compare live shape to the code models")
    ap.add_argument("--emit-models", action="store_true", help="codegen the per-type models")
    ap.add_argument("--emit-docs", action="store_true", help="write the committed reference docs")
    args = ap.parse_args()
    if args.emit_models:
        return emit_models()
    if args.verify:
        return verify()
    if args.emit_docs:
        return emit_docs()
    print("sampling all collections (one at a time)...", file=sys.stderr)
    type_schemas, family_schemas, collection_map = sample(args.limit)
    TYPE_OUT.write_text(json.dumps(type_schemas, indent=1) + "\n")
    SCHEMA_OUT.write_text(json.dumps(family_schemas, indent=1) + "\n")
    COLLECTION_OUT.write_text(json.dumps(collection_map, indent=1) + "\n")
    # the one committed artifact (offline --verify baseline)
    SNAPSHOT_OUT.write_text(json.dumps(_build_snapshot(type_schemas), indent=1) + "\n")
    # coverage report
    from vulners._models import bulletin as _bmod

    mapped = set(_bmod._FAMILY_MODELS)
    live = {f for f in family_schemas if f != "?"}
    # every distinct field name seen anywhere, and which types carry it
    field_types: dict[str, set[str]] = defaultdict(set)
    for t, tinfo in type_schemas.items():
        for name in tinfo["fields"]:
            field_types[name].add(t)
    lines = [
        "# Bulletin data-model coverage (generated by sample_collections.py)",
        "",
        f"- collections (type) sampled: {len(collection_map)}",
        f"- distinct bulletinFamily values: {len(live)}",
        f"- distinct field names across all types: {len(field_types)}",
        f"- mapped in `_FAMILY_MODELS`: {sorted(mapped)}",
        f"- **missing from `_FAMILY_MODELS`**: {sorted(live - mapped)}",
        "",
        "## Per bulletinFamily (union across its collections)",
        "",
        "| bulletinFamily | #docs | #fields | #collections | collections |",
        "|---|---|---|---|---|",
    ]
    for fam, info in family_schemas.items():
        cols = info["collections"]
        lines.append(
            f"| `{fam}` | {info['doc_count']} | {len(info['fields'])} | {len(cols)} | "
            f"{', '.join(cols[:8])}{'…' if len(cols) > 8 else ''} |"
        )
    lines += [
        "",
        "## Field → which collection types carry it",
        "",
        "| field | #types | example types |",
        "|---|---|---|",
    ]
    for name, types in sorted(field_types.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        ex = ", ".join(sorted(types)[:6])
        lines.append(f"| `{name}` | {len(types)} | {ex}{'…' if len(types) > 6 else ''} |")
    REPORT_OUT.write_text("\n".join(lines) + "\n")
    print(
        f"wrote {TYPE_OUT.name}, {SCHEMA_OUT.name}, {COLLECTION_OUT.name}, {REPORT_OUT.name}",
        file=sys.stderr,
    )
    print(f"families: {sorted(live)}", file=sys.stderr)
    print(f"MISSING from _FAMILY_MODELS: {sorted(live - mapped)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
