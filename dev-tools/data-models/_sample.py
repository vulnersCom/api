"""Live sampling: pull a few docs from every collection and derive its field shape.

Samples EVERY collection from ``/api/v4/search/collections`` (one at a time,
discarding the raw docs after extracting their shape) and derives the per-``type``
and per-``bulletinFamily`` field schema. Never writes or prints the API key — it is
read from an untracked file / env and redacted out of every saved example.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from typing import Any

import tomllib
from _paths import COLLECTION_OUT, REPO, REPORT_OUT, SCHEMA_OUT, TYPE_OUT


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


def write_sampled(type_schemas: dict, family_schemas: dict, collection_map: dict) -> None:
    """Write the regenerable sampled JSONs and the human coverage report."""
    from vulners._models import bulletin as bmod

    TYPE_OUT.write_text(json.dumps(type_schemas, indent=1) + "\n")
    SCHEMA_OUT.write_text(json.dumps(family_schemas, indent=1) + "\n")
    COLLECTION_OUT.write_text(json.dumps(collection_map, indent=1) + "\n")

    mapped = set(bmod._FAMILY_MODELS)
    live = {f for f in family_schemas if f != "?"}
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
