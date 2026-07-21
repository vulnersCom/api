"""Live sampling: pull a few docs from every collection and derive its field shape.

Samples EVERY collection from ``/api/v4/search/collections`` (concurrently,
discarding the raw docs after extracting their shape) and derives the per-``type``
field schema. Never writes or prints the API key — it is read from an untracked
file / env and redacted out of every saved example.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any

from _paths import COLLECTION_OUT, REPO, TYPE_OUT


def _load_key() -> tuple[str, str]:
    import os

    k = os.environ.get("VULNERS_API_KEY")
    if k:
        return k, os.environ.get("VULNERS_SERVER_URL", "https://vulners.com")
    try:
        import tomllib  # stdlib on 3.11+
    except ModuleNotFoundError:  # Python 3.10: no stdlib toml reader
        raise SystemExit(
            "no VULNERS_API_KEY in the environment and tomllib is unavailable on "
            "Python 3.10 — set VULNERS_API_KEY instead of tests/live.local.toml"
        ) from None
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


def sample(limit_per: int, workers: int = 12) -> tuple[dict, dict]:
    """Return (type_schemas, collection_map).

    Fields are aggregated per collection ``type`` (the field set differs per
    collection). Collections are fetched concurrently (each search returns only a
    handful of docs, so this is fast and light); the shared rate-limit bucket in
    the client still paces the actual request rate. Raw docs are dropped after
    their shape is extracted — aggregation runs on the main thread, so the shared
    accumulators are never touched concurrently.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from vulners import Vulners

    key, server = _load_key()
    redact = key
    client = Vulners(api_key=key, base_url=server)

    collections = client.get("/api/v4/search/collections")["result"]
    collection_map: dict[str, Any] = {}
    type_fields: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(_new_field)
    )
    type_docn: dict[str, int] = defaultdict(int)

    def _record(bucket: dict[str, dict[str, Any]], field: str, val: Any) -> None:
        # ``fields=["*"]`` pads inapplicable fields with EMPTY values ({} / "" /
        # []): those are template noise, not occurrences — counting them would
        # inflate every retained field's presence to ~100% (and pollute the type
        # column with object{} entries). Only a real value counts.
        if val in (None, "", [], {}):
            return
        slot = bucket[field]
        slot["count"] += 1
        slot["types"].add(_typedesc(val))
        if slot["example"] is None:
            # Redact BEFORE truncating: a key straddling the truncation boundary
            # would otherwise survive as an unredacted prefix fragment.
            slot["example"] = json.dumps(val).replace(redact, "[REDACTED]")[:160]

    def _fetch(col: dict) -> tuple[dict, list | None, str | None]:
        # Runs in a worker thread: httpx.Client is safe for concurrent requests
        # and the rate-limit bucket serialises pacing. Returns raw shape only.
        try:
            # fields=["*"] returns the FULL document (search otherwise trims to a
            # default subset), so the per-type field schema is complete.
            page = client.search.query(f"type:{col['type']}", limit=limit_per, fields=["*"])
            # exclude_none=True so the dump mirrors the wire document: declared
            # model fields the server did NOT send must not be None-padded into
            # the sample, or every field would count as "present" in every doc
            # and empty nested models would become all-null phantom examples.
            docs = [b.model_dump(by_alias=True, exclude_none=True) for b in page.data]
            return col, docs, None
        except Exception as exc:
            return col, None, type(exc).__name__

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_fetch, col) for col in collections]
            for i, fut in enumerate(as_completed(futs), 1):
                col, docs, err = fut.result()
                ctype = col["type"]
                if err is not None:
                    collection_map[ctype] = {
                        "error": err,
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
                if i % 40 == 0:
                    print(f"  ...{i}/{len(collections)} collections", file=sys.stderr)
    finally:
        client.close()

    def _finish(fields: dict[str, dict[str, Any]], docn: int) -> dict[str, Any]:
        # _record only counts real (non-empty) values, so a field is present here
        # iff it carried data in at least one sampled doc, and ``presence`` is the
        # honest non-empty rate.
        return {
            name: {
                "presence": round(f["count"] / max(docn, 1), 2),
                "types": sorted(f["types"]),
                "example": f["example"],
            }
            for name, f in sorted(fields.items())
        }

    type_schemas = {
        t: {
            "bulletinFamily": collection_map[t].get("bulletinFamily"),
            "doc_count": type_docn[t],
            "description": collection_map[t].get("description"),
            "fields": _finish(type_fields[t], type_docn[t]),
        }
        for t in sorted(type_fields)
    }
    return type_schemas, dict(sorted(collection_map.items()))


def write_records(type_schemas: dict, collection_map: dict) -> None:
    """Persist the raw sample as git-ignored JSON records (for inspection)."""
    TYPE_OUT.write_text(json.dumps(type_schemas, indent=1) + "\n")
    COLLECTION_OUT.write_text(json.dumps(collection_map, indent=1) + "\n")
