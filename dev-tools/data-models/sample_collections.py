#!/usr/bin/env python3
"""Refresh the Vulners bulletin data model from the live API.

One command. Give it an API key and it samples every collection, then updates the
repo locally (it never commits or pushes):

* if every collection field already has a human description in
  ``src/vulners/_models/_field_descriptions.py``, it regenerates the model data
  (``_collections_data.py``) and the reference docs and you're done;
* if some fields have no description, it lists them and asks whether to stop (so
  you can author them) or proceed anyway (undescribed fields get a ``TODO``
  placeholder you can fill in later).

New ``bulletinFamily`` values are handled automatically (they fall back to
``GenericBulletin``); it just prints a note so you can add a richer model later.

    python dev-tools/data-models/sample_collections.py            # refresh (20 docs/collection)
    python dev-tools/data-models/sample_collections.py --limit 50 # sample more per collection

Key source: VULNERS_API_KEY env, else tests/live.local.toml ([live] api_key=...).
It NEVER writes or prints the key. The raw sample JSONs are git-ignored; the
committed baseline is the generated ``_collections_data.py`` itself, and the test
suite re-checks coherence offline in CI. Implementation is split across sibling
modules: _sample / _emit_models / _emit_docs / _descriptions (paths in _paths).
"""

from __future__ import annotations

import argparse
import sys

from _descriptions import add_placeholders, field_types, missing_descriptions, prompt_missing
from _emit_docs import emit_docs
from _emit_models import build_collections, write_collections_data
from _sample import sample, write_records


def _retain_errored(collections: dict, type_schemas: dict, collection_map: dict) -> list[str]:
    """Keep the previously-committed spec for any collection that errored this run.

    A transient 429/500/empty-page during sampling must not silently remove a
    collection's model row and docs page from the repo; retained entries keep the
    committed field set (marked stale in the docs, without presence/example stats)
    and are reported so the maintainer can re-run or investigate.
    """
    from vulners._models.collections import COLLECTIONS as committed

    retained = []
    for ctype, info in collection_map.items():
        if "error" in info and ctype not in collections and ctype in committed:
            spec = committed[ctype]
            collections[ctype] = spec
            collection_map[ctype] = {
                **info,
                "bulletinFamily": spec["family"],
                "description": (info.get("description") or "").strip()
                + " (Field stats unavailable: this refresh could not sample the "
                "collection; the previously-committed field set was retained.)",
            }
            type_schemas[ctype] = {
                "bulletinFamily": spec["family"],
                "fields": {
                    w: {"presence": None, "types": [tok], "example": None}
                    for w, tok in spec["fields"].items()
                },
            }
            retained.append(f"{ctype} ({info['error']})")
    return retained


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=20, help="documents sampled per collection")
    args = ap.parse_args()

    print("sampling every collection (one at a time)...", file=sys.stderr)
    type_schemas, collection_map = sample(args.limit)
    write_records(type_schemas, collection_map)

    from vulners._models import bulletin as bmod
    from vulners._models._field_descriptions import FIELD_DESCRIPTIONS

    collections = build_collections(type_schemas, bmod)

    errored = _retain_errored(collections, type_schemas, collection_map)
    if errored:
        print(
            f"\nWARNING: {len(errored)} collection(s) errored while sampling; their "
            "previously-committed models were RETAINED (not refreshed):",
            file=sys.stderr,
        )
        for line in errored:
            print(f"  - {line}", file=sys.stderr)
        print("re-run to refresh them.\n", file=sys.stderr)

    new_families = sorted({c["family"] for c in collections.values()} - set(bmod._FAMILY_MODELS))
    if new_families:
        print(
            f"note: new bulletinFamily {new_families} → GenericBulletin. Add a dedicated "
            "model in src/vulners/_models/bulletin.py for richer typing.",
            file=sys.stderr,
        )

    descriptions = dict(FIELD_DESCRIPTIONS)
    ft = field_types(collections)
    missing = missing_descriptions(collections, set(descriptions))
    if missing:
        if prompt_missing(missing, ft) == "abort":
            print(
                "stopped — models/docs untouched. Add the descriptions and re-run.",
                file=sys.stderr,
            )
            return 1
        descriptions.update(add_placeholders(missing))
        print(
            f"added {len(missing)} TODO placeholder(s) to _field_descriptions.py", file=sys.stderr
        )
    else:
        print(f"all {len(ft)} type-specific fields have descriptions ✓", file=sys.stderr)

    n = write_collections_data(collections)
    emit_docs(type_schemas, collection_map, descriptions)
    print(
        f"updated src/vulners/_models/_collections_data.py ({n} collections) "
        "and documentation/reference/",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
