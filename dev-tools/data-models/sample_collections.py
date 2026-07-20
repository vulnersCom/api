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
import importlib
import sys

from _descriptions import add_placeholders, field_types, missing_descriptions, prompt_missing
from _emit_docs import emit_docs
from _emit_models import build_collections, write_collections_data
from _sample import sample, write_records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=20, help="documents sampled per collection")
    args = ap.parse_args()

    print("sampling every collection (one at a time)...", file=sys.stderr)
    type_schemas, collection_map = sample(args.limit)
    write_records(type_schemas, collection_map)

    from vulners._models import _field_descriptions as fd
    from vulners._models import bulletin as bmod

    collections = build_collections(type_schemas, bmod)

    new_families = sorted({c["family"] for c in collections.values()} - set(bmod._FAMILY_MODELS))
    if new_families:
        print(
            f"note: new bulletinFamily {new_families} → GenericBulletin. Add a dedicated "
            "model in src/vulners/_models/bulletin.py for richer typing.",
            file=sys.stderr,
        )

    ft = field_types(collections)
    missing = missing_descriptions(collections, set(fd.FIELD_DESCRIPTIONS))
    if missing:
        if prompt_missing(missing, ft) == "abort":
            print(
                "stopped — models/docs untouched. Add the descriptions and re-run.",
                file=sys.stderr,
            )
            return 1
        add_placeholders(missing)
        importlib.reload(fd)  # so the docs pick up the placeholders
        print(
            f"added {len(missing)} TODO placeholder(s) to _field_descriptions.py", file=sys.stderr
        )
    else:
        print(f"all {len(ft)} type-specific fields have descriptions ✓", file=sys.stderr)

    n = write_collections_data(collections)
    emit_docs(type_schemas, collection_map)
    print(
        f"updated src/vulners/_models/_collections_data.py ({n} collections) "
        "and documentation/reference/",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
