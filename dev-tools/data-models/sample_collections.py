#!/usr/bin/env python3
"""Refresh the Vulners bulletin data model from the live API.

One command. Give it an API key and it samples every collection, then regenerates
the whole ``base -> family -> type`` model hierarchy as real Python code
(``src/vulners/_models/bulletins/``) plus the reference docs — the generator is the
source of truth, there is nothing hand-written to keep in sync.

* if every type-specific collection field already has a human description in
  ``src/vulners/_models/_field_descriptions.py``, it regenerates and you're done;
* if some fields have no description, it lists them and asks whether to stop (so
  you can author them) or proceed anyway (undescribed fields get a ``TODO``
  placeholder you can fill in later).

    python dev-tools/data-models/sample_collections.py            # refresh (15 docs/collection)
    python dev-tools/data-models/sample_collections.py --limit 50 # sample more per collection

Key source: VULNERS_API_KEY env, else tests/live.local.toml ([live] api_key=...).
It NEVER writes or prints the key. The raw sample JSONs are git-ignored; the
committed baseline is the generated code itself, and the test suite re-checks
coherence (and generator idempotency) offline in CI. Implementation is split
across sibling modules: _sample / _emit_bulletins / _emit_docs / _emit_models
(derive_layers) / _descriptions (paths in _paths).
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict

from _descriptions import add_placeholders, missing_descriptions, prompt_missing
from _emit_bulletins import emit_bulletins
from _emit_docs import emit_docs
from _emit_models import derive_layers
from _sample import sample, write_records


def _type_specific(type_schemas: dict, collection_map: dict) -> dict[str, set[str]]:
    """collection ``type`` -> its type-specific wire fields (sampled fields that are
    neither in the data-driven base nor universal to its family)."""
    base, family = derive_layers(type_schemas)
    out: dict[str, set[str]] = {}
    for t, ts in type_schemas.items():
        fam = collection_map.get(t, {}).get("bulletinFamily")
        if fam:
            out[t] = set(ts.get("fields", {})) - base - family.get(fam, set())
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=15, help="documents sampled per collection")
    ap.add_argument("--workers", type=int, default=12, help="concurrent collection fetches")
    args = ap.parse_args()

    print("sampling every collection (in parallel)...", file=sys.stderr)
    type_schemas, collection_map = sample(args.limit, args.workers)
    write_records(type_schemas, collection_map)

    from vulners._models._field_descriptions import FIELD_DESCRIPTIONS

    errored = sorted(t for t, info in collection_map.items() if "error" in info)
    if errored:
        # A partial sample must not be written: the base/family layers are field
        # INTERSECTIONS, so a single dropped collection can silently promote a field
        # onto Bulletin (or a family) and reshape every unrelated model. Refuse and
        # let the maintainer re-run until every collection samples cleanly.
        print(
            f"\n{len(errored)} collection(s) errored while sampling — REFUSING to write "
            "(a partial sample would reshape the base/family field layers). Re-run:",
            file=sys.stderr,
        )
        for t in errored:
            print(f"  - {t} ({collection_map[t]['error']})", file=sys.stderr)
        return 1

    # Every type-specific field must carry a human description (base/family/nested
    # field descriptions live with those hand-written/authored layers).
    specific = _type_specific(type_schemas, collection_map)
    ft: dict[str, set[str]] = defaultdict(set)
    for t, wires in specific.items():
        for w in wires:
            ft[w].add(t)
    descriptions = dict(FIELD_DESCRIPTIONS)
    missing = missing_descriptions({t: {"fields": dict.fromkeys(w)} for t, w in specific.items()},
                                   set(descriptions))
    if missing:
        if prompt_missing(missing, ft) == "abort":
            print("stopped — nothing written. Add the descriptions and re-run.", file=sys.stderr)
            return 1
        descriptions.update(add_placeholders(missing))
        print(f"added {len(missing)} TODO placeholder(s) to _field_descriptions", file=sys.stderr)
    else:
        print(f"all {len(ft)} type-specific fields have descriptions ✓", file=sys.stderr)

    n = emit_bulletins(type_schemas, collection_map, descriptions)
    emit_docs(type_schemas, collection_map, descriptions)
    print(
        f"generated {n} collection models in src/vulners/_models/bulletins/ "
        "and documentation/reference/",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
