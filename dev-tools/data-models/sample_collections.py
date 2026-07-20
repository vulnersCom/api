#!/usr/bin/env python3
"""Maintainer toolset — study, generate & verify the Vulners bulletin data model.

Refreshes the bulletin models (``src/vulners/_models/``) and their reference docs
against the collections Vulners actually serves. Committed under ``dev-tools/`` so
maintainers can rerun it. It NEVER writes or prints the API key — the key is read
from an untracked file / env and redacted out of every saved example.

Usage (run from the repo root):
  python dev-tools/data-models/sample_collections.py               # sample -> schema JSONs
  python dev-tools/data-models/sample_collections.py --limit 20    # docs sampled per collection
  python dev-tools/data-models/sample_collections.py --emit-models # -> _collections_data.py
  python dev-tools/data-models/sample_collections.py --emit-docs   # -> documentation/reference/
  python dev-tools/data-models/sample_collections.py --verify      # OFFLINE coherence check

Key source: VULNERS_API_KEY env, else tests/live.local.toml ([live] api_key=...).

The sampled JSONs are regenerable and git-ignored (see ``.gitignore`` here). The
committed baseline of what Vulners serves is the generated
``src/vulners/_models/_collections_data.py`` itself, so ``--verify`` (and the test
suite) run offline in CI without a key. Implementation is split across sibling
modules: ``_sample`` / ``_emit_models`` / ``_emit_docs`` / ``_verify`` (paths in
``_paths``).
"""

from __future__ import annotations

import argparse
import sys

from _emit_docs import emit_docs
from _emit_models import emit_models
from _sample import sample, write_sampled
from _verify import verify


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=5, help="samples per collection (default 5)")
    ap.add_argument(
        "--verify", action="store_true", help="offline: model data vs the code models"
    )
    ap.add_argument("--emit-models", action="store_true", help="codegen _collections_data.py")
    ap.add_argument("--emit-docs", action="store_true", help="write the committed reference docs")
    args = ap.parse_args()
    if args.emit_models:
        return emit_models()
    if args.verify:
        return verify()
    if args.emit_docs:
        return emit_docs()
    print("sampling all collections (one at a time)...", file=sys.stderr)
    write_sampled(*sample(args.limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
