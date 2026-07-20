"""Field-description bookkeeping: what's missing, prompting, and TODO placeholders.

Every collection field must have a human description in
``src/vulners/_models/_field_descriptions.py`` (the single source used for the
models' IDE hints and the docs). This finds fields that lack one, asks the
maintainer what to do, and — if they choose to proceed anyway — appends TODO
placeholders so the repo stays consistent (grep ``TODO`` to fill them in later).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from _paths import FIELD_DESCRIPTIONS


def field_types(collections: dict) -> dict[str, set[str]]:
    """wire field -> the set of collection types that carry it."""
    ft: dict[str, set[str]] = defaultdict(set)
    for t, spec in collections.items():
        for w in spec["fields"]:
            ft[w].add(t)
    return ft


def missing_descriptions(collections: dict, described: set[str]) -> list[str]:
    """Collection fields with no entry in ``_field_descriptions.py``."""
    fields = {w for spec in collections.values() for w in spec["fields"]}
    return sorted(fields - described)


def prompt_missing(missing: list[str], ft: dict[str, set[str]]) -> str:
    """Show the undescribed fields and ask the maintainer: 'abort' or 'write'."""
    print(
        f"\n{len(missing)} field(s) have NO description in _field_descriptions.py:",
        file=sys.stderr,
    )
    for f in missing:
        seen = ", ".join(sorted(ft.get(f, []))[:6])
        print(f"  - {f:34s} seen in: {seen}", file=sys.stderr)
    print(
        "\nAuthor them in src/vulners/_models/_field_descriptions.py for the best result.",
        file=sys.stderr,
    )
    if not sys.stdin.isatty():
        print("(non-interactive session — stopping so you can add them)", file=sys.stderr)
        return "abort"
    while True:
        ans = (
            input("[a] abort and add them yourself  /  [w] write anyway with TODO placeholders: ")
            .strip()
            .lower()
        )
        if ans in ("a", "abort", ""):
            return "abort"
        if ans in ("w", "write"):
            return "write"


def add_placeholders(missing: list[str]) -> dict[str, str]:
    """Append ``"field": "TODO ..."`` entries for *missing* to _field_descriptions.py
    and return them, so the caller can merge without re-importing the module.

    Inserted before the dict's closing brace, preserving the hand-authored sections.
    Non-empty (so the model/description invariants still hold) and greppable.
    """
    text = FIELD_DESCRIPTIONS.read_text()
    # The splice anchors on the file's LAST closing brace, which is the dict's
    # only while the FIELD_DESCRIPTIONS literal stays the final statement — fail
    # loudly rather than silently splicing into some future trailing construct.
    if not text.rstrip().endswith("}"):
        raise SystemExit(
            "_field_descriptions.py no longer ends with the FIELD_DESCRIPTIONS "
            "dict — update add_placeholders() before re-running"
        )
    close = text.rindex("}")
    added = dict.fromkeys(missing, "TODO: describe this field.")
    block = "    # --- auto-added by sample_collections.py; replace each TODO ---\n"
    block += "".join(f"    {json.dumps(w)}: {json.dumps(d)},\n" for w, d in added.items())
    FIELD_DESCRIPTIONS.write_text(text[:close] + block + text[close:])
    return added
