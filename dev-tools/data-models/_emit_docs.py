"""Codegen the committed data-model reference docs.

Two artifacts, generated from the sampled schemas plus the code models (so the
field descriptions always match what your IDE shows):

* ``documentation/reference/data-models.md`` — the base -> family -> type story.
* ``documentation/reference/collections/`` — one atomically-editable page per
  collection ``type`` plus an ``index.md`` catalog.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from _paths import COLLECTION_OUT, DOC_DIR, TYPE_OUT


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _md_code(text: str) -> str:
    """Wrap *text* in a table-safe code span (so ``[..]`` etc. stay literal and
    don't trip mkdocs-autorefs / markdown link parsing)."""
    text = text.replace("`", "").replace("\n", " ").replace("|", "\\|").strip()
    return f"`{text}`" if text else ""


def _prose(text: str) -> str:
    """Collapse whitespace and neutralise ``[..]`` (prose, not a markdown link)."""
    return " ".join(text.split()).replace("[", "\\[").replace("]", "\\]")


def _slug(t: str) -> str:
    """Filesystem/URL-safe page name for a collection ``type``."""
    return re.sub(r"[^a-z0-9._-]+", "-", t.lower())


def _approx(n: Any) -> str:
    """Approximate document count (collection sizes change ~every 2h, so exact
    numbers would go stale): 2 significant figures with a k/M suffix, e.g. 1464 ->
    '~1.5k', 306 -> '~310'."""
    if not isinstance(n, int) or n < 100:
        return f"~{n}" if isinstance(n, int) else ""
    factor = 10 ** (len(str(n)) - 2)
    r = round(n / factor) * factor
    if r >= 1_000_000:
        return f"~{r / 1_000_000:g}M"
    if r >= 1000:
        return f"~{r / 1000:g}k"
    return f"~{r}"


def _annot(fi: Any) -> str:
    """Readable annotation for a pydantic FieldInfo (e.g. ``str | None``), with
    module qualifiers stripped so nested models read as ``Timestamps``, not
    ``vulners._models.bulletin.Timestamps``."""
    ann = fi.annotation
    text = getattr(ann, "__name__", None) or str(ann).replace("typing.", "")
    text = re.sub(r"\b[a-zA-Z_]\w*\.", "", text)  # drop module qualifiers
    return text.replace("NoneType", "None")


def _family_model_names() -> dict[str, str]:
    """Live ``bulletinFamily`` -> family model class name, read from the code."""
    from vulners._models import bulletin as bmod

    return {fam: model.__name__ for fam, model in bmod._FAMILY_MODELS.items()}


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


def _field_table(tinfo: dict, descriptions: dict) -> list[str]:
    rows = ["| field | type | in samples | description | example |", "|---|---|---|---|---|"]
    for name, meta in tinfo.get("fields", {}).items():
        types = ", ".join(meta["types"])
        fdesc = _md_escape(descriptions.get(name, ""))
        raw = meta.get("example") or ""
        if len(raw) > 48:
            raw = raw[:45] + "…"
        pct = int(meta["presence"] * 100)
        rows.append(f"| `{name}` | `{types}` | {pct}% | {fdesc} | {_md_code(raw)} |")
    return rows


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
        "[Collections reference](collections/index.md)), adding the fields specific "
        "to that collection.",
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


def _write_type_page(
    types_dir: Path, t: str, info: dict, tinfo: dict, fam_names: dict, descriptions: dict
) -> None:
    fam = info["bulletinFamily"]
    model = fam_names.get(fam, "GenericBulletin")
    cnt_s = _approx(info.get("count"))
    desc = _prose(info.get("description") or "")
    lines = [
        f"# `{t}`" + (f"  ·  {cnt_s} documents" if cnt_s else ""),
        "",
        desc or "_(no description)_",
        "",
        f"**Family model:** [`{model}`](../../data-models.md) — `bulletinFamily: {fam}`. "
        'Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how '
        "often the field appeared in the sampled documents.",
        "",
        *_field_table(tinfo, descriptions),
        "",
    ]
    (types_dir / f"{_slug(t)}.md").write_text("\n".join(lines) + "\n")


def _emit_collections_reference(
    type_schemas: dict, collection_map: dict, fam_names: dict, descriptions: dict
) -> None:
    """documentation/reference/collections/ — one atomically-editable page per
    collection ``type`` plus an index, so a changed collection touches only its own
    file (not a single multi-thousand-line monolith)."""
    coll_dir = DOC_DIR / "collections"
    types_dir = coll_dir / "types"
    if types_dir.exists():  # drop pages for collections that no longer exist
        shutil.rmtree(types_dir)
    types_dir.mkdir(parents=True, exist_ok=True)
    (DOC_DIR / "collections.md").unlink(missing_ok=True)  # remove the old monolith

    by_family: dict[str, list[str]] = defaultdict(list)
    for t, info in collection_map.items():
        if info.get("bulletinFamily"):
            by_family[info["bulletinFamily"]].append(t)
            _write_type_page(types_dir, t, info, type_schemas.get(t, {}), fam_names, descriptions)

    n_fam = len({fam_names.get(f, "GenericBulletin") for f in by_family})
    n_types = sum(len(v) for v in by_family.values())
    lines = [
        "# Collections reference",
        "",
        "Every Vulners **collection** (`type`) and the exact fields its documents "
        "carry — one page each. Regenerate with "
        "`python dev-tools/data-models/sample_collections.py` then `--emit-docs`.",
        "",
        f"**{n_types} collections** across **{n_fam} family models** "
        "(see [Data models](../data-models.md)).",
        "",
    ]
    for fam in sorted(by_family):
        model = fam_names.get(fam, "GenericBulletin")
        lines += [f"## `{fam}` family → `{model}`", ""]
        for t in sorted(by_family[fam]):
            info = collection_map[t]
            approx = _approx(info.get("count"))
            cnt_s = f" · {approx} docs" if approx else ""
            blurb = _prose(info.get("description") or "")
            if len(blurb) > 110:
                blurb = blurb[:107] + "…"
            lines.append(
                f"- [`{t}`](types/{_slug(t)}.md){cnt_s}" + (f" — {blurb}" if blurb else "")
            )
        lines.append("")
    (coll_dir / "index.md").write_text("\n".join(lines) + "\n")


def emit_docs() -> int:
    """Generate the committed data-model reference (no API key; reads the sampled
    JSONs plus the code models for the authored field descriptions)."""
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
    print(
        f"wrote {DOC_DIR / 'data-models.md'} and {DOC_DIR / 'collections'}/ "
        "(index + one page per type)",
        file=sys.stderr,
    )
    return 0
