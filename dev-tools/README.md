# dev-tools

Maintainer tooling for the Vulners SDK. Not shipped in the wheel — run from a
checkout. Everything here is safe for the public repo: no tool writes or prints
an API key.

## `data-models/` — bulletin data-model sampler & codegen

Keeps the bulletin models (`src/vulners/_models/`) and their reference docs in
sync with the collections Vulners actually serves. The hierarchy is
**base → family → type**, and all three layers are generated:

- `Bulletin` — the fields every document carries (`_models/bulletins/base.py`).
- family models (`CveBulletin`, …) — one per `bulletinFamily`, a module each
  (`_models/bulletins/<family>Bulletins.py`).
- per-collection models — one per collection `type`, inside its family's module.
  `FAMILY_MODELS` / `TYPE_MODELS` in `_models/bulletins/__init__.py` resolve a
  payload to its most specific class — 293 collections across 19 families as of
  the last refresh.

Nothing in that hierarchy is hand-written, so a new collection or field is a re-run
rather than an edit. What *is* hand-written sits beside it: `_models/bulletin.py`,
the runtime that picks and builds the most specific class (type → family →
`GenericBulletin`), and `_models/_field_descriptions.py`, where every field's human
description lives once and flows to both the models (attribute docstrings → IDE
hover) and the docs.

### Refresh workflow (when Vulners adds collections/fields)

**One command.** Needs an API key — `VULNERS_API_KEY` env, or `[live] api_key = "…"`
in the untracked `tests/live.local.toml`.

```bash
python dev-tools/data-models/sample_collections.py
```

It samples every collection, then updates the repo locally (never commits/pushes):

- if every collection field already has a description in `_field_descriptions.py`,
  it regenerates the model hierarchy and the reference docs — done;
- if some fields have none, it **lists them** and asks whether to stop (so you can
  author them) or proceed anyway (undescribed fields get a `TODO` placeholder you
  fill in later — grep `TODO`).

New `bulletinFamily` values are handled automatically — they fall back to
`GenericBulletin`; the tool just prints a note so you can add a richer family model
in `src/vulners/_models/bulletin.py` later. Offline coherence (every field
described, every collection modelled) is enforced by the test suite in CI.

### Layout

`sample_collections.py` is a thin CLI over one module per phase, so each is edited
in isolation: `_sample.py` (live sampling), `_emit_models.py` (the
`_collections_data.py` codegen), `_emit_docs.py` (the reference docs),
`_descriptions.py` (missing-description handling), with shared paths in `_paths.py`.

### What is committed vs regenerable

Committed: `sample_collections.py` and its sibling modules, plus everything they
emit — the generated models under `src/vulners/_models/bulletins/` and the pages
under `documentation/reference/bulletins/`. Those generated files *are* the baseline
of what Vulners serves, which is why the test suite re-checks coherence (and
generator idempotency) offline in CI without a key. Every sampled JSON
(`type_schemas.json`, `collection_map.json`) is regenerable and git-ignored (see
`data-models/.gitignore`).
