# dev-tools

Maintainer tooling for the Vulners SDK. Not shipped in the wheel — run from a
checkout. Everything here is safe for the public repo: no tool writes or prints
an API key.

## `data-models/` — bulletin data-model sampler & codegen

Keeps the bulletin models (`src/vulners/_models/`) and their reference docs in
sync with the collections Vulners actually serves. The model hierarchy is
**base → family → type**:

- `Bulletin` — fields common to every document (hand-written, `bulletin.py`).
- family models (`CveBulletin`, …) — one per `bulletinFamily` (hand-written).
- per-collection models — one per collection `type`, built lazily by the factory
  in `collections.py` from generated data in `_collections_data.py`. No wall of
  238 hand-written classes; adding a collection is a one-line data change.

Every field's human description lives once in
`src/vulners/_models/_field_descriptions.py` and flows to the models (attribute
docstrings → IDE hover on the hand-written models; `Field(description=…)` on the
factory-built ones) and to the docs.

### Refresh workflow (when Vulners adds collections/fields)

**One command.** Needs an API key — `VULNERS_API_KEY` env, or `[live] api_key = "…"`
in the untracked `tests/live.local.toml`.

```bash
python dev-tools/data-models/sample_collections.py
```

It samples every collection, then updates the repo locally (never commits/pushes):

- if every collection field already has a description in `_field_descriptions.py`,
  it regenerates `_collections_data.py` and the reference docs — done;
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

Committed: `sample_collections.py` and its sibling modules. The baseline of what
Vulners serves is the generated `src/vulners/_models/_collections_data.py` itself,
so the test suite re-checks coherence offline in CI without a key. Every sampled
JSON (`type_schemas.json`, …) is regenerable and git-ignored (see
`data-models/.gitignore`).
