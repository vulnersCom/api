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

Needs an API key — `VULNERS_API_KEY` env, or `[live] api_key = "…"` in the
untracked `tests/live.local.toml`.

```bash
# 1. sample every collection (20 docs each) -> regenerable schema JSONs
python dev-tools/data-models/sample_collections.py --limit 20

# 2. author a description for any NEW field the sampler reports as undescribed,
#    in src/vulners/_models/_field_descriptions.py

# 3. (re)generate the per-collection field data and the reference docs
python dev-tools/data-models/sample_collections.py --emit-models   # -> _collections_data.py
python dev-tools/data-models/sample_collections.py --emit-docs      # -> documentation/reference/

# 4. verify offline (no key): every collection/family/field is modelled & described
python dev-tools/data-models/sample_collections.py --verify
```

New `bulletinFamily` values need a hand-written family model in
`src/vulners/_models/bulletin.py` (families are dynamic; the sampler only
generates the per-`type` layer). `--verify` fails loudly until you add it.

### What is committed vs regenerable

Committed: `sample_collections.py` only. The baseline of what Vulners serves is
the generated `src/vulners/_models/_collections_data.py` itself, so `--verify`
(and the test suite) run offline in CI without a key. Every sampled JSON
(`type_schemas.json`, …) is regenerable and git-ignored (see
`data-models/.gitignore`).
