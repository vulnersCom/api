"""The data-driven field layers shared by the model and doc generators.

``derive_layers`` partitions the sampled fields into the three-level taxonomy the
whole toolset is cut by (see :mod:`_emit_bulletins` for the emitted models and
:mod:`_emit_docs` for the reference pages).
"""

from __future__ import annotations

from collections import defaultdict


def derive_layers(type_schemas: dict) -> tuple[set[str], dict[str, set[str]]]:
    """Data-driven field layers from the samples — the taxonomy the per-collection
    models and the reference docs share:

    * ``base``      — wire fields present in EVERY sampled document across all
      collections (the global intersection);
    * ``family[F]`` — wire fields present in every sampled document of
      ``bulletinFamily`` F, minus ``base``.

    A collection's remaining fields are collection-specific. ``presence == 1.0``
    means "the server sent the key in every sampled document of that collection"
    (field-presence, empty counts — presence is rounded to 2dp, exact at the tens
    of docs the sampler pulls). Collections that errored this run carry
    ``presence=None`` and are skipped so they cannot empty the intersections.
    """
    always = {
        t: {f for f, m in ti.get("fields", {}).items() if m.get("presence") == 1.0}
        for t, ti in type_schemas.items()
        if any(m.get("presence") is not None for m in ti.get("fields", {}).values())
    }
    if not always:
        return set(), {}
    base = set.intersection(*always.values())
    by_fam: dict[str, list[set[str]]] = defaultdict(list)
    for t, present in always.items():
        fam = type_schemas[t].get("bulletinFamily")
        if fam:
            by_fam[fam].append(present)
    family = {fam: set.intersection(*sets) - base for fam, sets in by_fam.items()}
    return base, family
