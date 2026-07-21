"""Bulletin construction machinery.

The model classes are **generated** — the whole ``base -> family -> type``
hierarchy lives in the :mod:`.bulletins` package (source of truth:
``dev-tools/data-models``), imported explicitly there so IDEs and type checkers
see every class. This module keeps the runtime that selects and builds the most
specific model for a payload, and re-exports :class:`Bulletin`/:class:`GenericBulletin`
and the nested value objects.

A payload's ``type`` selects the per-collection model (:data:`.bulletins.TYPE_MODELS`),
falling back to its ``bulletinFamily`` model (:data:`.bulletins.FAMILY_MODELS`), with
:class:`GenericBulletin` as the forward-compatible fallback. Construction stays
validation-free (see :func:`construct_type`); an opt-in *strict* path
(:func:`construct_bulletin` with ``strict=True``) runs full pydantic validation
against the same class the fast path would build.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._base import construct_type, register_discriminator
from ._nested import Cvss, Cvss2, Cvss3, Cvss4, Enchantments, EpssScore, Timestamps
from .bulletins import FAMILY_MODELS, TYPE_MODELS, Bulletin, GenericBulletin

# Legacy ``bulletinFamily`` tags the live API no longer emits (so the generator no
# longer models them) but older documents/mirrors still carry — mapped to the
# current family so they keep resolving to the right model. Not the family list
# (that is generated); just backward-compatible aliases.
_FAMILY_ALIASES = {"NVD": "cve"}


def _family_model(data: Any) -> type[Bulletin]:
    """Family model for *data*, read from ``bulletinFamily``/``bulletin_family``
    (mapping key or attribute), falling back to :class:`GenericBulletin`.

    Shared by the strict and non-strict paths, so a snake_case round-trip
    (``model_dump()`` output) resolves identically on both. Tolerant of arbitrary
    values: a non-str family is the fallback.
    """
    if isinstance(data, Mapping):
        family = data.get("bulletinFamily", data.get("bulletin_family"))
    else:
        family = getattr(data, "bulletin_family", None)
    if isinstance(family, str):
        return FAMILY_MODELS.get(_FAMILY_ALIASES.get(family, family), GenericBulletin)
    return GenericBulletin


def bulletin_class_for(data: Any) -> type[Bulletin]:
    """Return the most specific model to build for *data*.

    A known ``type`` selects the per-collection model; otherwise the family (via
    :func:`_family_model`) is selected, falling back to :class:`GenericBulletin`.
    Never raises on malformed server data — an unusable ``type``/``bulletinFamily``
    value just degrades the fallback chain.
    """
    if isinstance(data, Mapping):
        ctype = data.get("type")
        if isinstance(ctype, str):
            model = TYPE_MODELS.get(ctype)
            if model is not None:
                return model
        return _family_model(data)
    return GenericBulletin


# Register Bulletin in the generic discriminator registry so ANY field annotated
# ``Bulletin`` (or list[Bulletin], …) specializes through construct_type exactly
# like a direct construct_bulletin call — same mechanism the CVSS union uses.
register_discriminator(
    Bulletin, "bulletinFamily", {}, GenericBulletin, resolver=bulletin_class_for
)


def construct_bulletin(data: Any, *, strict: bool = False) -> Bulletin:
    """Build the most specific :class:`Bulletin` for *data*.

    ``strict=True`` runs full pydantic validation through ``model_validate``
    against the SAME class the fast path would construct (per-collection model
    first, then family, then :class:`GenericBulletin`) — so class identity never
    depends on which path built the object. A non-mapping input (e.g. an already
    constructed model) validates against its family model, read from its
    ``bulletin_family`` attribute. The default construct path never validates.
    """
    if strict:
        cls = bulletin_class_for(data) if isinstance(data, Mapping) else _family_model(data)
        return cls.model_validate(data)
    return construct_type(data, Bulletin)


__all__ = [
    "FAMILY_MODELS",
    "TYPE_MODELS",
    "Bulletin",
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "Enchantments",
    "EpssScore",
    "GenericBulletin",
    "Timestamps",
    "bulletin_class_for",
    "construct_bulletin",
]
