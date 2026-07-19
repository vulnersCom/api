"""Bulletin response models: a ``bulletinFamily`` discriminated hierarchy.

Construction stays validation-free (see :func:`construct_type`); this module adds
the family/version *shape* on top. A payload's ``bulletinFamily`` selects a
concrete subclass through :func:`construct_bulletin`, with :class:`GenericBulletin`
as the forward-compatible fallback, and a payload's CVSS ``version`` selects the
matching :class:`Cvss` subclass via the discriminator registry.

Scope for 4.0.0 is the handful of families that carry a distinct field set and
dominate real corpora (CVE/NVD, exploit, scanner, software advisory, info); every
other family lands in :class:`GenericBulletin`. Widening the hierarchy is a 4.x
minor, and because construction never validates, an under-typed family is safe.

An opt-in *strict* path (:func:`construct_bulletin` with ``strict=True``) runs
full pydantic validation: it selects the family model from :data:`_FAMILY_MODELS`
(the single source of truth) and validates through
:meth:`~pydantic.BaseModel.model_validate` instead of the construct fast path.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field

from ._base import VulnersModel, construct_type, register_discriminator

# ---------------------------------------------------------------------------
# CVSS — a union by Literal version
# ---------------------------------------------------------------------------


class Cvss(VulnersModel):
    """CVSS score block; the base/fallback across scoring versions."""

    version: str | None = None
    score: float | None = None
    vector: str | None = None


class Cvss2(Cvss):
    """CVSS v2 metrics."""


class Cvss3(Cvss):
    """CVSS v3.x metrics (adds a qualitative severity band)."""

    severity: str | None = None


class Cvss4(Cvss):
    """CVSS v4.0 metrics."""

    severity: str | None = None


# ``version`` picks the concrete model; an absent/unknown version stays ``Cvss``.
_CVSS_VERSIONS: dict[Any, type[Cvss]] = {
    "2.0": Cvss2,
    "3.0": Cvss3,
    "3.1": Cvss3,
    "4.0": Cvss4,
}
register_discriminator(Cvss, "version", _CVSS_VERSIONS, Cvss)


# ---------------------------------------------------------------------------
# Bulletin base + family hierarchy
# ---------------------------------------------------------------------------


class Bulletin(VulnersModel):
    """A single Vulners document; base for every ``bulletinFamily``."""

    id: str | None = None
    title: str | None = None
    description: str | None = None
    type: str | None = None
    bulletin_family: str | None = Field(default=None, alias="bulletinFamily")
    cvss: Cvss | None = None
    published: str | None = None
    modified: str | None = None
    last_seen: str | None = Field(default=None, alias="lastseen")
    href: str | None = None
    source_href: str | None = Field(default=None, alias="sourceHref")
    source_data: str | None = Field(default=None, alias="sourceData")
    cvelist: list[str] | None = None


class GenericBulletin(Bulletin):
    """Fallback for any family without a dedicated model (forward-compat)."""


class CveBulletin(Bulletin):
    """``bulletinFamily: NVD`` — a CVE record and its scoring/enrichment."""

    cvss2: Cvss | None = None
    cvss3: Cvss | None = None
    cpe: list[str] | None = None
    cwe: list[str] | None = None
    epss: list[Any] | None = None


class ExploitBulletin(Bulletin):
    """``bulletinFamily: exploit`` — exploit code and its provenance."""

    reporter: str | None = None
    references: list[str] | None = None


class ScannerBulletin(Bulletin):
    """``bulletinFamily: scanner`` — a vulnerability-scanner plugin."""

    reporter: str | None = None
    cpe: list[str] | None = None


class SoftwareBulletin(Bulletin):
    """``bulletinFamily: software`` — an OS/vendor package advisory."""

    affected_package: list[Any] | None = Field(default=None, alias="affectedPackage")


class InfoBulletin(Bulletin):
    """``bulletinFamily: info`` — news, blog and advisory write-ups."""

    reporter: str | None = None
    references: list[str] | None = None


# ``bulletinFamily`` -> concrete model. Kept to the 5 highest-signal families;
# everything else is a GenericBulletin.
_FAMILY_MODELS: dict[Any, type[Bulletin]] = {
    "NVD": CveBulletin,
    "exploit": ExploitBulletin,
    "scanner": ScannerBulletin,
    "software": SoftwareBulletin,
    "info": InfoBulletin,
}


def bulletin_class_for(data: Any) -> type[Bulletin]:
    """Return the model to build for *data*, by its ``bulletinFamily``."""
    if isinstance(data, Mapping):
        return _FAMILY_MODELS.get(data.get("bulletinFamily"), GenericBulletin)
    return GenericBulletin


# ---------------------------------------------------------------------------
# Opt-in strict validation path (module-level TypeAdapter)
# ---------------------------------------------------------------------------


def _family_tag(value: Any) -> str:
    if isinstance(value, Mapping):
        family = value.get("bulletinFamily", value.get("bulletin_family"))
    else:
        family = getattr(value, "bulletin_family", None)
    return str(family) if family in _FAMILY_MODELS else "generic"


def construct_bulletin(data: Any, *, strict: bool = False) -> Bulletin:
    """Build the family-specific :class:`Bulletin` for *data*.

    ``strict=True`` runs full pydantic validation: it selects the family model
    from :data:`_FAMILY_MODELS` (the single source of truth shared with the
    non-strict path via :func:`_family_tag`) and validates through
    ``model_validate``. The default construct path never validates.
    """
    if strict:
        model = _FAMILY_MODELS.get(_family_tag(data), GenericBulletin)
        return model.model_validate(data)
    return construct_type(data, bulletin_class_for(data))


__all__ = [
    "Bulletin",
    "CveBulletin",
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "ExploitBulletin",
    "GenericBulletin",
    "InfoBulletin",
    "ScannerBulletin",
    "SoftwareBulletin",
    "bulletin_class_for",
    "construct_bulletin",
]
