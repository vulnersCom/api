"""Per-collection (``type``) bulletin models, built lazily from data.

The model hierarchy is **base -> family -> type**. Rather than ship 238
hand-written subclasses, the per-type field data lives in
:mod:`._collections_data` (generated) and :func:`collection_model` materializes a
collection's model on first use with :func:`pydantic.create_model`, inheriting the
family model and adding that collection's fields — each carrying its authored
description from :mod:`._field_descriptions`. A type is built at most once (under
a lock, so concurrent first constructions share one class), registered as a module
attribute (so instances pickle), and cached; only the collections you actually
touch are ever built.

Per-type classes subclass their family model, and the family models are the
public ``isinstance``/annotation surface::

    from vulners import UnixBulletin

    bulletin = client.search.query("type:aix", limit=1).data[0]
    assert isinstance(bulletin, UnixBulletin)   # AixBulletin extends UnixBulletin

Adding a collection is a one-line data change (regenerate ``_collections_data``),
not a new class.
"""

from __future__ import annotations

import keyword
import re
import threading
from typing import Any

from pydantic import Field, create_model

from . import bulletin as _b
from ._collections_data import COLLECTIONS
from ._field_descriptions import FIELD_DESCRIPTIONS

# type token -> field annotation. The single token vocabulary: the generator
# (dev-tools/data-models/_emit_models.py) imports this mapping and refuses to
# emit a token that is not a key here.
_ANN: dict[str, Any] = {
    "str": str | None,
    "int": int | None,
    "float": float | None,
    "bool": bool | None,
    "list": list | None,
    "any": Any,
}

# Built models: collection type -> its class. Guarded by _BUILD_LOCK on write so
# racing first constructions of one type still yield a single class object.
_MODELS: dict[str, type[_b.Bulletin]] = {}
_BUILD_LOCK = threading.Lock()


def _pyname(wire: str, taken: set[str]) -> str:
    """snake_case Python attribute name for a wire field, kept a valid identifier
    and guaranteed not to collide with *taken* (base/family attributes and the
    collection's other fields) — a collision would silently override an inherited
    field's annotation and alias, misrouting data.

    Leading underscores are stripped (pydantic forbids them in field names); the
    original wire name is preserved as the field alias by the caller.
    """
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", wire).lower()
    snake = re.sub(r"__+", "_", snake.replace("-", "_")).lstrip("_")
    if not snake or snake[0].isdigit():
        snake = f"f_{snake}"
    if keyword.iskeyword(snake) or not snake.isidentifier():
        snake = f"{snake}_"
    while snake in taken:
        snake = f"{snake}_"
    return snake


def _classname(ctype: str) -> str:
    pascal = "".join(p[:1].upper() + p[1:] for p in ctype.replace("-", "_").split("_") if p)
    name = f"{pascal}Bulletin"
    if name[:1].isdigit():  # e.g. `0daydb` -> keep a valid Python identifier
        name = f"C{name}"
    if name in _FAMILY_NAMES:  # e.g. the `cve` type vs the CveBulletin family model
        name = name.replace("Bulletin", "CollectionBulletin")
    return name


_FAMILY_NAMES = {m.__name__ for m in set(_b._FAMILY_MODELS.values())} | {
    "Bulletin",
    "GenericBulletin",
}


def _build(ctype: str, spec: dict) -> type[_b.Bulletin]:
    """Create the pydantic model for one collection (called under _BUILD_LOCK)."""
    base = _b._FAMILY_MODELS.get(spec["family"], _b.GenericBulletin)
    taken = set(base.model_fields)
    fields: dict[str, Any] = {}
    for wire, token in spec["fields"].items():
        name = _pyname(wire, taken)
        taken.add(name)
        fields[name] = (
            _ANN.get(token, Any),
            Field(default=None, alias=wire, description=FIELD_DESCRIPTIONS.get(wire)),
        )
    model = create_model(_classname(ctype), __base__=base, **fields)
    # Register as a module attribute so instances pickle (pickle resolves classes
    # by module + qualname); class names are unique across collections (tested).
    globals()[model.__name__] = model
    return model


def _build_locked(ctype: str, spec: dict) -> type[_b.Bulletin]:
    """Build-or-reuse under the lock (double-checked so races share one class)."""
    with _BUILD_LOCK:
        model = _MODELS.get(ctype)
        if model is None:
            model = _build(ctype, spec)
            _MODELS[ctype] = model
        return model


def collection_model(ctype: object) -> type[_b.Bulletin] | None:
    """Return the model for collection *ctype* (a family-model subclass), or None.

    Built on first call and cached. Tolerant of arbitrary server data: a non-str
    (even unhashable) *ctype* or an unknown collection returns None — nothing is
    cached for misses, so memory stays bounded by the known collection set.
    """
    if not isinstance(ctype, str):
        return None
    model = _MODELS.get(ctype)
    if model is not None:
        return model
    spec = COLLECTIONS.get(ctype)
    if spec is None:
        return None
    return _build_locked(ctype, spec)


def collection_types() -> list[str]:
    """Every collection ``type`` the SDK models, sorted."""
    return sorted(COLLECTIONS)


__all__ = ["COLLECTIONS", "collection_model", "collection_types"]
