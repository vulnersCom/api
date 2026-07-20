"""Per-collection (``type``) bulletin models, built lazily from data.

The model hierarchy is **base -> family -> type**. Rather than ship 238
hand-written subclasses, the per-type field data lives in
:mod:`._collections_data` (generated) and :func:`collection_model` materializes a
collection's model on first use with :func:`pydantic.create_model`, inheriting the
family model and adding that collection's fields — each carrying its authored
description from :mod:`._field_descriptions`. Models are cached, so a ``type`` is
built at most once, and only the collections you actually touch are ever built.

    >>> from vulners._models.collections import collection_model
    >>> AixBulletin = collection_model("aix")        # UnixBulletin subclass
    >>> AixBulletin.model_fields["aix_fileset"].description
    'Affected AIX filesets (fileset, product, version).'

Adding a collection is a one-line data change (regenerate ``_collections_data``),
not a new class.
"""

from __future__ import annotations

import keyword
import re
from functools import cache
from typing import Any

from pydantic import Field, create_model

from . import bulletin as _b
from ._collections_data import COLLECTIONS
from ._field_descriptions import FIELD_DESCRIPTIONS

# type token (see the generator's ``_token``) -> field annotation.
_ANN: dict[str, Any] = {
    "str": str | None,
    "int": int | None,
    "float": float | None,
    "bool": bool | None,
    "list": list | None,
    "any": Any,
}

_RESERVED = {"id", "type"}  # base-model field names an extra must never shadow


def _pyname(wire: str) -> str:
    """snake_case Python attribute name for a wire field (kept a valid identifier).

    Leading underscores are stripped (pydantic forbids field names starting with
    ``_``); the original wire name is preserved as the field alias by the caller.
    """
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", wire).lower()
    snake = re.sub(r"__+", "_", snake.replace("-", "_")).lstrip("_")
    if not snake or snake[0].isdigit():
        snake = f"f_{snake}"
    if keyword.iskeyword(snake) or snake in _RESERVED or not snake.isidentifier():
        snake = f"{snake}_"
    return snake


def _classname(ctype: str) -> str:
    pascal = "".join(p[:1].upper() + p[1:] for p in ctype.replace("-", "_").split("_") if p)
    name = f"{pascal}Bulletin"
    return f"C{name}" if name[:1].isdigit() else name  # e.g. `0daydb` -> C0daydbBulletin


@cache
def collection_model(ctype: str) -> type[_b.Bulletin] | None:
    """Return the model for collection *ctype* (a family-model subclass), or None.

    Built on first call and cached. Every added field gets its authored
    description, so IDE/schema tooling explains the field rather than showing a
    bare alias.
    """
    spec = COLLECTIONS.get(ctype)
    if spec is None:
        return None
    base = _b._FAMILY_MODELS.get(spec["family"], _b.GenericBulletin)
    fields: dict[str, Any] = {
        _pyname(wire): (
            _ANN.get(token, Any),
            Field(default=None, alias=wire, description=FIELD_DESCRIPTIONS.get(wire)),
        )
        for wire, token in spec["fields"].items()
    }
    return create_model(_classname(ctype), __base__=base, **fields)


def collection_types() -> list[str]:
    """Every collection ``type`` the SDK models, sorted."""
    return sorted(COLLECTIONS)


__all__ = ["COLLECTIONS", "collection_model", "collection_types"]
