"""Base response model and the recursive validation-free constructor.

``construct_type`` builds pydantic models from already-trusted server JSON
*without* validation, recursing through nested models, lists and dicts. This is
deliberately not :meth:`pydantic.BaseModel.model_construct`, which only builds
the root object and leaves nested data as plain dicts (pydantic does not recurse
there on purpose, issue #8084). The pattern follows openai-python's ``_models``.
"""

from __future__ import annotations

import collections.abc
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, ConfigDict

try:
    from types import UnionType  # 3.10+: X | Y
except ImportError:  # pragma: no cover
    UnionType = None  # type: ignore[assignment, misc]


class VulnersModel(BaseModel):
    """Base for every response model.

    ``extra="allow"`` keeps unknown server fields (forward compatibility: a new
    field never breaks an old client); every subclass field is optional so a
    partial ``fields=`` projection constructs cleanly.
    """

    model_config = ConfigDict(extra="allow")


def _strip_annotated(type_: Any) -> Any:
    while getattr(type_, "__metadata__", None) is not None:
        type_ = get_args(type_)[0]
    return type_


def _is_model(type_: Any) -> bool:
    return isinstance(type_, type) and issubclass(type_, BaseModel)


def construct_type(value: Any, type_: Any) -> Any:
    """Recursively build *type_* from *value* without validation."""
    type_ = _strip_annotated(type_)
    origin = get_origin(type_)

    if type_ is Any or type_ is None:
        return value

    if origin is Union or (UnionType is not None and origin is UnionType):
        args = get_args(type_)
        if value is None and type(None) in args:
            return None
        members = [a for a in args if a is not type(None)]
        # Prefer a model member when the value is a mapping (discriminates the
        # common Optional[Model] / Model | dict case).
        if isinstance(value, collections.abc.Mapping):
            for member in members:
                if _is_model(_strip_annotated(member)):
                    return construct_type(value, member)
        return construct_type(value, members[0]) if members else value

    if origin in (list, collections.abc.Sequence, tuple):
        item_args = get_args(type_)
        item_t = item_args[0] if item_args else Any
        if isinstance(value, list):
            return [construct_type(v, item_t) for v in value]
        return value

    if origin in (dict, collections.abc.Mapping):
        args = get_args(type_)
        if isinstance(value, collections.abc.Mapping) and len(args) == 2:
            val_t = args[1]
            return {k: construct_type(v, val_t) for k, v in value.items()}
        return value

    if _is_model(type_):
        if isinstance(value, type_):
            return value
        if isinstance(value, collections.abc.Mapping):
            return _construct_model(type_, value)
        return value

    return value


def _construct_model(model_cls: type[BaseModel], data: collections.abc.Mapping[Any, Any]) -> Any:
    """Build one model, resolving field aliases and recursing into field types."""
    values: dict[str, Any] = {}
    fields_set: set[str] = set()
    consumed: set[Any] = set()

    for name, field in model_cls.model_fields.items():
        wire_key = field.alias or name
        if wire_key in data:
            key = wire_key
        elif name in data:
            key = name
        else:
            continue
        consumed.add(key)
        values[name] = construct_type(data[key], field.annotation)
        fields_set.add(name)

    # Preserve unknown fields as raw extras (extra="allow"); they are trusted
    # server data, so they pass through unconstructed.
    for key, raw in data.items():
        if key in consumed or key in values:
            continue
        values[key] = raw
        fields_set.add(key)

    return model_cls.model_construct(_fields_set=fields_set, **values)


__all__ = ["VulnersModel", "construct_type"]
