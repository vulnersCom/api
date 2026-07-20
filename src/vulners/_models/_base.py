"""Base response model and the recursive validation-free constructor.

``construct_type`` builds pydantic models from already-trusted server JSON
*without* validation, recursing through nested models, lists and dicts. This is
deliberately not :meth:`pydantic.BaseModel.model_construct`, which only builds
the root object and leaves nested data as plain dicts (pydantic does not recurse
there on purpose, issue #8084). The pattern follows openai-python's ``_models``.

A small discriminator registry lets a model class stand in for a family of
subclasses: when a registered base is met during construction, the concrete
subclass is chosen from a field in the payload (e.g. ``version`` picks the CVSS
model), falling back to the base when the tag is unknown. This keeps the
validation-free construct path while still returning the specific type.
"""

from __future__ import annotations

import collections.abc
from functools import cache
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, ConfigDict

try:
    from types import UnionType  # 3.10+: X | Y
except ImportError:  # pragma: no cover
    UnionType = None  # type: ignore[assignment, misc]

# Distinguishes "key absent" from a legitimate ``None`` value when popping the
# one server field name that would collide with model_construct's kwarg.
_UNSET: Any = object()


class VulnersModel(BaseModel):
    """Base for every response model.

    ``extra="allow"`` keeps unknown server fields (forward compatibility: a new
    field never breaks an old client); every subclass field is optional so a
    partial ``fields=`` projection constructs cleanly.

    ``use_attribute_docstrings=True`` promotes each field's attribute docstring
    to its ``description``, so one authored line serves the JSON schema, the docs
    and IDE hover (Pylance/basedpyright surface attribute docstrings; they do not
    surface ``Field(description=...)``). Pydantic reads the docstring from source;
    a model with no source available (never the case for these file-defined
    models) simply gets no description.

    ``validate_by_name=True`` lets the strict validation path accept the python
    (snake_case) spelling of aliased fields alongside the wire spelling — matching
    what the construct fast path already does, so a ``model_dump()`` round-trip
    keeps its data on either path.
    """

    model_config = ConfigDict(extra="allow", use_attribute_docstrings=True, validate_by_name=True)


class Discriminator:
    """Picks a concrete subclass for a payload from one tag field.

    ``mapping`` maps the tag value (read from ``field`` in the payload) to the
    subclass to build; an unknown or missing tag falls back to ``fallback``. A
    custom ``resolver`` callable replaces the mapping lookup entirely (used for
    multi-level dispatch like bulletin type -> family).
    """

    __slots__ = ("fallback", "field", "mapping", "resolver")

    def __init__(
        self,
        field: str,
        mapping: collections.abc.Mapping[Any, type[BaseModel]],
        fallback: type[BaseModel],
        resolver: collections.abc.Callable[[Any], type[BaseModel]] | None = None,
    ) -> None:
        self.field = field
        self.mapping = dict(mapping)
        self.fallback = fallback
        self.resolver = resolver

    def resolve(self, value: collections.abc.Mapping[Any, Any]) -> type[BaseModel]:
        if self.resolver is not None:
            return self.resolver(value)
        return self.mapping.get(value.get(self.field), self.fallback)


# base model class -> its discriminator. Populated by model modules (e.g. the
# bulletin module registers the CVSS-by-version discriminator on ``Cvss`` and
# the type/family resolver on ``Bulletin``).
_DISCRIMINATORS: dict[type[BaseModel], Discriminator] = {}


def register_discriminator(
    base: type[BaseModel],
    field: str,
    mapping: collections.abc.Mapping[Any, type[BaseModel]],
    fallback: type[BaseModel] | None = None,
    resolver: collections.abc.Callable[[Any], type[BaseModel]] | None = None,
) -> None:
    """Register *base* so ``construct_type`` discriminates it by *field* (or via
    a custom *resolver* callable for multi-level dispatch)."""
    _DISCRIMINATORS[base] = Discriminator(field, mapping, fallback or base, resolver)


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
            target = type_
            disc = _DISCRIMINATORS.get(type_)
            if disc is not None:
                target = disc.resolve(value)
            return _construct_model(target, value)
        return value

    return value


def _is_passthrough(type_: Any) -> bool:
    """Whether ``construct_type`` can never transform a value of this annotation.

    True for plain scalars, ``Any``/``None``, and unions whose every non-``None``
    member is itself passthrough (crucially ``str | None`` / ``Optional[scalar]``,
    where construct_type returns the value unchanged for both a scalar and
    ``None``). False for model fields and list/tuple/dict fields (which build a
    fresh container) and unions that contain a model or container — matching what
    ``construct_type`` actually does, so skipping the call is byte-identical.
    """
    type_ = _strip_annotated(type_)
    if type_ is Any or type_ is None:
        return True
    origin = get_origin(type_)
    if origin is Union or (UnionType is not None and origin is UnionType):
        return all(_is_passthrough(a) for a in get_args(type_) if a is not type(None))
    if origin is not None:
        return False  # list / tuple / dict / Sequence / Mapping -> fresh container
    return not _is_model(type_)


# Per-model construction plan: (attr_name, wire_key, passthrough, annotation) for
# each field, so _construct_model does a dict lookup + one branch per field instead
# of re-deriving the typing dispatch (get_origin/get_args/_strip_annotated) per row.
_Plan = tuple[tuple[str, str, bool, Any], ...]


# simplification: unbounded cache (functools.cache); a model's fields are fixed
# per class (models never generate them dynamically), so this is bounded by the
# finite model set. It memoizes the per-field passthrough classification too, so
# _is_passthrough runs once per field, not per row. Revisit only if models become
# dynamic.
@cache
def _model_plan(model_cls: type[BaseModel]) -> _Plan:
    return tuple(
        (name, field.alias or name, _is_passthrough(field.annotation), field.annotation)
        for name, field in model_cls.model_fields.items()
    )


def _construct_model(model_cls: type[BaseModel], data: collections.abc.Mapping[Any, Any]) -> Any:
    """Build one model, resolving field aliases and recursing into field types."""
    values: dict[str, Any] = {}
    fields_set: set[str] = set()
    consumed: set[Any] = set()

    for name, wire_key, passthrough, annotation in _model_plan(model_cls):
        if wire_key in data:
            key = wire_key
        elif name in data:
            key = name
        else:
            continue
        consumed.add(key)
        raw = data[key]
        values[name] = raw if passthrough else construct_type(raw, annotation)
        fields_set.add(name)

    # Preserve unknown fields as raw extras (extra="allow"); they are trusted
    # server data, so they pass through unconstructed.
    for key, raw in data.items():
        if key in consumed or key in values:
            continue
        values[key] = raw
        fields_set.add(key)

    # ``_fields_set`` is the sole reserved kwarg of model_construct; a server
    # field literally named that would raise "multiple values for keyword
    # argument". Keep it out of **values and reattach it as an extra so an
    # unexpected field name never breaks construction.
    reserved = values.pop("_fields_set", _UNSET)
    model = model_cls.model_construct(_fields_set=fields_set, **values)
    if reserved is not _UNSET:
        # extra="allow" makes __pydantic_extra__ a dict; guard None only in case a
        # non-allow model is ever constructed through this generic helper.
        if model.__pydantic_extra__ is None:  # pragma: no cover
            model.__pydantic_extra__ = {}
        model.__pydantic_extra__["_fields_set"] = reserved
    return model


__all__ = ["Discriminator", "VulnersModel", "construct_type", "register_discriminator"]
