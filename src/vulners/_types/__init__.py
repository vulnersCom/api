"""Shared v4-core sentinels and request-option typing.

Two distinct "no value" sentinels, both falsy so ``if value:`` skips them:

* ``not_given`` (:class:`NotGiven`) — the caller did not pass the argument at
  all. It is the default of every optional keyword so an omitted argument is
  distinguishable from an explicit ``None`` (which means "send null").
* ``omit`` (:class:`Omit`) — actively drop a value that would otherwise be sent
  (e.g. suppress a default header).

Both singletons return :data:`typing.Literal[False]` from ``__bool__`` so a type
checker knows ``bool(not_given)`` is always ``False``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, TypeAlias

import httpx
from typing_extensions import TypedDict


class NotGiven:
    """Sentinel for an argument the caller never supplied.

    Distinct from ``None``: ``timeout=None`` means "no timeout", while a
    ``timeout`` left at :data:`not_given` means "use the client default".
    """

    def __bool__(self) -> Literal[False]:
        return False

    def __repr__(self) -> str:
        return "NOT_GIVEN"


class Omit:
    """Sentinel that removes a value which would otherwise be sent.

    Passing ``omit`` for a header/param drops it from the request instead of
    sending an empty value.
    """

    def __bool__(self) -> Literal[False]:
        return False

    def __repr__(self) -> str:
        return "omit"


not_given: NotGiven = NotGiven()
omit: Omit = Omit()

# Type aliases shared across the core.
Headers: TypeAlias = Mapping[str, "str | Omit"]
Query: TypeAlias = Mapping[str, object]
Body: TypeAlias = object
# Concrete timeout input the client accepts.
TimeoutTypes: TypeAlias = "float | httpx.Timeout | None"


class RequestOptions(TypedDict, total=False):
    """Per-request overrides threaded through the request pipeline."""

    headers: Mapping[str, str | Omit]
    params: Mapping[str, object]
    timeout: float | httpx.Timeout | None
    max_retries: int
    extra_json: Mapping[str, object]


__all__ = [
    "Body",
    "Headers",
    "NotGiven",
    "Omit",
    "Query",
    "RequestOptions",
    "TimeoutTypes",
    "not_given",
    "omit",
]
