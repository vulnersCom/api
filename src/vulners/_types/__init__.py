"""Shared v4-core sentinels.

Two distinct "no value" sentinels, both falsy so ``if value:`` skips them:

* ``not_given`` (:class:`NotGiven`) — the caller did not pass the argument at
  all. It is the default of every optional keyword so an omitted argument is
  distinguishable from an explicit ``None`` (which means "send null").
* ``omit`` (:class:`Omit`) — an *internal* sentinel that actively drops a value
  which would otherwise be sent (e.g. suppress a default header in the request
  pipeline). It is not part of the public method surface.

Both singletons return :data:`typing.Literal[False]` from ``__bool__`` so a type
checker knows ``bool(not_given)`` is always ``False``.
"""

from __future__ import annotations

from typing import Literal


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
    """Internal sentinel that removes a value which would otherwise be sent.

    Passing ``omit`` for a header in the request pipeline drops it instead of
    sending an empty value. Used internally only.
    """

    def __bool__(self) -> Literal[False]:
        return False

    def __repr__(self) -> str:
        return "omit"


not_given: NotGiven = NotGiven()
omit: Omit = Omit()


__all__ = [
    "NotGiven",
    "Omit",
    "not_given",
    "omit",
]
