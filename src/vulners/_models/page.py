"""Lean page container for search results.

A minimal iterable page carrying the returned rows and the total match count.
Cursor/window helpers (``next_page``, ``SearchWindowExceeded`` on auto-iteration)
land with the pagination work package; this first slice exposes ``data`` +
``total`` and direct iteration.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass
class SearchPage(Generic[T]):
    """One page of search results."""

    data: list[T] = field(default_factory=list)
    total: int | None = None

    def __iter__(self) -> Iterator[T]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, index: int) -> T:
        return self.data[index]

    def __repr__(self) -> str:
        # Explicit repr (not dataclass-generated, which reprlib wraps) keeps this
        # from being scanned as a codegen endpoint by the test suite.
        return f"SearchPage(total={self.total}, count={len(self.data)})"


__all__ = ["SearchPage"]
