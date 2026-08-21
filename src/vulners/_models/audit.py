"""Response model for the package-metadata (license) audit lookup.

Hand-written like the value objects in :mod:`._nested`: the shape is small and
fixed, and it carries the ``found`` convenience that reads the endpoint's
"unknown package" signal (an empty ``range``).
"""

from __future__ import annotations

from ._base import VulnersModel


class PackageMetadata(VulnersModel):
    """License and version-range metadata for a single registry package.

    Returned by :meth:`vulners._resources._sync.audit.Audit.metadata`. ``license``
    is always a list — an empty list means a *known* package has no recorded
    license. Use :attr:`found` to tell that apart from a package name the registry
    does not know, which the endpoint answers (with HTTP 200) as an empty ``range``.
    """

    name: str | None = None
    """The package name echoed back by the registry."""
    version: str | None = None
    """The queried package version."""
    range: str | None = None
    """The version range this metadata covers; empty when the package name is unknown."""
    license: list[str] | None = None
    """SPDX-style license identifiers; an empty list when the registry records none."""

    @property
    def found(self) -> bool:
        """Whether the registry knows this package name.

        The endpoint answers HTTP 200 even for an unknown name, returning an empty
        ``range``; ``found`` is then ``False``. A ``True`` value with an empty
        :attr:`license` means the package is known but has no recorded license.
        """
        return bool(self.range)


__all__ = ["PackageMetadata"]
