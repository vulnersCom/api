"""The ``vulners`` logger, gated by ``VULNERS_LOG`` with key redaction.

Import has no side effects on the root logging config: the library never adds
handlers and never calls ``basicConfig``. ``VULNERS_LOG=info|debug`` only raises
the ``vulners`` logger's own level so an application that opts in sees output.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("vulners")

_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING}


def _configure_from_env() -> None:
    level = os.environ.get("VULNERS_LOG", "").strip().lower()
    if level in _LEVELS:
        logger.setLevel(_LEVELS[level])


_configure_from_env()


class _SecretRedactingFilter(logging.Filter):
    """Mask a known API key anywhere in a formatted log record."""

    def __init__(self, secret: str) -> None:
        super().__init__()
        self._secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secret and isinstance(record.msg, str) and self._secret in record.msg:
            record.msg = record.msg.replace(self._secret, "[REDACTED]")
        if record.args:
            record.args = tuple(
                a.replace(self._secret, "[REDACTED]")
                if isinstance(a, str) and self._secret and self._secret in a
                else a
                for a in (record.args if isinstance(record.args, tuple) else (record.args,))
            )
        return True


def install_key_redaction(secret: str) -> None:
    """Ensure the logger masks *secret* in any record it emits."""
    if not secret:
        return
    for existing in logger.filters:
        if isinstance(existing, _SecretRedactingFilter) and existing._secret == secret:
            return
    logger.addFilter(_SecretRedactingFilter(secret))


__all__ = ["install_key_redaction", "logger"]
