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
        secret = self._secret
        if not secret:
            return True
        if isinstance(record.msg, str) and secret in record.msg:
            record.msg = record.msg.replace(secret, "[REDACTED]")
        if record.args:
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            redacted: list[object] = []
            for arg in args:
                # httpx logs the request URL as an ``httpx.URL`` (not a str), and
                # a webhooks.read GET carries the key as ``?apiKey=``; stringify so
                # the key is caught before the record is formatted.
                text = str(arg)
                redacted.append(text.replace(secret, "[REDACTED]") if secret in text else arg)
            record.args = tuple(redacted)
        return True


# Loggers whose records can carry the API key: the SDK's own, plus ``httpx``
# (it logs the full request URL — including any ``?apiKey=`` — at INFO).
_REDACTED_LOGGERS = ("vulners", "httpx")


def install_key_redaction(secret: str) -> None:
    """Ensure the ``vulners`` and ``httpx`` loggers mask *secret* in any record."""
    if not secret:
        return
    for name in _REDACTED_LOGGERS:
        target = logging.getLogger(name)
        if any(
            isinstance(existing, _SecretRedactingFilter) and existing._secret == secret
            for existing in target.filters
        ):
            continue
        target.addFilter(_SecretRedactingFilter(secret))


__all__ = ["install_key_redaction", "logger"]
