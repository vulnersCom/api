"""Configuration loader for opt-in live tests against the real Vulners API.

Key sources, in order:
1. VULNERS_API_KEY environment variable (optionally VULNERS_SERVER_URL);
2. tests/live.local.toml (never committed; see .gitignore), expected shape:

    [live]
    api_key = "..."
    # server_url = "https://vulners.com"   # optional

Without a key every test marked "live" is skipped at collection time. Live
tests are structural only — no assertions on concrete vulnerabilities or
counts (the database is dynamic) — and must keep the key and echoed request
input out of assertion messages and logs (the server echoes input in
validation errors).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import vulners

_LOCAL_TOML = Path(__file__).resolve().parents[1] / "live.local.toml"
_DEFAULT_SERVER = "https://vulners.com"


def _load_live_config() -> tuple[str, str] | None:
    key = os.environ.get("VULNERS_API_KEY")
    if key:
        return key, os.environ.get("VULNERS_SERVER_URL", _DEFAULT_SERVER)
    if _LOCAL_TOML.exists():
        try:
            import tomllib
        except ModuleNotFoundError:  # Python 3.10: no stdlib toml reader, env var only
            return None
        with _LOCAL_TOML.open("rb") as fh:
            data = tomllib.load(fh)
        section = data.get("live", data)
        if isinstance(section, dict):
            key = section.get("api_key")
            if isinstance(key, str) and key:
                server = section.get("server_url", _DEFAULT_SERVER)
                return key, server if isinstance(server, str) and server else _DEFAULT_SERVER
    return None


_CONFIG = _load_live_config()


def pytest_collection_modifyitems(config, items):
    if _CONFIG is not None:
        return
    no_key = pytest.mark.skip(
        reason="live API key not configured (VULNERS_API_KEY or tests/live.local.toml)"
    )
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(no_key)


@pytest.fixture(scope="session")
def live_config() -> tuple[str, str]:
    assert _CONFIG is not None  # unreachable without a key: live tests are skipped above
    return _CONFIG


@pytest.fixture
def live_api(live_config):
    key, server_url = live_config
    api = vulners.VulnersApi(key, server_url=server_url)
    yield api
    api._client.close()
