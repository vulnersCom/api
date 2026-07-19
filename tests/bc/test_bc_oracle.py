"""Backward-compatibility oracle gate.

Pins the public surface and the exact on-the-wire requests of the v3 SDK against
the baseline recorded from the real ``vulners==3.2.0`` build (``surface.json``,
``golden/wire.json``). On the v4 branch this proves the deprecated shims never
drift from 3.2.0; today it guards the src-layout/packaging refactor.

``tests/bc`` is a read-only oracle zone — regenerate the baselines with the
scripts, never hand-edit the golden files.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))

from wire_baseline import CALLS, record_call  # noqa: E402

SURFACE_BASELINE = HERE / "surface.json"
WIRE_BASELINE = HERE / "golden" / "wire.json"


def _normalize_version(surface: dict) -> dict:
    surface = dict(surface)
    surface["version"] = "{VERSION}"
    return surface


def _live_snapshot() -> dict:
    # Snapshot in a clean subprocess: test-time autouse fixtures (which patch
    # vulners.base at runtime) must not leak into the recorded surface.
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "bc_snapshot.py")],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


class TestSurface:
    def test_public_surface_matches_baseline(self):
        baseline = _normalize_version(json.loads(SURFACE_BASELINE.read_text("utf-8")))
        current = _normalize_version(_live_snapshot())
        assert current == baseline, "public API surface drifted from the 3.2.0 baseline"

    def test_baseline_recorded_from_3_2_0(self):
        baseline = json.loads(SURFACE_BASELINE.read_text("utf-8"))
        assert baseline["version"] == "3.2.0"


@pytest.mark.filterwarnings("ignore::vulners.VulnersDeprecationWarning")
class TestWire:
    WIRE = json.loads(WIRE_BASELINE.read_text("utf-8"))

    def test_golden_covers_every_call(self):
        names = {name for name, _ in CALLS}
        assert set(self.WIRE) == names
        assert not [k for k, v in self.WIRE.items() if "error" in v]

    @pytest.mark.parametrize("name,fn", CALLS, ids=[name for name, _ in CALLS])
    def test_wire_matches_baseline(self, name, fn):
        assert record_call(fn) == self.WIRE[name], f"{name} wire drifted from the 3.2.0 baseline"
