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


def _surface_violations(baseline: dict, current: dict, *, check_signatures: bool) -> list[str]:
    """Backward-compat is *subset* preservation, not equality.

    Every v3 (3.2.0) symbol must still exist with the same kind; v4 may add new
    public names/classes and may *add* deprecation markers (False->True), but must
    never remove a symbol, change a member's kind, or un-deprecate one.

    Signature *strings* are only compared when the running interpreter matches the
    Python version the baseline was recorded on (``check_signatures``): the repr of
    typed signatures shifts across Python versions, which is not a BC change of
    ours. Member names/kinds are version-robust (builtin-inherited members are
    excluded from the snapshot) and are always checked.
    """
    errs: list[str] = []
    for mod, binfo in baseline["modules"].items():
        cinfo = current["modules"].get(mod)
        if cinfo is None:
            errs.append(f"module removed: {mod}")
            continue
        if binfo["all"] is not None:
            dropped = set(binfo["all"]) - set(cinfo["all"] or [])
            if dropped:
                errs.append(f"{mod}.__all__ dropped: {sorted(dropped)}")
        dropped_names = set(binfo["public_names"]) - set(cinfo["public_names"])
        if dropped_names:
            errs.append(f"{mod} public names dropped: {sorted(dropped_names)}")
    for cls, binfo in baseline["classes"].items():
        cinfo = current["classes"].get(cls)
        if cinfo is None:
            errs.append(f"class removed: {cls}")
            continue
        if binfo["bases"] != cinfo["bases"]:
            errs.append(f"{cls} bases changed: {binfo['bases']} -> {cinfo['bases']}")
        for mname, bmem in binfo["members"].items():
            cmem = cinfo["members"].get(mname)
            if cmem is None:
                errs.append(f"{cls}.{mname} removed")
                continue
            if bmem.get("kind") != cmem.get("kind"):
                errs.append(
                    f"{cls}.{mname} kind changed: {bmem.get('kind')} -> {cmem.get('kind')}"
                )
            if check_signatures and bmem.get("signature") != cmem.get("signature"):
                errs.append(f"{cls}.{mname} signature changed")
            if bmem.get("deprecated") and not cmem.get("deprecated"):
                errs.append(f"{cls}.{mname} un-deprecated")
    return errs


class TestSurface:
    def test_v3_surface_preserved(self):
        baseline = json.loads(SURFACE_BASELINE.read_text("utf-8"))
        current = _live_snapshot()
        # Signature reprs are Python-version-specific; only compare them when
        # running the interpreter the baseline was recorded on. Names/kinds
        # (version-robust) are always checked, on every interpreter.
        check_sigs = current.get("python") == baseline.get("python")
        violations = _surface_violations(baseline, current, check_signatures=check_sigs)
        assert not violations, "v3 public surface broke BC:\n" + "\n".join(violations)

    def test_v4_api_added_additively(self):
        # The additive v4 surface is present without disturbing v3.
        current = _live_snapshot()
        root_all = set(current["modules"]["vulners"]["all"] or [])
        assert {"Vulners", "AsyncVulners"} <= root_all
        # v3 names still exported too.
        assert {"VulnersApi", "VScannerApi", "VulnersApiError"} <= root_all

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
