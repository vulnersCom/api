"""Generated bulletin models (base -> family -> type) and the construction machinery.

The whole hierarchy is generated in ``vulners._models.bulletins`` from live samples;
these lock in the contract offline in CI: every collection ``type`` has its own
concrete class extending its family extending :class:`Bulletin`, class names are
unique, no generated field shadows an inherited one, every field is described, and
the construct path resolves ``type`` -> family -> generic and never raises on
malformed server data.
"""

from __future__ import annotations

import pickle

import vulners._models as vm
from vulners._models import construct_type
from vulners._models._field_descriptions import FIELD_DESCRIPTIONS
from vulners._models.bulletins import FAMILY_MODELS, TYPE_MODELS


class TestHierarchy:
    def test_registries_populated(self):
        assert len(FAMILY_MODELS) >= 15
        assert len(TYPE_MODELS) >= 200
        # every family value is a distinct Bulletin subclass
        assert all(issubclass(m, vm.Bulletin) for m in FAMILY_MODELS.values())

    def test_every_type_is_three_levels(self):
        # <Type>Bulletin -> <Family>Bulletin -> Bulletin, for all 238 types.
        families = set(FAMILY_MODELS.values())
        for model in TYPE_MODELS.values():
            mro = model.__mro__
            assert mro[1] in families, f"{model.__name__} parent {mro[1].__name__} not a family"
            assert mro[2] is vm.Bulletin, f"{model.__name__} grandparent {mro[2].__name__}"

    def test_class_names_unique(self):
        names = [m.__name__ for m in TYPE_MODELS.values()]
        assert len(names) == len(set(names))
        assert not (set(names) & {m.__name__ for m in FAMILY_MODELS.values()})

    def test_cve_type_does_not_shadow_family_model(self):
        model = TYPE_MODELS["cve"]
        assert model.__name__ == "CveCollectionBulletin"
        assert issubclass(model, vm.CveBulletin)

    def test_digit_leading_type_has_valid_classname(self):
        model = TYPE_MODELS.get("0daydb")
        if model is not None:  # collection set is live; only assert when present
            assert model.__name__.isidentifier()
            assert not model.__name__[0].isdigit()

    def test_no_field_shadows_inherited_field(self):
        # A generated field re-declaring an inherited one (same python name, other
        # wire alias) would silently override it: two python names would then map to
        # one alias, or one python name to two aliases across the MRO. Neither may
        # happen — the emitter renames on collision.
        for model in TYPE_MODELS.values():
            aliases = [(fi.alias or n) for n, fi in model.model_fields.items()]
            assert len(aliases) == len(set(aliases)), model.__name__


class TestConstruction:
    def test_type_wins_over_family(self):
        b = vm.construct_bulletin({"type": "cve", "bulletinFamily": "cve", "id": "CVE-1"})
        assert type(b) is TYPE_MODELS["cve"]
        assert isinstance(b, vm.CveBulletin)

    def test_unknown_type_falls_back_to_family(self):
        b = vm.construct_bulletin({"type": "brand-new", "bulletinFamily": "cve", "id": "z"})
        assert type(b) is vm.CveBulletin

    def test_unmapped_family_falls_back_to_generic(self):
        b = vm.construct_bulletin({"type": "x", "bulletinFamily": "brand-new-family"})
        assert type(b) is vm.GenericBulletin

    def test_non_mapping_input_is_generic(self):
        assert vm.bulletin_class_for(["not", "a", "mapping"]) is vm.GenericBulletin

    def test_bulletin_annotation_specializes_via_registry(self):
        # Bulletin is registered, so constructing against the Bulletin annotation
        # dispatches type-first — same mechanism as a direct construct_bulletin call.
        spec = construct_type({"type": "nessus", "bulletinFamily": "scanner"}, vm.Bulletin)
        assert type(spec) is TYPE_MODELS["nessus"]

    def test_pickles(self):
        inst = vm.construct_bulletin({"type": "nessus", "bulletinFamily": "scanner", "id": "x"})
        clone = pickle.loads(pickle.dumps(inst))
        assert type(clone) is type(inst)
        assert clone.id == "x"


class TestMalformedServerData:
    def test_unhashable_type_degrades_to_family(self):
        b = vm.construct_bulletin({"type": ["cve"], "bulletinFamily": "cve", "id": "x"})
        assert type(b) is vm.CveBulletin

    def test_unhashable_family_degrades_to_generic(self):
        b = vm.construct_bulletin({"bulletinFamily": ["cve"], "id": "x"})
        assert type(b) is vm.GenericBulletin

    def test_non_str_type_uses_family(self):
        b = vm.construct_bulletin({"type": 123, "bulletinFamily": "cve"})
        assert type(b) is vm.CveBulletin


class TestStrictPath:
    def test_snake_family_key_resolves_on_both_paths(self):
        dumped = {"bulletin_family": "cve", "id": "CVE-9"}
        assert type(vm.construct_bulletin(dumped)) is vm.CveBulletin
        assert type(vm.construct_bulletin(dumped, strict=True)) is vm.CveBulletin

    def test_strict_non_mapping_validates_against_family(self):
        obj = vm.construct_bulletin({"bulletinFamily": "cve", "id": "CVE-1"})
        again = vm.construct_bulletin(obj, strict=True)  # non-mapping input
        assert isinstance(again, vm.CveBulletin)


class TestCvssUnion:
    def test_version_selects_subclass(self):
        b = vm.construct_bulletin(
            {"bulletinFamily": "cve", "cvss": {"version": "3.1", "score": 9.8}}
        )
        assert type(b.cvss) is vm.Cvss3
        assert b.cvss.score == 9.8

    def test_unknown_version_stays_base_cvss(self):
        b = vm.construct_bulletin({"bulletinFamily": "cve", "cvss": {"version": "9.9"}})
        assert type(b.cvss) is vm.Cvss


class TestDescriptions:
    def test_every_type_specific_field_is_described(self):
        wires = {
            fi.alias or n
            for model in TYPE_MODELS.values()
            for n, fi in model.model_fields.items()
        }
        undescribed = sorted(w for w in wires if not (FIELD_DESCRIPTIONS.get(w) or "").strip())
        assert not undescribed, f"fields without a description: {undescribed[:20]}"

    def test_model_field_descriptions_match_registry(self):
        # The generator writes each field's description from FIELD_DESCRIPTIONS as an
        # attribute docstring; the two must never drift.
        def norm(text: str) -> str:
            return " ".join((text or "").split())

        drift = []
        for model in [vm.Bulletin, *FAMILY_MODELS.values(), *TYPE_MODELS.values()]:
            for name, fi in model.model_fields.items():
                wire = fi.alias or name
                reg = FIELD_DESCRIPTIONS.get(wire)
                if reg is not None and norm(reg) != norm(fi.description):
                    drift.append(f"{model.__name__}.{name}")
        assert not drift, f"description drift: {sorted(set(drift))[:20]}"
