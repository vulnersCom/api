"""Per-collection (``type``) model factory and data-model coherence.

These lock in the base -> family -> type contract and enforce the data-model
invariants offline in CI: every collection field is described, generated names
never shadow inherited fields, models pickle, racing builds share one class, and
the construct path never raises on malformed server data.
"""

from __future__ import annotations

import pickle
import threading

from vulners._models import bulletin as b
from vulners._models._base import construct_type
from vulners._models._field_descriptions import FIELD_DESCRIPTIONS
from vulners._models.collections import (
    _ANN,
    COLLECTIONS,
    _build_locked,
    _classname,
    _pyname,
    collection_model,
    collection_types,
)


class TestTypeDiscrimination:
    def test_known_type_builds_collection_model(self):
        # aix is a `unix` collection that adds `aixFileset`.
        bulletin = b.construct_bulletin(
            {"type": "aix", "bulletinFamily": "unix", "id": "x", "aixFileset": [{"a": 1}]}
        )
        assert type(bulletin) is collection_model("aix")
        assert isinstance(bulletin, b.UnixBulletin)  # base -> family -> type holds
        assert bulletin.aix_fileset == [{"a": 1}]

    def test_type_wins_over_family(self):
        model = b.bulletin_class_for({"type": "aix", "bulletinFamily": "unix"})
        assert model is collection_model("aix")
        assert model is not b.UnixBulletin

    def test_unknown_type_falls_back_to_family(self):
        bulletin = b.construct_bulletin(
            {"type": "brand-new-collection", "bulletinFamily": "cve", "id": "z"}
        )
        assert type(bulletin) is b.CveBulletin

    def test_digit_leading_type_has_valid_classname(self):
        model = collection_model("0daydb")
        assert model is not None
        assert model.__name__.isidentifier()  # e.g. C0daydbBulletin

    def test_collection_model_is_cached(self):
        assert collection_model("aix") is collection_model("aix")

    def test_unknown_collection_model_is_none(self):
        assert collection_model("definitely-not-a-collection") is None

    def test_bulletin_annotation_specializes_via_registry(self):
        # Bulletin is registered in the discriminator registry, so ANY value
        # constructed against the Bulletin annotation dispatches type-first —
        # same mechanism as a direct construct_bulletin call.
        spec = construct_type({"type": "aix", "bulletinFamily": "unix", "id": "y"}, b.Bulletin)
        assert type(spec) is collection_model("aix")


class TestMalformedServerData:
    """The construct path must degrade, never raise, on weird payloads."""

    def test_unhashable_type_degrades_to_family(self):
        bulletin = b.construct_bulletin({"type": ["cve"], "bulletinFamily": "cve", "id": "x"})
        assert type(bulletin) is b.CveBulletin

    def test_unhashable_family_degrades_to_generic(self):
        bulletin = b.construct_bulletin({"bulletinFamily": ["cve"], "id": "x"})
        assert type(bulletin) is b.GenericBulletin

    def test_non_str_type_returns_none_model(self):
        assert collection_model(123) is None
        assert collection_model(None) is None
        assert collection_model({"a": 1}) is None

    def test_misses_are_not_cached(self):
        from vulners._models import collections as c

        before = len(c._MODELS)
        for i in range(50):
            assert collection_model(f"junk-{i}") is None
        assert len(c._MODELS) == before  # unknown types never pin cache entries


class TestFactoryIntegrity:
    def test_per_type_bulletin_pickles(self):
        # create_model classes are registered as module attributes, so pickle's
        # module+qualname lookup resolves them.
        inst = b.construct_bulletin(
            {"type": "aix", "bulletinFamily": "unix", "id": "x", "aixFileset": [{"a": 1}]}
        )
        clone = pickle.loads(pickle.dumps(inst))
        assert type(clone) is type(inst)
        assert clone.aix_fileset == [{"a": 1}]

    def test_cve_type_does_not_shadow_family_model(self):
        # The `cve` collection's class is renamed so it cannot be confused with
        # (or pickle-collide with) the hand-written CveBulletin family model.
        model = collection_model("cve")
        assert model.__name__ == "CveCollectionBulletin"
        assert issubclass(model, b.CveBulletin)

    def test_classnames_unique_across_collections(self):
        names = [_classname(t) for t in COLLECTIONS]
        assert len(names) == len(set(names))  # module-attr registration relies on it

    def test_concurrent_first_build_yields_one_class(self):
        from vulners._models import collections as c

        c._MODELS.pop("ubuntu", None)
        results: list[type] = []
        barrier = threading.Barrier(8)

        def build() -> None:
            barrier.wait()
            results.append(collection_model("ubuntu"))

        threads = [threading.Thread(target=build) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len({id(r) for r in results}) == 1

    def test_build_locked_reuses_existing_model(self):
        # The double-checked branch: a second locked build returns the cached class.
        first = _build_locked("aix", COLLECTIONS["aix"])
        again = _build_locked("aix", COLLECTIONS["aix"])
        assert first is again

    def test_no_field_shadows_inherited_attribute(self):
        # A generated field whose snake name collides with a base/family python
        # attribute would silently override its annotation and alias — the
        # factory must rename instead. Every model therefore has exactly
        # base + delta fields.
        for ctype in collection_types():
            model = collection_model(ctype)
            base = model.__mro__[1]
            assert len(model.model_fields) == len(base.model_fields) + len(
                COLLECTIONS[ctype]["fields"]
            ), ctype

    def test_token_vocabulary_is_closed(self):
        # Generator and factory share one token set; an unknown token in the
        # committed data would silently type fields as Any.
        tokens = {tok for spec in COLLECTIONS.values() for tok in spec["fields"].values()}
        assert tokens <= set(_ANN)


class TestFieldNaming:
    def test_pyname_strips_leading_underscore(self):
        # pydantic forbids field names starting with `_`; the wire alias is kept.
        assert _pyname("_product", set()) == "product"
        assert _pyname("_vulncheck_xdb", set()) == "vulncheck_xdb"

    def test_pyname_camel_digit_keyword(self):
        assert _pyname("wildExploitedCategory", set()) == "wild_exploited_category"
        assert _pyname("0abc", set()).isidentifier()
        assert not _pyname("0abc", set())[0].isdigit()
        assert _pyname("class", set()).endswith("_")  # python keyword -> class_

    def test_pyname_avoids_taken_names(self):
        # Collisions with inherited attributes (or each other) get a suffix
        # instead of silently overriding the earlier field.
        assert _pyname("last_seen", {"last_seen"}) == "last_seen_"
        assert _pyname("lastSeen", {"last_seen", "last_seen_"}) == "last_seen__"

    def test_underscore_fields_roundtrip(self):
        # Every collection field that starts with `_` keeps its wire name as an
        # alias and is reachable through a valid (non-underscore) attribute.
        sample = {"str": "v", "int": 1, "float": 1.0, "bool": True, "list": ["v"], "any": "v"}
        for ctype, spec in COLLECTIONS.items():
            for wire, token in spec["fields"].items():
                if not wire.startswith("_"):
                    continue
                model = collection_model(ctype)
                name = next(n for n, fi in model.model_fields.items() if fi.alias == wire)
                assert not name.startswith("_")
                value = sample[token]
                inst = b.construct_bulletin(
                    {"type": ctype, "bulletinFamily": spec["family"], wire: value}
                )
                assert getattr(inst, name) == value
                assert inst.model_dump(by_alias=True, exclude_none=True)[wire] == value


class TestStrictNonStrictConsistency:
    def test_snake_family_key_resolves_on_both_paths(self):
        # model_dump() emits snake keys; both paths must resolve the same model.
        dumped = {"bulletin_family": "cve", "vuln_status": "Analyzed"}
        assert type(b.construct_bulletin(dumped)) is b.CveBulletin
        assert type(b.construct_bulletin(dumped, strict=True)) is b.CveBulletin

    def test_snake_fields_populate_on_strict_path(self):
        # validate_by_name lets strict validation accept the python spelling.
        strict = b.construct_bulletin(
            {"bulletin_family": "cve", "vuln_status": "Analyzed"}, strict=True
        )
        assert strict.vuln_status == "Analyzed"

    def test_bugbounty_cwe_id_is_a_string(self):
        # The wire sends a plain string (the docstring says "Single ... identifier").
        strict = b.construct_bulletin(
            {"bulletinFamily": "bugbounty", "cwe_id": "CWE-79"}, strict=True
        )
        assert strict.cwe_id == "CWE-79"


class TestDataModelCoherence:
    def test_unmapped_family_falls_back_to_generic(self):
        # Families are dynamic: a collection whose family has no dedicated model
        # still builds (base = GenericBulletin), so a new family is never a blocker.
        model = b.bulletin_class_for({"type": "x", "bulletinFamily": "brand-new-family"})
        assert model is b.GenericBulletin

    def test_every_collection_field_is_described(self):
        fields = {w for s in COLLECTIONS.values() for w in s["fields"]}
        undescribed = sorted(fields - set(FIELD_DESCRIPTIONS))
        assert not undescribed, f"fields without a description: {undescribed}"

    def test_every_model_field_has_a_description(self):
        # Build every collection model and confirm no field (base, family, or the
        # collection's own) is left without a human description.
        missing = []
        for ctype in collection_types():
            model = collection_model(ctype)
            for name, fi in model.model_fields.items():
                if not (fi.description or "").strip():
                    missing.append(f"{model.__name__}.{name}")
        assert not missing, f"fields without a description: {sorted(set(missing))[:20]}"

    def test_base_and_family_fields_have_descriptions(self):
        # use_attribute_docstrings must promote every hand-written docstring.
        models = {b.Bulletin, *b._FAMILY_MODELS.values()}
        missing = [
            f"{m.__name__}.{n}"
            for m in models
            for n, fi in m.model_fields.items()
            if not (fi.description or "").strip()
        ]
        assert not missing, f"base/family fields without a description: {missing}"

    def test_collection_field_description_matches_registry(self):
        model = collection_model("aix")
        assert model.model_fields["aix_fileset"].description == FIELD_DESCRIPTIONS["aixFileset"]

    def test_registry_and_docstrings_agree_where_both_exist(self):
        # FIELD_DESCRIPTIONS also describes wires the family models declare via
        # attribute docstrings (the per-collection docs render base fields too).
        # The two authored texts must not drift apart.
        def norm(text: str) -> str:
            return " ".join(text.split())

        diverged = []
        for model in {b.Bulletin, *b._FAMILY_MODELS.values()}:
            for name, fi in model.model_fields.items():
                wire = fi.alias or name
                registry = FIELD_DESCRIPTIONS.get(wire)
                if registry is not None and norm(registry) != norm(fi.description or ""):
                    diverged.append(f"{model.__name__}.{name} ({wire})")
        assert not diverged, f"description drift between docstrings and registry: {diverged}"
