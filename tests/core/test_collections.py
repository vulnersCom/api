"""Per-collection (``type``) model factory and data-model coherence.

These lock in the base -> family -> type contract and make CI enforce what the
``dev-tools`` ``--verify`` checks: every collection maps to a family, every field
the models declare is described, and the generated data stays in sync.
"""

from __future__ import annotations

from vulners._models import bulletin as b
from vulners._models._field_descriptions import FIELD_DESCRIPTIONS
from vulners._models.collections import (
    COLLECTIONS,
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


class TestFieldNaming:
    def test_pyname_strips_leading_underscore(self):
        # pydantic forbids field names starting with `_`; the wire alias is kept.
        assert _pyname("_product") == "product"
        assert _pyname("_vulncheck_xdb") == "vulncheck_xdb"

    def test_pyname_camel_digit_keyword(self):
        assert _pyname("wildExploitedCategory") == "wild_exploited_category"
        assert _pyname("0abc").isidentifier() and not _pyname("0abc")[0].isdigit()
        assert _pyname("class").endswith("_")  # python keyword -> class_

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


class TestDataModelCoherence:
    def test_every_collection_family_is_mapped(self):
        families = {s["family"] for s in COLLECTIONS.values()}
        assert families <= set(b._FAMILY_MODELS)

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
