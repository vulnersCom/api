"""Recursive validation-free construction of response models."""

from __future__ import annotations

from vulners._models import Bulletin, construct_type
from vulners._models.bulletin import Cvss


def test_nested_model_built_recursively():
    data = {
        "id": "CVE-2099-0001",
        "cvss": {"score": 9.8, "vector": "AV:N/AC:L"},
        "cvelist": ["CVE-2099-0001"],
    }
    bulletin = construct_type(data, Bulletin)
    assert isinstance(bulletin, Bulletin)
    # The nested cvss is a real Cvss model, not a leftover dict.
    assert isinstance(bulletin.cvss, Cvss)
    assert bulletin.cvss.score == 9.8
    assert bulletin.cvelist == ["CVE-2099-0001"]


def test_no_validation_happens():
    # A wrong scalar type passes straight through (no coercion, no error).
    bulletin = construct_type({"cvss": {"score": "not-a-number"}}, Bulletin)
    assert bulletin.cvss.score == "not-a-number"


def test_aliases_are_resolved():
    bulletin = construct_type({"bulletinFamily": "NVD", "lastseen": "2099-01-01"}, Bulletin)
    assert bulletin.bulletin_family == "NVD"
    assert bulletin.last_seen == "2099-01-01"


def test_unknown_fields_are_preserved():
    bulletin = construct_type({"id": "x", "brandNewField": [1, 2, 3]}, Bulletin)
    # extra="allow" keeps forward-compatible unknown fields accessible.
    assert bulletin.brandNewField == [1, 2, 3]


def test_list_of_models():
    # Bulletin is registered in the discriminator registry, so rows specialize
    # exactly like construct_bulletin: no family -> GenericBulletin fallback,
    # a family tag -> the family model.
    rows = construct_type([{"id": "a"}, {"id": "b", "bulletinFamily": "cve"}], list[Bulletin])
    assert [type(r).__name__ for r in rows] == ["GenericBulletin", "CveBulletin"]
    assert rows[0].id == "a"


def test_optional_none_stays_none():
    bulletin = construct_type({"cvss": None}, Bulletin)
    assert bulletin.cvss is None


def test_non_mapping_for_model_passes_through():
    # Defensive: a scalar where a model was expected is returned unchanged.
    assert construct_type("scalar", Bulletin) == "scalar"


class TestHasHelper:
    def test_has_by_python_name_and_alias(self):
        b = construct_type({"id": "x", "bulletinFamily": "cve"}, Bulletin)
        assert b.has("id")
        assert b.has("bulletin_family")
        assert b.has("bulletinFamily")  # wire alias resolves too

    def test_absent_field_is_false_even_though_attribute_is_none(self):
        b = construct_type({"id": "x"}, Bulletin)
        assert b.title is None and not b.has("title")
        assert not b.has("lastseen") and not b.has("unknownField")

    def test_extras_count_as_sent(self):
        b = construct_type({"id": "x", "brandNew": 1}, Bulletin)
        assert b.has("brandNew")

    def test_server_field_named_has_does_not_shadow_method(self):
        b = construct_type({"id": "x", "has": ["something"]}, Bulletin)
        assert callable(b.has)  # the method wins attribute lookup
        assert b.has("has")  # and the extra is still reported as sent
        assert b.model_extra["has"] == ["something"]
