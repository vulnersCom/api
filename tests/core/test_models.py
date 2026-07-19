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
    rows = construct_type([{"id": "a"}, {"id": "b"}], list[Bulletin])
    assert [type(r).__name__ for r in rows] == ["Bulletin", "Bulletin"]
    assert rows[0].id == "a"


def test_optional_none_stays_none():
    bulletin = construct_type({"cvss": None}, Bulletin)
    assert bulletin.cvss is None


def test_non_mapping_for_model_passes_through():
    # Defensive: a scalar where a model was expected is returned unchanged.
    assert construct_type("scalar", Bulletin) == "scalar"
