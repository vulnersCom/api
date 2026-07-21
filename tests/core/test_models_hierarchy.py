"""Bulletin family discrimination, CVSS-version union, and the strict path."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulners._models import (
    Bulletin,
    CveBulletin,
    Cvss,
    Cvss2,
    Cvss3,
    ExploitBulletin,
    GenericBulletin,
    ScannerBulletin,
    bulletin_class_for,
    construct_bulletin,
    construct_type,
)


class TestFamilyDiscrimination:
    def test_nvd_builds_cve_bulletin(self):
        b = construct_bulletin({"id": "CVE-2099-1", "bulletinFamily": "NVD", "cpe": ["a:b:c"]})
        assert isinstance(b, CveBulletin)
        assert isinstance(b, Bulletin)  # subclass relationship holds
        assert b.cpe == ["a:b:c"]

    def test_exploit_builds_exploit_bulletin(self):
        b = construct_bulletin({"bulletinFamily": "exploit", "reporter": "someone"})
        assert isinstance(b, ExploitBulletin)
        assert b.reporter == "someone"

    def test_scanner_builds_scanner_bulletin(self):
        b = construct_bulletin({"bulletinFamily": "scanner"})
        assert isinstance(b, ScannerBulletin)

    def test_unknown_family_falls_back_to_generic(self):
        b = construct_bulletin({"id": "X", "bulletinFamily": "brand-new-family"})
        assert type(b) is GenericBulletin
        assert isinstance(b, Bulletin)
        assert b.id == "X"

    def test_missing_family_falls_back_to_generic(self):
        b = construct_bulletin({"id": "no-family"})
        assert type(b) is GenericBulletin

    def test_non_mapping_falls_back_to_generic(self):
        # A scalar payload passes straight through unconstructed.
        assert construct_bulletin("scalar") == "scalar"

    def test_bulletin_class_for_helper(self):
        assert bulletin_class_for({"bulletinFamily": "NVD"}) is CveBulletin
        assert bulletin_class_for({"bulletinFamily": "nope"}) is GenericBulletin
        assert bulletin_class_for("scalar") is GenericBulletin


class TestNoValidationOnConstruct:
    def test_wrong_scalar_passes_through(self):
        b = construct_bulletin({"bulletinFamily": "NVD", "cvss": {"score": "not-a-number"}})
        assert isinstance(b, CveBulletin)
        assert b.cvss.score == "not-a-number"  # no coercion, no error

    def test_extra_fields_are_kept(self):
        b = construct_bulletin({"bulletinFamily": "NVD", "brandNewField": [1, 2, 3]})
        assert b.brandNewField == [1, 2, 3]

    def test_reserved_fields_set_field_name_does_not_crash(self):
        # A server field literally named "_fields_set" collides with
        # model_construct's kwarg; it must be preserved as an extra, not crash.
        b = construct_bulletin({"bulletinFamily": "NVD", "id": "CVE-1", "_fields_set": "boom"})
        assert isinstance(b, CveBulletin)
        assert b.id == "CVE-1"
        assert b.__pydantic_extra__["_fields_set"] == "boom"

    def test_reserved_fields_set_with_other_extras(self):
        # "_fields_set" alongside another unknown field: both land in extras.
        b = construct_bulletin({"bulletinFamily": "NVD", "_fields_set": [1], "otherUnknown": "x"})
        assert b.__pydantic_extra__["_fields_set"] == [1]
        assert b.otherUnknown == "x"

    def test_nested_family_field_is_recursed(self):
        # cvss2/cvss3 on a CVE are nested models built recursively.
        b = construct_bulletin(
            {"bulletinFamily": "NVD", "cvss3": {"version": "3.1", "score": 9.8}}
        )
        assert isinstance(b, CveBulletin)
        assert isinstance(b.cvss3, Cvss3)
        assert b.cvss3.score == 9.8


class TestCvssVersionUnion:
    def test_v2_selected(self):
        b = construct_bulletin(
            {"bulletinFamily": "NVD", "cvss": {"version": "2.0", "score": 5.0}}
        )
        assert isinstance(b.cvss, Cvss2)

    def test_v3_selected(self):
        c = construct_type({"version": "3.1", "score": 7.5, "severity": "HIGH"}, Cvss)
        assert isinstance(c, Cvss3)
        assert c.severity == "HIGH"

    def test_no_version_stays_base_cvss(self):
        c = construct_type({"score": 9.1}, Cvss)
        assert type(c) is Cvss

    def test_unknown_version_stays_base_cvss(self):
        c = construct_type({"version": "9.9"}, Cvss)
        assert type(c) is Cvss


class TestStrictPath:
    def test_strict_validates_and_discriminates(self):
        b = construct_bulletin({"bulletinFamily": "NVD", "id": "CVE-1"}, strict=True)
        assert isinstance(b, CveBulletin)
        assert b.id == "CVE-1"

    def test_strict_falls_back_to_generic(self):
        b = construct_bulletin({"bulletinFamily": "weird"}, strict=True)
        assert type(b) is GenericBulletin

    def test_strict_rejects_bad_type(self):
        # The strict adapter really validates: a wrong scalar type is rejected,
        # unlike the construct fast path.
        with pytest.raises(ValidationError):
            construct_bulletin({"bulletinFamily": "NVD", "cvss": {"score": "nope"}}, strict=True)
