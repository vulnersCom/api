"""Response models and the recursive validation-free constructor."""

from __future__ import annotations

from ._base import Discriminator, VulnersModel, construct_type, register_discriminator
from .bulletin import (
    Bulletin,
    CveBulletin,
    Cvss,
    Cvss2,
    Cvss3,
    Cvss4,
    ExploitBulletin,
    GenericBulletin,
    InfoBulletin,
    ScannerBulletin,
    SoftwareBulletin,
    bulletin_class_for,
    construct_bulletin,
)

__all__ = [
    "Bulletin",
    "CveBulletin",
    "Cvss",
    "Cvss2",
    "Cvss3",
    "Cvss4",
    "Discriminator",
    "ExploitBulletin",
    "GenericBulletin",
    "InfoBulletin",
    "ScannerBulletin",
    "SoftwareBulletin",
    "VulnersModel",
    "bulletin_class_for",
    "construct_bulletin",
    "construct_type",
    "register_discriminator",
]
