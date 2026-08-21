"""Response models and the recursive validation-free constructor.

The bulletin model classes are generated in :mod:`.bulletins` (base -> family ->
type) and re-exported here; the framework, nested value objects and construction
machinery are hand-written.
"""

from __future__ import annotations

from ._base import Discriminator as Discriminator
from ._base import VulnersModel as VulnersModel
from ._base import construct_type as construct_type
from ._base import register_discriminator as register_discriminator
from ._nested import Cvss as Cvss
from ._nested import Cvss2 as Cvss2
from ._nested import Cvss3 as Cvss3
from ._nested import Cvss4 as Cvss4
from ._nested import Enchantments as Enchantments
from ._nested import EpssScore as EpssScore
from ._nested import Timestamps as Timestamps
from .audit import PackageMetadata as PackageMetadata
from .bulletin import FAMILY_MODELS as FAMILY_MODELS
from .bulletin import TYPE_MODELS as TYPE_MODELS
from .bulletin import bulletin_class_for as bulletin_class_for
from .bulletin import construct_bulletin as construct_bulletin
from .bulletins import *  # noqa: F403  — re-export every generated model class
