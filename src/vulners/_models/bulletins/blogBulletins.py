"""GENERATED — the `blog` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class BlogBulletin(Bulletin):
    """`bulletinFamily: blog` — adds the fields shared across this family."""

    pass


class AkamaiblogBulletin(BlogBulletin):
    """`type: akamaiblog` — Akamai Blog provides security advisories and insights related to Akamai's products and services, focusing on web security and performance."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AnandprakaBulletin(BlogBulletin):
    """`type: anandpraka` — AnandPraka provides security advisories and CVEs focused on vulnerabilities in various software products and operating systems."""

    pass


class AvleonovBulletin(BlogBulletin):
    """`type: avleonov` — AVLeonov provides advisories and CVEs related to vulnerabilities in various software products, sourced from multiple vendors and security bulletins."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CarbonblackBulletin(BlogBulletin):
    """`type: carbonblack` — Carbon Black's collection includes vendor-specific advisories, CVEs, and threat intelligence related to endpoint security products."""

    pass


class CoalfireBulletin(BlogBulletin):
    """`type: coalfire` — Coalfire provides security advisories and vulnerability reports focused on various vendors and products, primarily for compliance and risk management."""

    pass


class D0znppBulletin(BlogBulletin):
    """`type: d0znpp` — The d0znpp collection provides vendor-specific advisories and CVEs related to vulnerabilities in various software products from the d0znpp database."""

    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class FilippoioBulletin(BlogBulletin):
    """`type: filippoio` — Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class HackreadBulletin(BlogBulletin):
    """`type: hackread` — HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ImpervablogBulletin(BlogBulletin):
    """`type: impervablog` — Imperva Blog provides insights and advisories on web application security, focusing on vulnerabilities and exploits related to Imperva products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class IntothesymmetryBulletin(BlogBulletin):
    """`type: intothesymmetry` — IntotheSymmetry provides advisories and CVEs focused on vulnerabilities in various software products and systems, sourced from multiple vendors."""

    pass


class JakearchibaldBulletin(BlogBulletin):
    """`type: jakearchibald` — Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class KrebsBulletin(BlogBulletin):
    """`type: krebs` — Krebs on Security provides in-depth articles and analysis on cybersecurity threats, breaches, and vulnerabilities, focusing on various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class MalwarebytesBulletin(BlogBulletin):
    """`type: malwarebytes` — Malwarebytes collection includes advisories and threat intelligence related to malware and security vulnerabilities affecting various software and systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class MmpcBulletin(BlogBulletin):
    """`type: mmpc` — MMPC is a Microsoft Malware Protection Center collection focusing on Microsoft products, providing advisories, CVEs, and malware threat intelligence."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class MsrcBulletin(BlogBulletin):
    """`type: msrc` — The MSRC collection includes Microsoft Security Response Center advisories and CVEs, focusing on vulnerabilities in Microsoft products and services."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class MssecureBulletin(BlogBulletin):
    """`type: mssecure` — Microsoft Security Update Guide collection featuring advisories and CVEs for Microsoft products and services across various platforms."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class PentestitBulletin(BlogBulletin):
    """`type: pentestit` — PentestIT provides vulnerability advisories and CVEs focused on various software products and services, primarily for penetration testing professionals."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class PentestlabBulletin(BlogBulletin):
    """`type: pentestlab` — PentestLab is a vulnerability database focused on penetration testing resources, including advisories, CVEs, and exploit techniques for various products."""

    pass


class PentestnepalBulletin(BlogBulletin):
    """`type: pentestnepal` — PentestNepal provides security advisories and vulnerability reports focused on various software products and services relevant to Nepal's cybersecurity landscape."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class PentestpartnersBulletin(BlogBulletin):
    """`type: pentestpartners` — Pentest Partners provides security advisories and vulnerability reports focused on various vendors and products, including CVEs and exploit techniques."""

    pass


class QualysblogBulletin(BlogBulletin):
    """`type: qualysblog` — Qualys Blog provides vendor-specific security advisories and insights, focusing on vulnerabilities, CVEs, and best practices for various products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class Rapid7communityBulletin(BlogBulletin):
    """`type: rapid7community` — Rapid7 Community provides vulnerability advisories and CVEs focused on various software products and platforms, sourced from community contributions."""

    pass


class RhinoBulletin(BlogBulletin):
    """`type: rhino` — Rhino is a vulnerability collection from the Rhino Security Labs, focusing on advisories and CVEs related to various software products and services."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class RipstechBulletin(BlogBulletin):
    """`type: ripstech` — Ripstech provides vulnerability data focused on web application security, including advisories and CVEs related to various vendors and products."""

    pass


class SchneierBulletin(BlogBulletin):
    """`type: schneier` — Schneier's collection provides security advisories and analyses focused on various vulnerabilities across software and systems, sourced from Bruce Schneier's insights."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SecurelistBulletin(BlogBulletin):
    """`type: securelist` — Securelist provides vendor-specific security advisories, CVEs, and threat intelligence reports focusing on malware and cyber threats."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SilentrobotsBulletin(BlogBulletin):
    """`type: silentrobots` — Silent Robots provides vulnerability data sourced from various vendors, focusing on advisories and CVEs related to web applications and services."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SonarsourceBulletin(BlogBulletin):
    """`type: sonarsource` — SonarSource provides security advisories and vulnerability data for various programming languages and frameworks, focusing on code quality and security issues."""

    pass


class TalosblogBulletin(BlogBulletin):
    """`type: talosblog` — Talos Blog provides security advisories and insights from Cisco Talos, focusing on vulnerabilities across various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class TaosecurityBulletin(BlogBulletin):
    """`type: taosecurity` — TaoSecurity provides advisories and CVEs focused on security vulnerabilities in various software products and operating systems."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class ThehackerblogBulletin(BlogBulletin):
    """`type: thehackerblog` — The Hacker Blog provides security advisories, CVEs, and exploits focused on various vendors and products, sourced from community contributions."""

    pass


class TrendmicroblogBulletin(BlogBulletin):
    """`type: trendmicroblog` — Trend Micro Blog provides vendor-specific advisories and insights on security threats, vulnerabilities, and product updates related to Trend Micro software."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class WallarmlabBulletin(BlogBulletin):
    """`type: wallarmlab` — Wallarm Lab provides security advisories and CVEs focused on web application vulnerabilities across various vendors and products."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class WebsecuritylogBulletin(BlogBulletin):
    """`type: websecuritylog` — WebSecurityLog provides security advisories and CVEs focused on web applications and services, sourced from various vendors and platforms."""

    pass


class WiredBulletin(BlogBulletin):
    """`type: wired` — Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""
