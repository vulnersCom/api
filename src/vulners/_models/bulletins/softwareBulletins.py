"""GENERATED — the `software` bulletin family and its collection models."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .base import Bulletin


class SoftwareBulletin(Bulletin):
    """`bulletinFamily: software` — adds the fields shared across this family."""

    pass


class AdobeBulletin(SoftwareBulletin):
    """`type: adobe` — Adobe's vulnerability collection includes advisories and CVEs related to Adobe products, addressing security issues across various software and platforms."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class AndroidBulletin(SoftwareBulletin):
    """`type: android` — Android vulnerabilities collection from various sources, covering advisories and CVEs related to Android OS and applications."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class AndroidsecurityBulletin(SoftwareBulletin):
    """`type: androidsecurity` — Android Security collection includes advisories and CVEs related to vulnerabilities in the Android OS and its ecosystem from Google's security updates."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AnthropicBulletin(SoftwareBulletin):
    """`type: anthropic` — Anthropic collection includes security advisories and CVEs related to vulnerabilities in Anthropic's AI products and services."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class AppercutBulletin(SoftwareBulletin):
    """`type: appercut` — Appercut provides security advisories and CVEs related to vulnerabilities in various software applications and platforms."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class AppleBulletin(SoftwareBulletin):
    """`type: apple` — Apple's vulnerability database includes advisories and CVEs related to security issues in Apple products and operating systems."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class AristaBulletin(SoftwareBulletin):
    """`type: arista` — Arista's vulnerability collection includes advisories and CVEs related to their networking products and software, sourced from Arista Networks."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class AtlassianBulletin(SoftwareBulletin):
    """`type: atlassian` — Atlassian's vulnerability collection includes security advisories and CVEs for its software products, focusing on vendor-specific vulnerabilities."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class BraveBulletin(SoftwareBulletin):
    """`type: brave` — Brave collection includes vulnerability advisories and CVEs specific to the Brave browser, sourced from security bulletins and vendor updates."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class BroadcomBulletin(SoftwareBulletin):
    """`type: broadcom` — Broadcom vulnerability collection includes advisories and CVEs for Broadcom products and services, focusing on security issues and patches."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CakephpBulletin(SoftwareBulletin):
    """`type: cakephp` — CakePHP vulnerabilities from the CVE database, covering security advisories and exploits related to the CakePHP framework."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class CheckpointSecurityBulletin(SoftwareBulletin):
    """`type: checkpoint_security` — Checkpoint Security provides advisories and CVEs related to vulnerabilities in Check Point products and services."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class ChromeBulletin(SoftwareBulletin):
    """`type: chrome` — Google Chrome vulnerability collection includes advisories and CVEs related to security issues in the Chrome browser and its components."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CiscoBulletin(SoftwareBulletin):
    """`type: cisco` — Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class CitrixBulletin(SoftwareBulletin):
    """`type: citrix` — Citrix vulnerability collection includes advisories and CVEs related to Citrix products and services, sourced from Citrix's official security bulletins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class ClickhouseBulletin(SoftwareBulletin):
    """`type: clickhouse` — ClickHouse vulnerability collection includes advisories and CVEs specific to ClickHouse database software, sourced from various security bulletins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CloudfoundryBulletin(SoftwareBulletin):
    """`type: cloudfoundry` — Cloud Foundry vulnerability data from various vendors, focusing on cloud platform advisories and CVEs related to Cloud Foundry components."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class ContaoBulletin(SoftwareBulletin):
    """`type: contao` — Contao vulnerability collection provides advisories and CVEs specific to the Contao CMS, sourced from security bulletins and community reports."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class CurlBulletin(SoftwareBulletin):
    """`type: curl` — This collection from the curl project includes advisories and CVEs related to vulnerabilities in the curl command-line tool and library across various platforms."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    curl_affects: str | None = Field(default=None, alias="curlAffects")
    """Affected curl versions (curl advisories)."""
    curl_severity: str | None = Field(default=None, alias="curlSeverity")
    """curl project's severity rating."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""


class DrupalBulletin(SoftwareBulletin):
    """`type: drupal` — Drupal security advisories from the Drupal security team, including CVEs and patches for vulnerabilities in Drupal CMS and its modules."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class ElasticBulletin(SoftwareBulletin):
    """`type: elastic` — Elastic's vulnerability collection includes advisories and CVEs related to Elastic products, focusing on security issues and patches for their software."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class F5Bulletin(SoftwareBulletin):
    """`type: f5` — F5 collection includes security advisories and CVEs related to F5 Networks products and services, focusing on vulnerabilities and exploits."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    related: list[str] | None = None
    """Ids of related Vulners documents."""


class FortinetBulletin(SoftwareBulletin):
    """`type: fortinet` — Fortinet collection includes security advisories and CVEs related to Fortinet products and services, focusing on vulnerabilities and patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class FriendsofphpBulletin(SoftwareBulletin):
    """`type: friendsofphp` — FriendsOfPHP is a community-driven collection of security advisories for PHP projects, including CVEs and vulnerability details."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class FuelphpBulletin(SoftwareBulletin):
    """`type: fuelphp` — FuelPHP vulnerabilities from the FuelPHP security advisory database, covering vulnerabilities in the FuelPHP framework, including CVEs and advisories."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class GithubBulletin(SoftwareBulletin):
    """`type: github` — GitHub collection includes vulnerability advisories and CVEs related to open-source projects hosted on GitHub, focusing on various software products and libraries."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    withdrawn: Any = None
    """Withdrawal date if the advisory was retracted."""


class GitlabBulletin(SoftwareBulletin):
    """`type: gitlab` — GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cwe_ids: list[str] | None = Field(default=None, alias="cweIds")
    """Associated CWE weakness identifiers (alternate key)."""
    solution: str | None = None
    """Recommended remediation/fix, as text."""
    vendor_cvss2: Any = Field(default=None, alias="vendorCvss2")
    """Vendor-assigned CVSS v2."""
    vendor_cvss3: str | None = Field(default=None, alias="vendorCvss3")
    """Vendor-assigned CVSS v3."""


class GrafanaBulletin(SoftwareBulletin):
    """`type: grafana` — Grafana collection includes security advisories and CVEs related to Grafana software, focusing on vulnerabilities affecting the Grafana product."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class HackappBulletin(SoftwareBulletin):
    """`type: hackapp` — HackApp is a vulnerability database focused on mobile applications, providing advisories, CVEs, and exploit information relevant to app security."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class HashicorpBulletin(SoftwareBulletin):
    """`type: hashicorp` — HashiCorp's vulnerability collection includes security advisories and CVEs related to its products and services, focusing on cloud infrastructure and automation tools."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    hashicorp_bulletin_id: str | None = Field(default=None, alias="hashicorpBulletinId")
    """HashiCorp advisory identifier."""
    hashicorp_products: list[str] | None = Field(default=None, alias="hashicorpProducts")
    """Affected HashiCorp products."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class HpBulletin(SoftwareBulletin):
    """`type: hp` — HP's vulnerability collection provides advisories and CVEs related to HP products and software, focusing on security issues and patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class HpeBulletin(SoftwareBulletin):
    """`type: hpe` — HPE collection includes security advisories and CVEs related to Hewlett Packard Enterprise products and services."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class HtbridgeBulletin(SoftwareBulletin):
    """`type: htbridge` — HTBridge provides security advisories and vulnerability assessments focused on web applications and related technologies."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class HttpdBulletin(SoftwareBulletin):
    """`type: httpd` — Apache HTTP Server vulnerabilities from the Apache Software Foundation, including advisories, CVEs, and security patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class HuaweiBulletin(SoftwareBulletin):
    """`type: huawei` — Huawei's collection includes security advisories and CVEs related to Huawei products and software vulnerabilities."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class IbmBulletin(SoftwareBulletin):
    """`type: ibm` — IBM's vulnerability collection includes advisories and CVEs specific to IBM products and software, sourced from IBM's security bulletins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class IvantiBulletin(SoftwareBulletin):
    """`type: ivanti` — Ivanti's vulnerability collection includes security advisories and CVEs related to Ivanti products and services, focusing on vendor-specific vulnerabilities."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class JenkinsBulletin(SoftwareBulletin):
    """`type: jenkins` — Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    jenkins_advisory_id: str | None = Field(default=None, alias="jenkinsAdvisoryId")
    """Jenkins advisory identifier."""
    jenkins_core: Any = Field(default=None, alias="jenkinsCore")
    """Affected Jenkins core version."""
    jenkins_kind: str | None = Field(default=None, alias="jenkinsKind")
    """Jenkins advisory kind (core/plugin)."""
    jenkins_plugins: Any = Field(default=None, alias="jenkinsPlugins")
    """Affected Jenkins plugins (name, fixed/previous versions)."""
    jenkins_reporter: str | None = Field(default=None, alias="jenkinsReporter")
    """Reporter credited by the Jenkins advisory."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class JetbrainsBulletin(SoftwareBulletin):
    """`type: jetbrains` — JetBrains collection includes security advisories and CVEs related to JetBrains products, focusing on vulnerabilities in their development tools and IDEs."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class JoomlaBulletin(SoftwareBulletin):
    """`type: joomla` — Joomla collection includes security advisories, CVEs, and patches specific to vulnerabilities in the Joomla CMS platform."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class KorelogicBulletin(SoftwareBulletin):
    """`type: korelogic` — KoreLogic provides security advisories and vulnerability data focused on various software products and services, including CVEs and exploit information."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class KubernetesBulletin(SoftwareBulletin):
    """`type: kubernetes` — Kubernetes collection includes security advisories, CVEs, and patches specific to Kubernetes and its components from various vendors."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    kubernetes_issue_number: int | None = Field(default=None, alias="kubernetesIssueNumber")
    """Kubernetes issue number for the advisory."""
    kubernetes_status: str | None = Field(default=None, alias="kubernetesStatus")
    """Status of the Kubernetes advisory."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class LaminasBulletin(SoftwareBulletin):
    """`type: laminas` — Laminas vulnerability collection includes advisories and CVEs related to the Laminas PHP framework, focusing on security issues affecting its components."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class ModxBulletin(SoftwareBulletin):
    """`type: modx` — MODX vulnerability collection includes advisories and CVEs related to the MODX CMS, focusing on security issues affecting its core and plugins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class MongodbBulletin(SoftwareBulletin):
    """`type: mongodb` — MongoDB vulnerability collection includes advisories and CVEs related to MongoDB database software, focusing on security issues and patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class MozillaBulletin(SoftwareBulletin):
    """`type: mozilla` — Mozilla collection includes security advisories and CVEs related to Mozilla products, primarily focusing on vulnerabilities in Firefox and other Mozilla software."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class MsvrBulletin(SoftwareBulletin):
    """`type: msvr` — MSVR is a Microsoft vulnerability database focusing on vendor-specific advisories and CVEs related to Microsoft products and services."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class NextcloudBulletin(SoftwareBulletin):
    """`type: nextcloud` — Nextcloud vulnerability collection includes advisories and CVEs related to Nextcloud software, focusing on security issues for the Nextcloud platform."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class NginxBulletin(SoftwareBulletin):
    """`type: nginx` — Nginx vulnerability collection includes advisories and CVEs related to the Nginx web server, focusing on security issues affecting its software."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class NodejsBulletin(SoftwareBulletin):
    """`type: nodejs` — Node.js vulnerability collection from various sources, focusing on advisories and CVEs related to Node.js applications and libraries."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class NodejsblogBulletin(SoftwareBulletin):
    """`type: nodejsblog` — Node.js Blog: A collection from various sources focusing on Node.js vulnerabilities, including advisories, CVEs, and security best practices."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class NvidiaBulletin(SoftwareBulletin):
    """`type: nvidia` — NVIDIA collection includes security advisories and CVEs related to NVIDIA products and drivers, focusing on vulnerabilities affecting their software and hardware."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class OpensslBulletin(SoftwareBulletin):
    """`type: openssl` — OpenSSL collection includes advisories, CVEs, and security updates specifically related to the OpenSSL cryptographic library."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class OperaBulletin(SoftwareBulletin):
    """`type: opera` — Opera collection includes vulnerability advisories and CVEs related to the Opera web browser, focusing on browser security issues and exploits."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class OracleBulletin(SoftwareBulletin):
    """`type: oracle` — Oracle's vulnerability database provides advisories and CVEs related to Oracle products and systems, focusing on security issues and patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class OssfBulletin(SoftwareBulletin):
    """`type: ossf` — OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class OssfuzzBulletin(SoftwareBulletin):
    """`type: ossfuzz` — OSFuzz is a vulnerability collection from the Open Source Security Foundation focusing on security issues in open-source software, including advisories and CVEs."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ossfuzz: Any = None
    """OSS-Fuzz crash details (crash type, project, issue)."""


class OwncloudBulletin(SoftwareBulletin):
    """`type: owncloud` — OwnCloud collection includes security advisories and CVEs related to the OwnCloud file sharing platform, focusing on vulnerabilities affecting its software."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class PaloaltoBulletin(SoftwareBulletin):
    """`type: paloalto` — Palo Alto Networks collection includes advisories and CVEs related to their security products and services."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class PatchstackBulletin(SoftwareBulletin):
    """`type: patchstack` — Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    classification: str | None = None
    """Source-specific classification/category of the issue."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    is_exploited: bool | None = Field(default=None, alias="isExploited")
    """Whether the vulnerability is known to be exploited."""
    owasp: Any = None
    """Related OWASP category."""
    vendor_cvss: Any = None
    """Vendor-assigned CVSS (raw object)."""


class PhpmyadminBulletin(SoftwareBulletin):
    """`type: phpmyadmin` — phpMyAdmin collection includes security advisories and CVEs related to vulnerabilities in the phpMyAdmin web-based database management tool."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class PostgresqlBulletin(SoftwareBulletin):
    """`type: postgresql` — PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class PypaBulletin(SoftwareBulletin):
    """`type: pypa` — The PyPA collection contains Python Package Authority advisories and CVEs related to Python packages and their vulnerabilities."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class RubygemsBulletin(SoftwareBulletin):
    """`type: rubygems` — RubyGems collection includes vulnerability advisories and CVEs specifically for Ruby libraries and gems, sourced from the Ruby community."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class RustsecBulletin(SoftwareBulletin):
    """`type: rustsec` — RustSec is a vulnerability database focused on Rust programming language packages, providing advisories and CVEs related to security issues in Rust crates."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class SecurityvulnsBulletin(SoftwareBulletin):
    """`type: securityvulns` — A collection of security vulnerabilities sourced from various vendors, covering advisories and CVEs across multiple products and operating systems."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    appercut: Any = None
    """AppercutScanner tool provenance (report pages)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    exploitpack: Any = None
    """ExploitPack tool provenance (platform, type)."""
    hackapp: Any = None
    """HackApp mobile-app scan provenance."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""
    tool_href: Any = Field(default=None, alias="toolHref")
    """Link to the associated tool/exploit."""
    w3af: Any = None
    """w3af scanner provenance (plugin type)."""


class SickBulletin(SoftwareBulletin):
    """`type: sick` — The "sick" collection includes advisories and CVEs from various vendors, focusing on vulnerabilities in software products and operating systems."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class SonicwallBulletin(SoftwareBulletin):
    """`type: sonicwall` — SonicWall collection includes advisories and CVEs related to SonicWall products and services, sourced from their security bulletins."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    cwe: list[str] | None = None
    """Associated CWE weakness identifiers."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class SqliteBulletin(SoftwareBulletin):
    """`type: sqlite` — SQLite vulnerabilities collection includes advisories and CVEs related to SQLite database software, focusing on security issues affecting its functionality."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class SymantecBulletin(SoftwareBulletin):
    """`type: symantec` — Symantec's collection includes security advisories and CVEs related to its software products and services, focusing on vulnerabilities and exploits."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""


class SymfonyBulletin(SoftwareBulletin):
    """`type: symfony` — Symfony collection includes vulnerability advisories and CVEs related to the Symfony framework, focusing on PHP applications and components."""

    attachments: Any = None
    """Binary/media attachments associated with the document."""


class TibcoBulletin(SoftwareBulletin):
    """`type: tibco` — TIBCO collection includes security advisories and CVEs related to TIBCO software products, focusing on vulnerabilities affecting their applications and services."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    ai_description: Any = Field(default=None, alias="aiDescription")
    """AI-generated summary of the vulnerability."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class TomcatBulletin(SoftwareBulletin):
    """`type: tomcat` — This collection includes advisories and CVEs related to Apache Tomcat vulnerabilities, sourced from official Apache security bulletins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class Typo3Bulletin(SoftwareBulletin):
    """`type: typo3` — TYPO3 vulnerability collection from various sources, covering advisories and CVEs specific to the TYPO3 CMS platform."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""


class VaadinBulletin(SoftwareBulletin):
    """`type: vaadin` — Vaadin collection includes security advisories and CVEs related to the Vaadin framework, focusing on vulnerabilities affecting web applications built with it."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    severity: str | None = None
    """Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class VeeamBulletin(SoftwareBulletin):
    """`type: veeam` — Veeam collection includes advisories and CVEs related to Veeam software products, focusing on vulnerabilities affecting backup and recovery solutions."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class VeracodeBulletin(SoftwareBulletin):
    """`type: veracode` — Veracode provides security advisories and vulnerability data focused on application security for various software products and vendors."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class VivaldiBulletin(SoftwareBulletin):
    """`type: vivaldi` — Vivaldi collection includes security advisories and CVEs related to the Vivaldi web browser, focusing on vulnerabilities affecting its functionality and security."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class VmwareBulletin(SoftwareBulletin):
    """`type: vmware` — VMware collection includes security advisories and CVEs related to VMware products and services, sourced from VMware's official security bulletins."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    vendor_cvss: Any = Field(default=None, alias="vendorCvss")
    """Vendor-assigned CVSS score block."""


class WpvulndbBulletin(SoftwareBulletin):
    """`type: wpvulndb` — Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""
    exploit: Any = None
    """Exploit availability/details (source-specific)."""
    generation: int | None = None
    """Internal generation/version counter of the record."""
    source_data: Any = Field(default=None, alias="sourceData")
    """Raw, unparsed source body as delivered by the origin."""


class XenBulletin(SoftwareBulletin):
    """`type: xen` — Xen collection includes security advisories and CVEs related to the Xen hypervisor, covering vulnerabilities affecting virtualization environments."""

    affected_software: list | None = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
    cpe_configurations: Any = Field(default=None, alias="cpeConfigurations")
    """CPE applicability configurations (NVD-style match tree)."""


class YubicoBulletin(SoftwareBulletin):
    """`type: yubico` — Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins."""

    affected_software: Any = Field(default=None, alias="affectedSoftware")
    """Affected software products (name/version/operator)."""
    attachments: Any = None
    """Binary/media attachments associated with the document."""
