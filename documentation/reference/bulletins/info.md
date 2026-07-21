# `info` family

**Model:** `InfoBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: info`.

## Family fields

Present in every `info` document, beyond the [common base](base.md).

_No fields beyond the layers above._

## Collections

### `amd` · ~190 documents → `AmdBulletin`

AMD's vulnerability collection includes advisories and CVEs related to AMD hardware and software products, focusing on security issues affecting their technology.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `attackerkb` · ~79k documents → `AttackerkbBulletin`

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"vendor": "HCLSoftware", "version": "3.0.05…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `attackerkb` | `Any` | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `last_activity` | `str | None` | Timestamp of the most recent activity on the item. | `"2026-07-21T05:30:13"` |
| `mitre_vector` | `Any` | MITRE ATT&CK vector mapping. |  |
| `references_categories` | `Any` | References grouped by category (canonical/misc). | `{"canonical": ["https://cve.mitre.org/cgi-bin…` |
| `tags` | `Any` | Classification tags applied to the document. |  |
| `wildExploited` | `bool | None` | Whether the vulnerability is exploited in the wild. | `false` |
| `wildExploitedCategory` | `Any` | Category of in-the-wild exploitation. |  |
| `wildExploitedReports` | `Any` | Reports evidencing in-the-wild exploitation. |  |

### `bdu_fstec` · ~91k documents → `BduFstecBulletin`

BDU FSTEC provides advisories from the Russian Federal Service for Technical and Export Control, focusing on vulnerabilities in software and hardware products.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"vendor": "\u041e\u041e\u041e \u00ab\u0420\…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### `binamuse` · ~15 documents → `BinamuseBulletin`

Binamuse is a vulnerability collection from the Binamuse database focusing on advisories and CVEs related to various software products and systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `cert` · ~3.7k documents → `CertBulletin`

A collection of advisories and alerts from the Computer Emergency Response Team (CERT) covering various vendors and products, including CVEs and security incidents.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `checkpoint_advisories` · ~14k documents → `CheckpointAdvisoriesBulletin`

Checkpoint Advisories provide security bulletins from Check Point Software Technologies, including advisories and CVEs for their products.

| field | type | description | example |
|---|---|---|---|
| `protected_by` | `list[str] | None` | Products/controls that protect against the issue. | `["Security Gateway R81", "Security Gateway R8…` |
| `severity` | `str | None` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"Medium"` |
| `vulnerable_products` | `list[str] | None` | Product identifiers known to be vulnerable. | `["Oracle MySQL Cluster 7.4.35 and prior", "Or…` |

### `circl` · ~180k documents → `CirclBulletin`

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `items` | `list | None` | Sub-items/entries contained in the document. | `[{"uuid": "240f319f-892d-4d24-85d7-ec2154beed…` |
| `wildExploited` | `bool | None` | Whether the vulnerability is exploited in the wild. | `false` |

### `cisa` · ~4.2k documents → `CisaBulletin`

CISA collection includes advisories and alerts from the Cybersecurity and Infrastructure Security Agency, focusing on vulnerabilities across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `wildExploited` | `bool | None` | Whether the vulnerability is exploited in the wild. | `true` |

### `cisa_kev` · ~1.7k documents → `CisaKevBulletin`

CISA KEV collection includes advisories and CVEs related to known exploited vulnerabilities across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `dueDate` | `str | None` | Remediation due date (e.g. CISA KEV required-action deadline). | `"2026-07-19T00:00:00"` |
| `knownRansomwareCampaignUse` | `str | None` | Ransomware-campaign-use marker, as a string ('Known'/'Unknown', per CISA KEV) — not a boolean. | `"Unknown"` |
| `notes` | `str | None` | Free-text notes. | `"https://fortiguard.fortinet.com/psirt/FG-IR-…` |
| `product` | `str | None` | Affected product name. | `"FortiSandbox"` |
| `requiredAction` | `str | None` | Required remediation action (e.g. CISA KEV directive). | `"Apply mitigations in accordance with vendor …` |
| `vendor` | `str | None` | Affected product's vendor. | `"Fortinet"` |
| `wildExploited` | `bool | None` | Whether the vulnerability is exploited in the wild. | `true` |

### `ciscothreats` · ~14k documents → `CiscothreatsBulletin`

Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `ciscoThreat` | `Any` | Cisco Talos threat details (files, hashes, subject). | `{"md5": "c130666367eb5724a23d046a7963df5e", "…` |

### `coresecurity` · ~250 documents → `CoresecurityBulletin`

Core Security provides vulnerability advisories and CVEs focused on various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `cve0day` · ~14 documents → `Cve0dayBulletin`

CVE0day is a collection from various sources focusing on zero-day vulnerabilities, typically including advisories and CVEs for multiple vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `duo` · ~54 documents → `DuoBulletin`

Duo Security's collection features advisories and CVEs related to its authentication products and services, focusing on security vulnerabilities and fixes.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `erpscan` · ~290 documents → `ErpscanBulletin`

ERPSCAN provides security advisories and CVEs specifically focused on vulnerabilities in ERP systems and related applications.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `fireeye` · ~540 documents → `FireeyeBulletin`

FireEye collection includes vendor-specific advisories and CVEs related to cybersecurity threats and exploits for various products and services.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `googleprojectzero` · ~250 documents → `GoogleprojectzeroBulletin`

Google Project Zero collection features advisories and CVEs focused on vulnerabilities in various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `hivepro` · ~1.6k documents → `HiveproBulletin`

HivePro provides a comprehensive database of vulnerability advisories, CVEs, and threat intelligence focused on various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `ics` · ~4.3k documents → `IcsBulletin`

This collection from the ICS-CERT includes advisories and CVEs related to vulnerabilities in industrial control systems across various vendors.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `intel` · ~1k documents → `IntelBulletin`

Intel's vulnerability collection includes advisories and CVEs related to Intel products and technologies, focusing on hardware and software security issues.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `severity` | `str | None` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"HIGH"` |

### `kaspersky` · ~4k documents → `KasperskyBulletin`

Kaspersky's collection includes security advisories and CVEs related to their antivirus products and software vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `lenovo` · ~1.2k documents → `LenovoBulletin`

Lenovo's vulnerability collection includes advisories and CVEs related to Lenovo products and software, sourced from their security bulletins.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `myhack58` · ~7.6k documents → `Myhack58Bulletin`

MyHack58 provides security advisories and CVEs focused on vulnerabilities related to various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `packetstormnews` · ~6.9k documents → `PacketstormnewsBulletin`

Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `sourceHref` | `str | None` | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/213585"` |

### `ptsecurity` · ~190k documents → `PtsecurityBulletin`

PTSecurity provides security advisories and CVEs focused on vulnerabilities affecting various software products and systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |

### `qt` · ~41 documents → `QtBulletin`

Qt vulnerabilities from the Qt Company, covering advisories and CVEs related to the Qt framework across various platforms and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `rapid7blog` · ~1.7k documents → `Rapid7blogBulletin`

Rapid7 Blog provides insights on security vulnerabilities, advisories, and exploit techniques relevant to various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `rdot` · ~230 documents → `RdotBulletin`

Rdot is a vulnerability collection from the Rdot database, focusing on advisories and CVEs related to various software products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). |  |

### `redhatcve` · ~210k documents → `RedhatcveBulletin`

Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-1287"]` |
| `sourceAffectedData` | `Any` | Affected-product data in the source's own shape. |  |
| `upstreamFix` | `Any` | Whether/where an upstream fix is available. |  |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:…` |

### `samba` · ~170 documents → `SambaBulletin`

Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `security_vulns` · ~80 documents → `SecurityVulnsBulletin`

A collection of security vulnerabilities from various vendors, including advisories, CVEs, and exploit information.

_No fields beyond the layers above._

### `spring` · ~930 documents → `SpringBulletin`

Spring collection includes vulnerability advisories and CVEs related to the Spring framework and its ecosystem, sourced from various security bulletins.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `talos` · ~2.2k documents → `TalosBulletin`

Talos provides threat intelligence from Cisco, focusing on vulnerabilities across various software and hardware products, including advisories and CVEs.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `tenable` · ~220 documents → `TenableBulletin`

Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `thn` · ~21k documents → `ThnBulletin`

The "thn" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `threatpost` · ~16k documents → `ThreatpostBulletin`

Threatpost provides security news and analysis, focusing on vulnerabilities, exploits, and advisories across various vendors and products.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `trellix` · ~610 documents → `TrellixBulletin`

Trellix provides security advisories and CVEs related to its cybersecurity products and services, focusing on vendor-specific vulnerabilities.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `vulncheck_kev` · ~5k documents → `VulncheckKevBulletin`

Vulncheck_kev aggregates security advisories and CVEs from various vendors, focusing on known exploited vulnerabilities across multiple products.

| field | type | description | example |
|---|---|---|---|
| `_product` | `str | None` | Affected product name (source-internal key). | `"Red Sea Cloud eHR"` |
| `_vendor` | `str | None` | Affected product's vendor (source-internal key). | `"Guangzhou Red Sea Cloud Computing Co., Ltd."` |
| `_vulncheck_reported_exploitation` | `list | None` | VulnCheck-reported exploitation evidence. | `[{"url": "https://www.cve.org/CVERecord?id=CV…` |
| `_vulncheck_xdb` | `list | None` | VulnCheck exploit/DB cross-references. | `[{"xdb_id": "c8884e9be221", "xdb_url": "https…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": false, "VulnCheckCpeConfiguration"…` |
| `cvssScore` | `float | None` | Flat numeric CVSS base score, when only a scalar is provided. | `9.3` |
| `source` | `str | None` | Source name/identifier for the record. | `"disclosure@vulncheck.com"` |
| `wildExploited` | `bool | None` | Whether the vulnerability is exploited in the wild. | `true` |

### `wizblog` · ~650 documents → `WizblogBulletin`

Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `wordfence` · ~520 documents → `WordfenceBulletin`

Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `zdi` · ~17k documents → `ZdiBulletin`

The ZDI collection includes advisories and CVEs from the Zero Day Initiative, focusing on vulnerabilities in various software products and vendors.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

