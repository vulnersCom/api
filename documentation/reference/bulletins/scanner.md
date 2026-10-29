# `scanner` family

**Model:** `ScannerBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: scanner`.

## Family fields

Present in every `scanner` document, beyond the [common base](base.md).

_No fields beyond the layers above._

## Collections

### `nessus` · ~390k documents → `NessusBulletin`

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpe` | `list[str] | None` | Affected products as CPE 2.2 URIs. | `["cpe:/o:canonical:ubuntu_linux:26.04:-:lts",…` |
| `cvssScoreSource` | `str | None` | Which party/standard the CVSS score was taken from. | `"CVE-2026-116816"` |
| `exploitAvailable` | `bool | None` | Whether a public exploit is available. | `false` |
| `exploitEase` | `str | None` | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `exploitableWith` | `Any` | Tools/frameworks the issue is exploitable with. |  |
| `naslFamily` | `str | None` | Nessus NASL plugin family. | `"Misc."` |
| `nessusSeverity` | `Any` | Severity as rated by the Nessus scanner. |  |
| `patchPublicationDate` | `Any` | Date the fixing patch was published. |  |
| `pluginID` | `str | None` | Scanner plugin identifier (e.g. Nessus plugin id). | `"372721"` |
| `solution` | `str | None` | Recommended remediation/fix, as text. | `"There is no known solution at this time."` |
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |
| `vendor_cvss2` | `Any` | Vendor-assigned CVSS v2 (score/vector). | `{"score": 6.8, "vector": "CVSS2#AV:N/AC:M/Au:…` |
| `vendor_cvss3` | `Any` | Vendor-assigned CVSS v3 (score/vector). | `{"score": 7.8, "vector": "CVSS:3.0/AV:L/AC:L/…` |
| `vpr` | `Any` | Tenable Vulnerability Priority Rating block. |  |
| `vulnerabilityPublicationDate` | `str | None` | Date the vulnerability itself was first published. | `"2026-10-27T00:00:00"` |

### `nmap` · ~610 documents → `NmapBulletin`

Nmap collection includes vulnerability data sourced from Nmap scans, focusing on various OS and services, typically containing CVEs and security advisories.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `nmap` | `Any` | Nmap script details (category, script type). | `{"scriptType": "portrule", "categories": ["de…` |
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"local shortport = require \"shortport\"\nloc…` |

### `nuclei` · ~4.5k documents → `NucleiBulletin`

Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"id: CVE-2020-27982\n\ninfo:\n  name: IceWarp…` |

### `openvas` · ~180k documents → `OpenvasBulletin`

OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `naslFamily` | `str | None` | Nessus NASL plugin family. | `"Product detection"` |
| `pluginID` | `str | None` | Scanner plugin identifier (e.g. Nessus plugin id). | `"1361412562310156935"` |
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"# SPDX-FileCopyrightText: 2026 Greenbone AG\…` |

### `rapid7` · ~420k documents → `Rapid7Bulletin`

Rapid7 provides vulnerability data focused on various vendors and products, including advisories, CVEs, and exploit information.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cisaKev` | `bool | None` | Whether Rapid7 marks the CVE as listed in CISA's Known Exploited Vulnerabilities catalog. | `false` |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). |  |
| `crossReferences` | `list[str] | None` | Rapid7 cross-references to other sources, each as 'SOURCE/ID' (e.g. 'NVD/NVD', 'CWE/CWE-122'). | `["NVD/NVD", "CWE/CWE-122"]` |
| `cwe` | `list[str] | None` | Associated CWE weakness identifiers. | `["CWE-122"]` |
| `exploitedInWild` | `bool | None` | Whether Rapid7 records in-the-wild exploitation (its key for wildExploited). | `false` |
| `hasMetasploitModule` | `bool | None` | Whether a Metasploit module exists for the issue; msfModuleCount holds how many. | `false` |
| `hasPoc` | `bool | None` | Whether Rapid7 knows of a public proof-of-concept (camelCase key for has_poc). | `false` |
| `hasRapid7VmCoverage` | `bool | None` | Whether Rapid7's vulnerability-management products detect the issue. | `true` |
| `isRapid7Critical` | `bool | None` | Whether Rapid7's own rating marks the issue critical. | `false` |
| `isZeroDay` | `bool | None` | Whether Rapid7 recorded the issue as a zero-day. | `false` |
| `msfModuleCount` | `int | None` | Number of Metasploit modules Rapid7 counts for the issue. | `0` |
| `rapid7Epss` | `Any` | Rapid7's copy of the EPSS forecast ('score' and 'percentile', both strings); an empty object when Rapid7 holds no EPSS data for the CVE. | `{"score": "0.00282", "percentile": "0.20609"}` |
| `rapid7Severity` | `Any` | Rapid7's own severity label — served empty on every document as of the last sampling, so prefer cvss/severity. |  |
| `rapid7UpdatedAt` | `str | None` | Date Rapid7 last updated its record, as 'YYYY-MM-DD'. | `"2026-10-28"` |
| `solution` | `Any` | Recommended remediation/fix, as text. |  |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"v3": {"vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI…` |

### `w3af` · ~140 documents → `W3afBulletin`

w3af is a vulnerability database focused on web application security, providing advisories, CVEs, and exploit information for various web technologies.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `aiDescription` | `Any` | AI-generated summary of the vulnerability. |  |
| `appercut` | `Any` | AppercutScanner tool provenance (report pages). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `exploitpack` | `Any` | ExploitPack tool provenance (platform, type). |  |
| `hackapp` | `Any` | HackApp mobile-app scan provenance. |  |
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"\"\"\"\nxml_file.py\n\nCopyright 2006 Andres…` |
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). | `{"pluginType": "Output"}` |

