# `scanner` family

**Model:** `ScannerBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: scanner`.

## Family fields

Present in every `scanner` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `sourceData` | `str | None` | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |

## Collections

### `nessus` · ~340k documents → `NessusBulletin`

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpe` | `list[str] | None` | Affected products as CPE 2.2 URIs. | `["cpe:/o:canonical:ubuntu_linux:14.04:-:lts",…` |
| `cvssScoreSource` | `str | None` | Which party/standard the CVSS score was taken from. | `"CVE-2026-63931"` |
| `exploitAvailable` | `bool | None` | Whether a public exploit is available. | `false` |
| `exploitEase` | `str | None` | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `exploitableWith` | `Any` | Tools/frameworks the issue is exploitable with. |  |
| `naslFamily` | `str | None` | Nessus NASL plugin family. | `"Misc."` |
| `nessusSeverity` | `str | None` | Severity as rated by the Nessus scanner. | `"Important"` |
| `patchPublicationDate` | `str | None` | Date the fixing patch was published. | `"2026-07-16T00:00:00"` |
| `pluginID` | `str | None` | Scanner plugin identifier (e.g. Nessus plugin id). | `"328307"` |
| `solution` | `str | None` | Recommended remediation/fix, as text. | `"There is no known solution at this time."` |
| `vendor_cvss2` | `Any` | Vendor-assigned CVSS v2 (score/vector). | `{"score": 2.1, "vector": "CVSS2#AV:L/AC:L/Au:…` |
| `vendor_cvss3` | `Any` | Vendor-assigned CVSS v3 (score/vector). | `{"score": 5.5, "vector": "CVSS:3.0/AV:L/AC:L/…` |
| `vpr` | `Any` | Tenable Vulnerability Priority Rating block. |  |
| `vulnerabilityPublicationDate` | `str | None` | Date the vulnerability itself was first published. | `"2026-07-19T00:00:00"` |

### `nmap` · ~610 documents → `NmapBulletin`

Nmap collection includes vulnerability data sourced from Nmap scans, focusing on various OS and services, typically containing CVEs and security advisories.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `nmap` | `Any` | Nmap script details (category, script type). | `{"scriptType": "portrule", "categories": ["de…` |

### `nuclei` · ~4.2k documents → `NucleiBulletin`

Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |

### `openvas` · ~180k documents → `OpenvasBulletin`

OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses.

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `naslFamily` | `str | None` | Nessus NASL plugin family. | `"Product detection"` |
| `pluginID` | `str | None` | Scanner plugin identifier (e.g. Nessus plugin id). | `"1361412562310156935"` |

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
| `toolHref` | `Any` | Link to the associated tool/exploit. |  |
| `w3af` | `Any` | w3af scanner provenance (plugin type). | `{"pluginType": "Output"}` |

