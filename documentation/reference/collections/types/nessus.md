# `nessus`  ·  ~340k documents

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"UNPATCHED_CVE_2026_63936.NASL"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:51:10"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:51:10.048000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Linux Distros Unpatched Vulnerability : CVE-…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nessus"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nessus/UNPATCHED_CVE_202…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `0` |

### Family fields

Present in every sampled `scanner`-family document (typed by [`ScannerBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The Linux/Unix host has one or more packages…` |
| `enchantments` | `object{aggregatedScoring,dependencies,short_description,tags}, object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Linux iio adc mt6359 C…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.tenable.com/plugins/nessus/328286"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Tenable"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |

### Collection fields

Specific to the `nessus` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpe` | `list[str]` | Affected products as CPE 2.2 URIs. | `["cpe:/o:canonical:ubuntu_linux:14.04:-:lts",…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-63936"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvssScoreSource` | `str` | Which party/standard the CVSS score was taken from. | `"CVE-2026-63936"` |
| `exploitAvailable` | `bool` | Whether a public exploit is available. | `false` |
| `exploitEase` | `str` | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `naslFamily` | `str` | Nessus NASL plugin family. | `"Misc."` |
| `nessusSeverity` | `str` | Severity as rated by the Nessus scanner. | `"Important"` |
| `patchPublicationDate` | `str` | Date the fixing patch was published. | `"2026-05-12T00:00:00"` |
| `pluginID` | `str` | Scanner plugin identifier (e.g. Nessus plugin id). | `"328286"` |
| `references` | `list[str]` | External reference URLs. | `["https://ubuntu.com/security/CVE-2026-63936"…` |
| `solution` | `str` | Recommended remediation/fix, as text. | `"There is no known solution at this time."` |
| `vendor_cvss2` | `object{score,vector}` | Vendor-assigned CVSS v2 (score/vector). | `{"score": 2.1, "vector": "CVSS2#AV:L/AC:L/Au:…` |
| `vendor_cvss3` | `object{score,vector}` | Vendor-assigned CVSS v3 (score/vector). | `{"score": 5.5, "vector": "CVSS:3.0/AV:L/AC:L/…` |
| `vulnerabilityPublicationDate` | `str` | Date the vulnerability itself was first published. | `"2026-07-19T00:00:00"` |

