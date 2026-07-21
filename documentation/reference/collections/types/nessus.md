# `nessus`  ·  ~340k documents

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-57825"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The remote Fedora 43 host has a package inst…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.tenable.com/plugins/nessus/327801"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FEDORA_2026-FB48505840.NASL"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T02:03:56"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-19T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://bodhi.fedoraproject.org/updates/FED…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Tenable"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T02:03:56.716000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Fedora 43 : opam (2026-fb48505840)"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nessus"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nessus/FEDORA_2026-FB485…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`ScannerBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpe` | `list[str]` | Affected products as CPE 2.2 URIs. | `["cpe:/o:fedoraproject:fedora:43", "p-cpe:/a:…` |
| `cvssScoreSource` | `str` | Which party/standard the CVSS score was taken from. | `"CVE-2026-57825"` |
| `exploitAvailable` | `bool` | Whether a public exploit is available. | `false` |
| `naslFamily` | `str` | Nessus NASL plugin family. | `"Fedora Local Security Checks"` |
| `nessusSeverity` | `str` | Severity as rated by the Nessus scanner. | `"High"` |
| `pluginID` | `str` | Scanner plugin identifier (e.g. Nessus plugin id). | `"327801"` |
| `solution` | `str` | Recommended remediation/fix, as text. | `"Update the affected opam package."` |

### Collection fields

Specific to the `nessus` collection.

| field | type | description | example |
|---|---|---|---|
| `exploitEase` | `str` | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `patchPublicationDate` | `str` | Date the fixing patch was published. | `"2026-07-10T00:00:00"` |
| `vendor_cvss2` | `object{score,vector}` | Vendor-assigned CVSS v2 (score/vector). | `{"score": 6.4, "vector": "CVSS2#AV:N/AC:L/Au:…` |
| `vendor_cvss3` | `object{score,vector}` | Vendor-assigned CVSS v3 (score/vector). | `{"score": 9.1, "vector": "CVSS:3.0/AV:N/AC:L/…` |
| `vulnerabilityPublicationDate` | `str` | Date the vulnerability itself was first published. | `"2026-07-10T00:00:00"` |

