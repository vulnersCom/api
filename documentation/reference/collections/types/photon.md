# `photon`  ·  ~3.7k documents

Photon is a vulnerability collection from the National Vulnerability Database (NVD) focusing on vendor-specific advisories and CVEs related to various software products.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PHSA-2026-4.0-1057"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T02:37:17"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T02:37:17.101000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Important Photon OS Security Update - PHSA-2…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"photon"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/photon/PHSA-2026-4.0-1057"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.2, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Updates of ['docker'] packages of Photon OS …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Photon"` |

### Collection fields

Specific to the `photon` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Photon", "OSVersion": "4.0", "arch":…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-42306"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31449", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://github.com/vmware/photon/wiki/Securi…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `vendorCvss` | `object{severity}` | Vendor-assigned CVSS score block. | `{"severity": "important"}` |

