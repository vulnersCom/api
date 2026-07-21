# `patchstack`  ·  ~47k documents

Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-53496"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://patchstack.com/database/npm/plugin/e…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PATCHSTACK:CBE40482C25309E8731F3439AF8CFEB4"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T20:37:03"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T20:19:39"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T20:19:39"` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/mattiasw/ExifReader/secu…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Patchstack"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T20:37:15.463000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"patchstack"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/patchstack/PATCHSTACK:CB…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `9` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "4.40.0", "operator": "le", "nam…` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `patchstack` collection.

| field | type | description | example |
|---|---|---|---|
| `classification` | `str` | Source-specific classification/category of the issue. | `"Other Vulnerability Type"` |
| `isExploited` | `bool` | Whether the vulnerability is known to be exploited. | `false` |
| `owasp` | `str` | Related OWASP category. | `"A1: Broken Access Control"` |

