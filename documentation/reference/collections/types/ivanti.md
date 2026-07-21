# `ivanti`  ·  ~290 documents

Ivanti's vulnerability collection includes security advisories and CVEs related to Ivanti products and services, focusing on vendor-specific vulnerabilities.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-55956"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Last Modified Date\n\nJul 15, 2026 9:18:40 A…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14902", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://forums.ivanti.com/s/article/kA1UL000…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"IVANTI:920A4DEE6CD4923E7C8257C0F0EDEB51"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T11:40:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T09:18:40"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T09:18:40"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Ivanti"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T11:40:50.852000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"EPMM: Impact of CVE-2026-55956 On EPMM And S…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ivanti"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ivanti/IVANTI:920A4DEE6C…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `ivanti` collection.

_None in the sample._

