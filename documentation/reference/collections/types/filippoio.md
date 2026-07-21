# `filippoio`  ·  ~110 documents

Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-26958"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A requirement for staying sane while working…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-26958", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://words.filippo.io/vuln-reports/"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FILIPPOIO:7E5AA1729D42CFF70B3B99F0B9C1A508"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T11:36:50"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T13:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-23T13:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Filippo Valsorda <feed@filippo.io>"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T15:36:50.439000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Vulnerability Reports Are Not Special Anymore"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"filippoio"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/filippoio/FILIPPOIO:7E5A…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `18` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `filippoio` collection.

_None in the sample._

