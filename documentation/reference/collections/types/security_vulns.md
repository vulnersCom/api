# `security_vulns`  ·  ~80 documents

A collection of security vulnerabilities from various vendors, including advisories, CVEs, and exploit information.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2007-0842"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\n\n\nTitle:        Microsoft Visual C++ 8.0…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2007-0842", "date": "2026-06-16…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY_VULNS:YEAR3000"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-08-25T14:27:26"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2007-12-02T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2007-12-02T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"SecurityVulns"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2007-12-01T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft Visual C++ 8.0 standard library ti…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"security_vulns"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/security_vulns/SECURITY_…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `83` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `security_vulns` collection.

_None in the sample._

