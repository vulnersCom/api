# `security_vulns`  ·  ~80 documents

A collection of security vulnerabilities from various vendors, including advisories, CVEs, and exploit information.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 10% | Related CVE identifiers referenced by this document. | `["CVE-2007-0842"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n\n\nTitle:        Microsoft Visual C++ 8.0…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2007-0842", "date": "2026-06-16…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY_VULNS:YEAR3000"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-08-25T14:27:26"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2007-12-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2007-12-02T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SecurityVulns"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2007-12-01T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Visual C++ 8.0 standard library ti…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"security_vulns"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/security_vulns/SECURITY_…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `83` |

