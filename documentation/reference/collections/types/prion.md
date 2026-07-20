# `prion`  ·  ~210k documents

Prion collection includes advisories and CVEs related to vulnerabilities in software products from various vendors, focusing on security issues and exploits.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-56067"]` |
| `cwe` | `list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-862"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Missing Authorization vulnerability in Azzar…` |
| `enchantments` | `object{dependencies,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Missing Authorization …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-56067", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.prio-n.com/kb/vulnerability/CVE-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PRION:CVE-2024-56067"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-29T19:14:25"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-12-31T13:15:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-12-31T13:15:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://patchstack.com/database/wordpress/p…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"PRIOn knowledge base"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-12-31T10:15:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2024-56067"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"prion"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/prion/PRION:CVE-2024-56067"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

