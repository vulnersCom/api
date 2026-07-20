# `wired`  ·  ~3.4k documents

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A first-of-its-kind analysis found more than…` |
| `enchantments` | `object{score,short_description,tags}, object{short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Study finds over one i…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wired.com/story/apps-marketed-to…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIRED:A9D458277D5316228DC658290387B1F1"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:39:47"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T09:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T09:30:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Dell Cameron"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:39:47.283000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Apps Marketed to US Troops Are Shipping Chin…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wired"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wired/WIRED:A9D458277D53…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

