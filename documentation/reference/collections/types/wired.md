# `wired`  ·  ~3.4k documents

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A first-of-its-kind analysis found more than…` |
| `enchantments` | `object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Study finds over one i…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wired.com/story/apps-marketed-to…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIRED:A9D458277D5316228DC658290387B1F1"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T09:39:47"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T09:30:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T09:30:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Dell Cameron"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T09:39:47.283000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Apps Marketed to US Troops Are Shipping Chin…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wired"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wired/WIRED:A9D458277D53…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `wired` collection.

_None in the sample._

