# `mssecure`  ·  ~1.6k documents

Microsoft Security Update Guide collection featuring advisories and CVEs for Microsoft products and services across various platforms.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In this article\n\n  1. Weston on the future…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/security/blo…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSSECURE:445281739FE098F23CF282B09A1B1B05"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:08:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T16:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Elliot Volkman"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:08:38.640000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft at Black Hat USA 2026: Defending t…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mssecure"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mssecure/MSSECURE:445281…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `mssecure` collection.

_None in the sample._

