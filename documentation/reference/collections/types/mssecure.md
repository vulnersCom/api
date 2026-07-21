# `mssecure`  ·  ~1.6k documents

Microsoft Security Update Guide collection featuring advisories and CVEs for Microsoft products and services across various platforms.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSSECURE:445281739FE098F23CF282B09A1B1B05"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:08:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T16:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T16:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:08:38.640000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Microsoft at Black Hat USA 2026: Defending t…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mssecure"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mssecure/MSSECURE:445281…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `11` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/security/blo…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Elliot Volkman"` |

### Collection fields

Specific to the `mssecure` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"In this article\n\n  1. Weston on the future…` |

