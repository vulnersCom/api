# `wired`  ·  ~3.4k documents

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIRED:1C17C83160CADA806C6B7446266F2C04"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T11:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T10:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T10:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T11:36:51.211000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"The ACLU Is Arming Lawyers to Expose State S…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wired"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wired/WIRED:1C17C83160CA…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wired.com/story/the-aclu-is-armi…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Dell Cameron"` |

### Collection fields

Specific to the `wired` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A new toolkit for attorneys in Massachusetts…` |

