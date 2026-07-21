# `schneier`  ·  ~3k documents

Schneier's collection provides security advisories and analyses focused on various vulnerabilities across software and systems, sourced from Bruce Schneier's insights.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SCHNEIER:AAA7D33440370BB6631734F203D47BF7"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T11:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T11:03:45"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T11:03:45"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T11:36:51.090000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"On Flock License Plate Tracking Cameras"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"schneier"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/schneier/SCHNEIER:AAA7D3…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.schneier.com/blog/archives/2026/…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Bruce Schneier"` |

### Collection fields

Specific to the `schneier` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A recent story of a writer who was mistakenl…` |

