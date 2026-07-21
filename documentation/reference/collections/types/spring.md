# `spring`  ·  ~930 documents

Spring collection includes vulnerability advisories and CVEs related to the Spring framework and its ecosystem, sourced from various security bulletins.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SPRING:5F62B7C8F014C10E2FD7C3B2BB3BC743"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:37:30"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:37:30.020000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"A Bootiful Podcast: Russ Miles on Safer, Mor…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"spring"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/spring/SPRING:5F62B7C8F0…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"joshlong"` |

### Collection fields

Specific to the `spring` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"I\u2019m joined, I think, for the second tim…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://spring.io/blog/2026/07/16/a-bootiful…` |

