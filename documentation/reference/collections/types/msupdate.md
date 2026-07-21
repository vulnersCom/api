# `msupdate`  ·  ~47k documents

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:0C7356A2-239E-40E5-AA6C-3114CA1BDF83"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T03:39:50"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T17:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T17:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T20:16:16.712000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"2026-07 Cumulative Update for Windows 10 Ver…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msupdate"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/msupdate/MS:0C7356A2-239…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `139` |

### Family fields

Present in every sampled `microsoft`-family document (typed by [`MicrosoftBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"2026-07 Cumulative Update for Windows 10 Ver…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.catalog.update.microsoft.com/Sco…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft"` |

### Collection fields

Specific to the `msupdate` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `bundledUpdates` | `list[str]` | Updates bundled into this one. | `["566e2a81-e81f-4130-88a5-b64340fb965f"]` |
| `kb` | `str` | Microsoft Knowledge Base article id. | `"KB5099539"` |
| `prerequisitesUpdates` | `list[str]` | Prerequisite updates required before this one. | `["59653007-e2e9-4f71-8525-2ff588527978", "700…` |
| `revision` | `str` | Revision number of the advisory. | `"200"` |
| `supersededUpdates` | `list[str]` | Updates superseded by this one. | `["0184c75f-f1e7-4baa-b220-fa4802f1c804", "050…` |

