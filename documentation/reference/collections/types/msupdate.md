# `msupdate`  ·  ~47k documents

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `enchantments` | `object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.catalog.update.microsoft.com/Sco…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:31951C3E-BA7B-4C43-833C-63A3CD1321AA"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:39:19"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T17:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-14T17:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T20:16:17.143000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msupdate"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/msupdate/MS:31951C3E-BA7…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`MicrosoftBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `kb` | `str` | Microsoft Knowledge Base article id. | `"KB5104034"` |

### Collection fields

Specific to the `msupdate` collection.

| field | type | description | example |
|---|---|---|---|
| `bundledUpdates` | `list[str]` | Updates bundled into this one. | `["4a0ac059-8f41-4ae2-9a0f-2a52dfc102c3", "e57…` |
| `prerequisitesUpdates` | `list[str]` | Prerequisite updates required before this one. | `["3e0afb10-a9fb-4c16-a60e-5790c3803437", "799…` |
| `revision` | `str` | Revision number of the advisory. | `"200"` |
| `supersededUpdates` | `list[str]` | Updates superseded by this one. | `["3912ee8f-5273-4d9a-9e5d-706bc5edc8a6", "3ad…` |

