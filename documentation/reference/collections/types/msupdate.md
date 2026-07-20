# `msupdate`  ·  ~47k documents

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `bundledUpdates` | `list[str]` | 100% | Updates bundled into this one. | `["4a0ac059-8f41-4ae2-9a0f-2a52dfc102c3", "e57…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `enchantments` | `object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.catalog.update.microsoft.com/Sco…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:31951C3E-BA7B-4C43-833C-63A3CD1321AA"` |
| `kb` | `str` | 100% | Microsoft Knowledge Base article id. | `"KB5104034"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:39:19"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T17:00:00"` |
| `prerequisitesUpdates` | `list[str]` | 100% | Prerequisite updates required before this one. | `["3e0afb10-a9fb-4c16-a60e-5790c3803437", "799…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T17:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `revision` | `str` | 100% | Revision number of the advisory. | `"200"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `supersededUpdates` | `list[str]` | 100% | Updates superseded by this one. | `["3912ee8f-5273-4d9a-9e5d-706bc5edc8a6", "3ad…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T20:16:17.143000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msupdate"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/msupdate/MS:31951C3E-BA7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

