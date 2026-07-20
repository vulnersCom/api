# `wizblog`  ·  ~650 documents

Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Part 3: How the Red Agent bypassed a credit …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wiz.io/blog/red-agent-pov-busine…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIZBLOG:DE537C472999F083DEFF7BACB77EEC15"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T15:36:53"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T13:33:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T13:33:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gal Nagli"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T15:36:53.962000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Red Agent POV: The One Boolean That Brok…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wizblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wizblog/WIZBLOG:DE537C47…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

