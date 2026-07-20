# `wired`  ·  ~3.4k documents

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Plus: Russian cyberspies turn to infrastruct…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wired.com/story/security-news-th…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIRED:EAF20DF879E70ED861FB02282E96B8EF"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:36:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T10:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T10:30:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Andy Greenberg, Dell Cameron, Lily Hay Newman"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:36:50.597000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Your Period Tracker Is (Probably) Spying on …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wired"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wired/WIRED:EAF20DF879E7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

