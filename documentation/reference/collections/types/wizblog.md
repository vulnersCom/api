# `wizblog`  ·  ~650 documents

Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIZBLOG:4A901FF2D14BDD326A4274A34B403DB0"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T21:36:57"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T18:00:08"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T18:00:08"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T21:36:58.232000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Exploitation in the Wild of wp2shell"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wizblog"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/wizblog/WIZBLOG:4A901FF2…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Gili Tikochinski"` |

### Collection fields

Specific to the `wizblog` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "contact@wpscan.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Wiz Research has identified exploitation of …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.wiz.io/blog/wp2shell-cve-2026-63…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |

