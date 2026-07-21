# `packetstorm`  ·  ~51k documents

Packet Storm is a security database that provides advisories, exploits, and tools primarily focused on various software and operating systems.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORM:226151"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:22:23"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:22:23.732000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"\ud83d\udcc4 EZ Game Booster 1.0.0 Insecure …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstorm"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/packetstorm/PACKETSTORM:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `32` |

### Family fields

Present in every sampled `exploit`-family document (typed by [`ExploitBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |

### Collection fields

Specific to the `packetstorm` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-31309"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"EZ Game Booster version 1.0.0 stores clearte…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31309", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/226151/"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Alireza Chegini"` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"# Exploit Title: EZ Game Booster v1.0.0 - Cl…` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/226151"` |

