# `packetstorm`  ·  ~51k documents

Packet Storm is a security database that provides advisories, exploits, and tools primarily focused on various software and operating systems.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-56877"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Skillable's SCORM lab launch endpoint valida…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31309", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/226162/"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORM:226162"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:20:43"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Greg Durys"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | Raw, unparsed source body as delivered by the origin. | `"Skillable's SCORM lab launch endpoint valida…` |
| `sourceHref` | `str` | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/226162"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:20:43.271000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"\ud83d\udcc4 Skillable SCORM userId Authoriz…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstorm"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/packetstorm/PACKETSTORM:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `34` |

### Family fields

Added by the [`ExploitBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `packetstorm` collection.

_None in the sample._

