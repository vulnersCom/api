# `packetstorm`  ·  ~51k documents

Packet Storm is a security database that provides advisories, exploits, and tools primarily focused on various software and operating systems.

**Family model:** [`ExploitBulletin`](../../data-models.md) — `bulletinFamily: exploit`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 65% | Related CVE identifiers referenced by this document. | `["CVE-2026-56877"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 60% | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "disclosure@vulncheck.c…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Skillable's SCORM lab launch endpoint valida…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 25% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31309", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/226162/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORM:226162"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:20:43"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}` | 60% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Greg Durys"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"Skillable's SCORM lab launch endpoint valida…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/226162"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:20:43.271000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\ud83d\udcc4 Skillable SCORM userId Authoriz…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstorm"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/packetstorm/PACKETSTORM:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `34` |

