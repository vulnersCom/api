# `krebs`  ·  ~1.1k documents

Krebs on Security provides in-depth articles and analysis on cybersecurity threats, breaches, and vulnerabilities, focusing on various vendors and products.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 25% | Related CVE identifiers referenced by this document. | `["CVE-2026-50661"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 25% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Microsoft Corp.** today released software …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "uncertanity": 3.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 25% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50661", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://krebsonsecurity.com/2026/07/microsof…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KREBS:E337AAA92EB8EC130AF8281A694FFF0E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T03:44:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 25% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T19:22:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T19:22:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"BrianKrebs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:44:37.768000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Patches a Record 570 Security Flaws"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"krebs"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/krebs/KREBS:E337AAA92EB8…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

