# `nmap`  ·  ~610 documents

Nmap collection includes vulnerability data sourced from Nmap scans, focusing on various OS and services, typically containing CVEs and security advisories.

**Family model:** [`ScannerBulletin`](../../data-models.md) — `bulletinFamily: scanner`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2012-1182", "CVE-2017-7494"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 10.0, "vector": "AV:N/AC:L/Au:N/C:C…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 100% | CVSS v2 score block. | `{"severity": "HIGH", "cvssV2": {"accessComple…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 100% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Retrieves IP addresses of the target's netwo…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2012-1182", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://nmap.org/nsedoc/scripts/nbns-interfa…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NMAP:NBNS-INTERFACES.NSE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-02-15T21:40:21"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-12-30T03:51:21"` |
| `nmap` | `object{categories,scriptType}` | 100% | Nmap script details (category, script type). | `{"scriptType": "portrule", "categories": ["de…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-12-30T03:51:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Andrey Zhukov from USSC"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"local shortport = require \"shortport\"\nloc…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-12-30T00:51:21Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"nbns-interfaces NSE Script"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nmap"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nmap/NMAP:NBNS-INTERFACE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `391` |

