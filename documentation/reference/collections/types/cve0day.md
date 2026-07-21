# `cve0day`  ·  ~14 documents

CVE0day is a collection from various sources focusing on zero-day vulnerabilities, typically including advisories and CVEs for multiple vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2019-6340"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 6.8, "vector": "AV:NETWORK/AC:MEDIU…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "acInsufInfo": false, …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "HIGH", "atta…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Description**\n\nThis Metasploit module ex…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.9, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-6340", "date": "2026-07-15…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cve0day.com/drupal-cve-2019-6340…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE0DAY:BD50F22FA4B45F74682F7562C2FA7C3E"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-03-07T15:55:08"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2019-03-07T14:06:06"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2019-03-07T14:06:06"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CVE 0day"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-03-07T11:06:06Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Drupal CVE-2019-6340 Remote Code Execution EXP"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve0day"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cve0day/CVE0DAY:BD50F22F…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `290` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `cve0day` collection.

_None in the sample._

