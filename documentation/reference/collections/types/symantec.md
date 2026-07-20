# `symantec`  ·  ~6.9k documents

Symantec's collection includes security advisories and CVEs related to its software products and services, focusing on vulnerabilities and exploits.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4", "operator": "eq", "name": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-4104", "CVE-2021-44228", "CVE-2021…` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 9.3, "vector": "AV:N/AC:M/Au:N/C:C/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 90% | CVSS v2 score block. | `{"severity": "HIGH", "cvssV2": {"version": "2…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 90% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Summary**\n\nSymantec products may be susc…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-4104", "date": "2026-06-16…` |
| `href` | `str` | 5% | Canonical URL of the document at its original source. | `"https://www.symantec.com/content/symantec/en…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SMNTC-19793"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-01-21T17:31:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-01-21T17:28:40"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-12-11T01:06:47"` |
| `references` | `list[str]` | 5% | External reference URLs. | `["http://www.kernel.org/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Symantec Security Response"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-12-10T22:06:47Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Symantec Security Advisory for Log4j Vulnera…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"symantec"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/symantec/SMNTC-19793"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `687` |

