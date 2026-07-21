# `symantec`  ·  ~6.9k documents

Symantec's collection includes security advisories and CVEs related to its software products and services, focusing on vulnerabilities and exploits.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2021-4104", "CVE-2021-44228", "CVE-2021…` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 9.3, "vector": "AV:N/AC:M/Au:N/C:C/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "HIGH", "cvssV2": {"version": "2…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Summary**\n\nSymantec products may be susc…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-4104", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.symantec.com/content/symantec/en…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SMNTC-19793"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-01-21T17:31:38"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-01-21T17:28:40"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2021-12-11T01:06:47"` |
| `references` | `list[str]` | External reference URLs. | `["http://www.kernel.org/"]` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Symantec Security Response"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-12-10T22:06:47Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Symantec Security Advisory for Log4j Vulnera…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"symantec"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/symantec/SMNTC-19793"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `687` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "4", "operator": "eq", "name": "…` |

### Collection fields

Specific to the `symantec` collection.

_None in the sample._

