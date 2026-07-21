# `typo3`  ·  ~470 documents

TYPO3 vulnerability collection from various sources, covering advisories and CVEs specific to the TYPO3 CMS platform.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-23638"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 4.3, "vector": "AV:N/AC:M/Au:N/C:N/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The SVG sanitizer library [enshrined/svg-san…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{backreferences,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.0, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-23638", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://typo3.org/security/advisory/typo3-ps…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TYPO3-PSA-2022-001"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-02-23T04:29:08"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-02-22T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-02-22T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"TYPO3 Association"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-21T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Sanitization bypass in SVG Sanitizer"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"typo3"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/typo3/TYPO3-PSA-2022-001"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `59` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "v11", "operator": "eq", "name":…` |

### Collection fields

Specific to the `typo3` collection.

_None in the sample._

