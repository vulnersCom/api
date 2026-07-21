# `fortinet`  ·  ~650 documents

Fortinet collection includes security advisories and CVEs related to Fortinet products and services, focusing on vulnerabilities and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FG-IR-23-104"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-11-02T16:04:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2023-10-10T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2023-10-10T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-10-09T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Protect"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fortinet"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/fortinet/FG-IR-23-104"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `41` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 4.9, "vector": "AV:N/AC:M/Au:S/C:P/…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "vector": "NONE"}, "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FortiGuard Labs"` |

### Collection fields

Specific to the `fortinet` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "7.2.5", "operator": "eq", "name…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-36555"]` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"An improper neutralization of script-related…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-36555", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.fortiguard.com/psirt/FG-IR-23-104"` |

