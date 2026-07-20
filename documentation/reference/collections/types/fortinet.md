# `fortinet`  ·  ~650 documents

Fortinet collection includes security advisories and CVEs related to Fortinet products and services, focusing on vulnerabilities and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "7.2.5", "operator": "eq", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-36555"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 4.9, "vector": "AV:N/AC:M/Au:S/C:P/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 80% | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 80% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An improper neutralization of script-related…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-36555", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.fortiguard.com/psirt/FG-IR-23-104"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FG-IR-23-104"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-11-02T16:04:07"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-10-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-10-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FortiGuard Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-10-09T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Protect"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fortinet"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fortinet/FG-IR-23-104"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `41` |

