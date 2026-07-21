# `checkpoint_advisories`  ·  ~14k documents

Checkpoint Advisories provide security bulletins from Check Point Software Technologies, including advisories and CVEs for their products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2022-21490"]` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 4.0, "vector": "AV:A/AC:H/Au:S/C:P/…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A remote code execution vulnerability exists…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-21490", "date": "2026-06-1…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CPAI-2022-0853"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-11-28T14:45:52"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2022-11-28T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2022-11-28T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Check Point Advisories"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-11-27T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Oracle MySQL Cluster Remote Code Execution (…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"checkpoint_advisories"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/checkpoint_advisories/CP…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `39` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `severity` | `str` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"Medium"` |

### Collection fields

Specific to the `checkpoint_advisories` collection.

| field | type | description | example |
|---|---|---|---|
| `protected_by` | `list[str]` | Products/controls that protect against the issue. | `["Security Gateway R81", "Security Gateway R8…` |
| `vulnerable_products` | `list[str]` | Product identifiers known to be vulnerable. | `["Oracle MySQL Cluster 7.4.35 and prior", "Or…` |

