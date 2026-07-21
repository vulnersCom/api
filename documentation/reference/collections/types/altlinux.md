# `altlinux`  ·  ~2.3k documents

AltLinux collection provides security advisories and CVEs specifically for Alt Linux OS, detailing vulnerabilities and patches for its software packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-1161", "CVE-2023-1992", "CVE-2023-…` |
| `cvss` | `object{score,vector}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"4.0.5-alt1 built May 9, 2023 Anton Farygin i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-1161", "date": "2026-06-16…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://packages.altlinux.org/en/p10/srpms/w…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"979C51F845EC9F54CED079693729AB6A"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-05-10T03:22:42"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2023-05-09T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2023-05-09T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"https://packages.altlinux.org/en/sisyphus/se…` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-08T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"Security fix for the ALT Linux 10 package wi…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"altlinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/altlinux/979C51F845EC9F5…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `188` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ALT Linux", "OSVersion": "10", "arch…` |

### Collection fields

Specific to the `altlinux` collection.

_None in the sample._

