# `altlinux`  ·  ~2.3k documents

AltLinux collection provides security advisories and CVEs specifically for Alt Linux OS, detailing vulnerabilities and patches for its software packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ALT Linux", "OSVersion": "10", "arch…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-1161", "CVE-2023-1992", "CVE-2023-…` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 0.0, "vector": "NONE"}` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 25% | CVSS v2 score block. | `{"severity": "MEDIUM", "cvssV2": {"version": …` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 85% | CVSS v3.x score block. | `{"cvssV3": {"version": "3.1", "vectorString":…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"4.0.5-alt1 built May 9, 2023 Anton Farygin i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-1161", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packages.altlinux.org/en/p10/srpms/w…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"979C51F845EC9F54CED079693729AB6A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-05-10T03:22:42"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-05-09T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-05-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://packages.altlinux.org/en/sisyphus/se…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-08T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security fix for the ALT Linux 10 package wi…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"altlinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/altlinux/979C51F845EC9F5…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `188` |

