# `android`  ·  ~610 documents

Android vulnerabilities collection from various sources, covering advisories and CVEs related to Android OS and applications.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 50% | Affected software products (name/version/operator). | `[{"operator": "lt", "version": "7.0", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2019-10539"]` |
| `cvss` | `object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"score": 10.0, "vector": "AV:N/AC:L/Au:N/C:C…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,severity,userInteractionRequired}` | 95% | CVSS v2 score block. | `{"severity": "HIGH", "acInsufInfo": false, "c…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore}` | 80% | CVSS v3.x score block. | `{"cvssV3": {"attackComplexity": "LOW", "attac…` |
| `description` | `str` | 45% | Full text or summary of the vulnerability/advisory. | `"Android 4.3 and below do not use Security-En…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.8, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-10539", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.androidvulnerabilities.org/vulner…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANDROID:CVE-2019-10539"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:34:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-08-12T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-08-01T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/data-feeds", "htt…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Xiling Gong of Tencent Blade Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-07-31T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2019-10539"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"android"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/android/ANDROID:CVE-2019…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `87` |

