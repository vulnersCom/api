# `securityvulns`  ·  ~47k documents

A collection of security vulnerabilities sourced from various vendors, covering advisories and CVEs across multiple products and operating systems.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "eq", "version": "0.3", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2015-7747"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crash on audiofiles processing."` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 3.1, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2015-7747", "date": "2026-06-21…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITYVULNS:VULN:14754"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-31T11:10:03"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-11-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-11-02T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://vulners.com/securityvulns/securityv…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"BUGTRAQ"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-11-01T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"audiofile memory corruption"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securityvulns"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `173` |

