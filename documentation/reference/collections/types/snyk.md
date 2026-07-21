# `snyk`  ·  ~36k documents

Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-30623"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "snyk", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "snyk", "version": "4.0…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Overview\n[chai-as-thread](https://www.np…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50289", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.snyk.io/vuln/SNYK-JS-CHAIAS…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SNYK:JS-CHAIASTHREAD-17996339"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T22:31:56"` |
| `metrics` | `object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "snyk", "vers…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T15:21:23"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T15:21:23"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.snyk.io/vuln/SNYK-JS-CHAIA…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Snyk Security Database"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T22:31:56.010000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Malicious Package"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"snyk"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/snyk/SNYK:JS-CHAIASTHREA…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Added by the [`LibraryBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{name,registry,versionEndExcluding,versionStartIncluding}], list[object{name,registry,versionEndExcluding}], list[object{name,registry}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "npm", "name": "chai-as-thread"}]` |

### Collection fields

Specific to the `snyk` collection.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `snykData` | `object{exploitMaturity,malicious,proprietary,socialTrendAlert}` | Snyk-specific data (exploit maturity, malicious flag). | `{"socialTrendAlert": false, "proprietary": fa…` |

