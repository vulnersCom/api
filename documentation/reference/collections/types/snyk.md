# `snyk`  ·  ~36k documents

Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SNYK:RUBY-ZZTARGETTEST18587-18015504"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:58:07"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T01:58:04"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T01:58:04"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:58:07.212000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Malicious Package"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"snyk"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/snyk/SNYK:RUBY-ZZTARGETT…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `0` |

### Family fields

Present in every sampled `library`-family document (typed by [`LibraryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Overview\n[zztargettest18587](https://rub…` |
| `enchantments` | `object{score,short_description,tags}, object{short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Malicious rubygems pac…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.snyk.io/vuln/SNYK-RUBY-ZZTA…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Snyk Security Database"` |

### Collection fields

Specific to the `snyk` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{name,registry}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "gem", "name": "zztargettest185…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "snyk", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "snyk", "version": "4.0…` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "snyk", "vers…` |
| `references` | `list[str]` | External reference URLs. | `["https://security.snyk.io/vuln/SNYK-RUBY-ZZT…` |
| `snykData` | `object{exploitMaturity,malicious,proprietary,socialTrendAlert}` | Snyk-specific data (exploit maturity, malicious flag). | `{"socialTrendAlert": false, "proprietary": fa…` |

