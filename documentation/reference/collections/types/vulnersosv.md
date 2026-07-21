# `vulnersosv`  ·  ~27k documents

Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNERSOSV:ZVNJKDJJTBACCOLN2NMHZBRHU4"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T12:57:20"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T18:18:18"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-30T18:10:28"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T12:57:20.917000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"dev.sigstore:sigstore-maven-plugin (=2.0.0),…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnersosv"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vulnersosv/VULNERSOSV:ZV…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `13` |

### Family fields

Present in every sampled `library`-family document (typed by [`LibraryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"dev.sigstore:sigstore-java (MAVEN) version =…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.1, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/GHSA-qqw8-7c2r…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Vulners OSV"` |

### Collection fields

Specific to the `vulnersosv` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `baseAffectedLibrary` | `object{name,purl,registry,versionEndIncluding,versionStartIncluding}, object{name,purl,registry,version}` | The primary affected library (name, purl, version range). | `{"name": "dev.sigstore:sigstore-java", "versi…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-48791"]` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44182", "date": "2026-07-1…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `snapshot_date` | `str` | Date of the data snapshot this record was taken from. | `"2026-06-23"` |
| `transitiveAffectedLibraries` | `list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,version}]` | Libraries affected transitively via dependencies. | `[{"name": "dev.sigstore:sigstore-maven-plugin…` |

