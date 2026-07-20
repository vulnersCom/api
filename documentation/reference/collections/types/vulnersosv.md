# `vulnersosv`  ·  ~27k documents

Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them.

**Family model:** [`LibraryBulletin`](../../data-models.md) — `bulletinFamily: library`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `baseAffectedLibrary` | `object{name,purl,registry,versionEndIncluding,versionStartIncluding}, object{name,purl,registry,version}` | 100% | The primary affected library (name, purl, version range). | `{"name": "dev.sigstore:sigstore-java", "versi…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[str]` | 90% | Related CVE identifiers referenced by this document. | `["CVE-2026-48791"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 65% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"dev.sigstore:sigstore-java (MAVEN) version =…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 25% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44182", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/GHSA-qqw8-7c2r…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNERSOSV:ZVNJKDJJTBACCOLN2NMHZBRHU4"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T12:57:20"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 65% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T18:18:18"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T18:10:28"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Vulners OSV"` |
| `snapshot_date` | `str` | 100% | Date of the data snapshot this record was taken from. | `"2026-06-23"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T12:57:20.917000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"dev.sigstore:sigstore-maven-plugin (=2.0.0),…` |
| `transitiveAffectedLibraries` | `list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,version}]` | 100% | Libraries affected transitively via dependencies. | `[{"name": "dev.sigstore:sigstore-maven-plugin…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnersosv"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnersosv/VULNERSOSV:ZV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

