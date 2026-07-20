# `oraclelinux`  ·  ~9.4k documents

Oracle Linux vulnerabilities collection includes advisories and CVEs specific to Oracle Linux OS, sourced from Oracle's security bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "oracle linux", "OSVersion": "10", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-8388", "CVE-2026-8391", "CVE-2026-…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "security", "version":…` |
| `cvss4` | `object{cvssV4}` | 20% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[140.12.0-1.0.1]\n- Add Oracle prefs\n[140.1…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 10% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10649", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://linux.oracle.com/errata/ELSA-2026-223…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELSA-2026-22325"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T19:36:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OracleLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T19:36:54.567000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"thunderbird security update"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oraclelinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/oraclelinux/ELSA-2026-22…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

