# `oraclelinux`  ·  ~9.4k documents

Oracle Linux vulnerabilities collection includes advisories and CVEs specific to Oracle Linux OS, sourced from Oracle's security bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELSA-2026-41897"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T19:36:54"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T19:36:54.911000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `".NET 10.0 security, bug fix, and enhancement…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oraclelinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/oraclelinux/ELSA-2026-41…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"[10.0.110-1.0.1]\n- Add support for Oracle L…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 2.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"OracleLinux"` |

### Collection fields

Specific to the `oraclelinux` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "oracle linux", "OSVersion": "10", "a…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-47300", "CVE-2026-47302", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://linux.oracle.com/errata/ELSA-2026-418…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |

