# `mariadbunix`  ·  ~400 documents

MariaDB Unix collection includes advisories and CVEs specific to Unix-based systems for the MariaDB database server.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MARIA:CVE-2026-49261"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T08:37:27"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T02:22:35"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-11T17:13:20"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-30T11:51:22.696000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-49261"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mariadbunix"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mariadbunix/MARIA:CVE-20…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `32` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 10.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Disclaimer**:\n_This data contains informa…` |
| `enchantments` | `object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 1.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"MariaDB"` |

### Collection fields

Specific to the `mariadbunix` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "7", "arch": "…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-49261"]` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49261", "date": "2026-07-0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://github.com/MariaDB/server/security/…` |
| `unofficial_repo` | `bool` | Whether the fix comes from an unofficial repository. | `true` |

