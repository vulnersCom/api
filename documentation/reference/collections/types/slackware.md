# `slackware`  ·  ~1.9k documents

Slackware vulnerability collection includes advisories and CVEs specific to the Slackware Linux distribution, focusing on security issues in its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SSA-2026-197-01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T01:36:54"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:07:03"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-17T00:07:03"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T01:36:54.140000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"[slackware-security]  netatalk"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"slackware"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/slackware/SSA-2026-197-01"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `6` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"New netatalk packages are available for Slac…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Slackware Linux Project"` |

### Collection fields

Specific to the `slackware` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Slackware", "OSVersion": "15.0", "ar…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-62318", "CVE-2026-62319", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "meissner@suse.de", "ve…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-13757", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"http://www.slackware.com/security/viewer.php…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |

