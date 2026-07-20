# `slackware`  ·  ~1.9k documents

Slackware vulnerability collection includes advisories and CVEs specific to the Slackware Linux distribution, focusing on security issues in its packages.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Slackware", "OSVersion": "15.0", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 50% | Related CVE identifiers referenced by this document. | `["CVE-2026-62318", "CVE-2026-62319", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 40% | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "meissner@suse.de", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"New netatalk packages are available for Slac…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 40% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-13757", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.slackware.com/security/viewer.php…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SSA-2026-197-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T01:36:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 40% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:07:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T00:07:03"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Slackware Linux Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T01:36:54.140000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[slackware-security]  netatalk"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"slackware"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/slackware/SSA-2026-197-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

