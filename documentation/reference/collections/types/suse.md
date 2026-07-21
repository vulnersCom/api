# `suse`  ·  ~5.7k documents

SUSE vulnerability collection includes advisories and CVEs specific to SUSE Linux products and services, detailing security issues and patches.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SUSE-SU-2026:3138-1"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T21:08:39"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T15:10:54"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T15:10:54"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T21:08:39.913000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security update for 389-ds"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"suse"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/suse/SUSE-SU-2026:3138-1"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This update for 389-ds fixes the following i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.6, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Suse"` |

### Collection fields

Specific to the `suse` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "suse", "OSVersion": "15", "arch": "a…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11610", "CVE-2026-11611", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "suse", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "suse", "version": "4.0…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.suse.com/support/update/announce…` |
| `metrics` | `object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "suse", "vers…` |
| `references` | `list[str]` | External reference URLs. | `["https://bugzilla.suse.com/show_bug.cgi?id=1…` |

