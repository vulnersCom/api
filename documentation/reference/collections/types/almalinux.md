# `almalinux`  ·  ~5.4k documents

AlmaLinux vulnerability collection includes advisories and CVEs specific to AlmaLinux OS, sourced from official security bulletins.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "almalinux", "OSVersion": "8", "arch"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-12505"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert", "version":…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@python.org", "vers…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The SMB/CIFS protocol is a standard file sha…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 45% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-12505", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://errata.almalinux.org/8/ALSA-2026-395…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALSA-2026:39575"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T14:37:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T09:07:41"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://access.redhat.com/errata/RHSA-2026:…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AlmaLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T14:37:04.563000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: cifs-utils security, bug fix, and…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"almalinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/almalinux/ALSA-2026:39575"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

