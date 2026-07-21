# `archlinux`  ·  ~1.9k documents

Arch Linux security advisories and CVEs related to Arch Linux packages and systems, sourced from the Arch Linux security team.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-6019"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.0, "vector": "C…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "meissner@suse.de", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Arch Linux Security Advisory ASA-202506-10\n…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-6019", "date": "2026-07-10…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.archlinux.org/ASA-202506-10"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASA-202506-10"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T11:37:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2025-06-22T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2025-06-22T00:00:00"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.archlinux.org/AVG-2905", "…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"ArchLinux"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-06-22T02:00:08.377000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"[ASA-202506-10] libblockdev: privilege escal…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"archlinux"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/archlinux/ASA-202506-10"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `49` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | Affected libraries/packages (name, purl, version range). | `[{"registry": "alpm", "name": "libblockdev", …` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Arch Linux", "OSVersion": "any", "ar…` |

### Collection fields

Specific to the `archlinux` collection.

_None in the sample._

