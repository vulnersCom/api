# `archlinux`  ·  ~1.9k documents

Arch Linux security advisories and CVEs related to Arch Linux packages and systems, sourced from the Arch Linux security team.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "alpm", "name": "libblockdev", …` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Arch Linux", "OSVersion": "any", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-6019"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.0, "vector": "C…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 90% | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert@redhat.com",…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "meissner@suse.de", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Arch Linux Security Advisory ASA-202506-10\n…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-6019", "date": "2026-07-10…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.archlinux.org/ASA-202506-10"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASA-202506-10"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T11:37:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-06-22T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-06-22T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.archlinux.org/AVG-2905", "…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ArchLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-06-22T02:00:08.377000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[ASA-202506-10] libblockdev: privilege escal…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"archlinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/archlinux/ASA-202506-10"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `49` |

