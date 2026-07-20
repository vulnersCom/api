# `freebsd_advisory`  ·  ~710 documents

FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49424"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 35% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "sep@nlnetlabs.nl", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\\-----BEGIN PGP SIGNED MESSAGE----- Hash: S…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 35% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10846", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.freebsd.org/security/advisories/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FREEBSD_ADVISORY:FREEBSD-SA-26:47.LINUX"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T23:40:46"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 35% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FreeBSD Org"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T23:40:47.318000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"FreeBSD-SA-26:47.linux"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd_advisory"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/freebsd_advisory/FREEBSD…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

