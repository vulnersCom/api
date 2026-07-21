# `freebsd_advisory`  ·  ~710 documents

FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-49424"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "sep@nlnetlabs.nl", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\\-----BEGIN PGP SIGNED MESSAGE----- Hash: S…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10846", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.freebsd.org/security/advisories/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FREEBSD_ADVISORY:FREEBSD-SA-26:47.LINUX"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T23:40:46"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-30T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FreeBSD Org"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T23:40:47.318000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"FreeBSD-SA-26:47.linux"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd_advisory"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/freebsd_advisory/FREEBSD…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Added by the [`UnixBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `freebsd_advisory` collection.

_None in the sample._

