# `freebsd_advisory`  ·  ~710 documents

FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FREEBSD_ADVISORY:FREEBSD-SA-26:39.EXECVE"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T23:40:47"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-30T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T23:40:48.257000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"FreeBSD-SA-26:39.execve"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd_advisory"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/freebsd_advisory/FREEBSD…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `18` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"\\-----BEGIN PGP SIGNED MESSAGE----- Hash: S…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.9, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"FreeBSD Org"` |

### Collection fields

Specific to the `freebsd_advisory` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-49415"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "secteam", "version": …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-45257", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.freebsd.org/security/advisories/…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secteam", "ver…` |

