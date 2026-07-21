# `susecve`  ·  ~60k documents

SUSE CVE Database: Contains advisories and CVEs related to vulnerabilities in SUSE Linux products and services.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SUSECVE:CVE-2025-58218"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T20:35:34"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:45:29"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-19T17:45:29"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T20:35:34.829000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"SUSE CVE-2025-58218"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"susecve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/susecve/SUSECVE:CVE-2025…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `unix`-family document (typed by [`UnixBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.2, "vector": "C…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Deserialization of Untrusted Data vulnerabil…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.7, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Suse CVE"` |

### Collection fields

Specific to the `susecve` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2025-58218"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "audit@patchstack.com"…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16206", "date": "2026-07-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.suse.com/security/cve/CVE-2025-5…` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.suse.com/security/cve/CVE-2025-…` |

