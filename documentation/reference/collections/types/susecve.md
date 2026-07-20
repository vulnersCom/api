# `susecve`  ·  ~60k documents

SUSE CVE Database: Contains advisories and CVEs related to vulnerabilities in SUSE Linux products and services.

**Family model:** [`UnixBulletin`](../../data-models.md) — `bulletinFamily: unix`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-58218"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.2, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 15% | CVSS v3.x score block. | `{"cvssV31": {"source": "audit@patchstack.com"…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Deserialization of Untrusted Data vulnerabil…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 35% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16206", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.suse.com/security/cve/CVE-2025-5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SUSECVE:CVE-2025-58218"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T20:35:34"` |
| `metrics` | `object{adp,cna}, object{cna}` | 20% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:45:29"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T17:45:29"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.suse.com/security/cve/CVE-2025-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Suse CVE"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T20:35:34.829000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SUSE CVE-2025-58218"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"susecve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/susecve/SUSECVE:CVE-2025…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

