# `broadcom`  ·  ~880 documents

Broadcom vulnerability collection includes advisories and CVEs for Broadcom products and services, focusing on security issues and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 65% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-4424", "CVE-2026-5121"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 95% | CVSS v3.x score block. | `{"cvssV31": {"source": "secalert", "version":…` |
| `cvss4` | `object{cvssV4}` | 10% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-5121 - Title: Libarchive: libarchiv…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.9, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31431", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.broadcom.com/web/ecx/support…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BSNSA37829"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T17:36:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-06T17:25:44"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-06T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Broadcom Security Response"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-06T17:37:00.702000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Libarchive security update (CVE-2026-5121, C…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"broadcom"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/broadcom/BSNSA37829"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

