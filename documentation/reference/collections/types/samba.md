# `samba`  ·  ~170 documents

Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-4408"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 95% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Description\n\nSamba file servers and cla…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 95% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-4408", "date": "2026-06-24…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.samba.org/samba/security/CVE-202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAMBA:CVE-2026-4408"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T15:49:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | 95% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-26T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Samba Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-27T19:48:40.832000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unauthenticated Remote Code Execution"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"samba"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/samba/SAMBA:CVE-2026-4408"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

