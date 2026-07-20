# `cert`  ·  ~3.7k documents

A collection of advisories and alerts from the Computer Emergency Response Team (CERT) covering various vendors and products, including CVEs and security incidents.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-44909", "CVE-2026-59173", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "f5sirt@f5.com", "vers…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Overview\n\nA denial-of-service (DoS) vu…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59173", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.kb.cert.org/vuls/id/885548"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VU:885548"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:27:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[str]` | 70% | External reference URLs. | `["https://datatracker.ietf.org/doc/rfc9113/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CERT"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T20:37:02.980000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Denial-of-service vulnerability in HTTP/2 se…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cert"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cert/VU:885548"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

