# `grafana`  ·  ~90 documents

Grafana collection includes security advisories and CVEs related to Grafana software, focusing on vulnerabilities affecting the Grafana product.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33380"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "security@grafana.com"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A vulnerability in SQL Expressions allows an…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33380", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://grafana.com/security/security-adviso…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GRAFANA:CVE-2026-33380"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-01T11:55:40"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@grafa…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Grafana Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-01T11:55:40.651000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SQL Expressions Read File From Disk"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"grafana"` |
| `vendorCvss` | `object{vector}` | 100% | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/grafana/GRAFANA:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

