# `grafana`  ·  ~90 documents

Grafana collection includes security advisories and CVEs related to Grafana software, focusing on vulnerabilities affecting the Grafana product.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-33380"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@grafana.com"…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A vulnerability in SQL Expressions allows an…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33380", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://grafana.com/security/security-adviso…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GRAFANA:CVE-2026-33380"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-01T11:55:40"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@grafa…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-13T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-13T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Grafana Labs"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-01T11:55:40.651000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"SQL Expressions Read File From Disk"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"grafana"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/grafana/GRAFANA:CVE-2026…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `12` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `grafana` collection.

| field | type | description | example |
|---|---|---|---|
| `vendorCvss` | `object{vector}` | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/…` |

