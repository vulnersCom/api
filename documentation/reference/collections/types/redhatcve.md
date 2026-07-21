# `redhatcve`  ·  ~210k documents

Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-64116"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "NONE", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "f5sirt@f5.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A flaw was found in the Linux kernel's IPv6 …` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "Linux kernel IPv6 IOAM…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16118", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://access.redhat.com/security/cve/cve-2…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RH:CVE-2026-64116"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:37:01"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,cna}, object{cna,vendor}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:28:31"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:28:31"` |
| `references` | `list[str]` | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-6…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"redhat.com"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:37:01.321000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-64116"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhatcve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/redhatcve/RH:CVE-2026-64…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-131"]` |

### Collection fields

Specific to the `redhatcve` collection.

| field | type | description | example |
|---|---|---|---|
| `sourceAffectedData` | `list[object{OS,OSVersion,packageName,packageVersion,status}]` | Affected-product data in the source's own shape. | `[{"OS": "redhat", "OSVersion": "10", "package…` |
| `vendorCvss` | `object{score,vector}` | Vendor-assigned CVSS score block. | `{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:…` |

