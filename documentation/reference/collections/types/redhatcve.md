# `redhatcve`  ·  ~210k documents

Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RH:CVE-2026-64190"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:39:10"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T05:20:34"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T05:20:34"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:39:10.998000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-64190"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhatcve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/redhatcve/RH:CVE-2026-64…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `1` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"redhat.com"` |

### Collection fields

Specific to the `redhatcve` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-64190"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "NONE", "version": "3.…` |
| `cwe` | `list[str]` | Associated CWE weakness identifiers. | `["CWE-1287"]` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A flaw was found in the Linux kernel's team …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://access.redhat.com/security/cve/cve-2…` |
| `metrics` | `object{cna,vendor}, object{cna}, object{vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-6…` |
| `vendorCvss` | `object{score,vector}` | Vendor-assigned CVSS score block. | `{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:…` |

