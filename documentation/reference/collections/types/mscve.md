# `mscve`  ·  ~23k documents

MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:CVE-2026-15905"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:45:53"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:42:44"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-18T00:42:44"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:45:53.916000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Chromium: CVE-2026-15905 Use after free in A…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mscve"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/mscve/MS:CVE-2026-15905"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `14` |

### Family fields

Present in every sampled `microsoft`-family document (typed by [`MicrosoftBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"This CVE was assigned by Chrome. Microsoft E…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.5, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://msrc.microsoft.com/update-guide/en-U…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Microsoft"` |

### Collection fields

Specific to the `mscve` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `customerActionRequired` | `bool` | Whether customer action is required. | `true` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-15905"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `denialOfService` | `str` | Denial-of-service impact marker, as a string (e.g. 'N/A') — not a boolean. | `"N/A"` |
| `faq` | `list[str]` | Advisory FAQ entries. | `["**Why is this Chrome CVE included in the Se…` |
| `issuingCna` | `str` | The CNA that issued the advisory. | `"Chrome"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `msDetailRevision` | `str` | Microsoft advisory detail revision. | `"2026-07-17T17:42:44-07:00"` |
| `mscve` | `str` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-15905"` |
| `tag` | `str` | A single classification tag. | `"Microsoft Edge (Chromium-based)"` |
| `vendorCvss` | `object{baseScore,temporalScore,vector}` | Vendor-assigned CVSS score block. | `{"baseScore": "", "temporalScore": "", "vecto…` |

