# `mscve`  ·  ~23k documents

MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products.

**Family model:** [`MicrosoftBulletin`](../../data-models.md) — `bulletinFamily: microsoft`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `customerActionRequired` | `bool` | 100% | Whether customer action is required. | `true` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15905"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 65% | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `denialOfService` | `str` | 100% | Denial-of-service impact marker, as a string (e.g. 'N/A') — not a boolean. | `"N/A"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This CVE was assigned by Chrome. Microsoft E…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.5, …` |
| `faq` | `list[str]` | 100% | Advisory FAQ entries. | `["**Why is this Chrome CVE included in the Se…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://msrc.microsoft.com/update-guide/en-U…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:CVE-2026-15905"` |
| `issuingCna` | `str` | 100% | The CNA that issued the advisory. | `"Chrome"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:45:53"` |
| `metrics` | `object{adp,cna}, object{cna}` | 65% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:42:44"` |
| `msDetailRevision` | `str` | 100% | Microsoft advisory detail revision. | `"2026-07-17T17:42:44-07:00"` |
| `mscve` | `str` | 100% | Microsoft's CVE identifier for the advisory. | `"CVE-2026-15905"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T00:42:44"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `tag` | `str` | 100% | A single classification tag. | `"Microsoft Edge (Chromium-based)"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:45:53.916000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Chromium: CVE-2026-15905 Use after free in A…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mscve"` |
| `vendorCvss` | `object{baseScore,temporalScore,vector}` | 100% | Vendor-assigned CVSS score block. | `{"baseScore": "", "temporalScore": "", "vecto…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mscve/MS:CVE-2026-15905"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

