# `cnvd`  ·  ~130k documents

CNVD is a Chinese vulnerability database that provides advisories and CVEs focused on various software products and systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: cnvd`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"cnvd"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-14036"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "chrome-cve-admin", "v…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cna@vuldb.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Chrome is a web browser developed by Google,…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.8, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cnvd.org.cn/flaw/show/CNVD-2026-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CNVD-2026-27212"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T17:40:53"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"China National Vulnerability Database"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:40:53.713000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Google Chrome Permission Elevation Vulnerabi…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cnvd"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cnvd/CNVD-2026-27212"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `10` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `cnvd` collection.

_None in the sample._

