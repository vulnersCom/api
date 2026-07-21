# `nozomi`  ·  ~59 documents

Nozomi Networks provides advisories and CVEs related to cybersecurity vulnerabilities in industrial control systems and critical infrastructure.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: nozomi`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"nozomi"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-33390"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nozomi", "version": "…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "nozomi", "version": "4…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# Summary\nAn Incorrect Privilege Assignment…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33390", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://security.nozominetworks.com/NN-2026:…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NN-2026:13-01"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T11:41:20"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,nvd,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "nozomi", "ve…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-07T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-07T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Nozomi Networks PSIRT"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T11:39:22.180000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Incorrect privilege assignment for Arc senso…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nozomi"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/nozomi/NN-2026:13-01"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Added by the [`AdvisoryBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,version}]` | Affected software products (name/version/operator). | `[{"version": "< v26.2.0", "name": "guardian"}…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `nozomi` collection.

_None in the sample._

