# `checkpoint_security`  ·  ~200 documents

Checkpoint Security provides advisories and CVEs related to vulnerabilities in Check Point products and services.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50752"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.4, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "NONE", "version": "3.…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "NONE", "version": "4.0…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Symptoms\n\n- A vulnerability in the cert…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50752", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.checkpoint.com/results/sk/sk…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CPS:SK185035"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-25T15:26:48"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-25T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-07T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CheckPoint"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-09T07:31:36.630000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-50752 - VPN site to site certificat…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"checkpoint_security"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/checkpoint_security/CPS:…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `35` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `checkpoint_security` collection.

_None in the sample._

