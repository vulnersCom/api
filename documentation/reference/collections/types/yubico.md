# `yubico`  ·  ~23 documents

Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-46419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve@mitre.org", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A security update is available for the Yubic…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-46419", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.yubico.com/support/security-advi…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"YSA-2026-02"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:37:06"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-02-20T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-02-20T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Yubico.com"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T16:08:35.427000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"YSA-2026-02 \| Yubico"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"yubico"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/yubico/YSA-2026-02"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `13` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

_None in the sample._

### Collection fields

Specific to the `yubico` collection.

_None in the sample._

