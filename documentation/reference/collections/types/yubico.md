# `yubico`  ·  ~23 documents

Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"YSA-2026-02"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T02:09:49"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-02-21T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-02-21T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T16:08:35.427000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"YSA-2026-02 \| Yubico"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"yubico"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/yubico/YSA-2026-02"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `13` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Yubico.com"` |

### Collection fields

Specific to the `yubico` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-46419"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve@mitre.org", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A security update is available for the Yubic…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-46419", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.yubico.com/support/security-advi…` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |

