# `intel`  ·  ~1k documents

Intel's vulnerability collection includes advisories and CVEs related to Intel products and technologies, focusing on hardware and software security issues.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"INTEL:INTEL-SA-01402"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-12T19:16:55"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-05-12T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-05-12T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T19:16:55.979000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Intel\u00ae Graphics Advisory"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"intel"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/intel/INTEL:INTEL-SA-01402"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `28` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Intel Security Center"` |

### Collection fields

Specific to the `intel` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-20751", "CVE-2026-20794", "CVE-202…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "secure@intel.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Summary: \n\nPotential security vulnerab…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-20751", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.intel.com/content/www/us/en/secu…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "secure@intel.co…` |
| `severity` | `str` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"CRITICAL"` |

