# `cnnvd`  ·  ~200k documents

CNNVD is a Chinese national vulnerability database that provides advisories and CVEs for various software products and systems.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: cnnvd`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cnnvd"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6250"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The TP-Link Tapo C110 is an indoor network c…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6250", "date": "2026-06-18…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cnnvd.org.cn/home/globalSearch?k…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CNNVD-202606-2882"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T03:50:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-11T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-6…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"China National Vulnerability Database of Inf…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T03:12:23.618000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"TP-Link Tapo C110 \u683c\u5f0f\u5316\u5b57\u…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cnnvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cnnvd/CNNVD-202606-2882"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `23` |

