# `yubico`  ·  ~23 documents

Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 65% | Related CVE identifiers referenced by this document. | `["CVE-2026-46419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 30% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}, object{cvssV3}` | 60% | CVSS v3.x score block. | `{"cvssV31": {"source": "cve@mitre.org", "vers…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "cve@mitre.org", "versi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A security update is available for the Yubic…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 90% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-46419", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.yubico.com/support/security-advi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"YSA-2026-02"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:37:06"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{nvd}` | 65% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-02-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-02-20T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Yubico.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T16:08:35.427000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"YSA-2026-02 \| Yubico"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"yubico"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/yubico/YSA-2026-02"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

