# `owncloud`  ·  ~310 documents

OwnCloud collection includes security advisories and CVEs related to the OwnCloud file sharing platform, focusing on vulnerabilities affecting its software.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 90% | Affected software products (name/version/operator). | `[{"version": "10.15.0", "operator": "lt", "na…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 90% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 75% | Related CVE identifiers referenced by this document. | `["CVE-2026-33634"]` |
| `cvss` | `object{score,severity,source,vector,version}, object{score,vector}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.4, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 5% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 5% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\nNo customer data was compromised.\nNo sour…` |
| `enchantments` | `object{cpe_configuration,dependencies,score,short_description,tags}, object{cpe_configuration,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.7, "uncertanity": 1.5, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 25% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33634", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://owncloud.com/security-advisories/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OWNCLOUD:SECURITY-NOTICE-IMPACT-OF-CVE-2026-…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T15:36:58"` |
| `metrics` | `object{adp,cna,nvd}` | 5% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-03-28T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-03-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ownCloud"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-03-28T11:28:00.664000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Notice: Impact of CVE-2026-33634 on…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"owncloud"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/owncloud/OWNCLOUD:SECURI…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

