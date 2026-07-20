# `ibm`  ·  ~36k documents

IBM's vulnerability collection includes advisories and CVEs specific to IBM products and software, sourced from IBM's security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.8.4", "operator": "ge", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 80% | Related CVE identifiers referenced by this document. | `["CVE-2015-8855", "CVE-2020-28469", "CVE-2025…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 10% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 75% | CVSS v3.x score block. | `{"cvssV3": {"source": "nvd", "version": "3.0"…` |
| `cvss4` | `object{cvssV4}` | 15% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Summary\n\nMultiple vulnerabilities were …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.5, "uncertanity": 0.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 30% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-27817", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.ibm.com/support/pages/node/7280476"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"5B14E174053C58B35D7760E3CFD72BCE1027D55FC052…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:37:12"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna}` | 75% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss3": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T09:05:14"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T09:05:14"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"IBM"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:37:13.152000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Bulletin: Multiple vulnerabilities …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ibm"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ibm/5B14E174053C58B35D77…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

