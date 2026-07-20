# `friendsofphp`  ·  ~1.7k documents

FriendsOfPHP is a community-driven collection of security advisories for PHP projects, including CVEs and vulnerability details.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "14.3.5", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15305"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 35% | CVSS v3.x score block. | `{"cvssV31": {"source": "security-advisories@g…` |
| `cvss4` | `object{cvssV4}` | 15% | CVSS v4.0 score block. | `{"cvssV4": {"source": "nvd", "version": "4.0"…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"More info at https://news.typo3.com/security…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 45% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15305", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/FriendsOfPHP/security-adv…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FRIENDSOFPHP:TYPO3:CMS-FORM:CVE-2026-15305"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T17:38:28"` |
| `metrics` | `object{adp,cna}, object{cna}` | 50% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T12:08:47"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T12:08:47"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenJS Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T17:38:28.294000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"TYPO3-CORE-SA-2026-020: TYPO3 CMS - Unrestri…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"friendsofphp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/friendsofphp/FRIENDSOFPH…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

