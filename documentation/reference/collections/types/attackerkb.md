# `attackerkb`  ·  ~78k documents

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,vendor,version}]` | 5% | Affected software products (name/version/operator). | `[{"vendor": "WSO2", "version": "4.2.0", "oper…` |
| `attackerkb` | `object{attackerValue,exploitability}` | 100% | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 5% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 15% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,short_description,tags}, object{dependencies,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "JS injection from unsa…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://attackerkb.com/topics/2a60cdf0-b14f-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKB:2A60CDF0-B14F-49F5-A435-BAF35AB38906"` |
| `last_activity` | `str` | 100% | Timestamp of the most recent activity on the item. | `"2026-07-20T08:30:16"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:37:03"` |
| `metrics` | `object{adp,cna}, object{cna}` | 15% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:30:16"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `references_categories` | `object{advisory,canonical,misc}, object{advisory,canonical}, object{canonical,misc}, object{canonical}` | 100% | References grouped by category (canonical/misc). | `{"advisory": ["https://security.docs.wso2.com…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AttackerKB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:37:03.364000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"attackerkb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/attackerkb/AKB:2A60CDF0-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

