# `attackerkb`  ·  ~78k documents

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-2445"]` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"The affected product accepts user-supplied i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,short_description,tags}, object{dependencies,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"short_description": "JS injection from unsa…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://attackerkb.com/topics/2a60cdf0-b14f-…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKB:2A60CDF0-B14F-49F5-A435-BAF35AB38906"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:37:03"` |
| `metrics` | `object{adp,cna}, object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T08:30:16"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T08:06:39"` |
| `references` | `list[str]` | External reference URLs. | `["https://security.docs.wso2.com/en/latest/se…` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"AttackerKB"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:37:03.364000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-2445"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"attackerkb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/attackerkb/AKB:2A60CDF0-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `3` |

### Family fields

Added by the [`InfoBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,vendor,version}]` | Affected software products (name/version/operator). | `[{"vendor": "WSO2", "version": "4.2.0", "oper…` |
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `false` |

### Collection fields

Specific to the `attackerkb` collection.

| field | type | description | example |
|---|---|---|---|
| `attackerkb` | `object{attackerValue,exploitability}` | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `last_activity` | `str` | Timestamp of the most recent activity on the item. | `"2026-07-20T08:30:16"` |
| `references_categories` | `object{advisory,canonical,misc}, object{advisory,canonical}, object{canonical,misc}, object{canonical}` | References grouped by category (canonical/misc). | `{"advisory": ["https://security.docs.wso2.com…` |

