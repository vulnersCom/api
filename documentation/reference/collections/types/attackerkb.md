# `attackerkb`  ·  ~78k documents

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,vendor,version}]` | 100% | Affected software products (name/version/operator). | `[{"vendor": "ci4-cms-erp", "version": "0.31.9…` |
| `attackerkb` | `object{attackerValue,exploitability}` | 100% | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-45138"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.4, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CI4MS is a CodeIgniter 4-based content manag…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 0.8, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://attackerkb.com/topics/07eb059d-749e-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKB:07EB059D-749E-4613-9F86-1E23FA4A521D"` |
| `last_activity` | `str` | 100% | Timestamp of the most recent activity on the item. | `"2026-07-20T00:30:13"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T02:37:03"` |
| `metrics` | `object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:30:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T23:18:51"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/ci4-cms-erp/ci4ms/releas…` |
| `references_categories` | `object{canonical,misc}` | 100% | References grouped by category (canonical/misc). | `{"misc": ["https://github.com/ci4-cms-erp/ci4…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AttackerKB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T02:37:03.281000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-45138"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"attackerkb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/attackerkb/AKB:07EB059D-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

