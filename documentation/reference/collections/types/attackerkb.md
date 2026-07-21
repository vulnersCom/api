# `attackerkb`  ·  ~78k documents

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKB:8AD50697-1FB0-4F66-B768-8B82D953525F"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-21T05:43:30"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-21T05:30:13"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-21T04:34:15"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-21T05:43:30.699000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2023-37508"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"attackerkb"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/attackerkb/AKB:8AD50697-…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `1` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 2.3, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"AttackerKB"` |

### Collection fields

Specific to the `attackerkb` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,vendor,version}]` | Affected software products (name/version/operator). | `[{"vendor": "HCLSoftware", "version": "3.0.05…` |
| `attackerkb` | `object{attackerValue,exploitability}` | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-37508"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "cna@vuldb.com", "versi…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@wordfence.co…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@hcl.com", "versi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"HCL DevOps Plan is potentially susceptible t…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://attackerkb.com/topics/8ad50697-1fb0-…` |
| `last_activity` | `str` | Timestamp of the most recent activity on the item. | `"2026-07-21T05:30:13"` |
| `metrics` | `object{cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt@hcl.com",…` |
| `references` | `list[str]` | External reference URLs. | `["https://cve.mitre.org/cgi-bin/cvename.cgi?n…` |
| `references_categories` | `object{advisory,canonical,misc}, object{advisory,canonical}, object{canonical,misc}` | References grouped by category (canonical/misc). | `{"canonical": ["https://cve.mitre.org/cgi-bin…` |
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `false` |

