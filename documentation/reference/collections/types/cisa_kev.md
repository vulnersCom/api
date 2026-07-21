# `cisa_kev`  ·  ~1.7k documents

CISA KEV collection includes advisories and CVEs related to known exploited vulnerabilities across various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISA-KEV-CVE-2026-39808"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T21:38:29"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:38:28.049000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Fortinet FortiSandbox OS Command Injection V…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisa_kev"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cisa_kev/CISA-KEV-CVE-20…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `4` |

### Family fields

Present in every sampled `info`-family document (typed by [`InfoBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.8, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"CISA"` |

### Collection fields

Specific to the `cisa_kev` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-39808"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "psirt@fortinet.com", …` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@joomla.org", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Fortinet FortiSandbox contains an OS command…` |
| `dueDate` | `str` | Remediation due date (e.g. CISA KEV required-action deadline). | `"2026-07-19T00:00:00"` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39808", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cisa.gov/known-exploited-vulnera…` |
| `knownRansomwareCampaignUse` | `str` | Ransomware-campaign-use marker, as a string ('Known'/'Unknown', per CISA KEV) — not a boolean. | `"Unknown"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@fortinet…` |
| `notes` | `str` | Free-text notes. | `"https://fortiguard.fortinet.com/psirt/FG-IR-…` |
| `product` | `str` | Affected product name. | `"FortiSandbox"` |
| `requiredAction` | `str` | Required remediation action (e.g. CISA KEV directive). | `"Apply mitigations in accordance with vendor …` |
| `vendor` | `str` | Affected product's vendor. | `"Fortinet"` |
| `wildExploited` | `bool` | Whether the vulnerability is exploited in the wild. | `true` |

