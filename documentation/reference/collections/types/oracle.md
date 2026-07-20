# `oracle`  ·  ~98 documents

Oracle's vulnerability database provides advisories and CVEs related to Oracle products and systems, focusing on security issues and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "24.1.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2020-17521", "CVE-2021-0341", "CVE-2021…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | 100% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "cve-assign@fb.com", "…` |
| `cvss4` | `object{cvssV4}` | 35% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@apache.org", …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A Critical Patch Update is a collection of p…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-17521", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.oracle.com/security-alerts/cpuap…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ORACLE:CPUAPR2026"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T08:30:52"` |
| `metrics` | `object{adp,cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-21T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-24T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Oracle"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-22T02:04:28.323000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Oracle Critical Patch Update Advisory - Apri…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oracle"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/oracle/ORACLE:CPUAPR2026"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

