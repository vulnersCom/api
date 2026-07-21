# `oracle`  ·  ~98 documents

Oracle's vulnerability database provides advisories and CVEs related to Oracle products and systems, focusing on security issues and patches.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2020-17521", "CVE-2021-0341", "CVE-2021…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve-assign@fb.com", "…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@apache.org", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"A Critical Patch Update is a collection of p…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-17521", "date": "2026-07-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.oracle.com/security-alerts/cpuap…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ORACLE:CPUAPR2026"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T08:30:52"` |
| `metrics` | `object{adp,cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-04-21T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-04-24T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Oracle"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-22T02:04:28.323000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Oracle Critical Patch Update Advisory - Apri…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oracle"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/oracle/ORACLE:CPUAPR2026"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `39` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "24.1.0", "operator": "le", "nam…` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |

### Collection fields

Specific to the `oracle` collection.

_None in the sample._

