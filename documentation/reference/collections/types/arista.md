# `arista`  ·  ~140 documents

Arista's vulnerability collection includes advisories and CVEs related to their networking products and software, sourced from Arista Networks.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-11704", "CVE-2026-11705", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@arista.com", "ve…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"##  Security Advisory 0143  PDF\n\n**Date: J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-49844", "date": "2026-06-3…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.arista.com/en/support/advisories…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ARISTA:0143"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T17:47:40"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-23T00:00:00"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Arista Networks, Inc"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T17:47:42.453000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Security Advisory 0143"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"arista"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/arista/ARISTA:0143"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `13` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "4.36.0", "operator": "eq", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

### Collection fields

Specific to the `arista` collection.

_None in the sample._

