# `arista`  ·  ~140 documents

Arista's vulnerability collection includes advisories and CVEs related to their networking products and software, sourced from Arista Networks.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 45% | Affected software products (name/version/operator). | `[{"version": "4.36.0", "operator": "eq", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 45% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 95% | Related CVE identifiers referenced by this document. | `["CVE-2026-11704", "CVE-2026-11705", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 80% | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `cvss4` | `object{cvssV4}` | 45% | CVSS v4.0 score block. | `{"cvssV4": {"source": "psirt@arista.com", "ve…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"##  Security Advisory 0143  PDF\n\n**Date: J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 80% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-49844", "date": "2026-06-3…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.arista.com/en/support/advisories…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ARISTA:0143"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T17:47:40"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 80% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-23T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Arista Networks, Inc"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T17:47:42.453000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory 0143"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"arista"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/arista/ARISTA:0143"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

