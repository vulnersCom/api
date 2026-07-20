# `drupal`  ·  ~1.9k documents

Drupal security advisories from the Drupal security team, including CVEs and patches for vulnerabilities in Drupal CMS and its modules.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-55805"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss3` | `object{cvssV31}` | 85% | CVSS v3.x score block. | `{"cvssV31": {"source": "mlhess", "version": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The Layout Builder module doesn't sufficient…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 85% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15081", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.drupal.org/sa-core-2026-012"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DRUPAL-SA-CORE-2026-012"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T06:53:32"` |
| `metrics` | `object{adp,cna}` | 85% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "mlhess", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.drupal.org/psa-2021-06-29", "ht…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Drupal Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T06:53:49.985000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Drupal core - Moderately critical - Cross-si…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"drupal"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/drupal/DRUPAL-SA-CORE-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

