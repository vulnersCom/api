# `rubygems`  ·  ~1.3k documents

RubyGems collection includes vulnerability advisories and CVEs specifically for Ruby libraries and gems, sourced from the Ruby community.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RUBY:DATADOG-2026-50276"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:12"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:37:12.173000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"dd-trace-rb - Improper parsing of W3C baggag…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rubygems"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/rubygems/RUBY:DATADOG-20…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `5` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"RubySec"` |

### Collection fields

Specific to the `rubygems` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "2.32.0", "operator": "lt", "nam…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-50276"]` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "cve", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"### Impact\n\nDatadog tracing libraries that…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-38969", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://rubysec.com/advisories/CVE-2026-50276/"` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `references` | `list[str]` | External reference URLs. | `["https://www.cve.org/CVERecord/SearchResults…` |

