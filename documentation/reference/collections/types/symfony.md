# `symfony`  ·  ~76 documents

Symfony collection includes vulnerability advisories and CVEs related to the Symfony framework, focusing on PHP applications and components.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SYMFONY:CVE-2023-46733-POSSIBLE-SESSION-FIXA…` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-06-21T18:33:00"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2023-11-10T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2023-11-10T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-11-09T21:00:00Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2023-46733: Possible session fixation"` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"symfony"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/symfony/SYMFONY:CVE-2023…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `68` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 0.1, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Symfony SAS"` |

### Collection fields

Specific to the `symfony` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2023-46733"]` |
| `cvss2` | `object{cvssV2}` | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "nvd", "version": "3.1…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"## Affected versions\n\nSymfony versions &gt…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-46733", "date": "2026-06-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://symfony.com/blog/cve-2023-46733-poss…` |
| `metrics` | `object{adp,cna,nvd}, object{cna,nvd}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |

