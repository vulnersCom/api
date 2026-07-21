# `filippoio`  ·  ~110 documents

Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers.

**Family model:** [`AdvisoryBulletin`](../../data-models.md) — `bulletinFamily: blog`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FILIPPOIO:28D83B9E8ADF490F0674AF5A4E5457F6"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T23:36:51"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T22:33:32"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-20T22:33:32"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}, object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T23:36:51.198000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"Opaque, Interoperable Passkey Records (and a…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"filippoio"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/filippoio/FILIPPOIO:28D8…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `2` |

### Family fields

Present in every sampled `blog`-family document (typed by [`AdvisoryBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `enchantments` | `object{dependencies,score,short_description,tags}, object{score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.3, …` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://words.filippo.io/passkey-record/"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Filippo Valsorda <feed@filippo.io>"` |

### Collection fields

Specific to the `filippoio` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-26958"]` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security-advisories@gi…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Passkeys are the most important thing happen…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-26958", "date": "2026-06-1…` |
| `metrics` | `object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |

