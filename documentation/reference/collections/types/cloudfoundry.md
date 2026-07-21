# `cloudfoundry`  ·  ~1.1k documents

Cloud Foundry vulnerability data from various vendors, focusing on cloud platform advisories and CVEs related to Cloud Foundry components.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CFOUNDRY:ADA25F6CC25DA8143948B2E10E299089"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-09T17:36:58"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-08T17:36:55.754000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"CVE-2026-41857 - BOSH CLI Shell Injection \| …` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cloudfoundry"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/cloudfoundry/CFOUNDRY:AD…` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `7` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.3, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Cloud Foundry"` |

### Collection fields

Specific to the `cloudfoundry` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-41857"]` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | CVSS v3.x score block. | `{"cvssV3": {"source": "security@vmware.com", …` |
| `cvss4` | `object{cvssV4}` | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@vmware.com", …` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"# \n\nHigh\n\n\u25cf **CVSSv4:** High 7.1(CV…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41857", "date": "2026-07-1…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://www.cloudfoundry.org/blog/cve-2026-4…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@vmware…` |

