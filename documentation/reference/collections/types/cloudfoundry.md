# `cloudfoundry`  ·  ~1.1k documents

Cloud Foundry vulnerability data from various vendors, focusing on cloud platform advisories and CVEs related to Cloud Foundry components.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47831"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.7, "vector": "C…` |
| `cvss3` | `object{cvssV3,cvssV31}, object{cvssV31}, object{cvssV3}` | 100% | CVSS v3.x score block. | `{"cvssV3": {"source": "security@vmware.com", …` |
| `cvss4` | `object{cvssV4}` | 75% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@vmware.com", …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# \n\nHigh \n\n**CVSSv4:** High 7.7 (CVSS:4.…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47831", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cloudfoundry.org/blog/cve-2026-4…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CFOUNDRY:DC2D54BDCE228F610C0C070CF783C1B0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-09T13:36:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"source": "security@vmware…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cloud Foundry"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-08T21:36:56.779000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-47831 - Cryptographically Weak Pass…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cloudfoundry"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cloudfoundry/CFOUNDRY:DC…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

