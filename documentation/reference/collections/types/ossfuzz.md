# `ossfuzz`  ·  ~5.3k documents

OSFuzz is a vulnerability collection from the Open Source Security Foundation focusing on security issues in open-source software, including advisories and CVEs.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they're modelled; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Base [`Bulletin`](../../data-models.md) fields — every document carries these.

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"Detailed Report: https://oss-fuzz.com/testca…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://bugs.chromium.org/p/oss-fuzz/issues/…` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSFUZZ-28239"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-03T13:06:48"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2020-12-03T13:01:26"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2020-12-03T13:01:26"` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-12-03T10:01:26Z", "updated"…` |
| `title` | `str` | Human-readable title of the document. | `"serenity:FuzzGIFLoader: Global-buffer-overfl…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossfuzz"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/ossfuzz/OSSFUZZ-28239"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `107` |

### Family fields

Added by the [`SoftwareBulletin`](../../data-models.md) family model.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "any", "operator": "eq", "name":…` |

### Collection fields

Specific to the `ossfuzz` collection.

| field | type | description | example |
|---|---|---|---|
| `ossfuzz` | `object{crashType,error,issue,project,ref,revisions,status}, object{crashType,issue,project,project_repos,ref,revisions,status,tags}, object{crashType,issue,project,ref,status}` | OSS-Fuzz crash details (crash type, project, issue). | `{"issue": 28239, "status": "New", "project": …` |

