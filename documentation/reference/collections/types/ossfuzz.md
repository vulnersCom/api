# `ossfuzz`  ·  ~5.3k documents

OSFuzz is a vulnerability collection from the Open Source Security Foundation focusing on security issues in open-source software, including advisories and CVEs.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "any", "operator": "eq", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Detailed Report: https://oss-fuzz.com/testca…` |
| `enchantments` | `object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://bugs.chromium.org/p/oss-fuzz/issues/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSFUZZ-28239"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-03T13:06:48"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-12-03T13:01:26"` |
| `ossfuzz` | `object{crashType,error,issue,project,ref,revisions,status}, object{crashType,issue,project,project_repos,ref,revisions,status,tags}, object{crashType,issue,project,ref,status}` | 100% | OSS-Fuzz crash details (crash type, project, issue). | `{"issue": 28239, "status": "New", "project": …` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-12-03T13:01:26"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-12-03T10:01:26Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"serenity:FuzzGIFLoader: Global-buffer-overfl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossfuzz"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ossfuzz/OSSFUZZ-28239"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `107` |

