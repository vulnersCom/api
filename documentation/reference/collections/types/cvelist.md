# `cvelist`  ·  ~370k documents

CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata.

**Family model:** [`CveBulletin`](../../data-models.md) — `bulletinFamily: cve`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-07-19T15:48:13"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cnaAffected` | `list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"collectionURL": "https://cpan.org/modules"…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-16235"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-338"]` |
| `dateUpdated` | `str` | 100% | Source-reported last-update date. | `"2026-07-20T07:02:11"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": "Crypt::…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cve.org/CVERecord?id=CVE-2026-16…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVELIST:CVE-2026-16235"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:07:33"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:02:11"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"cve.mitre.org"` |
| `provider` | `str` | 100% | Organization that produced the record (e.g. the CNA). | `"CPANSec"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://metacpan.org/release/DRSTEVE/Crypt-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CPANSec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:07:33.517000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-16235 Crypt::Password versions thro…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cvelist"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cvelist/CVELIST:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |
| `workarounds` | `list[?], list[object{lang,value}]` | 100% | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Users can generate …` |

