# `hackapp`  ·  ~24k documents

HackApp is a vulnerability database focused on mobile applications, providing advisories, CVEs, and exploit information relevant to app security.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "le", "version": "Varies with d…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"HackApp vulnerability scanner discovered tha…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.0, "vector": "NONE"}, "…` |
| `hackapp` | `object{apk,bugs,icon,link,name,release,store,vendor,version}` | 100% | HackApp mobile-app scan provenance. | `{"apk": "COM.COINBASE.ANDROID.APK", "bugs": […` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hackapp.com/report/be556ac4576d8d5c2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKAPP:COM.COINBASE.ANDROID.APK"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T18:51:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2018-03-28T20:14:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2018-03-28T20:14:42"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://play.google.com/store/apps/details?…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Hackapp.org"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-03-28T17:14:42Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Coinbase - Buy Bitcoin & more. Secure Wallet…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackapp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hackapp/HACKAPP:COM.COIN…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `688` |

