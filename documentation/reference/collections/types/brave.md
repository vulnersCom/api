# `brave`  ·  ~58 documents

Brave collection includes vulnerability advisories and CVEs specific to the Brave browser, sourced from security bulletins and vendor updates.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.91.168", "operator": "lt", "n…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"- Added the ability to disable or delay auto…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/brave/brave-browser/relea…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BRAVE-DESKTOP-1.91.168"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-05T07:10:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-03T05:18:53"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-03T05:18:53"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/brave/brave-browser/issu…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Brave Software"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-05T07:10:32.630000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Brave Desktop 1.91.168 Security Fixes"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"brave"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/brave/BRAVE-DESKTOP-1.91…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `24` |

