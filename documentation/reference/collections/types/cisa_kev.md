# `cisa_kev`  ·  ~1.7k documents

CISA KEV collection includes advisories and CVEs related to known exploited vulnerabilities across various vendors and products.

**Family model:** [`InfoBulletin`](../../data-models.md) — `bulletinFamily: info`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58644"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2}` | 5% | CVSS v2 score block. | `{"cvssV2": {"source": "nvd", "version": "2.0"…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "secure@microsoft.com"…` |
| `cvss4` | `object{cvssV4}` | 30% | CVSS v4.0 score block. | `{"cvssV4": {"source": "security@joomla.org", …` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Microsoft SharePoint contains a deserializat…` |
| `dueDate` | `str` | 100% | Remediation due date (e.g. CISA KEV required-action deadline). | `"2026-07-19T00:00:00"` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-58644", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cisa.gov/known-exploited-vulnera…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISA-KEV-CVE-2026-58644"` |
| `knownRansomwareCampaignUse` | `str` | 100% | Ransomware-campaign-use marker, as a string ('Known'/'Unknown', per CISA KEV) — not a boolean. | `"Unknown"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T21:38:29"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `notes` | `str` | 100% | Free-text notes. | `"https://msrc.microsoft.com/update-guide/vuln…` |
| `product` | `str` | 100% | Affected product name. | `"SharePoint"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CISA"` |
| `requiredAction` | `str` | 100% | Required remediation action (e.g. CISA KEV directive). | `"Apply mitigations in accordance with vendor …` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:38:28.037000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft SharePoint Deserialization of Untr…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisa_kev"` |
| `vendor` | `str` | 100% | Affected product's vendor. | `"Microsoft"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cisa_kev/CISA-KEV-CVE-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `true` |

