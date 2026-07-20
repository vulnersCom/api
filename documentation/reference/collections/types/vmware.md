# `vmware`  ·  ~550 documents

VMware collection includes security advisories and CVEs related to VMware products and services, sourced from VMware's official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields beyond the model stay accessible via `extra="allow"`; *in samples* is how often the field appeared in the sampled documents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 60% | Affected software products (name/version/operator). | `[{"version": "26H1", "operator": "lt", "name"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 60% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-41722", "CVE-2026-41723", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `cvss3` | `object{cvssV31}` | 100% | CVSS v3.x score block. | `{"cvssV31": {"source": "security@vmware.com",…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Advisory ID:** \|  VMSA-2026-0004  \n---\|--…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.8, "uncertanity": 1.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41722", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.broadcom.com/web/ecx/support…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VMSA-2026-0004"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-15T23:16:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@vmwar…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-08T07:26:38"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-08T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://cve.mitre.org/cgi-bin/cvename.cgi?n…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"VMware"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-08T07:06:22.108000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VMSA-2026-0004: VMware Cloud Foundation Oper…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vmware"` |
| `vendorCvss` | `object{CVSSv3,severity}` | 95% | Vendor-assigned CVSS score block. | `{"severity": "Important", "CVSSv3": "8.0"}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vmware/VMSA-2026-0004"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `132` |

