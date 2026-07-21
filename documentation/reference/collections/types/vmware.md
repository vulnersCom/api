# `vmware`  ·  ~550 documents

VMware collection includes security advisories and CVEs related to VMware products and services, sourced from VMware's official security bulletins.

**Family model:** [`SoftwareBulletin`](../../data-models.md) — `bulletinFamily: software`. Fields are grouped by where they appear across the samples; anything Vulners adds beyond the models stays accessible via `extra="allow"`.

### Common document fields

Present in every sampled document, across all collections (the base [`Bulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `bulletinFamily` | `str` | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `id` | `str` | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VMSA-2026-0004"` |
| `lastseen` | `str` | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-15T23:16:04"` |
| `modified` | `str` | Last modification timestamp at the source (ISO-8601). | `"2026-06-08T07:26:38"` |
| `published` | `str` | Original publication timestamp (ISO-8601). | `"2026-06-08T00:00:00"` |
| `sourceAvailable` | `bool` | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated}` | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-08T07:06:22.108000Z", "u…` |
| `title` | `str` | Human-readable title of the document. | `"VMSA-2026-0004: VMware Cloud Foundation Oper…` |
| `type` | `str` | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vmware"` |
| `vhref` | `str` | URL of the document on vulners.com. | `"https://vulners.com/vmware/VMSA-2026-0004"` |
| `viewCount` | `int` | How many times the document has been viewed on Vulners. | `133` |

### Family fields

Present in every sampled `software`-family document (typed by [`SoftwareBulletin`](../../data-models.md)).

| field | type | description | example |
|---|---|---|---|
| `cvss` | `object{score,severity,source,vector,version}` | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.8, "uncertanity": 1.2, …` |
| `reporter` | `str` | Person or organization credited with reporting/authoring it. | `"VMware"` |

### Collection fields

Specific to the `vmware` collection, beyond the common and family sets.

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | Affected software products (name/version/operator). | `[{"version": "26H1", "operator": "lt", "name"…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | Related CVE identifiers referenced by this document. | `["CVE-2026-41722", "CVE-2026-41723", "CVE-202…` |
| `cvss3` | `object{cvssV31}` | CVSS v3.x score block. | `{"cvssV31": {"source": "security@vmware.com",…` |
| `description` | `str` | Full text or summary of the vulnerability/advisory. | `"**Advisory ID:** \|  VMSA-2026-0004  \n---\|--…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41722", "date": "2026-06-2…` |
| `href` | `str` | Canonical URL of the document at its original source. | `"https://support.broadcom.com/web/ecx/support…` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@vmwar…` |
| `references` | `list[str]` | External reference URLs. | `["https://cve.mitre.org/cgi-bin/cvename.cgi?n…` |
| `vendorCvss` | `object{CVSSv3,severity}` | Vendor-assigned CVSS score block. | `{"severity": "Important", "CVSSv3": "8.0"}` |

