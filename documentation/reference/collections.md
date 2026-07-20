# Collections reference

Every Vulners **collection** (`type`) and the exact fields its documents carry, sampled from `/api/v4/search/collections`. Regenerate with `python dev-tools/data-models/sample_collections.py` then `--emit-docs`.

**238 collections** across **10 family models** (see [Data models](data-models.md)). Fields beyond a model's declared set stay accessible because every model keeps `extra="allow"`. The *in samples* column is how often the field appeared in the sampled documents.

## `blog` family → `AdvisoryBulletin`

### `akamaiblog`  ·  2,397 documents

Akamai Blog provides security advisories and insights related to Akamai's products and services, focusing on web security and performance.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48282"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Discover why traditional security fails agai…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48282", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.akamai.com/blog/security/2026/ju…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKAMAIBLOG:7103E27A864DCBEAFE161C3413006BC9"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:36:50"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@adobe.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T06:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T06:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Guy Amit"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:36:50.421000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"From Recon to Free Flights: Precision Prompt…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"akamaiblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/akamaiblog/AKAMAIBLOG:71…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `anandpraka`  ·  6 documents

AnandPraka provides security advisories and CVEs focused on vulnerabilities in various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Summary:\n\nThis blog post is about an I…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.anandpraka.sh/2017/05/how-i-took-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANANDPRAKA:E923C02933F806CD63FC04F38A23CAA2"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-07-29T13:18:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-05-28T14:38:32"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-05-28T14:38:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Anand Prakash (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-05-28T11:38:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"How I took control of your Twitter account (…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"anandpraka"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/anandpraka/ANANDPRAKA:E9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `161` |

### `avleonov`  ·  389 documents

AVLeonov provides advisories and CVEs related to vulnerabilities in various software products, sourced from multiple vendors and security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42897"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![About Cross Site Scripting - Microsoft Exc…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-59788", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://avleonov.com/2026/07/02/i089-about-c…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AVLEONOV:5A4D4FA71C7AFD6D5C3C47E9EF85410A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-02T21:56:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T15:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T15:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Alexander Leonov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T21:56:00.959000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"About Cross Site Scripting - Microsoft Excha…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"avleonov"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/avleonov/AVLEONOV:5A4D4F…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `carbonblack`  ·  849 documents

Carbon Black's collection includes vendor-specific advisories, CVEs, and threat intelligence related to endpoint security products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-26855", "CVE-2021-26857", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"For the third year in a row, VMware Carbon B…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-26855", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.carbonblack.com/blog/vmware-carb…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CARBONBLACK:E25E4441A040B53F58E36EDB86493899"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-04-22T16:27:59"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-04-21T15:00:28"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-04-21T15:00:28"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chris Prall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-04-21T12:00:28Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VMware Carbon Black Delivers High-Fidelity I…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"carbonblack"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/carbonblack/CARBONBLACK:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `63` |

### `coalfire`  ·  603 documents

Coalfire provides security advisories and vulnerability reports focused on various vendors and products, primarily for compliance and risk management.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Organizations that want to pursue ISO 42001 …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.8, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.coalfire.com/the-coalfire-blog/p…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"COALFIRE:A3A400ED82636541769021632F5593B0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-06T21:53:03"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-02-06T16:23:35"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-02-06T16:23:35"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"The Coalfire Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-02-06T13:23:35Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Privacy information management system consid…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coalfire"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/coalfire/COALFIRE:A3A400…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

### `d0znpp`  ·  138 documents

The d0znpp collection provides vendor-specific advisories and CVEs related to vulnerabilities in various software products from the d0znpp database.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In today\u2019s fast-paced digital world, re…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.7, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://d0znpp.medium.com/the-hand-y-etiquet…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"D0ZNPP:0C2FCF0287AEFF54B886B3013D571884"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-04T08:13:23"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-05-14T06:55:29"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-05-14T06:55:29"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Ivan Novikov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-14T03:55:29Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Hand-y Etiquette of Modern All-Remote Cu…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"d0znpp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/d0znpp/D0ZNPP:0C2FCF0287…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `25` |

### `filippoio`  ·  106 documents

Filippo.io provides security advisories and CVEs focused on vulnerabilities in various software products and libraries, primarily for developers.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-26958"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A requirement for staying sane while working…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-26958", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://words.filippo.io/vuln-reports/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FILIPPOIO:7E5AA1729D42CFF70B3B99F0B9C1A508"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T11:36:50"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T13:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-23T13:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Filippo Valsorda <feed@filippo.io>"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T15:36:50.439000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability Reports Are Not Special Anymore"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"filippoio"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/filippoio/FILIPPOIO:7E5A…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

### `hackread`  ·  7,466 documents

HackRead provides cybersecurity news and insights, focusing on vulnerabilities, exploits, and advisories related to various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An email that appears to contain a shipping …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hackread.com/ttf-trap-phishing-fake-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HACKREAD:AF31C6761373B8B4F878D3C67311F51B"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T15:36:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T13:51:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T13:51:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Waqas"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T15:36:50.664000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\u201cTTF Trap\u201d Phishing Emails Use Fak…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackread"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hackread/HACKREAD:AF31C6…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `impervablog`  ·  1,026 documents

Imperva Blog provides insights and advisories on web application security, focusing on vulnerabilities and exploits related to Imperva products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"_**TL;DR :****** A critical pre-authenticati…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.imperva.com/blog/imperva-custome…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"IMPERVABLOG:9228B71EDF0F5FABCFC52890D7714F10"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T17:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T17:02:40"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T17:02:40"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Bar Menachem"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T17:36:53.454000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Imperva Customers Protected Against \u201cwp…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"impervablog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/impervablog/IMPERVABLOG:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

### `intothesymmetry`  ·  42 documents

IntotheSymmetry provides advisories and CVEs focused on vulnerabilities in various software products and systems, sourced from multiple vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2016-0701"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 3.7, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**tl;dr** Mozilla Firefox prior to version 7…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-0701", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://blog.intothesymmetry.com/2020/01/the-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"INTOTHESYMMETRY:E90923CAE21ADFC423A96B462BCB…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T09:59:28"` |
| `metrics` | `object{adp,nvd}, object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-01-09T10:32:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-01-07T15:08:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ll (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-01-07T12:08:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Curious Case of WebCrypto Diffie-Hellman…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"intothesymmetry"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/intothesymmetry/INTOTHES…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `278` |

### `jakearchibald`  ·  116 documents

Jake Archibald's collection features security advisories and CVEs primarily focused on web technologies and browser vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"I recently gave a talk on customizable (as i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jakearchibald.com/2026/goldilocks-se…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JAKEARCHIBALD:097FA566D8C7BEEB98D0851DF5C8AE8E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-08T10:00:44"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T01:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-29T01:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jake Archibald's Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-29T14:36:50.719000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Goldilocks customizable select height"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jakearchibald"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jakearchibald/JAKEARCHIB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

### `krebs`  ·  1,094 documents

Krebs on Security provides in-depth articles and analysis on cybersecurity threats, breaches, and vulnerabilities, focusing on various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50661"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Microsoft Corp.** today released software …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "uncertanity": 3.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50661", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://krebsonsecurity.com/2026/07/microsof…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KREBS:E337AAA92EB8EC130AF8281A694FFF0E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T03:44:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T19:22:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T19:22:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"BrianKrebs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:44:37.768000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Patches a Record 570 Security Flaws"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"krebs"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/krebs/KREBS:E337AAA92EB8…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `malwarebytes`  ·  4,714 documents

Malwarebytes collection includes advisories and threat intelligence related to malware and security vulnerabilities affecting various software and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47865", "CVE-2026-53412"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Last week on Malwarebytes Labs:\n\n  * Shark…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47865", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.malwarebytes.com/blog/news/2026/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MALWAREBYTES:6FCE1BA094D54C0C07186D2989135450"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@vmwar…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:02:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Malwarebytes blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:36:50.591000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"A week in security (July 13 &#8211; July 19)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"malwarebytes"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/malwarebytes/MALWAREBYTE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `mmpc`  ·  726 documents

MMPC is a Microsoft Malware Protection Center collection focusing on Microsoft products, providing advisories, CVEs, and malware threat intelligence.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-6448"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{attackComplexity,attackVector,availabilityImpact,baseScore,baseSeverity,confidentialityImpact,integrityImpact,privilegesRequired,scope,score,severity,source}, object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": "3.1", "score": null, "vector": n…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Since late 2023, Microsoft has observed an i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.7, "uncertanity": 0.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-6448", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/security/blo…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MMPC:D41D8CD98F00B204E9800998ECF8427E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-06-20T19:17:49"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-05-30T17:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-05-30T17:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft Threat Intelligence"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-05-30T14:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Exposed and vulnerable: Recent attacks highl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mmpc"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mmpc/MMPC:D41D8CD98F00B2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `87` |

### `msrc`  ·  1,371 documents

The MSRC collection includes Microsoft Security Response Center advisories and CVEs, focusing on vulnerabilities in Microsoft products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Congratulations to the researchers recognize…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/msrc/blog/20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSRC:9B6CEA5A4AC7F49F199A68D9B7755824"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T15:42:55"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft Security Response Center"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T15:42:55.439000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Congratulations to the top MSRC 2026 Q2 secu…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msrc"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/msrc/MSRC:9B6CEA5A4AC7F4…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `mssecure`  ·  1,567 documents

Microsoft Security Update Guide collection featuring advisories and CVEs for Microsoft products and services across various platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In this article\n\n  1. Weston on the future…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.microsoft.com/en-us/security/blo…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSSECURE:445281739FE098F23CF282B09A1B1B05"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:08:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T16:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T16:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Elliot Volkman"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:08:38.640000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft at Black Hat USA 2026: Defending t…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mssecure"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mssecure/MSSECURE:445281…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `pentestit`  ·  154 documents

PentestIT provides vulnerability advisories and CVEs focused on various software products and services, primarily for penetration testing professionals.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Empire v3.4.0 was released a couple of days …` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 2.5, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://pentestit.com/empire-v3-4-0-post-exp…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PENTESTIT:A43800E956AC2D68FD2C69158754FEC7"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-07T22:21:17"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-09-18T18:30:07"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-09-18T18:30:07"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Black"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-09-18T15:30:07Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"UPDATE: Empire v3.4.0"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pentestit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pentestit/PENTESTIT:A438…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `44` |

### `pentestlab`  ·  118 documents

PentestLab is a vulnerability database focused on penetration testing resources, including advisories, CVEs, and exploit techniques for various products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Microsoft introduced Data Protection Applica…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 2.0, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://pentestlab.blog/2024/08/20/web-browse…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PENTESTLAB:2A71D967A257970C5C6A955D66ABECEC"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-05-04T06:18:02"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-08-20T07:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-08-20T07:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Administrator"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-05-04T06:18:02.045000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Web Browser Stored Credentials"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pentestlab"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pentestlab/PENTESTLAB:2A…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `pentestnepal`  ·  9 documents

PentestNepal provides security advisories and vulnerability reports focused on various software products and services relevant to Nepal's cybersecurity landscape.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In part two of G Suite vulnerability discuss…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://blog.pentestnepal.tech/post/156959105…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PENTESTNEPAL:CE7ADC79FD41F30AF176880CE03A4C62"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-04-18T22:36:36"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-02-08T02:49:51"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-02-08T02:49:51"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"White Hats - Nepal blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-02-07T23:49:51Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"This domain is my domain - G Suite A record …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pentestnepal"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pentestnepal/PENTESTNEPA…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `65` |

### `pentestpartners`  ·  506 documents

Pentest Partners provides security advisories and vulnerability reports focused on various vendors and products, including CVEs and exploit techniques.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-41438", "CVE-2025-46352"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://www.pentestpartners.com/content/…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 9.6, "uncertanity": 0.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-41438", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.pentestpartners.com/security-blo…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PENTESTPARTNERS:2473B2F2F92AFF1BFFC52E90EF09…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-05-30T14:22:42"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-05-29T05:55:27"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-05-29T05:55:27"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Andrew Tierney"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-05-29T16:22:47.822000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Fire detection system been pwned? You\u2019r…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pentestpartners"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pentestpartners/PENTESTP…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `qualysblog`  ·  1,097 documents

Qualys Blog provides vendor-specific security advisories and insights, focusing on vulnerabilities, CVEs, and best practices for various products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Microsoft's July 2026 Patch Tuesday delivers…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.5, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.qualys.com/category/vulnerabili…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"QUALYSBLOG:0DF34A114C8559DDD2ED23540B410CA0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T21:36:51"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T21:23:09"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T21:23:09"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Diksha Ojha"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:36:51.845000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft and Adobe Patch Tuesday,\u00a0July…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"qualysblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/qualysblog/QUALYSBLOG:0D…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `rapid7community`  ·  138 documents

Rapid7 Community provides vulnerability advisories and CVEs focused on various software products and platforms, sourced from community contributions.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2017-7442", "CVE-2017-8464"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"To many, emails are boring. It&#x27;s been a…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-7442", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://community.rapid7.com/community/rapid…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7COMMUNITY:2B17DEA73DC543DE4E26A8BC5E2B…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-08-25T16:08:08"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-08-25T16:02:15"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-08-25T16:02:15"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Naveen Bibinagar"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-08-25T13:02:15Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Gone Phishing: A Case Study on Conducting In…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7community"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rapid7community/RAPID7CO…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `173` |

### `rhino`  ·  83 documents

Rhino is a vulnerability collection from the Rhino Security Labs, focusing on advisories and CVEs related to various software products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-26147"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The post Referral Beware, Your Rewards are M…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 1.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-55963", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rhinosecuritylabs.com/research/refer…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHINO:20781BBEA88200A8CED8AE3D3EBEFE46"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-08-27T17:11:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-08-27T17:03:12"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-08-27T17:03:12"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Whit Taylor"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-08-27T17:11:36.722000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Referral Beware, Your Rewards are Mine (Part…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rhino"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rhino/RHINO:20781BBEA882…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `ripstech`  ·  101 documents

Ripstech provides vulnerability data focused on web application security, including advisories and CVEs related to various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2019-12598", "CVE-2019-12601"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"You can read the official announcement here.…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12598", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.ripstech.com/2020/rips-acquired…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RIPSTECH:AB5B8CF1930B43298FDB86523D84A28C"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-05-13T14:04:55"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-05-13T07:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-05-13T07:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"RIPS Technologies Blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-05-13T04:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"RIPS and SonarSource are Joining Forces"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ripstech"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ripstech/RIPSTECH:AB5B8C…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `33` |

### `schneier`  ·  2,988 documents

Schneier's collection provides security advisories and analyses focused on various vulnerabilities across software and systems, sourced from Bruce Schneier's insights.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Lots of articles about this.\n\nAs usual, yo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.schneier.com/blog/archives/2026/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SCHNEIER:76E7539B789382D6B0A8B5E807B65F60"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:36:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T21:01:37"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T21:01:37"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Bruce Schneier"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:36:50.490000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Friday Squid Blogging: Squid Washing Up on C…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"schneier"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/schneier/SCHNEIER:76E753…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `securelist`  ·  1,028 documents

Securelist provides vendor-specific security advisories, CVEs, and threat intelligence reports focusing on malware and cyber threats.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-2658"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://media.kasperskycontenthub.com/wp…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 1.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-27925", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://securelist.com/tr/hellonet-vipnet/12…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURELIST:B789138E8D4DB2F0D45B23C33091F8F8"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "psirt-cna@flexe…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T13:05:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T13:05:56"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Konstantin Isakov, Georgy Kucherin, Anton Ka…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T15:36:50.995000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"HelloNet campaign \u2014 new malicious modul…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securelist"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/securelist/SECURELIST:B7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `23` |

### `silentrobots`  ·  22 documents

Silent Robots provides vulnerability data sourced from various vendors, focusing on advisories and CVEs related to web applications and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2016-4264"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"SSRF protocol smuggling involves an attacker…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.3, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-4264", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.silentrobots.com/blog/2019/02/06…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SILENTROBOTS:0DC5D72435E65CEB453D75B8B0F45904"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-08-07T08:03:43"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-02-06T17:58:21"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-02-06T17:58:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Silent Robot Systems blog"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-02-06T14:58:21Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SSRF Protocol Smuggling in Plaintext Credent…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"silentrobots"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/silentrobots/SILENTROBOT…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `69` |

### `sonarsource`  ·  38 documents

SonarSource provides security advisories and vulnerability data for various programming languages and frameworks, focusing on code quality and security issues.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-46088", "CVE-2022-23131", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![A woman running a performance comparison t…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{aggregatedScoring,backreferences,dependencies,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.5, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-46088", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.sonarsource.com/5-things-to-con…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONARSOURCE:D0C5296C81770997D6DB807F2C38F1F0"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-03-01T15:30:19"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-03-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-03-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SonarSource"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-28T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"5 things to consider in performance comparis…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonarsource"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sonarsource/SONARSOURCE:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

### `talosblog`  ·  2,041 documents

Talos Blog provides security advisories and insights from Cisco Talos, focusing on vulnerabilities across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42982", "CVE-2026-48561", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![Begun, the Patch Wars have](https://storag…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42982", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.talosintelligence.com/begun-the…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TALOSBLOG:44007DB019F02AD1D5DB6CF9A85D8C92"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:00:50"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T18:00:50"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Joe Marshall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:36:50.995000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Begun, the Patch Wars have"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"talosblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/talosblog/TALOSBLOG:4400…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `taosecurity`  ·  109 documents

TaoSecurity provides advisories and CVEs focused on security vulnerabilities in various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-44228"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"On average, the FreeBSD security team releas…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-44228", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://taosecurity.blogspot.com/2026/07/fre…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TAOSECURITY:F514823959D5726EAA22AC1802A8D33F"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T03:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T01:47:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T01:43:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Richard Bejtlich (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T03:36:50.687000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"FreeBSD Released the Most Security Advisorie…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"taosecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/taosecurity/TAOSECURITY:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `thehackerblog`  ·  31 documents

The Hacker Blog provides security advisories, CVEs, and exploits focused on various vendors and products, sourced from community contributions.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2018-11101"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**NOTE:** _If you\u2019re just looking for t…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-11101", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"/zero-days-without-incident-compromising-ang…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THEHACKERBLOG:1F455E324E949389BD5A301D6CC18F69"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T15:27:50"` |
| `metrics` | `object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-11T08:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-11T08:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Matthew Bryant (mandatory) (mandatory(cat)gm…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-11T05:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\"Zero-Days\" Without Incident - Compromisin…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thehackerblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/thehackerblog/THEHACKERB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `35` |

### `trendmicroblog`  ·  2,304 documents

Trend Micro Blog provides vendor-specific advisories and insights on security threats, vulnerabilities, and product updates related to Trend Micro software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33017"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"TrendAI\u2122 Research analyzed over 200 Gem…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33017", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.trendmicro.com/en_us/research/26…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TRENDMICROBLOG:10589891CF146AADC64E8E743B0F7…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T03:36:50"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Joseph C Chen"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T03:36:50.636000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Six Minutes to Compromise: How \u2018Patriot…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"trendmicroblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/trendmicroblog/TRENDMICR…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

### `wallarmlab`  ·  549 documents

Wallarm Lab provides security advisories and CVEs focused on web application vulnerabilities across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"_Editor's note: This article was originally …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.6, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lab.wallarm.com/clearing-up-the-term…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WALLARMLAB:F205C6FCD2CFCEAC7B97D09EA6187C01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T21:36:51"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-13T21:18:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-13T21:18:13"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Tim Erlin"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-13T21:36:51.376000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"AI Control Platform vs. AI Firewall vs. AI G…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wallarmlab"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wallarmlab/WALLARMLAB:F2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `websecuritylog`  ·  9 documents

WebSecurityLog provides security advisories and CVEs focused on web applications and services, sourced from various vendors and platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2014-0130"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Yahoo Web Security Bug Bounty :   Phpmyadm…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-0130", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.websecuritylog.com/2016/11/yahoo-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WEBSECURITYLOG:0015FD108480E9500D1618ED9FD20…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T15:59:53"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2016-11-23T16:01:02"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2016-11-23T12:01:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Anonymous (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-11-23T09:01:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Yahoo Web Security Bug Bounty :  Phpmyadmin …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"websecuritylog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/websecuritylog/WEBSECURI…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `33` |

### `wired`  ·  3,429 documents

Wired provides security news and analysis, covering various vendors and products, typically featuring advisories, CVEs, and expert commentary.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"blog"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Plus: Russian cyberspies turn to infrastruct…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wired.com/story/security-news-th…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIRED:EAF20DF879E70ED861FB02282E96B8EF"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:36:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T10:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T10:30:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Andy Greenberg, Dell Cameron, Lily Hay Newman"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:36:50.597000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Your Period Tracker Is (Probably) Spying on …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wired"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wired/WIRED:EAF20DF879E7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

## `bugbounty` family → `BugBountyBulletin`

### `hackerone`  ·  15,380 documents

HackerOne collection includes vulnerability reports and advisories from various vendors, focusing on security issues discovered through bug bounty programs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bounty` | `float` | 100% | Bounty amount/details paid for the report. | `0.0` |
| `bountyState` | `str` | 100% | State of the bounty (awarded, pending, …). | `"not-applicable"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-27782", "CVE-2023-27538"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Summary:\n\nCurl_close() (lib/url.c:21…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-9080", "date": "2026-07-10…` |
| `h1reporter` | `object{__typename,id,name,username}` | 100% | HackerOne reporter profile. | `{"id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvNDUwNDg0M…` |
| `h1team` | `object{handle,medium_profile_picture,name,url}` | 100% | HackerOne team/program the report belongs to. | `{"url": "https://hackerone.com/curl", "handle…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hackerone.com/reports/3833577"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"H1:3833577"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T12:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T12:31:07"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T07:12:59"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"carehi1324"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T12:36:54.023000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"curl: heap-use-after-free in curl_easy_clean…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hackerone"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hackerone/H1:3833577"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `48` |

### `huntr`  ·  4,075 documents

Huntr is a vulnerability database that aggregates security advisories, CVEs, and exploits primarily focused on open-source software projects.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-12484"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe_id` | `str` | 100% | Single associated CWE identifier. | `"d32d"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This report is not public"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.4, "uncertanity": 0.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-12228", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.huntr.dev/bounties/ab14df49-13b5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AB14DF49-13B5-4442-B754-3189430BFA28"` |
| `language` | `str` | 100% | Language of the report. | `"Python"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T21:36:58"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"source": "security@huntr.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-17T02:52:34"` |
| `patch_commit_sha` | `str` | 100% | Commit SHA of the fixing patch. | `"f9b1eb510478570609ef451984a255775aa4b937"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-20T19:47:09"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"jinyimeng01"` |
| `repository` | `str` | 100% | Source code repository associated with the report. | `"https://github.com/mlflow/mlflow"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `status` | `str` | 100% | Workflow status of the record. | `"valid"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T21:36:58.151000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unsafe Deserialization in Public keras.laye…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huntr"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/huntr/AB14DF49-13B5-4442…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `openbugbounty`  ·  1,261,610 documents

OpenBugBounty is a community-driven platform that catalogs security advisories and vulnerabilities reported by researchers across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Following the coordinated and responsible vu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 0.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.openbugbounty.org/reports/4049116/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OBB:4049116"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T16:25:10"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-07-23T13:56:00"` |
| `openbugbounty` | `object{mirror,patchStatus}` | 100% | Open Bug Bounty metadata (mirror, patch status). | `{"patchStatus": "On Hold", "mirror": ""}` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-04-24T13:56:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"EzioPaglia"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-24T14:20:05.467000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"krinner.com.gr Cross Site Scripting vulnerab…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openbugbounty"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openbugbounty/OBB:4049116"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `90` |

### `xssed`  ·  31,160 documents

XSSed is a vulnerability database focused on cross-site scripting (XSS) vulnerabilities, providing advisories and exploit details for various web applications.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"bugbounty"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Security researcher 0x73F, has submitted on …` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.xssed.com/mirror/81499/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"XSSED:81499"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2016-03-20T00:54:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-03-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-12-03T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["http://lavillette.com"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"0x73F"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-12-02T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unfixed XSS vulnerability at lavillette.com"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"xssed"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/xssed/XSSED:81499"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `64` |

## `cnnvd` family → `AdvisoryBulletin`

### `cnnvd`  ·  195,539 documents

CNNVD is a Chinese national vulnerability database that provides advisories and CVEs for various software products and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cnnvd"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6250"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The TP-Link Tapo C110 is an indoor network c…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6250", "date": "2026-06-18…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cnnvd.org.cn/home/globalSearch?k…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CNNVD-202606-2882"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T03:50:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-11T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-6…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"China National Vulnerability Database of Inf…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T03:12:23.618000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"TP-Link Tapo C110 \u683c\u5f0f\u5316\u5b57\u…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cnnvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cnnvd/CNNVD-202606-2882"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `23` |

## `cnvd` family → `AdvisoryBulletin`

### `cnvd`  ·  131,179 documents

CNVD is a Chinese vulnerability database that provides advisories and CVEs focused on various software products and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cnvd"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-13967"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Chrome is a web browser developed by Google,…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.9, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cnvd.org.cn/flaw/show/CNVD-2026-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CNVD-2026-27213"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T17:40:53"` |
| `metrics` | `object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"China National Vulnerability Database"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:40:53.507000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Google Chrome buffer overflow vulnerability …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cnvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cnvd/CNVD-2026-27213"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

## `crypto` family → `AdvisoryBulletin`

### `code423n4`  ·  10,190 documents

Code423n4 is a vulnerability database focused on security advisories and reports for smart contracts and blockchain projects.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"crypto"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[Lines of code](https://github.com/code-423n…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/code-423n4/2024-01-canto-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CODE423N4:2024-01-CANTO-FINDINGS-ISSUES-12"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-02-07T20:21:07"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-02-05T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-01-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Code4rena"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-01-27T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"secRewardsPerShare Insufficient precision"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"code423n4"` |
| `vendor_severity` | `str` | 100% | Vendor's own qualitative severity rating. | `"2 (Med Risk)"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/code423n4/CODE423N4:2024…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `30` |

## `cve` family → `CveBulletin`

### `cve`  ·  372,839 documents

The CVE collection from MITRE provides a comprehensive list of publicly disclosed vulnerabilities across various vendors, OS, and products, including CVEs and related advisories.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-07-19T15:48:13"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cnaAffected` | `list[object{collectionURL,defaultStatus,packageName,product,programFiles,programRoutines,vendor,versions}], list[object{defaultStatus,product,vendor,versions}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"collectionURL": "https://cpan.org/modules"…` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-16235"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-338"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `extraReferences` | `list[object{url}]` | 100% | Additional reference URLs beyond the primary set. | `[{"url": "https://metacpan.org/release/DRSTEV…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE-2026-16235"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:20:07"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:16:37"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"composite"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://metacpan.org/release/DRSTEVE/Crypt-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CPANSec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:13:03.434000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-16235"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cve/CVE-2026-16235"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |
| `vulnStatus` | `str` | 100% | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |
| `webApplicability` | `object{applicable,vulnerabilities}` | 100% | Web-application applicability assessment. | `{"applicable": null, "vulnerabilities": []}` |
| `workarounds` | `list[?], list[object{lang,value}]` | 100% | Structured workaround entries when no fix is available. | `[{"lang": "en", "value": "Users can generate …` |

### `cvelist`  ·  367,614 documents

CVE List from NVD provides a comprehensive database of publicly disclosed vulnerabilities, including CVEs, advisories, and related metadata.

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

### `nvd`  ·  367,609 documents

The NVD (National Vulnerability Database) provides a comprehensive repository of CVEs and security advisories across various vendors, operating systems, and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6656"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-208"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": "CVE-202…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVD:CVE-2026-6656"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:17:17"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:16:42"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"nvd.nist.gov"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:16:42"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://rt.cpan.org/Ticket/Display.html?id=…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"nvd@nist.gov"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `source_references` | `list[object{source,url}]` | 100% | References with their originating source. | `[{"url": "https://metacpan.org/release/DRSTEV…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:17:17.832000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-6656"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nvd/NVD:CVE-2026-6656"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |
| `vulnStatus` | `str` | 100% | NVD analysis status of the CVE (Analyzed, Awaiting Analysis, …). | `"Received"` |

### `prion`  ·  213,680 documents

Prion collection includes advisories and CVEs related to vulnerabilities in software products from various vendors, focusing on security issues and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-56067"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": null, "vector": nu…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-862"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Missing Authorization vulnerability in Azzar…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": "Missing…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-56067", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.prio-n.com/kb/vulnerability/CVE-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PRION:CVE-2024-56067"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-29T19:14:25"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-12-31T13:15:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-12-31T13:15:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://patchstack.com/database/wordpress/p…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"PRIOn knowledge base"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-12-31T10:15:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2024-56067"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"prion"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/prion/PRION:CVE-2024-56067"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

### `vulnrichment`  ·  163,940 documents

Vulnrichment provides enriched vulnerability data from various sources, focusing on vendor advisories and CVEs for enhanced security insights.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `assigned` | `str` | 100% | Assignment date/owner recorded by the source (e.g. CVE assignment). | `"2026-07-08T16:10:36"` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"cve"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15093"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-601"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"IBM Engineering AI Hub 1.0.0, 1.1.0, and 1.2…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.9, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15093", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/cisagov/vulnrichment/blob…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNRICHMENT:CVE-2026-15093"` |
| `impacts` | `list[?], list[object{capecId,descriptions}]` | 100% | Structured impact records (CVE JSON 5.x). | `[{"capecId": "CAPEC-66", "descriptions": [{"l…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T00:23:49"` |
| `metrics` | `object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "ibm", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T19:37:57"` |
| `origin` | `str` | 100% | Ingestion origin/pipeline the record came through. | `"cisa.gov"` |
| `provider` | `str` | 100% | Organization that produced the record (e.g. the CNA). | `"ibm"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T19:37:57"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.ibm.com/support/pages/node/7279…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ibm"` |
| `solutions` | `list[?], list[object{lang,supportingMedia,value}]` | 100% | Structured remediation entries (CVE JSON 5.x). | `[{"lang": "en", "value": "IBM strongly recomm…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T00:23:49.406000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-15093 Multiple Vulnerabilities in I…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnrichment"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnrichment/VULNRICHMEN…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

## `euvd` family → `AdvisoryBulletin`

### `euvd`  ·  421,777 documents

The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"euvd"` |
| `cnaAffected` | `list[object{enisaIdProduct,enisaIdVendor}]` | 100% | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"enisaIdVendor": [{"id": "2c1872ad-cf0a-3f1…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-16235"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crypt::Password versions through 0.28 for Pe…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": null, "t…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://euvd.enisa.europa.eu/vulnerability/E…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EUVD-2026-45895"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T08:03:48"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T07:02:11"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T07:02:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://metacpan.org/release/DRSTEVE/Crypt-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"EUVD"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T08:03:48.354000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"EUVD-2026-45895"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"euvd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/euvd/EUVD-2026-45895"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `0` |

## `exploit` family → `ExploitBulletin`

### `0daydb`  ·  71 documents

0daydb is a vulnerability database focused on zero-day exploits, providing advisories and detailed information on vulnerabilities across various software and platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2019-12169"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"PHP-Fusion version 9.03.60 suffers from a PH…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-12169", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://0daydb.com/php-fusion-9-03-60-php-ob…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"0DAYDB:B906BFDBDE502CE63C0691A9F1882E35"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-07-02T19:14:05"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-07-02T15:46:53"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-07-02T15:46:51"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"0daydb.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# Exploit Title: PHP-Fusion 9.03.60 - PHP Ob…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-07-02T12:46:51Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PHP-Fusion 9.03.60 - PHP Object Injection"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"0daydb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/0daydb/0DAYDB:B906BFDBDE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `142` |

### `canvas`  ·  619 documents

Canvas is a vulnerability database focused on educational software, providing advisories, CVEs, and security updates for the Canvas LMS platform.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2020-0796"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 7.5, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Name**\|  smbghost_lpe  \n---\|---  \n**CVE*…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-0796", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://exploitlist.immunityinc.com/home/expl…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SMBGHOST_LPE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:33:14"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-03-12T16:15:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-03-12T16:15:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Immunity Canvas"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-12T13:15:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Immunity Canvas: SMBGHOST_LPE"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"canvas"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/canvas/SMBGHOST_LPE"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `209` |

### `d2`  ·  185 documents

The d2 collection contains vendor-specific advisories and CVEs related to security vulnerabilities in various software products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2012-4284"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 10.0, "vector": "A…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Name**\|  d2sec_viscosity  \n---\|---  \n**C…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.7, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2012-4284", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://exploitlist.immunityinc.com/home/expl…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"D2SEC_VISCOSITY"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:32:17"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-01-10T20:15:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-01-10T20:15:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"DSquare"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-01-10T17:15:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"DSquare Exploit Pack: D2SEC_VISCOSITY"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"d2"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/d2/D2SEC_VISCOSITY"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `273` |

### `dsquare`  ·  740 documents

Dsquare provides vulnerability advisories and CVEs focused on various software products and services from multiple vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-24827"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 7.5, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"SQL Injection vulnerabilty in WordPress Asga…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.9, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-24827", "date": "2026-06-2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"E-734"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-11-26T18:37:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-10-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-10-20T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Dsquare Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"For the exploit source code contact DSquare …` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-10-19T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WordPress Asgaros Forum < 1.15.13 SQL Inject…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"dsquare"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/dsquare/E-734"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `516` |

### `exploitdb`  ·  47,904 documents

ExploitDB is a database of exploits and vulnerable software, primarily focusing on various applications and operating systems, providing detailed advisories and proof-of-concept code.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-60188"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-60188", "date": "2026-07-1…` |
| `exploitType` | `str` | 100% | Type of exploit (remote, local, webapps, …). | `"webapps"` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.exploit-db.com/exploits/52628"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EDB-ID:52628"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-09T05:37:23"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Mohammad Hossein Sadeghian"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# Exploit Title: Atarim WordPress Plugin  4.…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://www.exploit-db.com/raw/52628"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T05:37:24.695000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Atarim WordPress Plugin  4.2.2 - Sensitive I…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"exploitdb"` |
| `verified` | `bool` | 100% | Whether the exploit/finding was verified. | `false` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/exploitdb/EDB-ID:52628"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `36` |

### `exploitpack`  ·  41,207 documents

ExploitPack is a data source focused on exploits and vulnerabilities, primarily targeting various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2020-5725"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\nGrandstream UCM6200 Series WebSocket 1.0.2…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-5725", "date": "2026-06-16…` |
| `exploitpack` | `object{platform,type}` | 100% | ExploitPack tool provenance (platform, type). | `{"type": "webapps", "platform": "hardware"}` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"EXPLOITPACK:7544F9A22341C9F232C7ABF19097111B"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-04-01T20:40:02"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-03-31T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-03-31T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jacob Baines"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# Exploit Title: Grandstream UCM6200 Series …` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-30T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Grandstream UCM6200 Series WebSocket 1.0.20.…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"exploitpack"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/exploitpack/EXPLOITPACK:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `275` |

### `gitee`  ·  1,886 documents

Gitee provides vulnerability advisories and CVEs related to open-source projects hosted on its platform, primarily focusing on software security.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `attachments` | `list[?], list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | 100% | Binary/media attachments associated with the document. | `[{"id": "3772fb53-757e-3af2-b36d-778f80a1e641…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47291", "CVE-2026-49160"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-49160 \u4e0e CVE-2026-47291\uff1aHT…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.0, "uncertanity": 1.0, …` |
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | 100% | Model-based exploit-probability scoring. | `{"url": "https://gitee.com/jinghunsanzu/CVE-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://gitee.com/jinghunsanzu/CVE-2026-4916…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"22E955DB-9127-5532-BFEB-AC714FDCA474"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:11:09"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T16:23:41"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T16:23:41"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"\u5929\u5802\u96be\u53d7\u7684\u5730\u72f1"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:11:09.912000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Exploit for Uncontrolled Resource Consumptio…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitee"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gitee/22E955DB-9127-5532…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |

### `githubexploit`  ·  15,800 documents

GitHub Exploit collection includes exploits and proof-of-concept code sourced from GitHub, focusing on various software vulnerabilities across multiple platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `attachments` | `list[object{content_type,created,description,extension,file_path,filename,id,last_modified,sha256,size,type}]` | 100% | Binary/media attachments associated with the document. | `[{"id": "70774c64-f94a-3c26-a4dc-1380dfede627…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-57819"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# CVE-2025-57819 \u2014 FreePBX SQL Injectio…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 10.0, "uncertanity": 1.2,…` |
| `exploitProbabilityScoring` | `object{error,files_scanned,group_scores,probability,scan_at,total_score,url,version}` | 100% | Model-based exploit-probability scoring. | `{"url": "https://github.com/Neobee714/CVE-202…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/Neobee714/CVE-2025-57819-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"C5096BEF-00D9-5E49-9834-B2C7D92D9B2F"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T06:34:23"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T06:32:01"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T06:20:30"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Neobee714"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T06:34:23.396000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Exploit for SQL Injection in Sangoma Freepbx"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"githubexploit"` |
| `vendorId` | `str` | 100% | Vendor's own identifier for the advisory, when provided. | `"GITHUBEXPL:NEOBEE714-CVE-2025-57819-POC"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/githubexploit/C5096BEF-0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `metasploit`  ·  7,296 documents

Metasploit collection includes exploit modules and payloads for various vulnerabilities, primarily targeting software and systems across multiple platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This module supports running an HTTP server …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.rapid7.com/db/modules/auxiliary/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSF:AUXILIARY-SERVER-RELAY-HTTP_TO_SMB-"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:40:16"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T19:06:26"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T19:06:26"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"jheysel-r7"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# frozen_string_literal: true\n\n##\n# This …` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://github.com/rapid7/metasploit-framewo…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:40:20.867000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Windows HTTP to SMB Relay"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"metasploit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/metasploit/MSF:AUXILIARY…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `56` |

### `packetstorm`  ·  50,797 documents

Packet Storm is a security database that provides advisories, exploits, and tools primarily focused on various software and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-56877"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Skillable's SCORM lab launch endpoint valida…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31309", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/226162/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORM:226162"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:20:43"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Greg Durys"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"Skillable's SCORM lab launch endpoint valida…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/226162"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:20:43.271000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\ud83d\udcc4 Skillable SCORM userId Authoriz…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstorm"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/packetstorm/PACKETSTORM:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `34` |

### `pwnmalw`  ·  46 documents

Pwnmalw is a collection from various security sources focused on malware advisories and exploits targeting multiple vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Type: Flood Bots\n\nAuthor: [Xylitol](<https…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.5, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.pwnmalw.re/Http Botnets/vertexnet"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PWNMALW:VERTEXNET"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2017-03-15T07:30:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-01-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-01-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Xylitol"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"<code>#!/usr/bin/perl\n# VertexNet v1.1.1 Fl…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-01-13T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Malware exploit: Vertexnet"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pwnmalw"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pwnmalw/PWNMALW:VERTEXNET"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `572` |

### `saint`  ·  4,305 documents

SAINT provides vulnerability advisories and CVEs focused on various software products and operating systems, sourced from multiple security vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-8037"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Added: 07/02/2026  \nCVE: CVE-2026-8037  \n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-8037", "date": "2026-07-15…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://download.saintcorporation.com/cgi-bi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAINT:B94055400BC099146F61734DD1B7933A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-13T20:16:52"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SAINT Corporation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T07:56:39.754000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Progress LoadMaster API command injection"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"saint"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/saint/SAINT:B94055400BC0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `seebug`  ·  56,796 documents

Seebug is a vulnerability database focused on security advisories and exploits for various software products and systems, primarily sourced from community contributions.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-26086"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Fortinet FortiWeb OS Command Injection\n\n…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 2.3, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-26086", "date": "2026-06-1…` |
| `has_poc` | `bool` | 100% | Whether a proof-of-concept is available. | `true` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.seebug.org/vuldb/ssvid-99336"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SSV:99336"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-08-20T07:29:10"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-08-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-08-20T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Knownsec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `status` | `str` | 100% | Workflow status of the record. | `"cve"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-08-19T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Atlassian Jira \u6587\u4ef6\u8bfb\u53d6\u6f0…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"seebug"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/seebug/SSV:99336"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `834` |

### `srcincite`  ·  293 documents

SrcIncite provides vulnerability advisories and CVEs focused on various software products and services, sourced from multiple security vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-25202"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Vulnerability Details:**\n\nThis vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-25202", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://srcincite.io/advisories/src-2025-0006/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SRC-2025-0006"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-28T22:49:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@samsung.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-28T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-09-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Steven Seeley of Source Incite"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"#!/usr/bin/env python3\n\"\"\"\nSamsung Magi…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://srcincite.io/pocs/src-2025-0006.py.txt"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-29T04:06:30.344000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SRC-2025-0006 : Samsung MagicINFO 9 Server M…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"srcincite"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/srcincite/SRC-2025-0006"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `151` |

### `vulnerlab`  ·  3,408 documents

VulnerLab provides advisories and CVEs focused on various software products and vulnerabilities, sourced from community contributions and research.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `category` | `str` | 100% | Category assigned by the source. | `"Website Vulnerabilities"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-3786"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.4, "uncertanity": 1.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-3786", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.vulnerability-lab.com/get_conten…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNERABLE:2327"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-09-25T13:33:56"` |
| `metrics` | `object{cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-07-25T00:00:00"` |
| `price` | `object{EUR}` | 100% | Exploit price (for commercial exploit feeds). | `{"EUR": "1000-2000"}` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-07-25T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"L. Guenther - https://www.vulnerability-lab.…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"Document Title:\r\n===============\r\nETSI W…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-07-24T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ETSI WEBstore 2023 - Persistent Cross Site V…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnerlab"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnerlab/VULNERABLE:2327"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `407` |

### `wpexploit`  ·  4,359 documents

Wpexploit is a vulnerability database focusing on WordPress plugins and themes, providing advisories, CVEs, and exploit details.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-15481"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Description The plugin exposes an unauthenti…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-13823", "date": "2026-06-1…` |
| `generation` | `int` | 100% | Internal generation/version counter of the record. | `0` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPEX-ID:A5FB18FA-BE2C-41A5-81EF-CA27DE024D34"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-22T05:55:37"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-01-08T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://wordpress.org/news/2024/06/wordpres…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Khaled Alenazi (Nxploited)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"https://example.com/wp-content/plugins/8-deg…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-15T17:51:21.340000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Notification Bar for WordPress <= 1.1.8 \u20…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpexploit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wpexploit/WPEX-ID:A5FB18…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `146` |

### `zdt`  ·  39,001 documents

ZDT collection from the NVD includes vendor-specific advisories and CVEs focusing on zero-day vulnerabilities across various products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `category` | `str` | 100% | Category assigned by the source. | `"web applications"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-1639"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An attacker who can pass input to the asteva…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.9, "uncertanity": 0.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-1639", "date": "2026-07-09…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://0day.today/exploit/description/39943"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"1337DAY-ID-39943"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-03-22T05:18:21"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-03-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-03-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nxploited"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"import argparse\nimport requests\nfrom bs4 i…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://0day.today/exploit/39943"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-14T00:58:58Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WordPress Elementor Pro Animation Addon 1.6 …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdt"` |
| `verified` | `bool` | 100% | Whether the exploit/finding was verified. | `true` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/zdt/1337DAY-ID-39943"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `424` |

### `zeroscience`  ·  1,109 documents

ZeroScience provides detailed advisories and CVEs focused on vulnerabilities in various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"exploit"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58478"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Summary\n\nSIP is a free Raspberry Pi based …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-58478", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.zeroscience.mk/advisories/ZSL-20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ZSL-2026-5998"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T06:51:47"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "disclosure@vuln…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gjoko Krstic"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"<html><body><p>#!/usr/bin/env python3\r\n#\r…` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://www.zeroscience.mk/codes/sip_ssrf.txt"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T06:51:51.749000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SIP Sustainable Irrigation Platform 5.x (nr-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zeroscience"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/zeroscience/ZSL-2026-5998"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `38` |

## `info` family → `InfoBulletin`

### `amd`  ·  186 documents

AMD's vulnerability collection includes advisories and CVEs related to AMD hardware and software products, focusing on security issues affecting their technology.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-0466", "CVE-2026-28237"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## CVE Details\n\nRefer to Glossary for expl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-0466", "date": "2026-06-18…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.amd.com/en/resources/product-sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AMD-SB-9025"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-17T08:22:46"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-09T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"amd.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T00:53:46.762000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"AMD uProf Vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/amd/AMD-SB-9025"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `22` |

### `attackerkb`  ·  77,779 documents

AttackersKB is a vulnerability database focused on threat actor tactics, techniques, and procedures, providing advisories and CVEs related to various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,vendor,version}]` | 100% | Affected software products (name/version/operator). | `[{"vendor": "ci4-cms-erp", "version": "0.31.9…` |
| `attackerkb` | `object{attackerValue,exploitability}` | 100% | AttackerKB assessment (attacker value, exploitability). | `{"attackerValue": 0.0, "exploitability": 0.0}` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-45138"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.4, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CI4MS is a CodeIgniter 4-based content manag…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 0.8, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://attackerkb.com/topics/07eb059d-749e-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"AKB:07EB059D-749E-4613-9F86-1E23FA4A521D"` |
| `last_activity` | `str` | 100% | Timestamp of the most recent activity on the item. | `"2026-07-20T00:30:13"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T02:37:03"` |
| `metrics` | `object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:30:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T23:18:51"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/ci4-cms-erp/ci4ms/releas…` |
| `references_categories` | `object{canonical,misc}` | 100% | References grouped by category (canonical/misc). | `{"misc": ["https://github.com/ci4-cms-erp/ci4…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AttackerKB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T02:37:03.281000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-45138"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"attackerkb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/attackerkb/AKB:07EB059D-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

### `bdu_fstec`  ·  91,078 documents

BDU FSTEC provides advisories from the Russian Federal Service for Technical and Export Control, focusing on vulnerabilities in software and hardware products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,platform,type,vendor,version,versionRaw}]` | 100% | Affected software products (name/version/operator). | `[{"vendor": "\u041e\u041e\u041e \u00ab\u0420\…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-8715"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "2.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The vulnerability of the pg_dump utility in …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-8715", "date": "2026-07-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://bdu.fstec.ru/vul/2025-09830"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BDU:2025-09830"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T23:43:07"` |
| `metrics` | `object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "vendor", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T23:43:07"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://www.postgresql.org/support/security…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FSTEC of Russia \u2014 Information Security …` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T12:57:05.185000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The vulnerability of the pg_dump utility in …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"bdu_fstec"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/bdu_fstec/BDU:2025-09830"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

### `binamuse`  ·  15 documents

Binamuse is a vulnerability collection from the Binamuse database focusing on advisories and CVEs related to various software products and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2014-4481"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 6.8, "vector": "AV…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](http://1.bp.blogspot.com/-BEbEha_KlFc/VB…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-4481", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://blog.binamuse.com/2015/01/coregraphic…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BINAMUSE:F61C45CDC72EEDA3B26D9A56201D5E74"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:33:18"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-01-28T00:40:23"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-01-28T00:39:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"feliam (noreply@blogger.com)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-01-27T21:39:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CoreGraphics CCITT Memory Corruption - CVE-2…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"binamuse"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/binamuse/BINAMUSE:F61C45…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `661` |

### `cert`  ·  3,706 documents

A collection of advisories and alerts from the Computer Emergency Response Team (CERT) covering various vendors and products, including CVEs and security incidents.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14890"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Overview\n\nA Pickle deserialization vul…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.4, "uncertanity": 2.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14890", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.kb.cert.org/vuls/id/326070"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VU:326070"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T20:37:03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cret", "versio…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T14:43:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/sgl-project/sglang/issue…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CERT"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:38:00.429000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SGLang contains a vulnerable pickle deserial…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cert"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cert/VU:326070"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `checkpoint_advisories`  ·  13,538 documents

Checkpoint Advisories provide security bulletins from Check Point Software Technologies, including advisories and CVEs for their products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-21490"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 4.0, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A remote code execution vulnerability exists…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-21490", "date": "2026-06-1…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CPAI-2022-0853"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-11-28T14:45:52"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-11-28T00:00:00"` |
| `protected_by` | `list[str]` | 100% | Products/controls that protect against the issue. | `["Security Gateway R81", "Security Gateway R8…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-11-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Check Point Advisories"` |
| `severity` | `str` | 100% | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"Medium"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-11-27T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Oracle MySQL Cluster Remote Code Execution (…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"checkpoint_advisories"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/checkpoint_advisories/CP…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |
| `vulnerable_products` | `list[str]` | 100% | Product identifiers known to be vulnerable. | `["Oracle MySQL Cluster 7.4.35 and prior", "Or…` |

### `circl`  ·  175,119 documents

CIRCL provides vulnerability advisories and CVEs focused on various vendors and products, sourced from multiple security feeds and reports.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-7708"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"creation_timestamp\| type\| source  \n---\|---\|…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.8, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://cve.circl.lu/api/sighting"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CIRCL:CVE-2024-7708"` |
| `items` | `list[object{content,creation_timestamp,source,type,uuid,vulnerability_lookup_origin}]` | 100% | Sub-items/entries contained in the document. | `[{"uuid": "47fce2b0-b875-4aa1-badb-22d5b07806…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:37:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "emo@eclipse.or…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:47:11"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:47:11"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bsky.app/profile/khesefxyz.bsky.soc…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Circl"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:37:45.115000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2024-7708"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"circl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/circl/CIRCL:CVE-2024-7708"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `false` |

### `cisa`  ·  4,188 documents

CISA collection includes advisories and alerts from the Cybersecurity and Infrastructure Security Agency, focusing on vulnerabilities across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48907"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CISA has added one new vulnerability to its …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48907", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cisa.gov/news-events/alerts/2026…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISA:DD804083B370CD5692E9EFFB700BBA8F"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-18T05:43:51"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-16T12:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-16T12:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["/known-exploited-vulnerabilities-catalog", …` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CISA"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-17T05:43:59.841000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\nCISA Adds One Known Exploited Vulnerabilit…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisa"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cisa/CISA:DD804083B370CD…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `true` |

### `cisa_kev`  ·  1,652 documents

CISA KEV collection includes advisories and CVEs related to known exploited vulnerabilities across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58644"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Microsoft SharePoint contains a deserializat…` |
| `dueDate` | `str` | 100% | Remediation due date (e.g. CISA KEV required-action deadline). | `"2026-07-19T00:00:00"` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-58644", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cisa.gov/known-exploited-vulnera…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISA-KEV-CVE-2026-58644"` |
| `knownRansomwareCampaignUse` | `str` | 100% | Whether it is known to be used in ransomware campaigns. | `"Unknown"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T21:38:29"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `notes` | `str` | 100% | Free-text notes. | `"https://msrc.microsoft.com/update-guide/vuln…` |
| `product` | `str` | 100% | Affected product name. | `"SharePoint"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CISA"` |
| `requiredAction` | `str` | 100% | Required remediation action (e.g. CISA KEV directive). | `"Apply mitigations in accordance with vendor …` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:38:28.037000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft SharePoint Deserialization of Untr…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisa_kev"` |
| `vendor` | `str` | 100% | Affected product's vendor. | `"Microsoft"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cisa_kev/CISA-KEV-CVE-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `true` |

### `ciscothreats`  ·  13,924 documents

Cisco Threats collection provides advisories and CVEs related to vulnerabilities in Cisco products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `ciscoThreat` | `object{files,md5,messageBody,size,subject}` | 100% | Cisco Talos threat details (files, hashes, subject). | `{"md5": "c130666367eb5724a23d046a7963df5e", "…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Medium\n\nAlert ID: \n\n58703\n\nFirst Publi…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/view…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-THREAT-58703"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-15T17:08:31"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2018-08-15T15:55:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2018-08-15T15:55:56"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-08-15T12:55:56Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Threat Outbreak Alert RuleID33317: Email Mes…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ciscothreats"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ciscothreats/CISCO-THREA…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `542` |

### `coresecurity`  ·  247 documents

Core Security provides vulnerability advisories and CVEs focused on various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-24121"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## 1\\. Advisory Information \n\n**Title:** …` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.2, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-24121", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.coresecurity.com/advisories/logi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CORE-2022-0001"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-07T14:08:39"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Core Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-01-31T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unified Office Total Connect Now\u2120 Cooki…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"coresecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/coresecurity/CORE-2022-0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `43` |

### `cve0day`  ·  14 documents

CVE0day is a collection from various sources focusing on zero-day vulnerabilities, typically including advisories and CVEs for multiple vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2019-6340"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 6.8, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Description**\n\nThis Metasploit module ex…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.9, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-6340", "date": "2026-07-15…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cve0day.com/drupal-cve-2019-6340…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CVE0DAY:BD50F22FA4B45F74682F7562C2FA7C3E"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-03-07T15:55:08"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-03-07T14:06:06"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-03-07T14:06:06"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CVE 0day"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-03-07T11:06:06Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Drupal CVE-2019-6340 Remote Code Execution EXP"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cve0day"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cve0day/CVE0DAY:BD50F22F…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `288` |

### `duo`  ·  54 documents

Duo Security's collection features advisories and CVEs related to its authentication products and services, focusing on security vulnerabilities and fixes.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Duo Product Security Advisory\n\n**Advisor…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://duo.com/labs/psa/duo-psa-2014-007"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DUO:D3F6F5E7B4015B33735F13DE1D5791B4"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-01-29T20:54:29"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2014-10-15T04:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2014-10-15T04:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Duo Security Advisories"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2014-10-15T01:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"DUO-PSA-2014-007: Duo Product Security Advis…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"duo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/duo/DUO:D3F6F5E7B4015B33…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `28` |

### `erpscan`  ·  291 documents

ERPSCAN provides security advisories and CVEs specifically focused on vulnerabilities in ERP systems and related applications.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2018-2636"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Application:** SAP Redwood BPA  \n**Vendor…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": -0.0, "vector": "NONE"}, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-2636", "date": "2026-06-30…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://erpscan.io/advisories/erpscan-18-006…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ERPSCAN-18-006"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-09-15T10:41:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2017-09-11T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-09-11T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ERPScan"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-09-10T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SAP Redwood BPA Message Service crypto secre…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"erpscan"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/erpscan/ERPSCAN-18-006"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `518` |

### `fireeye`  ·  545 documents

FireEye collection includes vendor-specific advisories and CVEs related to cybersecurity threats and exploits for various products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-31207", "CVE-2021-34473", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Since our initial public release of capa, in…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.1, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-31207", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.fireeye.com/blog/threat-research…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FIREEYE:A7220068AE8525CC3BBB5F13CD1C2492"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-09-15T13:48:34"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-09-15T13:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-09-15T13:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/fireeye/capa", "https://…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FireEye"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-09-15T10:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ELFant in the Room \u2013 capa v3"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fireeye"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fireeye/FIREEYE:A7220068…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

### `googleprojectzero`  ·  253 documents

Google Project Zero collection features advisories and CVEs focused on vulnerabilities in various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-54957"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Posted by Seth Jenkins\n\nWe recently publis…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-54957", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://projectzero.google/2026/05/pixel-10-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GOOGLEPROJECTZERO:6829A4B13E4B1C7ABB1562D1BB…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-14T03:14:58"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"GoogleProjectZero"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T03:14:58.783000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"A 0-click exploit chain for the Pixel 10: Wh…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"googleprojectzero"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/googleprojectzero/GOOGLE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `40` |

### `hivepro`  ·  1,589 documents

HivePro provides a comprehensive database of vulnerability advisories, CVEs, and threat intelligence focused on various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-45185"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Persistent exposure backlogs do not shrink w…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-45185", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://hivepro.com/blog/zafran-vs-hive-pro-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HIVEPRO:592FA80144C11B4FE007F3315B105DE5"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-02T12:05:55"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-02T10:06:20"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-02T10:06:20"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Amit Mishra"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-02T12:05:55.160000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Zafran vs Hive Pro: CTEM Platform Comparison"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hivepro"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hivepro/HIVEPRO:592FA801…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `ics`  ·  4,265 documents

This collection from the ICS-CERT includes advisories and CVEs related to vulnerabilities in industrial control systems across various vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-63397"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## 1. RISK EVALUATION\n\nremorses/genql befo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 1.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63397", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://raw.githubusercontent.com/cisagov/CS…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VA-26-197-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T13:36:53"` |
| `metrics` | `object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T18:56:28"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T18:56:28"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://raw.githubusercontent.com/cisagov/C…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Industrial Control Systems Cyber Emergency R…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T13:36:53.257000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"remorses/genql code injection"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ics"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ics/VA-26-197-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `intel`  ·  1,002 documents

Intel's vulnerability collection includes advisories and CVEs related to Intel products and technologies, focusing on hardware and software security issues.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-27723"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Summary: \n\nA potential security vulner…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-27723", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.intel.com/content/www/us/en/secu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"INTEL:INTEL-SA-01426"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-12T19:16:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "secure@intel.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-12T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-12T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Intel Security Center"` |
| `severity` | `str` | 100% | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"MEDIUM"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T19:16:54.910000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Intel\u00ae 800 Series Ethernet Linux Driver…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"intel"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/intel/INTEL:INTEL-SA-01426"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `15` |

### `kaspersky`  ·  4,027 documents

Kaspersky's collection includes security advisories and CVEs related to their antivirus products and software vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Multiple vulnerabilities were found in Googl…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "uncertanity": 1.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47301", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://threats.kaspersky.com/en/vulnerabili…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KLA91155"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:02"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://chromereleases.googleblog.com/2026/…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Kaspersky Lab"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:37:02.711000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"KLA91155 Multiple vulnerabilities in Google …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kaspersky"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kaspersky/KLA91155"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

### `lenovo`  ·  1,176 documents

Lenovo's vulnerability collection includes advisories and CVEs related to Lenovo products and software, sourced from their security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"No description provided"` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.lenovo.com/us/en/product_sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"LENOVO:PS500844-NOSID"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T18:49:10"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T19:11:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T19:05:47"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Lenovo"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T18:49:11.070000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"NVIDIA Networking Vulnerabilities - Lenovo S…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"lenovo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/lenovo/LENOVO:PS500844-N…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `myhack58`  ·  7,620 documents

MyHack58 provides security advisories and CVEs focused on vulnerabilities related to various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2020-1938"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 7.5, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The content of the article introduction \nTh…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 9.6, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-1938", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.myhack58.com/Article/html/3/62/20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MYHACK58:62202097573"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-02-01T03:40:51"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-03-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-03-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"\u4f5a\u540d"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-03-16T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Apache Tomcat from file contains to RCE expl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"myhack58"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/myhack58/MYHACK58:622020…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `230` |

### `packetstormnews`  ·  6,907 documents

Packet Storm News provides security advisories, exploits, and vulnerability information primarily focused on various software products and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14440"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"GNUnet is a peer-to-peer framework with focu…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packetstorm.news/files/id/213585/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PACKETSTORMNEWS:213585"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-08T07:35:00"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cna", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-12-29T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-12-29T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Christian Grothoff"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceHref` | `str` | 100% | URL of the raw source object, when it differs from href. | `"https://packetstorm.news/download/213585"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T07:35:00.709000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"GNUnet P2P Framework 0.26.2"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"packetstormnews"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/packetstormnews/PACKETST…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `369` |

### `ptsecurity`  ·  188,147 documents

PTSecurity provides security advisories and CVEs focused on vulnerabilities affecting various software products and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-44359"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Meshtastic is an open source mesh networking…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16226", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://dbugs.ptsecurity.com/vulnerability/P…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PT-2026-61516"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:39:01"` |
| `metrics` | `object{cna,vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "dbugs", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/meshtastic/firmware/comm…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Positive Technologies"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T23:46:54.889000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PT-2026-61516"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ptsecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ptsecurity/PT-2026-61516"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `qt`  ·  41 documents

Qt vulnerabilities from the Qt Company, covering advisories and CVEs related to the Qt framework across various platforms and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-12385"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Improper Validation of Specified Quantity in…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-12385", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.qt.io/blog/security-advisory-imp…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"QT:B48ED91285C0207980E4D3AF7DB01E1A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-12-04T03:22:18"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "a59d8014-47c4-4…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-12-03T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-12-03T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Tuukka Kettunen"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-12-03T20:42:27.230000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security advisory: Improper validation of ta…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"qt"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/qt/QT:B48ED91285C0207980…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `15` |

### `rapid7blog`  ·  1,731 documents

Rapid7 Blog provides insights on security vulnerabilities, advisories, and exploit techniques relevant to various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Overview\n\nOn July 17, 2026, a GitHub Se…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 0.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.rapid7.com/blog/post/etr-cve-202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RAPID7BLOG:20F3692F768CBC3939DA6DEE73C29ECC"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:38:32"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T22:23:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T22:23:03"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Rapid7 Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:36:54.236000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-63030: wp2shell a Critical Remote C…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rapid7blog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rapid7blog/RAPID7BLOG:20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `rdot`  ·  234 documents

Rdot is a vulnerability collection from the Rdot database, focusing on advisories and CVEs related to various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\u0412\u0441\u0435\u043c \u043f\u0440\u0438\…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rdot.org/forum/showthread.php?t=4958"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RDOT:4958"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-02-09T00:35:50"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-02-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-02-07T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Zecurion"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-02-06T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"\u041f\u0440\u0438\u0433\u043b\u0430\u0448\u…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rdot"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rdot/RDOT:4958"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `30` |

### `redhatcve`  ·  206,826 documents

Red Hat CVE collection provides advisories and CVE entries specifically for Red Hat products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-64077"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-131"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A flaw was found in the Linux kernel's netfi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16118", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://access.redhat.com/security/cve/cve-2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RH:CVE-2026-64077"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:39:20"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,cna}, object{cna,vendor}, object{vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:25:57"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:25:57"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-6…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"redhat.com"` |
| `sourceAffectedData` | `list[?], list[object{OS,OSVersion,packageName,packageVersion,status}]` | 100% | Affected-product data in the source's own shape. | `[{"OS": "redhat", "OSVersion": "10", "package…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:39:20.861000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-64077"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhatcve"` |
| `vendorCvss` | `object{score,vector}, object{}` | 100% | Vendor-assigned CVSS score block. | `{"score": "5.5", "vector": "CVSS:3.1/AV:L/AC:…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/redhatcve/RH:CVE-2026-64…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `samba`  ·  174 documents

Samba vulnerability collection from various sources includes advisories and CVEs related to Samba software on multiple operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-4408"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Description\n\nSamba file servers and cla…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-4408", "date": "2026-06-24…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.samba.org/samba/security/CVE-202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SAMBA:CVE-2026-4408"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T15:49:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-26T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-26T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Samba Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-27T19:48:40.832000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unauthenticated Remote Code Execution"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"samba"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/samba/SAMBA:CVE-2026-4408"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `security_vulns`  ·  80 documents

A collection of security vulnerabilities from various vendors, including advisories, CVEs, and exploit information.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2007-0842"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n\n\nTitle:        Microsoft Visual C++ 8.0…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2007-0842", "date": "2026-06-16…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY_VULNS:YEAR3000"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-08-25T14:27:26"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2007-12-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2007-12-02T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SecurityVulns"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2007-12-01T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Microsoft Visual C++ 8.0 standard library ti…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"security_vulns"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/security_vulns/SECURITY_…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `83` |

### `talos`  ·  2,224 documents

Talos provides threat intelligence from Cisco, focusing on vulnerabilities across various software and hardware products, including advisories and CVEs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-5263"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.0, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Summary\n\nA improper input validation v…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5263", "date": "2026-07-04…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.talosintelligence.com/vulnerabil…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TALOS-2026-2410"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-02T13:40:41"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Talos Intelligence"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T13:41:17.997000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WolfSSL wolfSSL X.509 registeredID name cons…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"talos"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/talos/TALOS-2026-2410"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `tenable`  ·  223 documents

Tenable provides vulnerability data from various vendors and products, including advisories, CVEs, and security assessments.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-11187", "CVE-2025-13034", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11187", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.tenable.com/security/tns-2026-18"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TENABLE:629066FB944DD92B1B80C9706A10934B"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:37:25"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T21:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T21:30:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Aaron Roy"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:37:25.953000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[R1] Tenable Agent Versions 11.2.1 and 11.1.…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tenable"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/tenable/TENABLE:629066FB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

### `thn`  ·  20,929 documents

The "thn" collection from the Threat Hunter Network includes advisories and CVEs focused on various software products and vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42533"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://thehackernews.com/2026/07/worlds-lar…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THN:7587C446CD8ECAF56452CA3708CEC3AF"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:33:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:27:26"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:27:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"The Hacker News"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:33:50.695000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"World's Largest AI Model Repository Hugging …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"thn"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/thn/THN:7587C446CD8ECAF5…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `threatpost`  ·  15,946 documents

Threatpost provides security news and analysis, focusing on vulnerabilities, exploits, and advisories across various vendors and products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-36260"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n\nEdFinancial and the Oklahoma Student Loa…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-36260", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://threatpost.com/student-loan-breach-e…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"THREATPOST:671939D0AFDC28B6E98676767DE43622"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T14:41:47"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-08-31T12:57:48"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-08-31T12:57:48"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://apps.web.maine.gov/online/aeviewer/…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nate Nelson"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-08-31T09:57:48Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Student Loan Breach Exposes 2.5M Records"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"threatpost"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/threatpost/THREATPOST:67…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `125` |

### `trellix`  ·  608 documents

Trellix provides security advisories and CVEs related to its cybersecurity products and services, focusing on vendor-specific vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-20045"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# PureRAT: A Multi-Stage, Fileless RAT Utili…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 0.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-10561", "date": "2026-04-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.trellix.com/content/mainsite/en-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TRELLIX:AC25BB751DE50B70ACF0B27808C9D8D4"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-20T00:00:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-20T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Trellix"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-20T15:40:35.743000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PureRAT: A Multi-Stage, Fileless RAT Utilizi…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"trellix"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/trellix/TRELLIX:AC25BB75…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `vulncheck_kev`  ·  4,985 documents

Vulncheck_kev aggregates security advisories and CVEs from various vendors, focusing on known exploited vulnerabilities across multiple products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `_product` | `str` | 100% | Affected product name (source-internal key). | `"Landry Office Automation (OA)"` |
| `_vendor` | `str` | 100% | Affected product's vendor (source-internal key). | `"Shenzhen Landray Software Co., Ltd."` |
| `_vulncheck_reported_exploitation` | `list[object{date_added,url}]` | 100% | VulnCheck-reported exploitation evidence. | `[{"url": "https://www.cve.org/CVERecord?id=CV…` |
| `_vulncheck_xdb` | `list[?], list[object{clone_ssh_url,date_added,exploit_type,xdb_id,xdb_url}]` | 100% | VulnCheck exploit/DB cross-references. | `[{"xdb_id": "c8884e9be221", "xdb_url": "https…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{VulnCheckCpeConfiguration,_index}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": false, "VulnCheckCpeConfiguration"…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-58352"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.7, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvssScore` | `float` | 100% | Flat numeric CVSS base score, when only a scalar is provided. | `8.7` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Landray OA contains an unauthenticated HQL i…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-58352", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://console.vulncheck.com/cve/CVE-2024-5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNCHECK-KEV:CVE-2024-58352"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T05:11:39"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-02T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://console.vulncheck.com/cve/CVE-2024-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"VulnCheck"` |
| `source` | `str` | 100% | Source name/identifier for the record. | `"disclosure@vulncheck.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T05:11:39.451000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VulnCheck KEV: CVE-2024-58352"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulncheck_kev"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulncheck_kev/VULNCHECK-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |
| `wildExploited` | `bool` | 100% | Whether the vulnerability is exploited in the wild. | `true` |

### `wizblog`  ·  652 documents

Wizblog provides security advisories and insights focused on cloud security vulnerabilities and best practices for cloud service providers.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Part 3: How the Red Agent bypassed a credit …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wiz.io/blog/red-agent-pov-busine…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WIZBLOG:DE537C472999F083DEFF7BACB77EEC15"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T15:36:53"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T13:33:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T13:33:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gal Nagli"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T15:36:53.962000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"The Red Agent POV: The One Boolean That Brok…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wizblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wizblog/WIZBLOG:DE537C47…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `wordfence`  ·  524 documents

Wordfence provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"On July 17, 2026, the WordPress Security Tea…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 1.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.wordfence.com/blog/2026/07/psa-w…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WORDFENCE:A70814AA347845ABF82AC8B4A9E7CB5F"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T05:36:54"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T23:03:48"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T23:03:48"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chloe Chamberland"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:38:26.874000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PSA: WordPress Core Patched Unauthenticated …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wordfence"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wordfence/WORDFENCE:A708…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `zdi`  ·  16,763 documents

The ZDI collection includes advisories and CVEs from the Zero Day Initiative, focusing on vulnerabilities in various software products and vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-27220"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This vulnerability allows remote attackers t…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 0.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-27220", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.zerodayinitiative.com/advisories…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ZDI-26-355"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-11T05:58:44"` |
| `metrics` | `object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "zdi", "versi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-10T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://helpx.adobe.com/security/products/a…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Mark Vincent Yason (markyason.github.io)"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-11T05:58:44.411000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Adobe Acrobat Reader DC Annotation Use-After…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"zdi"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/zdi/ZDI-26-355"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

## `jvn` family → `AdvisoryBulletin`

### `jvn`  ·  5,631 documents

The JVN collection provides advisories and CVEs related to vulnerabilities in various software products and operating systems sourced from Japan's security community.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"jvn"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-54518", "CVE-2026-21530", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Overview\n\nCVE-2025-54518 \| AMD: CVE-2025…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 0.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44024", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jvndb.jvn.jp/en/contents/2026/JVNDB-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JVNDB-2026-024104"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T01:37:02"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T03:28:23"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T03:28:23"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.hitachi.com/products/it/storage…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Japan Vulnerability Notes"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T01:37:02.979000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security information for Hitachi Disk Array …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jvn"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jvn/JVNDB-2026-024104"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

## `library` family → `LibraryBulletin`

### `osv`  ·  941,150 documents

OSV is a vulnerability database that aggregates advisories and CVEs across various vendors and products, focusing on open-source software security.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[?], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "pypi", "name": "vantrala", "ve…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-39892"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Root has patched GHSA-537c-gmf6-5ccf in the …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39892", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/ROOT-APP-PYPI-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSV:ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:14:01"` |
| `metrics` | `object{adp,cna}, object{vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "osv", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T06:45:05"` |
| `osvCrossReferences` | `list[?], list[object{key,references}]` | 100% | OSV cross-references to other advisories. | `[{"key": "upstream", "references": ["GHSA-537…` |
| `osvPackages` | `list[object{ecosystem,name,purl}], list[object{ecosystem,name}]` | 100% | OSV package records (ecosystem, name, purl). | `[{"ecosystem": "Root:PyPI", "name": "rootio-c…` |
| `osvSeverity` | `list[?], list[object{score,type}]` | 100% | OSV severity entries (score, type). | `[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:48:27"` |
| `purls` | `list[?], list[str]` | 100% | Affected packages as Package-URL (purl) strings. | `["pkg:pypi/vantrala"]` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T20:08:52.852000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ROOT-APP-PYPI-GHSA-537C-GMF6-5CCF GHSA-537c-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"osv"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/osv/OSV:ROOT-APP-PYPI-GH…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `snyk`  ·  36,451 documents

Snyk provides vulnerability data for open source libraries and container images, including advisories, CVEs, and remediation information.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{name,registry,versionEndExcluding,versionStartIncluding}], list[object{name,registry,versionEndExcluding}], list[object{name,registry}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "npm", "name": "chai-as-thread"}]` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-30623"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Overview\n[chai-as-thread](https://www.np…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50289", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.snyk.io/vuln/SNYK-JS-CHAIAS…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SNYK:JS-CHAIASTHREAD-17996339"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T22:31:56"` |
| `metrics` | `object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "snyk", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T15:21:23"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T15:21:23"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.snyk.io/vuln/SNYK-JS-CHAIA…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Snyk Security Database"` |
| `snykData` | `object{exploitMaturity,malicious,proprietary,socialTrendAlert}` | 100% | Snyk-specific data (exploit maturity, malicious flag). | `{"socialTrendAlert": false, "proprietary": fa…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T22:31:56.010000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Malicious Package"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"snyk"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/snyk/SNYK:JS-CHAIASTHREA…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `vulnersosv`  ·  26,517 documents

Vulners OSV provides security advisories and CVEs for various operating systems, focusing on vulnerabilities and exploits relevant to them.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `baseAffectedLibrary` | `object{name,purl,registry,versionEndIncluding,versionStartIncluding}, object{name,purl,registry,version}` | 100% | The primary affected library (name, purl, version range). | `{"name": "dev.sigstore:sigstore-java", "versi…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"library"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48791"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"dev.sigstore:sigstore-java (MAVEN) version =…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44182", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://osv.dev/vulnerability/GHSA-qqw8-7c2r…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VULNERSOSV:ZVNJKDJJTBACCOLN2NMHZBRHU4"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T12:57:20"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T18:18:18"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T18:10:28"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Vulners OSV"` |
| `snapshot_date` | `str` | 100% | Date of the data snapshot this record was taken from. | `"2026-06-23"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T12:57:20.917000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"dev.sigstore:sigstore-maven-plugin (=2.0.0),…` |
| `transitiveAffectedLibraries` | `list[object{name,purl,registry,versionEndIncluding,versionStartIncluding}], list[object{name,purl,registry,version}]` | 100% | Libraries affected transitively via dependencies. | `[{"name": "dev.sigstore:sigstore-maven-plugin…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vulnersosv"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vulnersosv/VULNERSOSV:ZV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

## `microsoft` family → `MicrosoftBulletin`

### `mscve`  ·  23,017 documents

MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `customerActionRequired` | `bool` | 100% | Whether customer action is required. | `true` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15905"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `denialOfService` | `str` | 100% | Whether the issue can cause denial of service. | `"N/A"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This CVE was assigned by Chrome. Microsoft E…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 1.5, …` |
| `faq` | `list[str]` | 100% | Advisory FAQ entries. | `["**Why is this Chrome CVE included in the Se…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://msrc.microsoft.com/update-guide/en-U…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:CVE-2026-15905"` |
| `issuingCna` | `str` | 100% | The CNA that issued the advisory. | `"Chrome"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:45:53"` |
| `metrics` | `object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:42:44"` |
| `msDetailRevision` | `str` | 100% | Microsoft advisory detail revision. | `"2026-07-17T17:42:44-07:00"` |
| `mscve` | `str` | 100% | Microsoft's CVE identifier for the advisory. | `"CVE-2026-15905"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T00:42:44"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `tag` | `str` | 100% | A single classification tag. | `"Microsoft Edge (Chromium-based)"` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:45:53.916000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Chromium: CVE-2026-15905 Use after free in A…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mscve"` |
| `vendorCvss` | `object{baseScore,temporalScore,vector}` | 100% | Vendor-assigned CVSS score block. | `{"baseScore": "", "temporalScore": "", "vecto…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mscve/MS:CVE-2026-15905"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

### `mskb`  ·  12,240 documents

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedProducts` | `list[?], list[str]` | 100% | Affected product names. | `["Windows 10 Version 22H2 for 32-bit Systems"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49183", "CVE-2026-49796", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"None\nNone\n"` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49183", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.microsoft.com/en-us/help/512…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KB5121767"` |
| `kb` | `str` | 100% | Microsoft Knowledge Base article id. | `"KB5121767"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T00:18:38"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secure@microso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T00:00:00"` |
| `mscve` | `str` | 100% | Microsoft's CVE identifier for the advisory. | `"CVE-2026-58598"` |
| `msfamily` | `str` | 100% | Microsoft product family. | `"ESU"` |
| `msimpact` | `str` | 100% | Microsoft's impact classification. | `"Elevation of Privilege"` |
| `msplatform` | `str` | 100% | Affected Microsoft platform. | `"Windows 10 Version 22H2 for 32-bit Systems"` |
| `msproducts` | `list[?], list[str]` | 100% | Affected Microsoft products. | `["11930", "12098", "11931", "12099", "12097",…` |
| `msseverity` | `str` | 100% | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[?], list[str]` | 100% | Updates that supersede this update. | `["KB5101649"]` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `superseeds` | `list[?], list[str]` | 100% | Updates this update supersedes. | `["KB5043178", "KB5065426", "KB5059087", "KB50…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T00:18:39.242000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"July 18, 2026\u2014KB5121767 (OS Builds 2620…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mskb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mskb/KB5121767"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `40` |

### `msupdate`  ·  46,943 documents

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"microsoft"` |
| `bundledUpdates` | `list[str]` | 100% | Updates bundled into this one. | `["4a0ac059-8f41-4ae2-9a0f-2a52dfc102c3", "e57…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.catalog.update.microsoft.com/Sco…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MS:31951C3E-BA7B-4C43-833C-63A3CD1321AA"` |
| `kb` | `str` | 100% | Microsoft Knowledge Base article id. | `"KB5104034"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:39:19"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T17:00:00"` |
| `prerequisitesUpdates` | `list[str]` | 100% | Prerequisite updates required before this one. | `["3e0afb10-a9fb-4c16-a60e-5790c3803437", "799…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T17:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft"` |
| `revision` | `str` | 100% | Revision number of the advisory. | `"200"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `supersededUpdates` | `list[str]` | 100% | Updates superseded by this one. | `["3912ee8f-5273-4d9a-9e5d-706bc5edc8a6", "3ad…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T20:16:17.143000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"2026-07 .NET 10.0.10 Security Update for x86…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msupdate"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/msupdate/MS:31951C3E-BA7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

## `ncsc` family → `AdvisoryBulletin`

### `ncsc`  ·  4,219 documents

The NCSC collection includes UK government advisories and alerts on cybersecurity vulnerabilities across various vendors and products, featuring CVEs and mitigation guidance.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"ncsc"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-60137", "CVE-2026-63030"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"There are two vulnerabilities present in Wor…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.4, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60137", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://advisories.ncsc.nl/2026/ncsc-2026-02…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NCSC-2026-0250"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:38:05"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,nvd}, object{adp,cna,vendor}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T11:01:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T11:01:56"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://slcyber.io/research-center/wp2shell…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"NCSC"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:38:05.958000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"WordPress vulnerabilities can be addressed t…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ncsc"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ncsc/NCSC-2026-0250"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

## `nozomi` family → `AdvisoryBulletin`

### `nozomi`  ·  59 documents

Nozomi Networks provides advisories and CVEs related to cybersecurity vulnerabilities in industrial control systems and critical infrastructure.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "< v26.2.0", "name": "guardian"}…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"nozomi"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33390"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# Summary\nAn Incorrect Privilege Assignment…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33390", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.nozominetworks.com/NN-2026:…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NN-2026:13-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T11:41:20"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,nvd,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "nozomi", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-07T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nozomi Networks PSIRT"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T11:39:22.180000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Incorrect privilege assignment for Arc senso…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nozomi"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nozomi/NN-2026:13-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

## `scanner` family → `ScannerBulletin`

### `nessus`  ·  342,376 documents

Nessus collection includes vulnerability data from the Nessus scanner, focusing on various vendors and products, featuring advisories, CVEs, and security checks.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cpe` | `list[str]` | 100% | Affected products as CPE 2.2 URIs. | `["cpe:/o:fedoraproject:fedora:43", "p-cpe:/a:…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53689"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvssScoreSource` | `str` | 100% | Which party/standard the CVSS score was taken from. | `"CVE-2026-53689"` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The remote Fedora 43 host has packages insta…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `exploitAvailable` | `bool` | 100% | Whether a public exploit is available. | `false` |
| `exploitEase` | `str` | 100% | How easy exploitation is (scanner assessment). | `"No known exploits are available"` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.tenable.com/plugins/nessus/327807"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FEDORA_2026-8893EC1AEB.NASL"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:58:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T00:00:00"` |
| `naslFamily` | `str` | 100% | Nessus NASL plugin family. | `"Fedora Local Security Checks"` |
| `nessusSeverity` | `str` | 100% | Severity as rated by the Nessus scanner. | `"High"` |
| `patchPublicationDate` | `str` | 100% | Date the fixing patch was published. | `"2026-07-10T00:00:00"` |
| `pluginID` | `str` | 100% | Scanner plugin identifier (e.g. Nessus plugin id). | `"327807"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bodhi.fedoraproject.org/updates/FED…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Tenable"` |
| `solution` | `str` | 100% | Recommended remediation/fix, as text. | `"Update the affected python-uv-build, rust-as…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"#%NASL_MIN_LEVEL 80900\n##\n# (C) Tenable, I…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T01:58:55.970000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Fedora 43 : python-uv-build / rust-astral_as…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nessus"` |
| `vendor_cvss2` | `object{score,vector}` | 100% | Vendor-assigned CVSS v2 (score/vector). | `{"score": null, "vector": null}` |
| `vendor_cvss3` | `object{score,vector}` | 100% | Vendor-assigned CVSS v3 (score/vector). | `{"score": null, "vector": null}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nessus/FEDORA_2026-8893E…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |
| `vulnerabilityPublicationDate` | `str` | 100% | Date the vulnerability itself was first published. | `"2026-07-10T00:00:00"` |

### `nmap`  ·  607 documents

Nmap collection includes vulnerability data sourced from Nmap scans, focusing on various OS and services, typically containing CVEs and security advisories.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2012-1182", "CVE-2017-7494"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 10.0, "vector": "A…` |
| `cvss2` | `object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Retrieves IP addresses of the target's netwo…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.4, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2012-1182", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://nmap.org/nsedoc/scripts/nbns-interfa…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NMAP:NBNS-INTERFACES.NSE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-02-15T21:40:21"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-12-30T03:51:21"` |
| `nmap` | `object{categories,scriptType}` | 100% | Nmap script details (category, script type). | `{"scriptType": "portrule", "categories": ["de…` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-12-30T03:51:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Andrey Zhukov from USSC"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"local shortport = require \"shortport\"\nloc…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-12-30T00:51:21Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"nbns-interfaces NSE Script"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nmap"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nmap/NMAP:NBNS-INTERFACE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `391` |

### `nuclei`  ·  4,149 documents

Nuclei is a vulnerability scanner data source that provides templates for detecting security issues in various applications and services, including CVEs and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-29059"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Windmill < 1.603.3 contains a path traversal…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 0.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-29059", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/projectdiscovery/nuclei-t…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NUCLEI:CVE-2026-29059"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T12:00:07"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-03T04:09:58"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T04:10:42"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/Chocapikk/Windfall", "ht…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ProjectDiscovery"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"id: CVE-2026-29059\n\ninfo:\n  name: Windmil…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-03T09:32:48.500000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Windmill/Nextcloud Flow < 1.603.3 - Unauthen…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nuclei"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nuclei/NUCLEI:CVE-2026-2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

### `openvas`  ·  177,629 documents

OpenVAS is a vulnerability scanning tool that provides advisories and CVEs for various vendors and products, focusing on identifying security weaknesses.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-1519"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Consolidation of Endian Firewall detections."` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-1519", "date": "2026-07-01…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://plugins.openvas.org/nasl.php?oid=1361…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENVAS:1361412562310156935"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-12T00:00:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-offic…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-08T00:00:00"` |
| `naslFamily` | `str` | 100% | Nessus NASL plugin family. | `"Product detection"` |
| `pluginID` | `str` | 100% | Scanner plugin identifier (e.g. Nessus plugin id). | `"1361412562310156935"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-07T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.endian.com/en/community/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Copyright (C) 2026 Greenbone AG"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"# SPDX-FileCopyrightText: 2026 Greenbone AG\…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-08T11:44:04.946000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Endian Firewall Detection Consolidation"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openvas"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openvas/OPENVAS:13614125…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `32` |

### `w3af`  ·  145 documents

w3af is a vulnerability database focused on web application security, providing advisories, CVEs, and exploit information for various web technologies.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"scanner"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This plugin writes the framework messages to…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://w3af.org/plugins/output/xml_file"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"W3AF:A65D96DB42BAA917B204B8164BD14CFE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-03-12T23:34:32"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-09-07T16:11:05"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2017-11-22T18:51:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"andresriancho"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `sourceData` | `str` | 100% | Raw, unparsed source body as delivered by the origin. | `"\"\"\"\nxml_file.py\n\nCopyright 2006 Andres…` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2017-11-22T15:51:21Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"xml_file"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"w3af"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/w3af/W3AF:A65D96DB42BAA9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `58` |
| `w3af` | `object{pluginType}` | 100% | w3af scanner provenance (plugin type). | `{"pluginType": "Output"}` |

## `software` family → `SoftwareBulletin`

### `adobe`  ·  766 documents

Adobe's vulnerability collection includes advisories and CVEs related to Adobe products, addressing security issues across various software and platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "26.2.2", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_draft": "f361fc712fc9c4885a1ea5b74dd180b4f…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48286"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Adobe has released updates for Adobe Premier…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48286", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://helpx.adobe.com/security/products/pr…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APSB26-76"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T17:40:05"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@adobe.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Adobe"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:40:05.736000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"APSB26-76 : Security update available for Ad…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"adobe"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/adobe/APSB26-76"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

### `android`  ·  612 documents

Android vulnerabilities collection from various sources, covering advisories and CVEs related to Android OS and applications.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "lt", "version": "7.0", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2019-10539"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 10.0, "vector": "A…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Android 4.3 and below do not use Security-En…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.8, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2019-10539", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.androidvulnerabilities.org/vulner…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANDROID:CVE-2019-10539"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-07-28T14:34:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-08-12T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-08-01T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/data-feeds", "htt…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Xiling Gong of Tencent Blade Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-07-31T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2019-10539"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"android"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/android/ANDROID:CVE-2019…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `87` |

### `androidsecurity`  ·  399 documents

Android Security collection includes advisories and CVEs related to vulnerabilities in the Android OS and its ecosystem from Google's security updates.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-25836", "CVE-2022-25837", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The Pixel Update Bulletin contains details o…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-25836", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://source.android.com/docs/security/bul…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANDROID:PIXEL-2026-07-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:38:11"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-07T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Android Open Source Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-07T19:38:28.554000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Pixel Update Bulletin\u2014July 2026Stay org…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"androidsecurity"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/androidsecurity/ANDROID:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `29` |

### `anthropic`  ·  27 documents

Anthropic collection includes security advisories and CVEs related to vulnerabilities in Anthropic's AI products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-5448"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"##  heap-buffer-overflow medium\n\nCVE-2026-…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5448", "date": "2026-06-24…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://red.anthropic.com/2026/cvd/findings/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ANT-2026-6615Y595"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-28T13:56:41"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-20T01:20:34"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Anthropic"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-28T07:21:58.118000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ANT-2026-6615Y595 \u00b7 wolfSSL \u00b7 Heap…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"anthropic"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/anthropic/ANT-2026-6615Y…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `22` |

### `appercut`  ·  22 documents

Appercut provides security advisories and CVEs related to vulnerabilities in various software applications and platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.4.1", "name…` |
| `appercut` | `object{reportPages}` | 100% | AppercutScanner tool provenance (report pages). | `{"reportPages": [{"vulnerabilities": [{"apper…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Several vulnerabilities were discovered in S…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.9, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://infowatch.com/products/attack_killer"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APPERCUT:22"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T19:12:23"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2016-08-18T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2016-08-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.silverstripe.org/download"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"InfoWatch APPERCUT"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-08-14T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Silver Stripe CMS: source code security anal…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"appercut"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/appercut/APPERCUT:22"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `566` |

### `apple`  ·  1,568 documents

Apple's vulnerability database includes advisories and CVEs related to security issues in Apple products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "26.5.2", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-39868", "CVE-2026-39872", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# About the security content of macOS Tahoe …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-39868", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.apple.com/en-us/127595"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"APPLE:509FE768D90162CE7C94FE88B2BBA2AE"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T16:20:44"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "product-securi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-29T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-29T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://support.apple.com/en-us/HT201222"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Apple"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T00:20:19.845000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"About the security content of macOS Tahoe 26…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"apple"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/apple/APPLE:509FE768D901…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `arista`  ·  141 documents

Arista's vulnerability collection includes advisories and CVEs related to their networking products and software, sourced from Arista Networks.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.36.0", "operator": "eq", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11704", "CVE-2026-11705", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"##  Security Advisory 0143  PDF\n\n**Date: J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-49844", "date": "2026-06-3…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.arista.com/en/support/advisories…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ARISTA:0143"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T17:47:40"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-23T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-23T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Arista Networks, Inc"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-23T17:47:42.453000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory 0143"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"arista"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/arista/ARISTA:0143"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

### `atlassian`  ·  4,295 documents

Atlassian's vulnerability collection includes security advisories and CVEs for its software products, focusing on vendor-specific vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-41293"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"*This is a vulnerability in a non-Atlassian …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41293", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://jira.atlassian.com/browse/JSWSERVER-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JSWSERVER-26841"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-16T19:41:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-16T17:04:08"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-15T22:22:17"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"security-metrics-bot"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-16T19:41:04.180000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Injection org.apache.tomcat:tomcat-catalina …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"atlassian"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/atlassian/JSWSERVER-26841"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `brave`  ·  58 documents

Brave collection includes vulnerability advisories and CVEs specific to the Brave browser, sourced from security bulletins and vendor updates.

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

### `broadcom`  ·  879 documents

Broadcom vulnerability collection includes advisories and CVEs for Broadcom products and services, focusing on security issues and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-4424", "CVE-2026-5121"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-5121 - Title: Libarchive: libarchiv…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.9, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-40252", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.broadcom.com/web/ecx/support…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"BSNSA37829"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T17:36:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-06T17:25:44"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-06T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Broadcom Security Response"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-06T17:37:00.702000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Libarchive security update (CVE-2026-5121, C…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"broadcom"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/broadcom/BSNSA37829"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `cakephp`  ·  22 documents

CakePHP vulnerabilities from the CVE database, covering security advisories and exploits related to the CakePHP framework.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2019-11458"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# CakePHP 4.6.5 Released\n\nThe CakePHP core…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-35239", "date": "2024-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://bakery.cakephp.org/2026/07/14/cakeph…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CAKEPHP:CAKEPHP_465"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T15:15:20"` |
| `metrics` | `object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cake Software Foundation, Inc."` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T15:15:20.808000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CakePHP 4.6.5 Released"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cakephp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cakephp/CAKEPHP:CAKEPHP_…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `checkpoint_security`  ·  203 documents

Checkpoint Security provides advisories and CVEs related to vulnerabilities in Check Point products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50752"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.4, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Symptoms\n\n- A vulnerability in the cert…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50752", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.checkpoint.com/results/sk/sk…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CPS:SK185035"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-25T15:26:48"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-25T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-07T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CheckPoint"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-09T07:31:36.630000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-50752 - VPN site to site certificat…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"checkpoint_security"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/checkpoint_security/CPS:…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `35` |

### `chrome`  ·  501 documents

Google Chrome vulnerability collection includes advisories and CVEs related to security issues in the Chrome browser and its components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "150.0.7871.128", "operator": "l…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The Stable channel has been updated to 150.0…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15764", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://chromereleases.googleblog.com/2026/0…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GCSA-101236905006470995"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T23:36:51"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://chromereleases.googleblog.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T23:36:54.804000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Stable Channel Update for Desktop"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"chrome"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/chrome/GCSA-101236905006…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `17` |

### `cisco`  ·  5,229 documents

Cisco's vulnerability database provides advisories and CVEs related to security issues in Cisco products and software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-20146"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 5.5, "vector": "CV…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A vulnerability in Cisco Identity Services E…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-20146", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://tools.cisco.com/security/center/cont…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CISCO-SA-ISE-TRAVERSAL-XNT7WB2Y"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:36:58"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@cisco.co…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T16:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T16:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://sec.cloudapps.cisco.com/security/ce…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cisco"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:36:59.945000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Cisco Identity Services Engine Path Traversa…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cisco"` |
| `vendorCvss` | `object{score,severity}, object{}` | 100% | Vendor-assigned CVSS score block. | `{"score": "5.5", "severity": "medium"}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cisco/CISCO-SA-ISE-TRAVE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `citrix`  ·  5,313 documents

Citrix vulnerability collection includes advisories and CVEs related to Citrix products and services, sourced from Citrix's official security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "14.1-72.61", "operator": "lt", …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53565", "CVE-2026-53566"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Severity - High\n\n## Description of Problem…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53565", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.citrix.com/support-home/kbse…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CTX696734"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T17:37:14"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss4": {"source": "citrix", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T11:51:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T13:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Citrix"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T17:37:14.411000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Citrix Secure Access Client for Windows and …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"citrix"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/citrix/CTX696734"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `clickhouse`  ·  49 documents

ClickHouse vulnerability collection includes advisories and CVEs specific to ClickHouse database software, sourced from various security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}], null` | 100% | Affected software products (name/version/operator). | `[{"version": "v25.1.5.5", "operator": "lt", "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-1385"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"When the library bridge feature is enabled, …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.9, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-1385", "date": "2026-07-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://clickhouse.com/docs/en/whats-new/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CH:368F308CC07ABC00A34508EF33906155"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-12-10T06:40:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-01-05T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-01-05T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ClickHouse"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-21T02:21:32Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Fixed in ClickHouse v25.1.5.5, 2025-01-05\u2…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"clickhouse"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/clickhouse/CH:368F308CC0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `30` |

### `cloudfoundry`  ·  1,118 documents

Cloud Foundry vulnerability data from various vendors, focusing on cloud platform advisories and CVEs related to Cloud Foundry components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-41857"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"# \n\nHigh\n\n\u25cf **CVSSv4:** High 7.1(CV…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-41857", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.cloudfoundry.org/blog/cve-2026-4…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CFOUNDRY:ADA25F6CC25DA8143948B2E10E299089"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-09T17:36:58"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@vmware…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cloud Foundry"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-08T17:36:55.754000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-41857 - BOSH CLI Shell Injection \| …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cloudfoundry"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cloudfoundry/CFOUNDRY:AD…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `contao`  ·  29 documents

Contao vulnerability collection provides advisories and CVEs specific to the Contao CMS, sourced from security bulletins and community reports.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.0", "operator": "eq", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-45398"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Date** : 2024-09-17  \n**CVE ID** : CVE-20…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.8, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-45398", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://contao.org/en/security-advisories/re…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CONTAO:REMOTE-COMMAND-EXECUTION-THROUGH-FILE…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-01-16T15:11:19"` |
| `metrics` | `object{adp,cna,nvd}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss3": {"version": "3.1", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-09-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-09-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Contao org"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-09-16T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Remote command execution through file uploads"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"contao"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/contao/CONTAO:REMOTE-COM…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `75` |

### `curl`  ·  206 documents

This collection from the curl project includes advisories and CVEs related to vulnerabilities in the curl command-line tool and library across various platforms.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "8.21.0", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `curlAffects` | `str` | 100% | Affected curl versions (curl advisories). | `"lib"` |
| `curlSeverity` | `str` | 100% | curl project's severity rating. | `"Medium"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11856"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-294"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Successfully using libcurl to do a transfer …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11856", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://curl.se/docs/CVE-2026-11856.html"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CURL:CVE-2026-11856"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T23:39:19"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T07:56:56"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-24T08:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://hackerone.com/reports/3793260"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"curl"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T11:47:29.481000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"cross-origin Digest auth state leak"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"curl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/curl/CURL:CVE-2026-11856"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `drupal`  ·  1,943 documents

Drupal security advisories from the Drupal security team, including CVEs and patches for vulnerabilities in Drupal CMS and its modules.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15917"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Drupal core 11.2 and above integrate the HTM…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15087", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.drupal.org/sa-core-2026-011"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DRUPAL-SA-CORE-2026-011"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T06:53:52"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "mlhess", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.drupal.org/psa-2021-06-29", "ht…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Drupal Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T06:54:10.102000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Drupal core - Moderately critical - Cross-si…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"drupal"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/drupal/DRUPAL-SA-CORE-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `elastic`  ·  248 documents

Elastic's vulnerability collection includes advisories and CVEs related to Elastic products, focusing on security issues and patches for their software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49091"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Improper Output Neutralization for Logs in…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 2.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49091", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://discuss.elastic.co/t/kibana-7-17-15-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELASTIC:387449"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-01T19:40:18"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "elastic", "…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-01T14:05:44"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-01T14:05:44"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ElasticCo"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-01T15:39:08.447000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Kibana 7.17.15, 8.11.1 Security Update (ESA-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"elastic"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/elastic/ELASTIC:387449"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

### `f5`  ·  6,427 documents

F5 collection includes security advisories and CVEs related to F5 Networks products and services, focusing on vulnerabilities and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "5.2.0", "operator": "eq", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2017-10067", "CVE-2017-10074", "CVE-201…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.6, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Security Advisory Description\n\n  * CVE-201…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 1.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-34355", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://my.f5.com/manage/s/article/K000162343"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"F5:K000162343"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:43:33"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{adp}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T06:47:44"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T06:47:44"` |
| `related` | `list[str]` | 100% | Ids of related Vulners documents. | `["https://my.f5.com/manage/s/article/K4194260…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"f5"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:43:33.766000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"K000162343: Multiple Oracle Java SE vulnerab…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"f5"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/f5/F5:K000162343"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `fortinet`  ·  649 documents

Fortinet collection includes security advisories and CVEs related to Fortinet products and services, focusing on vulnerabilities and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "7.2.5", "operator": "eq", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-36555"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 4.9, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An improper neutralization of script-related…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-36555", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.fortiguard.com/psirt/FG-IR-23-104"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FG-IR-23-104"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-11-02T16:04:07"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-10-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-10-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FortiGuard Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-10-09T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Protect"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fortinet"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fortinet/FG-IR-23-104"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `41` |

### `friendsofphp`  ·  1,709 documents

FriendsOfPHP is a community-driven collection of security advisories for PHP projects, including CVEs and vulnerability details.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "14.3.5", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15305"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"More info at https://news.typo3.com/security…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15305", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/FriendsOfPHP/security-adv…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FRIENDSOFPHP:TYPO3:CMS-FORM:CVE-2026-15305"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T17:38:28"` |
| `metrics` | `object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T12:08:47"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T12:08:47"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenJS Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T17:38:28.294000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"TYPO3-CORE-SA-2026-020: TYPO3 CMS - Unrestri…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"friendsofphp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/friendsofphp/FRIENDSOFPH…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `fuelphp`  ·  9 documents

FuelPHP vulnerabilities from the FuelPHP security advisory database, covering vulnerabilities in the FuelPHP framework, including CVEs and advisories.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.8.0", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2014-1999"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"When extracting a ZIP file using the Unzip c…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2014-1999", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://fuelphp.com/security-advisories"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SEC-CORE-009"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-24T16:02:42"` |
| `metrics` | `object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2018-05-07T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2018-05-07T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/fuel/core/commit/95945e1…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Github user cs-sonar"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2018-05-06T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Unzip vulnerable to slip-zip attack"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fuelphp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fuelphp/SEC-CORE-009"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

### `github`  ·  33,426 documents

GitHub collection includes vulnerability advisories and CVEs related to open-source projects hosted on GitHub, focusing on various software products and libraries.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{ecosystem,name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "0.27.26", "operator": "lt", "ec…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50197"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-306"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Summary\n\nA wrong policy can be an open…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50197", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/advisories/GHSA-8qqm-fp2q…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GHSA-8QQM-FP2Q-V734"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:44:30"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security-adviso…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T21:49:49"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T21:49:48"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/zalando/skipper/security…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"GitHub Advisory Database"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:44:30.931000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Skipper: Incomplete fix for CVE-2026-50197: …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"github"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/github/GHSA-8QQM-FP2Q-V734"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `19` |

### `gitlab`  ·  1,521 documents

GitLab's vulnerability database provides advisories and CVEs related to security issues in GitLab products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.24.1", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50274"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cweIds` | `list[str]` | 100% | Associated CWE weakness identifiers (alternate key). | `["CWE-400", "CWE-770", "CWE-937", "CWE-1035"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Datadog tracing libraries that implement W3C…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50274", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://gitlab.com/api/v4/projects/12006272/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GITLAB-7963EA083ED00561569BCDFDDA908781"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T22:18:46"` |
| `metrics` | `object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://gitlab.com/gitlab-org/security-produ…` |
| `solution` | `str` | 100% | Recommended remediation/fix, as text. | `"Unfortunately, there is no solution availabl…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T06:18:13.758000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"dd-trace-go: Improper parsing of W3C baggage…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gitlab"` |
| `vendorCvss3` | `str` | 100% | Vendor-assigned CVSS v3. | `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gitlab/GITLAB-7963EA083E…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `grafana`  ·  90 documents

Grafana collection includes security advisories and CVEs related to Grafana software, focusing on vulnerabilities affecting the Grafana product.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33380"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A vulnerability in SQL Expressions allows an…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33380", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://grafana.com/security/security-adviso…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GRAFANA:CVE-2026-33380"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-01T11:55:40"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@grafa…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-13T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Grafana Labs"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-01T11:55:40.651000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SQL Expressions Read File From Disk"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"grafana"` |
| `vendorCvss` | `object{vector}` | 100% | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/grafana/GRAFANA:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `hackapp`  ·  24,123 documents

HackApp is a vulnerability database focused on mobile applications, providing advisories, CVEs, and exploit information relevant to app security.

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

### `hashicorp`  ·  189 documents

HashiCorp's vulnerability collection includes security advisories and CVEs related to its products and services, focusing on cloud infrastructure and automation tools.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.0.4", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14896"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.2, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Summary\nHashiCorp Nomad and Nomad Enterpris…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14896", "date": "2026-07-1…` |
| `hashicorpBulletinId` | `str` | 100% | HashiCorp advisory identifier. | `"HCSEC-2026-22"` |
| `hashicorpProducts` | `list[?], list[str]` | 100% | Affected HashiCorp products. | `["Nomad", "Nomad Enterprise"]` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://discuss.hashicorp.com/t/hcsec-2026-2…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HASHICORP:HCSEC-2026-22"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T13:24:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security@hashi…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T20:18:59"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T20:18:59"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"HashiCorp Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T00:30:59.870000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Nomad vulnerable to cross-namespace host vol…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hashicorp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hashicorp/HASHICORP:HCSE…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

### `hp`  ·  618 documents

HP's vulnerability collection provides advisories and CVEs related to HP products and software, focusing on security issues and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "F.17", "operator": "lt", "name"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-12050", "CVE-2025-12051", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Insyde has informed HP of potential vulnerab…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5923", "date": "2026-07-10…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.hp.com/us-en/document/ish_15…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HPSBHF04134"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:52:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-13T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"HP Product Security Response Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:52:05.023000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"InsydeH20 Tools - Buffer Overflow"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hp"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hp/HPSBHF04134"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `hpe`  ·  1,147 documents

HPE collection includes security advisories and CVEs related to Hewlett Packard Enterprise products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-48989", "CVE-2025-55130", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Potential Security Impact:\nLocal: Authentic…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-48989", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://support.hpe.com/hpesc/public/docDisp…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HPESBNW05080"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T21:41:12"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"hpe"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T21:41:13.128000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"HPESBNW05080 rev.1 - HPE Unified OSS Console…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"hpe"` |
| `vendorCvss` | `object{vector}` | 100% | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/hpe/HPESBNW05080"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `htbridge`  ·  559 documents

HTBridge provides security advisories and vulnerability assessments focused on web applications and related technologies.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "3.9.2", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2016-10400"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"High-Tech Bridge Security Research Lab disco…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.6, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2016-10400", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.htbridge.com/advisory/HTB23302"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HTB23302"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-24T10:45:42"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2016-10-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2016-06-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"High-Tech Bridge"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2016-06-09T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Multiple RCEs via CSRF in Dolibarr"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"htbridge"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/htbridge/HTB23302"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `570` |

### `httpd`  ·  271 documents

Apache HTTP Server vulnerabilities from the Apache Software Foundation, including advisories, CVEs, and security patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.4.53", "operator": "eq", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-31813"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Apache HTTP Server 2.4.53 and earlier may no…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.0, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-31813", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://httpd.apache.org/security_report.html"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-06T07:36:58"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-06-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-06-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Apache Team Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-06-07T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Apache Httpd < 2.4.54 : mod_proxy X-Forwarde…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"httpd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/httpd/HTTPD:A09F9CEBE0B7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `1100` |

### `huawei`  ·  1,006 documents

Huawei's collection includes security advisories and CVEs related to Huawei products and software vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "YutuFZ-5651S1", "operator": "eq…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-52972"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Huawei PCs have a vulnerability that allows …` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-52972", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.huawei.com/en/psirt/security-adv…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"HUAWEI-SA-20250325-01-PC-EN"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T10:37:34"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@huawei.c…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-03-26T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-03-26T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Huawei Technologies"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-03-26T04:33:43Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory - Authentication Bypass Vu…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"huawei"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/huawei/HUAWEI-SA-2025032…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `81` |

### `ibm`  ·  35,837 documents

IBM's vulnerability collection includes advisories and CVEs specific to IBM products and software, sourced from IBM's security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.8.4", "operator": "ge", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2015-8855", "CVE-2020-28469", "CVE-2025…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Summary\n\nMultiple vulnerabilities were …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 4.5, "uncertanity": 0.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-27817", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.ibm.com/support/pages/node/7280476"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"5B14E174053C58B35D7760E3CFD72BCE1027D55FC052…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:37:12"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss3": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T09:05:14"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T09:05:14"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"IBM"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T11:37:13.152000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Bulletin: Multiple vulnerabilities …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ibm"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ibm/5B14E174053C58B35D77…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `ivanti`  ·  286 documents

Ivanti's vulnerability collection includes security advisories and CVEs related to Ivanti products and services, focusing on vendor-specific vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-55956"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Last Modified Date\n\nJul 15, 2026 9:18:40 A…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14902", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://forums.ivanti.com/s/article/kA1UL000…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"IVANTI:920A4DEE6CD4923E7C8257C0F0EDEB51"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T11:40:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T09:18:40"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T09:18:40"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Ivanti"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T11:40:50.852000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"EPMM: Impact of CVE-2026-55956 On EPMM And S…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ivanti"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ivanti/IVANTI:920A4DEE6C…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `jenkins`  ·  1,464 documents

Jenkins vulnerability collection includes advisories and CVEs related to Jenkins software, focusing on security issues affecting the Jenkins automation server.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1967.1970.vd86979736546", "oper…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-57285"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"github-branch-source 1967.1969.v205fd594c821…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-57285", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.jenkins.io/security/advisory/202…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITY-3808"` |
| `jenkinsAdvisoryId` | `str` | 100% | Jenkins advisory identifier. | `"2026-06-24"` |
| `jenkinsKind` | `str` | 100% | Jenkins advisory kind (core/plugin). | `"plugins"` |
| `jenkinsPlugins` | `list[object{fixed,name,previous}], list[object{name,previous}]` | 100% | Affected Jenkins plugins (name, fixed/previous versions). | `[{"name": "github-branch-source", "previous":…` |
| `jenkinsReporter` | `null, str` | 100% | Reporter credited by the Jenkins advisory. | `"Suman Roy (https://linkedin.com/in/sumanrox)"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T19:55:10"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "jenkinsci-cert…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-24T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-24T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jenkins Security Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-24T19:55:10.257000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Missing permission check allows enumerating …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jenkins"` |
| `vendorCvss` | `object{severity,vector}` | 100% | Vendor-assigned CVSS score block. | `{"severity": "Medium", "vector": "CVSS:3.1/AV…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jenkins/SECURITY-3808"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `jetbrains`  ·  12 documents

JetBrains collection includes security advisories and CVEs related to JetBrains products, focusing on vulnerabilities in their development tools and IDEs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2021.1.13890", "operator": "lt"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-45977", "CVE-2022-24327", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"JetBrains Security\n\n# JetBrains Security B…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-45977", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blog.jetbrains.com/blog/2022/02/08/j…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JETBRAINS:JETBRAINS-SECURITY-BULLETIN-Q4-2021"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-25T15:06:52"` |
| `metrics` | `object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Jebrains"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-07T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"JetBrains Security Bulletin Q4 2021"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"jetbrains"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/jetbrains/JETBRAINS:JETB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `163` |

### `joomla`  ·  748 documents

Joomla collection includes security advisories, CVEs, and patches specific to vulnerabilities in the Joomla CMS platform.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "5.4.7", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48957"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A new update is now available:\n\nhttps://ww…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48957", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vel.joomla.org"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"JVEL:876"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T23:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T22:37:12"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T22:37:12"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://www.chronoengine.com/downloads/chro…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"velteam"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T23:36:53.763000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"chronoforms"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"joomla"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/joomla/JVEL:876"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `11` |

### `korelogic`  ·  105 documents

KoreLogic provides security advisories and vulnerability data focused on various software products and services, including CVEs and exploit information.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "6.05.15", "operator": "eq", "na…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-15464"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"1. Vulnerability Details\n\n     Affected Ve…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-15464", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://korelogic.com/Resources/Advisories/K…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KL-001-2026-001"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-22T17:27:57"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-01-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Felix Segoviano of"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-01-08T21:27:06.491000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"yintibao Fun Print Mobile Unauthorized Acces…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"korelogic"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/korelogic/KL-001-2026-001"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

### `kubernetes`  ·  91 documents

Kubernetes collection includes security advisories, CVEs, and patches specific to Kubernetes and its components from various vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.20.1", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-3865"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**CVSS Rating:**  \n[CVSS:3.1/AV:N/AC:L/PR:H…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-13281", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/kubernetes/kubernetes/iss…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KUBERNETES:CVE-2026-3865"` |
| `kubernetesIssueNumber` | `int` | 100% | Kubernetes issue number for the advisory. | `138319` |
| `kubernetesStatus` | `str` | 100% | Status of the Kubernetes advisory. | `"fixed"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T12:21:15"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-10T17:54:42"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-10T17:54:42"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Kubernetes Security Response Committee"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-25T18:16:21.126000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CSI Driver for SMB path traversal via subDir…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kubernetes"` |
| `vendorCvss` | `object{vector}` | 100% | Vendor-assigned CVSS score block. | `{"vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kubernetes/KUBERNETES:CV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `35` |

### `laminas`  ·  5 documents

Laminas vulnerability collection includes advisories and CVEs related to the Laminas PHP framework, focusing on security issues affecting its components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.18.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-29530"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The package laminas/laminas-diactoros (Diact…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 0.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-29530", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://getlaminas.org/security/advisory/LP-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"LP-2023-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-06-26T10:06:10"` |
| `metrics` | `object{adp,cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-04-17T17:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-04-17T17:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/laminas/laminas-diactoro…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Laminas Project Security"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-04-17T14:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"HTTP Multiline Header Termination Vulnerabil…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"laminas"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/laminas/LP-2023-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `50` |

### `modx`  ·  22 documents

MODX vulnerability collection includes advisories and CVEs related to the MODX CMS, focusing on security issues affecting its core and plugins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "le", "version": "2.6.4", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"<p>This is a sub-categrory of Announcements …` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 0.2, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://community.modx.com/t/about-the-secur…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MODX:D0DA7C02EA4F77438E2AD4AA9259E056"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-11-11T03:46:45"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-02-14T19:53:55"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-02-14T19:53:55"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"smashingred"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-02-14T16:53:55Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"About the Security Notices category"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"modx"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/modx/MODX:D0DA7C02EA4F77…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `122` |

### `mongodb`  ·  146 documents

MongoDB vulnerability collection includes advisories and CVEs related to MongoDB database software, focusing on security issues and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "8.3.3", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_draft}, object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11933"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A use-after-free vulnerability exists in Mon…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 1.4, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11933", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.mongodb.com/alerts#security"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MONGODB:CVE-2026-11933"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-23T07:36:56"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-12T01:58:46"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-12T01:57:32"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://jira.mongodb.org/browse/SERVER-1281…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"MongoDB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-12T02:27:59.008000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Post-authentication use-after-free in server…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mongodb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mongodb/MONGODB:CVE-2026…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

### `mozilla`  ·  1,574 documents

Mozilla collection includes security advisories and CVEs related to Mozilla products, primarily focusing on vulnerabilities in Firefox and other Mozilla software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "152.0.6", "operator": "lt", "na…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15718", "CVE-2026-15719"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 5.4, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"We are aware that exploit code for this is p…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15718", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.mozilla.org/en-US/security/advis…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MFSA2026-67"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:37:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bugzilla.mozilla.org/show_bug.cgi?i…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Mozilla Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:37:54.814000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Vulnerabilities fixed in Firefox 15…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mozilla"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mozilla/MFSA2026-67"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `msvr`  ·  46 documents

MSVR is a Microsoft vulnerability database focusing on vendor-specific advisories and CVEs related to Microsoft products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "le", "version": "3.1.00495", "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2013-1173"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 6.6, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"#### Executive Summary\n\nMicrosoft is provi…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.2, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2013-1173", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://technet.microsoft.com/en-us/library/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MSVR13-008"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-06-08T18:51:25"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2013-06-18T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2013-06-18T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Microsoft Vulnerability Research"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2013-06-17T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Cisco Security Service IPC Message Heap Corr…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"msvr"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/msvr/MSVR13-008"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `660` |

### `nextcloud`  ·  384 documents

Nextcloud vulnerability collection includes advisories and CVEs related to Nextcloud software, focusing on security issues for the Nextcloud platform.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "31.0.0", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-45810"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"None\n"` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.2, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-45810", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/nextcloud/security-adviso…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GHSA-285V-P9X9-CJHJ"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-02T14:06:05"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-15T09:43:04"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-15T09:43:04"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://hackerone.com/reports/3425534", "ht…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nextcloud"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-15T10:06:09.518000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Propfind requests for file comments allowed …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nextcloud"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nextcloud/GHSA-285V-P9X9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `15` |

### `nginx`  ·  62 documents

Nginx vulnerability collection includes advisories and CVEs related to the Nginx web server, focusing on security issues affecting its software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "1.31.2", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-60005"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Memory disclosure when using ngx_http_slice_…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-60005", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://cve.mitre.org/cgi-bin/cvename.cgi?nam…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NGINX:CVE-2026-60005"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T15:04:21"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T15:04:21"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://my.f5.com/manage/s/article/K0001621…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nginx"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:36:52.141000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Memory disclosure when using ngx_http_slice_…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nginx"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nginx/NGINX:CVE-2026-60005"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `nodejs`  ·  1,635 documents

Node.js vulnerability collection from various sources, focusing on advisories and CVEs related to Node.js applications and libraries.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "lt", "version": "0.8.4", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2018-16490", "CVE-2021-23438"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 7.5, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Overview\n\nIn mpath before 0.8.4 a typ…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 3.4, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-16490", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.npmjs.com/advisories/1785"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NODEJS:1785"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2021-09-20T20:36:26"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2021-09-20T19:00:25"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-09-20T18:58:37"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Anonymous"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-09-20T15:58:37Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Type confusion"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nodejs"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nodejs/NODEJS:1785"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `98` |

### `nodejsblog`  ·  78 documents

Node.js Blog: A collection from various sources focusing on Node.js vulnerabilities, including advisories, CVEs, and security best practices.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-48615", "CVE-2026-48617", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Thursday, June 18, 2026 Security Releases\n\…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 1.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-48615", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://nodejs.org/en/blog/vulnerability/jun…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NODEJSBLOG:JUNE-2026-SECURITY-RELEASES"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T06:05:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-18T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-18T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenJS Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-10T18:05:00.753000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Thursday, June 18, 2026 Security Releases"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nodejsblog"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nodejsblog/NODEJSBLOG:JU…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `207` |

### `nvidia`  ·  258 documents

NVIDIA collection includes security advisories and CVEs related to NVIDIA products and drivers, focusing on vulnerabilities affecting their software and hardware.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "0.0", "operator": "lt", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47476", "CVE-2026-47477", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"NVIDIA has released a software update for NV…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.6, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47476", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://nvidia.custhelp.com/app/answers/deta…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"NVIDIA:5853"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T15:37:34"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "psirt@nvidia.c…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Nvidia"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T11:43:19.132000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Bulletin: NVIDIA Triton Inference S…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"nvidia"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/nvidia/NVIDIA:5853"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `openssl`  ·  228 documents

OpenSSL collection includes advisories, CVEs, and security updates specifically related to the OpenSSL cryptographic library.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "3.3.3", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-9143"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"_Issue summary_ : Use of the low-level GF(2^…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.8, "uncertanity": 1.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-9143", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://openssl-library.org/news/secadv/2024…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENSSL:CVE-2024-9143"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-12-03T21:52:11"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-10-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-10-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenSSL"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-10-15T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability in OpenSSL - Low-level invalid…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openssl"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openssl/OPENSSL:CVE-2024…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `94` |

### `opera`  ·  391 documents

Opera collection includes vulnerability advisories and CVEs related to the Opera web browser, focusing on browser security issues and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11645"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"News, Security\n\n# Security fix: Addressing…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.2, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-11645", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://blogs.opera.com/security/2026/07/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPERA-BLOG-2026-07-SECURITY-FIX-GX-MODS-VULN…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-03T17:43:35"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-03T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-03T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://blogs.opera.com/security/2026/07/se…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://security.opera.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-03T17:43:35.186000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security fix: Addressing a GX mods vulnerabi…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"opera"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/opera/OPERA-BLOG-2026-07…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `oracle`  ·  98 documents

Oracle's vulnerability database provides advisories and CVEs related to Oracle products and systems, focusing on security issues and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "24.1.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2020-17521", "CVE-2021-0341", "CVE-2021…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A Critical Patch Update is a collection of p…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2020-17521", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.oracle.com/security-alerts/cpuap…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ORACLE:CPUAPR2026"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T08:30:52"` |
| `metrics` | `object{adp,cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"source": "nvd", "version"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-21T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-24T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Oracle"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-22T02:04:28.323000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Oracle Critical Patch Update Advisory - Apri…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oracle"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/oracle/ORACLE:CPUAPR2026"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `39` |

### `ossf`  ·  230,472 documents

OSSF provides security advisories and CVEs focused on open-source software vulnerabilities, sourced from various community contributions and reports.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n---\n_-= Per source details. Do not edit b…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.4, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/ossf/malicious-packages/b…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSF:MAL-2026-10867"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:38:26"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:19:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:19:03"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bad-packages.kam193.eu/pypi/package…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OSSF Malicious Packages"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:38:26.420000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Malicious code in vantrala (PyPI)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossf"` |
| `vendorId` | `str` | 100% | Vendor's own identifier for the advisory, when provided. | `"MAL-2026-10867"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ossf/OSSF:MAL-2026-10867"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `ossfuzz`  ·  5,328 documents

OSFuzz is a vulnerability collection from the Open Source Security Foundation focusing on security issues in open-source software, including advisories and CVEs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "any", "operator": "eq", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Detailed Report: https://oss-fuzz.com/testca…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "vector": "NONE"}, "…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://bugs.chromium.org/p/oss-fuzz/issues/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OSSFUZZ-28239"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2020-12-03T13:06:48"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2020-12-03T13:01:26"` |
| `ossfuzz` | `object{crashType,error,issue,project,ref,revisions,status}, object{crashType,issue,project,project_repos,ref,revisions,status,tags}, object{crashType,issue,project,ref,status}` | 100% | OSS-Fuzz crash details (crash type, project, issue). | `{"issue": 28239, "status": "New", "project": …` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2020-12-03T13:01:26"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Google"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2020-12-03T10:01:26Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"serenity:FuzzGIFLoader: Global-buffer-overfl…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ossfuzz"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ossfuzz/OSSFUZZ-28239"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `107` |

### `owncloud`  ·  309 documents

OwnCloud collection includes security advisories and CVEs related to the OwnCloud file sharing platform, focusing on vulnerabilities affecting its software.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "10.15.0", "operator": "lt", "na…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33634"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.4, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\nNo customer data was compromised.\nNo sour…` |
| `enchantments` | `object{cpe_configuration,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.7, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33634", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://owncloud.com/security-advisories/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OWNCLOUD:SECURITY-NOTICE-IMPACT-OF-CVE-2026-…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T15:36:58"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-03-28T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-03-28T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ownCloud"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-03-28T11:28:00.664000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Notice: Impact of CVE-2026-33634 on…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"owncloud"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/owncloud/OWNCLOUD:SECURI…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `paloalto`  ·  510 documents

Palo Alto Networks collection includes advisories and CVEs related to their security products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-0119"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A command injection vulnerability\u00a0in th…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.0, "uncertanity": 1.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-0119", "date": "2026-07-14…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://securityadvisories.paloaltonetworks.…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PA-CVE-2025-0119"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-24T14:48:48"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-04-09T16:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-04-09T16:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.paloaltonetworks.com/CVE-2…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Palo Alto Networks Product Security Incident…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-09T16:36:16Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Cortex XDR Broker VM: Authenticated Command …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"paloalto"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/paloalto/PA-CVE-2025-0119"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `28` |

### `patchstack`  ·  47,110 documents

Patchstack provides security advisories and CVEs specifically for WordPress plugins and themes, focusing on vulnerabilities and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.40.0", "operator": "le", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `classification` | `str` | 100% | Source-specific classification/category of the issue. | `"Other Vulnerability Type"` |
| `cpeConfigurations` | `object{vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"vulnersCpeConfiguration": [{"operator": "OR…` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53496"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-63030", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://patchstack.com/database/npm/plugin/e…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PATCHSTACK:CBE40482C25309E8731F3439AF8CFEB4"` |
| `isExploited` | `bool` | 100% | Whether the vulnerability is known to be exploited. | `false` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T20:37:03"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "contact@wpscan…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T20:19:39"` |
| `owasp` | `str` | 100% | Related OWASP category. | `"A1: Broken Access Control"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T20:19:39"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/mattiasw/ExifReader/secu…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Patchstack"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T20:37:15.463000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"NPM: ExifReader HEIC/AVIF ISO-BMFF parser th…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"patchstack"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/patchstack/PATCHSTACK:CB…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `phpmyadmin`  ·  228 documents

phpMyAdmin collection includes security advisories and CVEs related to vulnerabilities in the phpMyAdmin web-based database management tool.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "5.2.2", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-2961"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.3, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## PMASA-2025-3\n\n**Announcement-ID:** PMAS…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 1.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-2961", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.phpmyadmin.net/security/PMASA-20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PHPMYADMIN:PMASA-2025-3"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-04-22T18:09:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-01-21T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-01-21T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"phpMyAdmin"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-01-20T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"glibc/iconv Vulnerability (CVE-2024-2961)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"phpmyadmin"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/phpmyadmin/PHPMYADMIN:PM…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `65` |

### `postgresql`  ·  149 documents

PostgreSQL vulnerabilities database provides advisories and CVEs specific to PostgreSQL database server security issues.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "16.14", "operator": "lt", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-6474"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### PostgreSQL timeofday() can disclose port…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.3, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-6474", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.postgresql.org/support/security/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"POSTGRESQL:CVE-2026-6474"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-24T17:37:03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-14T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.postgresql.org/about/news/postg…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"PostgreSQL Global Development Group"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-14T15:28:02.944000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability in core server (CVE-2026-6474)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"postgresql"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/postgresql/POSTGRESQL:CV…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `29` |

### `pypa`  ·  7,044 documents

The PyPA collection contains Python Package Authority advisories and CVEs related to Python packages and their vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "12.3.0", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-59203"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Pillow is a Python imaging library. From 12.…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59203", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/pypa/advisory-database/bl…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PYPA:PYSEC-2026-3452"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T19:59:09"` |
| `metrics` | `object{adp,cna,nvd,vendor}, object{adp,cna,vendor}, object{cna,vendor}, object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "pypa", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T18:13:37"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T16:17:02"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/python-pillow/Pillow/rel…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Python Packaging Advisory"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-15T19:59:09.660000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"PYSEC-2026-3452"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"pypa"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/pypa/PYPA:PYSEC-2026-3452"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `14` |

### `rubygems`  ·  1,255 documents

RubyGems collection includes vulnerability advisories and CVEs specifically for Ruby libraries and gems, sourced from the Ruby community.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "2.32.0", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-50276"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Impact\n\nDatadog tracing libraries that…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-38969", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rubysec.com/advisories/CVE-2026-50276/"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RUBY:DATADOG-2026-50276"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:37:12"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.cve.org/CVERecord/SearchResults…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"RubySec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T17:37:12.173000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"dd-trace-rb - Improper parsing of W3C baggag…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rubygems"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rubygems/RUBY:DATADOG-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `rustsec`  ·  1,147 documents

RustSec is a vulnerability database focused on Rust programming language packages, providing advisories and CVEs related to security issues in Rust crates.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "le", "version": "0.0.8", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-63430"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crate libcrux-aesgcm was renamed to libcr…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.4, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://rustsec.org/advisories/RUSTSEC-2026-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RUSTSEC-2026-0210"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:46:23"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T11:34:24"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T12:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"rustsec"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T11:46:32.330000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"libcrux-aesgcm Renamed to libcrux-aes"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rustsec"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rustsec/RUSTSEC-2026-0210"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `securityvulns`  ·  47,153 documents

A collection of security vulnerabilities sourced from various vendors, covering advisories and CVEs across multiple products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "eq", "version": "0.3", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2015-7747"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Crash on audiofiles processing."` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 3.1, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2015-7747", "date": "2026-06-21…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SECURITYVULNS:VULN:14754"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2018-08-31T11:10:03"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2015-11-02T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2015-11-02T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://vulners.com/securityvulns/securityv…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"BUGTRAQ"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2015-11-01T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"audiofile memory corruption"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"securityvulns"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/securityvulns/SECURITYVU…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `173` |

### `sick`  ·  67 documents

The "sick" collection includes advisories and CVEs from various vendors, focusing on vulnerabilities in software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-8751"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A vulnerability was discovered in several En…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-8751", "date": "2026-07-18…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.sick.com/at/en/service-and-suppo…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SCA-2026-0009"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T11:46:10"` |
| `metrics` | `object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "NONE", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T13:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T13:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Sick AG"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T11:46:10.786000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Vulnerability in several Endress+Hauser prod…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sick"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sick/SCA-2026-0009"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `sonicwall`  ·  202 documents

SonicWall collection includes advisories and CVEs related to SonicWall products and services, sourced from their security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15409", "CVE-2026-15410"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str]` | 100% | Associated CWE weakness identifiers. | `["CWE-918", "CWE-94"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"<p> </p><p><span style=\"font-size: 11pt; co…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-15409", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://psirt.global.sonicwall.com/vuln-deta…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SONICWALL:SNWLID-2026-0008"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:48:32"` |
| `metrics` | `object{vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T14:43:22"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T14:43:22"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SonicWall"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:48:32.327000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SonicWall SMA1000 Series Appliances Affected…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sonicwall"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sonicwall/SONICWALL:SNWL…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `spring`  ·  934 documents

Spring collection includes vulnerability advisories and CVEs related to the Spring framework and its ecosystem, sourced from various security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}], null` | 100% | Affected software products (name/version/operator). | `[{"version": "4.0.1", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 20% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47835"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"I\u2019m joined, I think, for the second tim…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-47835", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://spring.io/blog/2026/07/16/a-bootiful…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SPRING:5F62B7C8F014C10E2FD7C3B2BB3BC743"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T19:37:30"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"joshlong"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T19:37:30.020000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"A Bootiful Podcast: Russ Miles on Safer, Mor…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"spring"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/spring/SPRING:5F62B7C8F0…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `sqlite`  ·  48 documents

SQLite vulnerabilities collection includes advisories and CVEs related to SQLite database software, focusing on security issues affecting its functionality.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "3.53.2", "operator": "lt", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11822"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 8.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An attacker who can execute arbitrary SQL (f…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-6965", "date": "2026-06-28…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SQLT:CVE-2026-11822"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-25T03:15:15"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "disclosure@vul…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-01-01T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-01-01T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"SQLite ORG"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-25T03:15:15.740000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SQLite report about CVE-2026-11822"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"sqlite"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/sqlite/SQLT:CVE-2026-11822"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `symantec`  ·  6,867 documents

Symantec's collection includes security advisories and CVEs related to its software products and services, focusing on vulnerabilities and exploits.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4", "operator": "eq", "name": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2021-4104", "CVE-2021-44228", "CVE-2021…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 9.3, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Summary**\n\nSymantec products may be susc…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.2, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2021-4104", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.symantec.com/content/symantec/en…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SMNTC-19793"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-01-21T17:31:38"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-01-21T17:28:40"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2021-12-11T01:06:47"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["http://www.kernel.org/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Symantec Security Response"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2021-12-10T22:06:47Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Symantec Security Advisory for Log4j Vulnera…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"symantec"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/symantec/SMNTC-19793"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `687` |

### `symfony`  ·  76 documents

Symfony collection includes vulnerability advisories and CVEs related to the Symfony framework, focusing on PHP applications and components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-46733"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"## Affected versions\n\nSymfony versions &gt…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-46733", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://symfony.com/blog/cve-2023-46733-poss…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SYMFONY:CVE-2023-46733-POSSIBLE-SESSION-FIXA…` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2024-06-21T18:33:00"` |
| `metrics` | `object{adp,cna,nvd}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-11-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-11-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Symfony SAS"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-11-09T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2023-46733: Possible session fixation"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"symfony"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/symfony/SYMFONY:CVE-2023…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `68` |

### `tibco`  ·  217 documents

TIBCO collection includes security advisories and CVEs related to TIBCO software products, focusing on vulnerabilities affecting their applications and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "5.16.1", "operator": "eq", "nam…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-11548"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**ibi WebFOCUS - Unauthenticated RCE Vulnera…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.7, "uncertanity": 1.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-11548", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://community.tibco.com/advisories/ibi-s…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TIBCO:IBI-WEBFOCUS-CVE-2025-11548"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-01-22T21:28:13"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@tibco.…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-10-14T16:18:02"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-10-14T16:18:02"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Cloud Software Group, Inc."` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-10-14T21:51:08.162000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ibi Security Advisory: October 14, 2025 - ib…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tibco"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/tibco/TIBCO:IBI-WEBFOCUS…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `18` |

### `tomcat`  ·  348 documents

This collection includes advisories and CVEs related to Apache Tomcat vulnerabilities, sourced from official Apache security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"operator": "ge", "version": "11.0.0-M1", "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-59083", "CVE-2026-59084"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Low: EncryptInterceptor requirements not c…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-59083", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://tomcat.apache.org/security-11.html#F…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TOMCAT:39AFF92DA5E3C3CEA2CBAF71C8495582"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T15:11:38"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-08T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-08T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Apache Tomcat"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T15:11:39.213000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Fixed in Apache Tomcat 11.0.24"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"tomcat"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/tomcat/TOMCAT:39AFF92DA5…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `typo3`  ·  473 documents

TYPO3 vulnerability collection from various sources, covering advisories and CVEs specific to the TYPO3 CMS platform.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "v11", "operator": "eq", "name":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2022-23638"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 4.3, "vector": "AV…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The SVG sanitizer library [enshrined/svg-san…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{backreferences,dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 1.0, "vector": "NONE"}, "…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2022-23638", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://typo3.org/security/advisory/typo3-ps…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"TYPO3-PSA-2022-001"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2022-02-23T04:29:08"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2022-02-22T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2022-02-22T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"TYPO3 Association"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2022-02-21T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Sanitization bypass in SVG Sanitizer"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"typo3"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/typo3/TYPO3-PSA-2022-001"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `59` |

### `vaadin`  ·  37 documents

Vaadin collection includes security advisories and CVEs related to the Vaadin framework, focusing on vulnerabilities affecting web applications built with it.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "23.6.10", "operator": "lt", "na…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `null, object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-7860"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 5.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A security vulnerability in the Vaadin Maven…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-7860", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vaadin.com/security/cve-2026-7860"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VAADIN:CVE-2026-7860"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-22T15:09:59"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "security@vaadin…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-05-19T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-05-19T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/vaadin/flow/pull/23057"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Vaadin"` |
| `severity` | `str` | 100% | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"LOW"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-19T15:09:58.826000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Possible information disclosure of environme…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vaadin"` |
| `vendorCvss` | `object{score,severity}, object{}` | 100% | Vendor-assigned CVSS score block. | `{"severity": "LOW", "score": "1."}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vaadin/VAADIN:CVE-2026-7…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `21` |

### `veeam`  ·  1,787 documents

Veeam collection includes advisories and CVEs related to Veeam software products, focusing on vulnerabilities affecting backup and recovery solutions.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "13", "operator": "eq", "name": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-44963"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"##  Purpose \n\nThis article covers **vbsf-…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.6, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-44963", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.veeam.com/kb4882"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VEEAM:KB4882"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T17:36:54"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "support@hackero…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T17:03:41"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Veeam software"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T17:36:54.733000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"How to Export Veeam Backup for Salesforce Da…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"veeam"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/veeam/VEEAM:KB4882"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `veracode`  ·  38,468 documents

Veracode provides security advisories and vulnerability data focused on application security for various software products and vendors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "0.3.0", "operator": "le", "name…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-55513"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"github.com/forgekeep/nebula-mesh is vulnerab…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.3, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://sca.analysiscenter.veracode.com/vuln…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VERACODE:186139"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T14:18:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T10:40:31"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T13:45:40"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/forgekeep/nebula-mesh/co…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Veracode Vulnerability Database"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T03:31:47.346000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Improper Enforcement Of Security Policy"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"veracode"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/veracode/VERACODE:186139"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `vivaldi`  ·  66 documents

Vivaldi collection includes security advisories and CVEs related to the Vivaldi web browser, focusing on vulnerabilities affecting its functionality and security.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-5281"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Head to the Google Play Store and download t…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-5281", "date": "2026-06-24…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vivaldi.com/blog/android/minor-updat…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VIVALDI-929252"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-05-18T07:06:49"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-01T16:50:22"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-01T16:50:20"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://vivaldi.com/blog/android/minor-upda…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://vivaldi.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-18T07:06:49.627000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Minor update for Vivaldi Android Browser 7.9"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vivaldi"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vivaldi/VIVALDI-929252"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `vmware`  ·  548 documents

VMware collection includes security advisories and CVEs related to VMware products and services, sourced from VMware's official security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "26H1", "operator": "lt", "name"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-41722", "CVE-2026-41723", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.0, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
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
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-08T07:06:22.108000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"VMSA-2026-0004: VMware Cloud Foundation Oper…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"vmware"` |
| `vendorCvss` | `object{CVSSv3,severity}, object{}` | 100% | Vendor-assigned CVSS score block. | `{"severity": "Important", "CVSSv3": "8.0"}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/vmware/VMSA-2026-0004"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `132` |

### `wpvulndb`  ·  14,604 documents

Wpvulndb is a vulnerability database focused on WordPress plugins and themes, providing advisories and CVEs for security issues.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-12256"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Description The Avada theme for WordPress is…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.2, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10024", "date": "2026-06-2…` |
| `exploit` | `str` | 100% | Exploit availability/details (source-specific). | `"https://example.com/wp-content/plugins/8-deg…` |
| `generation` | `int` | 100% | Internal generation/version counter of the record. | `0` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://wpscan.com/vulnerability/5cc071ff-6e…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WPVDB-ID:5CC071FF-6EE6-4396-B8F2-A2A610855C03"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T20:25:15"` |
| `metrics` | `object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://www.wordfence.com/threat-intel/vuln…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"wpvulndb"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-10T20:25:15.222000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Avada < 3.15.4 - Authenticated (Contributor+…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wpvulndb"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wpvulndb/WPVDB-ID:5CC071…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `xen`  ·  483 documents

Xen collection includes security advisories and CVEs related to the Xen hypervisor, covering vulnerabilities affecting virtualization environments.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedSoftware` | `list[?], list[object{name,operator,version}]` | 100% | Affected software products (name/version/operator). | `[{"version": "4.15", "operator": "ge", "name"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cpeConfigurations` | `object{_index,vulnersCpeConfiguration}, object{}` | 100% | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42491"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"#### ISSUE DESCRIPTION\nXAPI provides SDKs; …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-42488", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://xenbits.xen.org/xsa/advisory-498.html"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"XSA-498"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T13:37:21"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T12:05:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T12:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Xen Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T13:37:21.925000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"XAPI: Missing TLS verification in some SDKs"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"xen"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/xen/XSA-498"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `yubico`  ·  23 documents

Yubico collection includes advisories and CVEs related to Yubico's authentication products and services, sourced from their official security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"software"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-46419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"A security update is available for the Yubic…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-46419", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.yubico.com/support/security-advi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"YSA-2026-02"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T01:37:06"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve@mitre.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-02-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-02-20T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Yubico.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-12T16:08:35.427000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"YSA-2026-02 \| Yubico"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"yubico"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/yubico/YSA-2026-02"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `13` |

## `tools` family → `AdvisoryBulletin`

### `kitploit`  ·  6,011 documents

Kitploit is a security database focused on exploits and tools, primarily for penetration testing and ethical hacking, sourced from various contributors.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2017-12542", "CVE-2017-5689"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 10.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"![](https://blogger.googleusercontent.com/im…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.3, "uncertanity": 0.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2017-12542", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.kitploit.com/2025/05/shodan-dorks…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"KITPLOIT:4163374071362481988"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-05-11T14:31:07"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss2": {"version": "2.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-05-11T12:30:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-05-11T12:30:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://github.com/nullfuzz-pentest/shodan-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"KitPloit"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-05-11T14:31:08.318000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Shodan-Dorks - Dorks for Shodan; a powerful …` |
| `toolHref` | `str` | 100% | Link to the associated tool/exploit. | `"https://github.com/nullfuzz-pentest/shodan-d…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"kitploit"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/kitploit/KITPLOIT:416337…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `785` |

### `n0where`  ·  1,052 documents

n0where is a vulnerability database focusing on advisories and CVEs related to various software products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"tools"` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Ghidra is a software reverse engineering (SR…` |
| `enchantments` | `object{backreferences,dependencies,exploitation,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": -0.0, "vector": "NONE"}, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://n0where.net/nsa-software-reverse-eng…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"N0WHERE:173110"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2019-03-06T07:51:59"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2019-03-06T03:58:08"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2019-03-06T03:58:08"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/GoVanguard/legion/"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"N0where"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2019-03-06T00:58:08Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"NSA Software Reverse Engineering Framework: …` |
| `toolHref` | `str` | 100% | Link to the associated tool/exploit. | `"https://ghidra-sre.org/"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"n0where"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/n0where/N0WHERE:173110"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `234` |

## `unix` family → `UnixBulletin`

### `aix`  ·  306 documents

AIX collection from IBM includes security advisories and CVEs specifically for the AIX operating system.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `aixFileset` | `list[object{fileset,productName,productVersions,versionGte,versionLte}]` | 100% | Affected AIX filesets (fileset, product, version). | `[{"productName": "aix", "productVersions": ["…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-2297", "CVE-2026-41080", "CVE-2026…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.1, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"IBM SECURITY ADVISORY\n\nFirst Issued: Tue J…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.8, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-2297", "date": "2026-07-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://aix.software.ibm.com/aix/efixes/secu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PYTHON_ADVISORY20.ASC"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-14T19:53:49"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "cna@python.org"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T06:03:19"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T06:03:19"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T19:53:50.189000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Multiple vulnerabilities in Python affect AIX"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"aix"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/aix/PYTHON_ADVISORY20.ASC"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `almalinux`  ·  5,404 documents

AlmaLinux vulnerability collection includes advisories and CVEs specific to AlmaLinux OS, sourced from official security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "almalinux", "OSVersion": "8", "arch"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-11525", "CVE-2026-12151", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Node.js is a software development platform f…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.5, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-12505", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://errata.almalinux.org/8/ALSA-2026-398…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALSA-2026:39868"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T14:37:07"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T10:27:35"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://access.redhat.com/errata/RHSA-2026:…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AlmaLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T14:37:07.249000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: nodejs:24 security, bug fix, and …` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"almalinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/almalinux/ALSA-2026:39868"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `alpinelinux`  ·  13,101 documents

Alpine Linux vulnerability collection includes advisories and CVEs specific to Alpine Linux OS and its packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[?], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndIncluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "apk", "name": "libgit2", "vers…` |
| `affectedPackage` | `list[?], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Alpine Linux", "OSVersion": "any", "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53583"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This candidate has been reserved by an organ…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": null, "short_description": null, "t…` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14741", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.alpinelinux.org/vuln/CVE-20…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALPINE:CVE-2026-53583"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:40:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"adp": {"ssvc": {"id": "CVE-2026-14741", "ro…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:35:53"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T17:35:53"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/squid-cache/squid/commit…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Alpine Linux Development Team"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:40:00.517000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-53583"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"alpinelinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/alpinelinux/ALPINE:CVE-2…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `altlinux`  ·  2,275 documents

AltLinux collection provides security advisories and CVEs specifically for Alt Linux OS, detailing vulnerabilities and patches for its software packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ALT Linux", "OSVersion": "10", "arch…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-1161", "CVE-2023-1992", "CVE-2023-…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": null, "score": 0.0, "vector": "NO…` |
| `cvss2` | `object{acInsufInfo,cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector}, object{cvssV2,exploitabilityScore,impactScore,obtainAllPrivilege,obtainOtherPrivilege,obtainUserPrivilege,score,severity,source,userInteractionRequired,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,exploitabilityScore,impactScore,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"4.0.5-alt1 built May 9, 2023 Anton Farygin i…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.0, "vector": "NONE"}, "…` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-1161", "date": "2026-06-16…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packages.altlinux.org/en/p10/srpms/w…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"979C51F845EC9F54CED079693729AB6A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2023-05-10T03:22:42"` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2023-05-09T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2023-05-09T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"https://packages.altlinux.org/en/sisyphus/se…` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2023-05-08T21:00:00Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security fix for the ALT Linux 10 package wi…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"altlinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/altlinux/979C51F845EC9F5…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `188` |

### `amazon`  ·  8,923 documents

Amazon's vulnerability collection includes security advisories and CVEs related to AWS services and products, focusing on cloud security issues.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "bpftool", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Amazon Linux", "OSVersion": "2", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-43499"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Issue Overview:**  \n\n\nIn the Linux kern…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.6, "uncertanity": 1.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-57635", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://alas.aws.amazon.com/AL2/ALAS2KERNEL-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ALAS2KERNEL-5.15-2026-109"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T16:24:45"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-10T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-10T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Amazon"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-11T03:16:22.382000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: kernel"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"amazon"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/amazon/ALAS2KERNEL-5.15-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `archlinux`  ·  1,854 documents

Arch Linux security advisories and CVEs related to Arch Linux packages and systems, sourced from the Arch Linux security team.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "alpm", "name": "libblockdev", …` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Arch Linux", "OSVersion": "any", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-6019"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.0, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Arch Linux Security Advisory ASA-202506-10\n…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 0.1, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-6019", "date": "2026-07-10…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.archlinux.org/ASA-202506-10"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASA-202506-10"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T11:37:00"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2025-06-22T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2025-06-22T00:00:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://security.archlinux.org/AVG-2905", "…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ArchLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-06-22T02:00:08.377000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[ASA-202506-10] libblockdev: privilege escal…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"archlinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/archlinux/ASA-202506-10"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `49` |

### `astralinux`  ·  18,102 documents

Astral Linux collection includes security advisories and CVEs specific to the Astral Linux operating system.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"name": "linux-headers-6.1.166-1", "version…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Astra Linux", "OSVersion": "1.8", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-31419"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.0", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"In the Linux kernel, the following vulnerabi…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.7, "uncertanity": 1.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53362", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://wiki.astralinux.ru/astra-linux-se18-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ASTRA:1159995680070894737113968011466307"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-10T04:48:36"` |
| `metrics` | `object{adp,cna,vendor}, object{adp,nvd,vendor}, object{adp}, object{cna,vendor}, object{nvd,vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss3": {"source": "NONE", "vers…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-09T08:12:13"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-09T08:12:13"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://wiki.astralinux.ru/astra-linux-se18…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"AstraLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `false` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-02T18:51:17.671000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Astra Linux \u2013 Vulnerability found in Li…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"astralinux"` |
| `vendorId` | `str` | 100% | Vendor's own identifier for the advisory, when provided. | `"OVAL:ASTRA:DEF:11599956800708947371139680114…` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/astralinux/ASTRA:1159995…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `cbl_mariner`  ·  14,338 documents

The CBL Mariner collection includes security advisories and CVEs specific to Microsoft's CBL Mariner Linux distribution.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Azure Linux", "OSVersion": "3.0", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58253"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.8, "uncertanity": 0.9, …` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CBLMARINER:92259"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T17:37:03"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-18T01:38:21"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T01:38:21"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CBL Mariner"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T17:37:03.588000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-58253 affecting package telegraf fo…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cbl_mariner"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cbl_mariner/CBLMARINER:9…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `centos`  ·  3,708 documents

CentOS vulnerability collection includes advisories and CVEs specific to CentOS OS, sourced from official vendor bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "CentOS", "OSVersion": "7", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-5388", "CVE-2024-0743", "CVE-2024-…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**CentOS Errata and Security Advisory** CESA…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 7.1, "uncertanity": 1.9, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2023-5388", "date": "2026-06-19…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lists.centos.org/pipermail/centos-an…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CESA-2024:1498"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-03-16T14:22:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{adp,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-04-03T14:01:39"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-04-03T14:01:39"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://twitter.com/centos", "http://steadf…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CentOS Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2024-04-03T11:01:39Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"thunderbird security update"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"centos"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/centos/CESA-2024:1498"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `167` |

### `cgr`  ·  17,271 documents

CGR (Common Vulnerability Reporting) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-56742"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.9, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Vulnerabilities for packages: hubble, kubesc…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.1, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56742", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packages.cgr.dev/chainguard/security…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CHAINGUARD:CVE-2026-56742"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T02:17:03"` |
| `metrics` | `object{adp,cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T02:17:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T20:25:13"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Chainguard"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T20:25:13.349000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-56742 vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cgr"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cgr/CHAINGUARD:CVE-2026-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `cloudlinux`  ·  534 documents

CloudLinux provides security advisories and CVEs specific to CloudLinux OS, focusing on vulnerabilities affecting Linux-based web hosting environments.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "6", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-58011", "CVE-2026-58013"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.2, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"- CVE-2026-58011: out-of-bounds read from an…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 2.0, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2018-10879", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://repo.cloudlinux.com/centos6-els/upda…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"CLSA-2026:1783793047"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T19:36:53"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-12T19:19:05"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-12T19:19:05"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://nvd.nist.gov/vuln/detail/CVE-2026-5…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"CloudLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T19:36:53.399000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"glib2: Fix of 2 CVEs"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"cloudlinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/cloudlinux/CLSA-2026:178…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `debian`  ·  14,444 documents

Debian vulnerability collection includes security advisories and CVEs specific to Debian OS packages and software components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "13", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15764", "CVE-2026-15765", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.6, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"- ------------------------------------------…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.8, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-40393", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lists.debian.org/debian-security-ann…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DEBIAN:DSA-6390-1:5928A"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T07:39:23"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "chrome-cve-adm…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T06:08:43"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-16T06:08:43"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Debian"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T07:39:25.316000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[SECURITY] [DSA 6390-1] chromium security up…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"debian"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/debian/DEBIAN:DSA-6390-1…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `debiancve`  ·  60,458 documents

Debian Vulnerability Database (Debian VDE) provides security advisories and CVEs for Debian OS packages and related software vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding}], list[object{distro,name,purl,registry,versionEndIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"name": "imagemagick", "versionEndExcluding…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Debian", "OSVersion": "14", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-61870"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 2.9, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"ImageMagick before 7.1.2-26 contains a memor…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-61870", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security-tracker.debian.org/tracker/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"DEBIANCVE:CVE-2026-61870"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-12T07:37:40"` |
| `metrics` | `object{adp,cna}, object{cna,nvd}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"source": "disclosure@vuln…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-11T13:01:09"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-11T13:01:09"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Debian Security Bug Tracker"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-11T23:37:52.353000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-61870"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"debiancve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/debiancve/DEBIANCVE:CVE-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `fedora`  ·  34,088 documents

Fedora collection includes security advisories, CVEs, and patches for vulnerabilities affecting Fedora OS and its packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "openssh", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Fedora Linux", "OSVersion": "44", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-59996", "CVE-2026-60002"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.4, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"SSH (Secure SHell) is a program for logging …` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 2.2, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lists.fedoraproject.org/archives/lis…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FEDORA:0D89A7F645"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T07:39:30"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T05:48:22"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T05:48:22"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Fedora"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T07:39:30.881000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[SECURITY] Fedora 44 Update: openssh-10.2p1-…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"fedora"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/fedora/FEDORA:0D89A7F645"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `freebsd`  ·  6,592 documents

FreeBSD vulnerability collection includes advisories and CVEs specific to FreeBSD operating system vulnerabilities and security updates.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{name,registry,versionEndExcluding,versionStartIncluding}], list[object{name,registry,versionEndExcluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "pkg", "name": "mailpit", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "FreeBSD", "OSVersion": "any", "arch"…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42533", "CVE-2026-56434", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\n\nMailpit author reports:\n\nMailpit's SMT…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.4, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56001", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://vuxml.freebsd.org/freebsd/562ff91e-8…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"562FF91E-8407-11F1-BFDE-10FFE07F9334"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T07:38:31"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "f5sirt@f5.com"…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/axllent/mailpit/security…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FreeBSD"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T07:38:31.737000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Mailpit -- SMTP DATA line reader buffers ove…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/freebsd/562FF91E-8407-11…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `2` |

### `freebsd_advisory`  ·  713 documents

FreeBSD advisories provide security updates and patches for FreeBSD operating systems, including CVEs and vulnerability advisories.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49424"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"\\-----BEGIN PGP SIGNED MESSAGE----- Hash: S…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 1.9, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-10846", "date": "2026-06-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.freebsd.org/security/advisories/…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"FREEBSD_ADVISORY:FREEBSD-SA-26:47.LINUX"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-30T23:40:46"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-30T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-30T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"FreeBSD Org"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-30T23:40:47.318000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"FreeBSD-SA-26:47.linux"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"freebsd_advisory"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/freebsd_advisory/FREEBSD…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `7` |

### `gentoo`  ·  3,816 documents

Gentoo collection includes vulnerability advisories and CVEs specific to Gentoo Linux packages and systems.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Gentoo", "OSVersion": "any", "arch":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-33150", "CVE-2026-33179"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.8, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"### Background\n\nFUSE (Filesystem in Usersp…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.9, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-33150", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://security.gentoo.org/glsa/202604-03"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"GLSA-202604-03"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T05:36:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-04-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-04-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-04-17T20:05:58.799000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"FUSE: Multiple Vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"gentoo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/gentoo/GLSA-202604-03"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `12` |

### `mageia`  ·  6,044 documents

Mageia security advisories provide information on vulnerabilities affecting Mageia Linux, including CVEs and patches for various software packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{distro,name,purl,registry,version}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "perl-String-Uti…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Mageia", "OSVersion": "9", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-14895"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The updated package fixes a security vulnera…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://advisories.mageia.org/MGASA-2026-027…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MGASA-2026-0272"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T07:40:10"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T06:29:10"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T06:29:10"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bugs.mageia.org/show_bug.cgi?id=358…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Gentoo Foundation"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T07:40:10.522000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Updated perl-String-Util package fixes a sec…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mageia"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mageia/MGASA-2026-0272"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `mariadbunix`  ·  396 documents

MariaDB Unix collection includes advisories and CVEs specific to Unix-based systems for the MariaDB database server.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[?], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Centos", "OSVersion": "7", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-49261"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 10.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"**Disclaimer**:\n_This data contains informa…` |
| `enchantments` | `object{dependencies,ossf_scorecard,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.6, "uncertanity": 1.8, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-49261", "date": "2026-07-0…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://web.nvd.nist.gov/view/vuln/detail?vu…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"MARIA:CVE-2026-49261"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-15T08:37:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T02:22:35"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-11T17:13:20"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://github.com/MariaDB/server/security/…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"MariaDB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-05-30T11:51:22.696000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-49261"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"mariadbunix"` |
| `unofficial_repo` | `bool` | 100% | Whether the fix comes from an unofficial repository. | `true` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/mariadbunix/MARIA:CVE-20…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `32` |

### `opensuse`  ·  7,982 documents

OpenSUSE vulnerability collection includes advisories and CVEs related to OpenSUSE OS and its packages, sourced from the OpenSUSE security team.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[?], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "opensuse backports", "OSVersion": "1…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-15899", "CVE-2026-15900", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"openSUSE Security Update: Security update fo…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-50163", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://lists.opensuse.org/archives/list/sec…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENSUSE-SU-2026:0254-1"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T05:45:32"` |
| `metrics` | `object{adp,cna}, object{nvd}, object{vendor}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "opensuse", …` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["#1271656"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenSuse"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T05:45:32.375000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security update for chromium (important)"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"opensuse"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/opensuse/OPENSUSE-SU-202…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `openwrt`  ·  33 documents

OpenWrt vulnerability collection includes advisories and CVEs related to OpenWrt firmware, focusing on security issues affecting routers and embedded devices.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2024-54143"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 9.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"** DESCRIPTION ** \nDue to the combination o…` |
| `enchantments` | `object{aggregatedScoring,backreferences,dependencies,exploitation,score,short_description,tags}, object{aggregatedScoring,dependencies,score,short_description,tags}, object{backreferences,dependencies,exploitation,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.3, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2024-54143", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://openwrt.org/advisory/2024-12-06"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"OPENWRT-SA-2024-12-06"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2025-04-04T15:56:07"` |
| `metrics` | `object{adp,cna}, object{adp,nvd}, object{cna,nvd}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss4": {"version": "4.0", "vectorS…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2024-12-07T07:31:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2024-12-06T00:00:00"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://lxr.openwrt.org/ident?i=blobmsg_for…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OpenWrt Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2025-04-04T15:56:07Z", "updated"…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security Advisory 2024-12-06-1 - OpenWrt Att…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"openwrt"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/openwrt/OPENWRT-SA-2024-…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `50` |

### `oraclelinux`  ·  9,369 documents

Oracle Linux vulnerabilities collection includes advisories and CVEs specific to Oracle Linux OS, sourced from Oracle's security bulletins.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "oracle linux", "OSVersion": "10", "a…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-23868"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.0, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"[5.2.1-25]\n- fix CVE-2026-26740: buffer ove…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.5, "uncertanity": 2.1, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-4800", "date": "2026-07-18…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://linux.oracle.com/errata/ELSA-2026-191…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ELSA-2026-19154"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T19:36:55"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "cve-assign", "…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"OracleLinux"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T19:36:55.397000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"giflib security update"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"oraclelinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/oraclelinux/ELSA-2026-19…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `photon`  ·  3,749 documents

Photon is a vulnerability collection from the National Vulnerability Database (NVD) focusing on vendor-specific advisories and CVEs related to various software products.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Photon", "OSVersion": "4.0", "arch":…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-46862", "CVE-2026-46863"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Updates of ['mysql'] packages of Photon OS h…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-31449", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://github.com/vmware/photon/wiki/Securi…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"PHSA-2026-4.0-1058"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T02:37:17"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert_us@or…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-15T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-15T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Photon"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T02:37:17.227000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important Photon OS Security Update - PHSA-2…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"photon"` |
| `vendorCvss` | `object{severity}` | 100% | Vendor-assigned CVSS score block. | `{"severity": "important"}` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/photon/PHSA-2026-4.0-1058"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `redhat`  ·  117,973 documents

Red Hat's vulnerability database provides advisories and CVEs related to Red Hat products and Linux distributions, focusing on security updates and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], null` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "dovecot", "vers…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}], null` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Red Hat Enterprise Linux", "OSVersio…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"info"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-42006"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cwe` | `list[?], list[str], null` | 100% | Associated CWE weakness identifiers. | `["CWE-770"]` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An update for dovecot is now available for R…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.8, "uncertanity": 1.5, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://access.redhat.com/errata/RHSA-2026:4…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RHSA-2026:41905"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T06:25:50"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}, object{nvd}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security", "ve…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T05:34:24"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-20T05:33:50"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://access.redhat.com/security/updates/…` |
| `relatesTo` | `null, str` | 100% | Identifier this document relates to. | `"RHSA-2026:41905"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"RedHat"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-20T06:25:50.259000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Important: Red Hat Security Advisory: doveco…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redhat"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/redhat/RHSA-2026:41905"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `4` |

### `redos`  ·  8,719 documents

Redos collection from various security databases focuses on vulnerabilities related to Regular Expression Denial of Service (ReDoS) across multiple vendors and products, typically including advisories and CVEs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "redos", "operator": "lt", "packageFi…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2023-1233"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 4.3, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"The vulnerability of the Resource Timing app…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 8.2, "uncertanity": 1.3, …` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://redos.red-soft.ru/support/secure/uya…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ROS-20260717-73-0038"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T11:50:18"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Redos"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T11:50:18.849000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"ROS-20260717-73-0038"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"redos"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/redos/ROS-20260717-73-0038"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `rocky`  ·  9,384 documents

Rocky Linux vulnerability collection from the Rocky Linux project includes advisories and CVEs related to Rocky Linux OS security.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedLibraries` | `list[object{arch,distro,name,purl,registry,versionEndExcluding,versionStartIncluding}], list[object{distro,name,purl,registry,versionEndExcluding,versionStartIncluding}]` | 100% | Affected libraries/packages (name, purl, version range). | `[{"registry": "rpm", "name": "jackson-annotat…` |
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Rocky Linux", "OSVersion": "9", "arc…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-54512", "CVE-2026-54513"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.1, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"An update is available for jackson-modules-b…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.3, "uncertanity": 2.3, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-14544", "date": "2026-07-1…` |
| `fixes` | `list[str]` | 100% | Fix references (fixed versions / patches). | `["https://bugzilla.redhat.com/show_bug.cgi?id…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://errata.rockylinux.org/RLSA-2026:40895"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"RLSA-2026:40895"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T14:37:04"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T12:03:25"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T12:03:25"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Rockylinux Product Errata"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T14:37:04.885000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"jackson-annotations, jackson-core, jackson-d…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rocky"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rocky/RLSA-2026:40895"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `rosalinux`  ·  1,374 documents

Rosalinux collection includes security advisories and CVEs specific to the Rosalyn Linux OS, sourced from the official Rosalyn security team.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[?], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "ROSA", "OSVersion": "any", "arch": "…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-34743"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "4.0", "score": 6.3, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV3,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Component: xz 5.2.9  \nOS: ROSA-CHROME  \nUn…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.0, "uncertanity": 2.0, …` |
| `epss` | `list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-34743", "date": "2026-06-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://abf.rosa.ru/advisories/ROSA-SA-2026-…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"ROSA-SA-2026-3313"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-06-01T19:20:42"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{nvd}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-06-01T12:39:24"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-06-01T12:39:24"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ROSA LAB"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-06-01T19:20:44.006000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Advisory ROSA-SA-2026-3313"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"rosalinux"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/rosalinux/ROSA-SA-2026-3…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `16` |

### `slackware`  ·  1,893 documents

Slackware vulnerability collection includes advisories and CVEs specific to the Slackware Linux distribution, focusing on security issues in its packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Slackware", "OSVersion": "15.0", "ar…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-62318", "CVE-2026-62319", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "NONE", "score": 0.0, "vector": "…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"New netatalk packages are available for Slac…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-13757", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"http://www.slackware.com/security/viewer.php…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SSA-2026-197-01"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T01:36:54"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "secalert@redha…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T00:07:03"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T00:07:03"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Slackware Linux Project"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T01:36:54.140000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"[slackware-security]  netatalk"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"slackware"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/slackware/SSA-2026-197-01"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `6` |

### `suse`  ·  5,671 documents

SUSE vulnerability collection includes advisories and CVEs specific to SUSE Linux products and services, detailing security issues and patches.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[?], list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "suse", "OSVersion": "12", "arch": "n…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-47734"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 6.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This update for python-dulwich fixes the fol…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.2, "uncertanity": 2.4, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2025-14575", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.suse.com/support/update/announce…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SUSE-SU-2026:3117-1"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T21:37:12"` |
| `metrics` | `object{vendor}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"vendor": {"cvss31": {"source": "suse", "ver…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T15:37:51"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T15:37:51"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://bugzilla.suse.com/show_bug.cgi?id=1…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Suse"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-17T21:37:12.807000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Security update for python-dulwich"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"suse"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/suse/SUSE-SU-2026:3117-1"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

### `susecve`  ·  60,258 documents

SUSE CVE Database: Contains advisories and CVEs related to vulnerabilities in SUSE Linux products and services.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2025-58218"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.2, "vector": "C…` |
| `cvss2` | `object{cvssV2,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV3,cvssV31,score,severity,source,vector,version}, object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Deserialization of Untrusted Data vulnerabil…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.3, "uncertanity": 1.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-16206", "date": "2026-07-2…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://www.suse.com/security/cve/CVE-2025-5…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"SUSECVE:CVE-2025-58218"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-19T20:35:34"` |
| `metrics` | `object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "audit@patchsta…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-19T17:45:29"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-19T17:45:29"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.suse.com/security/cve/CVE-2025-…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Suse CVE"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-19T20:35:34.829000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"SUSE CVE-2025-58218"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"susecve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/susecve/SUSECVE:CVE-2025…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `3` |

### `ubuntu`  ·  10,953 documents

Ubuntu vulnerability collection from the Ubuntu Security Notices, covering advisories and CVEs related to Ubuntu OS and its packages.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{EvaluationStatus,OS,OSExtraInfo,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}], list[object{EvaluationStatus,OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "24.04", "arch…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-43341", "CVE-2026-31669", "CVE-202…` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 9.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Several security issues were discovered in t…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.9, "uncertanity": 1.5, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-43341", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://ubuntu.com/security/notices/USN-8490-2"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"USN-8490-2"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-17T17:36:52"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-17T10:10:48"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-17T10:10:48"` |
| `references` | `list[?], list[str]` | 100% | External reference URLs. | `["https://launchpad.net/bugs/2160650"]` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Ubuntu"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-09T09:36:58.735000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"USN-8490-2: Linux kernel (Real-time) vulnera…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ubuntu"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ubuntu/USN-8490-2"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `9` |

### `ubuntucve`  ·  71,772 documents

Ubuntu CVE database provides security advisories and CVEs specifically for Ubuntu OS vulnerabilities.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{EvaluationStatus,OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion,status}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "Ubuntu", "OSVersion": "18.04", "arch…` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-54572"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 7.5, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{cvssV4,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Rclone is a command-line program to sync fil…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-54572", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://ubuntu.com/security/CVE-2026-54572"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"UB:CVE-2026-54572"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-16T14:56:36"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna,nvd}, object{cna}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "security-advis…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-16T10:55:55"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T22:17:00"` |
| `references` | `list[str]` | 100% | External reference URLs. | `["https://www.cve.org/CVERecord?id=CVE-2026-5…` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"ubuntu.com"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-16T14:56:36.068000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-54572"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"ubuntucve"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/ubuntucve/UB:CVE-2026-54…` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `10` |

### `virtuozzo`  ·  1,135 documents

Virtuozzo collection includes security advisories and CVEs related to Virtuozzo virtualization software and its components.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-53359"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.8, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"This update provides a security fix.\n**Vuln…` |
| `enchantments` | `object{aggregatedScoring,dependencies,score,short_description,tags}, object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 6.1, "uncertanity": 2.7, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-53359", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://docs.virtuozzo.com/vza/VZA-2026-018.…` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"VZA-2026-018"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-18T11:37:01"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"cna": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-14T00:00:00"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-14T00:00:00"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Virtuozzo"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-14T12:29:35.425000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"Virtuozzo Infrastructure 7.2 Hotfix 4 (7.2.0…` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"virtuozzo"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/virtuozzo/VZA-2026-018"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `5` |

### `wolfi`  ·  11,707 documents

Wolfi is a vulnerability collection from the Wolfi project, focusing on Linux OS packages, typically containing advisories and CVEs.

| field | type | in samples | description | example |
|---|---|---|---|---|
| `affectedPackage` | `list[object{OS,OSVersion,arch,operator,packageFilename,packageManager,packageName,packageVersion}]` | 100% | Affected OS/distribution packages (name, version, OS, arch). | `[{"OS": "wolfi", "OSVersion": "any", "arch": …` |
| `bulletinFamily` | `str` | 100% | Broad family the document belongs to (cve, exploit, software, …). | `"unix"` |
| `cvelist` | `list[?], list[str]` | 100% | Related CVE identifiers referenced by this document. | `["CVE-2026-56742"]` |
| `cvss` | `object{score,severity,source,vector,version}` | 100% | Primary CVSS score block (version, base score, vector, severity, source). | `{"version": "3.1", "score": 8.9, "vector": "C…` |
| `cvss2` | `object{score,severity,source,vector,version}` | 100% | CVSS v2 score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss3` | `object{cvssV31,score,severity,source,vector,version}, object{score,severity,source,vector,version}` | 100% | CVSS v3.x score block. | `{"version": null, "score": null, "vector": nu…` |
| `cvss4` | `object{score,severity,source,vector,version}` | 100% | CVSS v4.0 score block. | `{"version": null, "score": null, "vector": nu…` |
| `description` | `str` | 100% | Full text or summary of the vulnerability/advisory. | `"Vulnerabilities for packages: hubble, kubesc…` |
| `enchantments` | `object{dependencies,score,short_description,tags}` | 100% | Vulners-computed enrichment layer (AI score, tags, related docs). | `{"score": {"value": 5.1, "uncertanity": 2.2, …` |
| `epss` | `list[?], list[object{cve,date,epss,percentile}]` | 100% | EPSS exploitation-probability forecast datapoints (score + percentile). | `[{"cve": "CVE-2026-56742", "date": "2026-07-1…` |
| `href` | `str` | 100% | Canonical URL of the document at its original source. | `"https://packages.wolfi.dev/os/security.json"` |
| `id` | `str` | 100% | Unique document identifier (e.g. a CVE id, exploit id or advisory id). | `"WOLFI:CVE-2026-56742"` |
| `lastseen` | `str` | 100% | Last time Vulners observed/refreshed the document (ISO-8601). | `"2026-07-20T02:16:27"` |
| `metrics` | `object{adp,cna,nvd}, object{adp,cna}, object{}` | 100% | Raw scoring metrics blob (CNA/ADP/NVD/vendor sub-objects). | `{"nvd": {"cvss31": {"source": "nvd", "version…` |
| `modified` | `str` | 100% | Last modification timestamp at the source (ISO-8601). | `"2026-07-20T02:16:27"` |
| `published` | `str` | 100% | Original publication timestamp (ISO-8601). | `"2026-07-18T20:24:31"` |
| `reporter` | `str` | 100% | Person or organization credited with reporting/authoring it. | `"Wolfi"` |
| `sourceAvailable` | `bool` | 100% | Whether the raw source data is available for this document. | `true` |
| `timestamps` | `object{contentUpdated,created,enriched,metricsUpdated,reviewed,updated,webApplicabilityUpdated}` | 100% | Vulners lifecycle timestamps (created/updated/enriched/reviewed/…). | `{"created": "2026-07-18T20:24:31.654000Z", "u…` |
| `title` | `str` | 100% | Human-readable title of the document. | `"CVE-2026-56742 vulnerabilities"` |
| `type` | `str` | 100% | Source collection the document comes from (cve, exploitdb, ubuntu, …). | `"wolfi"` |
| `vhref` | `str` | 100% | URL of the document on vulners.com. | `"https://vulners.com/wolfi/WOLFI:CVE-2026-56742"` |
| `viewCount` | `int` | 100% | How many times the document has been viewed on Vulners. | `8` |

