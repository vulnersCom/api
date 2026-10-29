# `microsoft` family

**Model:** `MicrosoftBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: microsoft`.

## Family fields

Present in every `microsoft` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `msrc` | `Any` | Microsoft Security Response Center identifier. |  |

## Collections

### `mscve` · ~32k documents → `MscveBulletin`

MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `customerActionRequired` | `bool | None` | Whether customer action is required. | `true` |
| `cweList` | `list[str] | None` | Associated CWE weakness identifiers (alternate key). | `["CWE-639: Authorization Bypass Through User-…` |
| `denialOfService` | `str | None` | Denial-of-service impact marker, as a string (e.g. 'N/A') — not a boolean. | `"N/A"` |
| `exploitability` | `Any` | Exploitability assessment block. | `{"publiclyDisclosed": "No", "exploited": "No"}` |
| `faq` | `list[str] | None` | Advisory FAQ entries. | `["**According to the CVSS metrics, successful…` |
| `impact` | `str | None` | Impact description/classification. | `"Spoofing"` |
| `issuingCna` | `str | None` | The CNA that issued the advisory. | `"kubernetes"` |
| `kbList` | `Any` | Microsoft KB article ids covered by the update. |  |
| `mitigations` | `Any` | Mitigation measures for the issue. |  |
| `msAffectedSoftware` | `Any` | Affected Microsoft software entries. |  |
| `msDetailRevision` | `str | None` | Microsoft advisory detail revision. | `"2026-10-28T01:02:06-07:00"` |
| `mscve` | `str | None` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-2270"` |
| `severity` | `str | None` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). | `"Moderate"` |
| `tag` | `str | None` | A single classification tag. | `"Mariner"` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"baseScore": "4.3", "temporalScore": "3.8", …` |

### `mskb` · ~13k documents → `MskbBulletin`

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedProducts` | `list[str] | None` | Affected product names. | `[".NET 8.0 installed on Mac OS", ".NET 8.0 in…` |
| `kb` | `str | None` | Microsoft Knowledge Base article id. | `"KB5127653"` |
| `mscve` | `str | None` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-114148"` |
| `msfamily` | `str | None` | Microsoft product family. | `"Developer Tools"` |
| `msimpact` | `str | None` | Microsoft's impact classification. | `"Elevation of Privilege"` |
| `msplatform` | `Any` | Affected Microsoft platform. |  |
| `msproducts` | `list[str] | None` | Affected Microsoft products. | `["22222", "22220", "22221"]` |
| `msseverity` | `str | None` | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[str] | None` | Updates that supersede this update. | `["KB5127653"]` |
| `primarySupportAreaPath` | `Any` | Primary Microsoft support taxonomy path. |  |
| `superseeds` | `list[str] | None` | Updates this update supersedes. | `["KB5095051", "KB5077239", "KB5089548", "KB50…` |
| `supportAreaPathNodes` | `Any` | Microsoft support taxonomy nodes. |  |
| `supportAreaPaths` | `Any` | Microsoft support taxonomy paths. |  |

### `msupdate` · ~48k documents → `MsupdateBulletin`

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `bundledUpdates` | `list[str] | None` | Updates bundled into this one. | `["c66869d8-8068-45dd-8463-be4fa6fd477b", "41d…` |
| `kb` | `str | None` | Microsoft Knowledge Base article id. | `"KB5133965"` |
| `prerequisitesUpdates` | `list[str] | None` | Prerequisite updates required before this one. | `["3e0afb10-a9fb-4c16-a60e-5790c3803437", "e1a…` |
| `revision` | `str | None` | Revision number of the advisory. | `"200"` |
| `supersededUpdates` | `list[str] | None` | Updates superseded by this one. | `["02297cf4-4fcc-4491-be68-14a5aa4046b5", "12a…` |

