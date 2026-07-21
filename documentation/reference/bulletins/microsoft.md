# `microsoft` family

**Model:** `MicrosoftBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: microsoft`.

## Family fields

Present in every `microsoft` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `msrc` | `Any` | Microsoft Security Response Center identifier. |  |

## Collections

### `mscve` · ~23k documents → `MscveBulletin`

MSCVEs are Microsoft-specific vulnerability advisories that include CVEs and detailed security updates for Windows OS and Microsoft products.

| field | type | description | example |
|---|---|---|---|
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `customerActionRequired` | `bool | None` | Whether customer action is required. | `true` |
| `cweList` | `Any` | Associated CWE weakness identifiers (alternate key). |  |
| `denialOfService` | `str | None` | Denial-of-service impact marker, as a string (e.g. 'N/A') — not a boolean. | `"N/A"` |
| `exploitability` | `Any` | Exploitability assessment block. |  |
| `faq` | `list[str] | None` | Advisory FAQ entries. | `["**Why is this Chrome CVE included in the Se…` |
| `impact` | `Any` | Impact description/classification. |  |
| `issuingCna` | `str | None` | The CNA that issued the advisory. | `"Chrome"` |
| `kbList` | `Any` | Microsoft KB article ids covered by the update. |  |
| `mitigations` | `Any` | Mitigation measures for the issue. |  |
| `msAffectedSoftware` | `Any` | Affected Microsoft software entries. |  |
| `msDetailRevision` | `str | None` | Microsoft advisory detail revision. | `"2026-07-17T17:42:44-07:00"` |
| `mscve` | `str | None` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-15905"` |
| `severity` | `Any` | Qualitative severity band (LOW/MEDIUM/HIGH/CRITICAL). |  |
| `tag` | `str | None` | A single classification tag. | `"Microsoft Edge (Chromium-based)"` |
| `vendorCvss` | `Any` | Vendor-assigned CVSS score block. | `{"baseScore": "", "temporalScore": "", "vecto…` |

### `mskb` · ~12k documents → `MskbBulletin`

The MSKB collection from Microsoft includes security bulletins and advisories related to Microsoft products and services, detailing vulnerabilities and patches.

| field | type | description | example |
|---|---|---|---|
| `affectedProducts` | `list[str] | None` | Affected product names. | `["Windows 10 Version 22H2 for 32-bit Systems"…` |
| `kb` | `str | None` | Microsoft Knowledge Base article id. | `"KB5121767"` |
| `mscve` | `str | None` | Microsoft's CVE identifier for the advisory. | `"CVE-2026-58598"` |
| `msfamily` | `str | None` | Microsoft product family. | `"ESU"` |
| `msimpact` | `str | None` | Microsoft's impact classification. | `"Elevation of Privilege"` |
| `msplatform` | `str | None` | Affected Microsoft platform. | `"Windows Server 2025"` |
| `msproducts` | `list[str] | None` | Affected Microsoft products. | `["11930", "12098", "11931", "12099", "12097",…` |
| `msseverity` | `str | None` | Microsoft's severity rating for the advisory. | `"Important"` |
| `parentseeds` | `list[str] | None` | Updates that supersede this update. | `["KB5101649"]` |
| `primarySupportAreaPath` | `Any` | Primary Microsoft support taxonomy path. |  |
| `superseeds` | `list[str] | None` | Updates this update supersedes. | `["KB5043178", "KB5065426", "KB5059087", "KB50…` |
| `supportAreaPathNodes` | `Any` | Microsoft support taxonomy nodes. |  |
| `supportAreaPaths` | `Any` | Microsoft support taxonomy paths. |  |

### `msupdate` · ~47k documents → `MsupdateBulletin`

Microsoft Update collection provides advisories and CVEs related to vulnerabilities in Microsoft products and operating systems.

| field | type | description | example |
|---|---|---|---|
| `bundledUpdates` | `list[str] | None` | Updates bundled into this one. | `["e06eb090-b47f-4f74-8cae-c9a0a4a4a7dd", "650…` |
| `kb` | `str | None` | Microsoft Knowledge Base article id. | `"KB5104032"` |
| `prerequisitesUpdates` | `list[str] | None` | Prerequisite updates required before this one. | `["4103af66-247a-4782-b970-8899394c27c3", "5f9…` |
| `revision` | `str | None` | Revision number of the advisory. | `"200"` |
| `supersededUpdates` | `list[str] | None` | Updates superseded by this one. | `["0680d415-fc09-4c0a-aaf7-c9296014d78e", "49f…` |

