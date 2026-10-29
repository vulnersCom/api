# `cvd` family

**Model:** `CvdBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: cvd`.

## Family fields

Present in every `cvd` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `harness` | `str | None` | Tooling credited with finding the issue in a coordinated-disclosure record (e.g. 'Claude Code', 'VulnForge'). | `"Claude Code"` |
| `introducedYear` | `Any` | Year the flaw was introduced into the affected code, when the disclosure pins it down. |  |
| `researcher` | `str | None` | Researcher or team credited with the disclosure. | `"Fukun"` |
| `sourceData` | `Any` | Raw, unparsed source body as delivered by the origin. |  |
| `status` | `str | None` | Workflow status of the record. | `"revealed"` |
| `vendor_severity` | `str | None` | Vendor's own qualitative severity rating. | `"medium"` |

## Collections

### `cvd` · ~2.4k documents → `CvdCollectionBulletin`

CVD (Common Vulnerability Disclosure) provides vendor-specific advisories and CVEs related to security vulnerabilities across various products and operating systems.

_No fields beyond the layers above._

