# `euvd` family

**Model:** `EuvdBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: euvd`.

## Family fields

Present in every `euvd` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cnaAffected` | `list | None` | Affected products as reported by the CNA (CVE JSON 5.x). | `[{"enisaIdVendor": [{"id": "92e8510a-4ee4-3ea…` |

## Collections

### `euvd` · ~470k documents → `EuvdCollectionBulletin`

The EUVDB (European Vulnerability Database) provides advisories and CVEs focused on vulnerabilities across various vendors and products in the EU.

_No fields beyond the layers above._

