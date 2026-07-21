# `cnvd` family

**Model:** `CnvdBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: cnvd`.

## Family fields

Present in every `cnvd` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `Any` | Affected software products (name/version/operator). |  |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |
| `vendorCVSS` | `Any` | Vendor-assigned CVSS, as a raw string. |  |

## Collections

### `cnvd` · ~130k documents → `CnvdCollectionBulletin`

CNVD is a Chinese vulnerability database that provides advisories and CVEs focused on various software products and systems.

_No fields beyond the layers above._

