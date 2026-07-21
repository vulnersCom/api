# `nozomi` family

**Model:** `NozomiBulletin` — extends [`Bulletin`](base.md); `bulletinFamily: nozomi`. 1 collection.

## Family fields

Present in every `nozomi` document, beyond the [common base](base.md).

| field | type | description | example |
|---|---|---|---|
| `affectedSoftware` | `list | None` | Affected software products (name/version/operator). | `[{"version": "< v26.2.0", "name": "guardian"}…` |
| `attachments` | `Any` | Binary/media attachments associated with the document. |  |
| `cpeConfigurations` | `Any` | CPE applicability configurations (NVD-style match tree). | `{"_index": true, "vulnersCpeConfiguration": […` |

## Collections

### `nozomi` · ~59 documents → `NozomiCollectionBulletin`

Nozomi Networks provides advisories and CVEs related to cybersecurity vulnerabilities in industrial control systems and critical infrastructure.

_No fields beyond the layers above._

