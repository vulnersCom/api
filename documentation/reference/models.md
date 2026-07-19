# Models & pagination

## Bulletins

Search and lookup methods return `Bulletin` objects. The concrete subclass is chosen by the
document's `bulletinFamily`; families without a dedicated model fall back to
`GenericBulletin`. Fields are accessed as attributes and are all optional (a missing field is
`None`).

::: vulners._models.bulletin.Bulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.CveBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.ExploitBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.ScannerBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.SoftwareBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.InfoBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.GenericBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

### CVSS

::: vulners._models.bulletin.Cvss
    options:
      heading_level: 4
      show_root_heading: true
      members: []

## Pagination

`search.query` returns a `SearchPage` (async: `AsyncSearchPage`). It knows its place in the
result window and walks further pages when you iterate it.

::: vulners._pagination.SearchPage
    options:
      heading_level: 3
      show_root_heading: true

::: vulners._pagination.AsyncSearchPage
    options:
      heading_level: 3
      show_root_heading: true

## Client configuration

The resolved, immutable configuration for a client instance is available as `client.config`.

::: vulners._config.ClientConfig
    options:
      heading_level: 3
      show_root_heading: true
