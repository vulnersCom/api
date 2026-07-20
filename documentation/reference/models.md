# Models & pagination

## Bulletins

Search and lookup methods return `Bulletin` objects. The most specific model is chosen for
each document: a known collection `type` selects a per-collection model (see the
[Collections reference](collections/index.md)), otherwise the `bulletinFamily` selects a
family model, falling back to `GenericBulletin`. Per-collection models subclass their family
model, so family classes are the stable `isinstance`/annotation surface. Fields are accessed
as attributes and are all optional (a missing field is `None`); see
[Data models](data-models.md) for every field with its description.

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

::: vulners._models.bulletin.UnixBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.InfoBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.LibraryBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.MicrosoftBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.BugBountyBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.AdvisoryBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

::: vulners._models.bulletin.GenericBulletin
    options:
      heading_level: 3
      show_root_heading: true
      members: []

### CVSS & nested objects

::: vulners._models.bulletin.Cvss
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.Timestamps
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.Enchantments
    options:
      heading_level: 4
      show_root_heading: true
      members: []

::: vulners._models.bulletin.EpssScore
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
