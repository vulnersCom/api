# The 10,000-document search window

Lucene search is backed by Elasticsearch, which caps its result window at **10,000
documents** (`offset + limit ≤ 10000`). This is a hard server-side limit, not an SDK choice,
and it shapes how pagination works.

## What the SDK does

`search.query` returns a `SearchPage`. The page's `total` may be far larger than 10,000 — it
is the true match count — but you can only *page through* the first 10,000:

```python
with Vulners() as v:
    page = v.search.query("type:cve", limit=100)
    print(page.total)          # e.g. 250000 — the full match count
    for bulletin in page:      # iterates only up to the 10,000th document
        ...
```

Iterating a page (or using `iter_query`) transparently fetches subsequent pages and **stops
cleanly** at the window. You never get a partial/garbage page at the boundary.

## When you cross the line

Asking for data *past* the window fails loudly rather than silently truncating:

- `search.query(query, offset=10000)` raises `SearchWindowExceeded` before sending a request.
- Calling `next_page()` on a page whose next page would cross the window raises
  `SearchWindowExceeded`.

`SearchWindowExceeded` also subclasses `ValueError`, so existing `except ValueError` handlers
around pagination keep working.

```python
from vulners import Vulners, SearchWindowExceeded

with Vulners() as v:
    try:
        v.search.query("type:cve", offset=10001)
    except SearchWindowExceeded as err:
        print(err)   # clear message pointing you at the archive API
```

## Retrieving more than 10,000 documents

To process an entire collection, don't paginate search — use the
[archive API](../how-to/stream-the-archive.md). `archive.aiter_collection("cve")` streams
every document in a collection with no window limit, which is the right tool for mirrors and
bulk pipelines.
