# Quickstart

This tutorial walks you from an empty file to your first **search** and first **audit**, in
both the synchronous and asynchronous styles. It assumes you have installed the SDK
(`pip install vulners`) and have a Vulners API key.

## 1. Authenticate

The client takes the key as an argument, or reads it from the `VULNERS_API_KEY`
environment variable:

=== "Sync"

    ```python
    from vulners import Vulners

    v = Vulners(api_key="YOUR_API_KEY_HERE")
    # ...or, with `export VULNERS_API_KEY=...` set:
    v = Vulners()
    ```

=== "Async"

    ```python
    from vulners import AsyncVulners

    v = AsyncVulners(api_key="YOUR_API_KEY_HERE")
    # ...or, with `export VULNERS_API_KEY=...` set:
    v = AsyncVulners()
    ```

Use it as a context manager so the underlying connection pool is released on exit:

=== "Sync"

    ```python
    with Vulners() as v:
        ...  # do work here
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        ...  # do work here
    ```

## 2. Your first search

`search.query` runs a [Lucene query](https://vulners.com/help) and returns a
`SearchPage` of typed `Bulletin` objects. `page.data` holds this page's results;
iterating the page itself (`for b in page`) transparently walks further pages, up to the
[10,000-document window](../explanation/search-window.md):

=== "Sync"

    ```python
    with Vulners() as v:
        page = v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=10)

        print(page.total, "documents match")     # total match count
        for bulletin in page.data:                # this page's results (limit=10)
            print(bulletin.id, "-", bulletin.title)
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        page = await v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=10)

        print(page.total, "documents match")     # total match count
        for bulletin in page.data:                # this page's results (limit=10)
            print(bulletin.id, "-", bulletin.title)
    ```

Each row is a `Bulletin` model — access fields as attributes (not dict keys):

```python
b = page[0]
print(b.id, b.type, b.published)
if b.cvss:
    print(b.cvss.score, getattr(b.cvss, "severity", None))
```

Fetch a single document by id:

=== "Sync"

    ```python
    cve = v.search.get_bulletin("CVE-2021-44228")   # -> Bulletin | None
    if cve is not None:
        print(cve.title)
    ```

=== "Async"

    ```python
    cve = await v.search.get_bulletin("CVE-2021-44228")   # -> Bulletin | None
    if cve is not None:
        print(cve.title)
    ```

## 3. Your first audit

Audit a list of software for known vulnerabilities. Entries can be CPE 2.3 strings or
simple `{"product": ..., "version": ...}` dicts:

=== "Sync"

    ```python
    with Vulners() as v:
        results = v.audit.software([
            {"product": "openssl", "version": "1.0.1"},
            "cpe:2.3:a:apache:log4j:2.14.1",
        ])
        for entry in results:
            vulns = entry.get("vulnerabilities", [])
            print(entry.get("matched_criteria"), "->", len(vulns), "vulnerabilities")
    ```

=== "Async"

    ```python
    async with AsyncVulners() as v:
        results = await v.audit.software([
            {"product": "openssl", "version": "1.0.1"},
            "cpe:2.3:a:apache:log4j:2.14.1",
        ])
        for entry in results:
            vulns = entry.get("vulnerabilities", [])
            print(entry.get("matched_criteria"), "->", len(vulns), "vulnerabilities")
    ```

To audit a Linux host by its installed packages, see
[Audit a host](../how-to/audit-a-host.md).

## 4. The same, asynchronously

Every resource method exists on `AsyncVulners` with an identical signature; you just
`await` it. (Iterating a page with `async for` auto-paginates, exactly like the sync
`for`.) A complete program looks like this:

```python
import asyncio
from vulners import AsyncVulners

async def main() -> None:
    async with AsyncVulners() as v:
        page = await v.search.query("bulletinFamily:exploit AND wordpress", limit=10)
        for exploit in page.data:
            print(exploit.id, exploit.href)

        results = await v.audit.software(["cpe:2.3:a:apache:log4j:2.14.1"])
        print(len(results), "products audited")

asyncio.run(main())
```

## 5. Handle errors

Failed requests raise a subclass of `VulnersError`. Catch the whole family, or a specific
one such as `RateLimitError`:

=== "Sync"

    ```python
    from vulners import Vulners, RateLimitError, VulnersError

    try:
        with Vulners() as v:
            v.search.query("type:cve", limit=10)
    except RateLimitError as err:
        print("slow down; retry after", err.retry_after, "seconds")
    except VulnersError as err:
        print("request failed:", err)
    ```

=== "Async"

    ```python
    from vulners import AsyncVulners, RateLimitError, VulnersError

    try:
        async with AsyncVulners() as v:
            await v.search.query("type:cve", limit=10)
    except RateLimitError as err:
        print("slow down; retry after", err.retry_after, "seconds")
    except VulnersError as err:
        print("request failed:", err)
    ```

The full hierarchy is described in [Error model](../explanation/error-model.md).

## Next steps

- [How-to guides](../how-to/audit-a-host.md) — practical, task-focused recipes.
- [API reference](../reference/clients.md) — every method and model.
