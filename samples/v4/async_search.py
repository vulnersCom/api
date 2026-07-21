"""The same search, fully async with AsyncVulners (v4 API).

Docs: https://docs.vulners.com/docs/
"""

import asyncio
import os

from vulners import AsyncVulners


async def main() -> None:
    # Direct: AsyncVulners(api_key="YOUR_API_KEY_HERE"), or from the environment:
    async with AsyncVulners(api_key=os.environ["VULNERS_API_KEY"]) as v:
        # `limit` is the page size; iterating with `async for doc in page` would
        # auto-paginate the whole result window (thousands of high-severity CVEs).
        # For a quick look, read just the first page's items.
        page = await v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=5)
        for doc in page.data:
            print(doc.id, "-", (doc.title or "")[:60])


asyncio.run(main())
