"""The same search, fully async with AsyncVulners (v4 API).

Docs: https://docs.vulners.com/docs/
"""

import asyncio
import os

from vulners import AsyncVulners


async def main() -> None:
    # Direct: AsyncVulners(api_key="YOUR_API_KEY_HERE"), or from the environment:
    async with AsyncVulners(api_key=os.environ["VULNERS_API_KEY"]) as v:
        page = await v.search.query("type:cve AND cvss.score:[9 TO 10]", limit=5)
        async for doc in page:
            print(doc.id, "-", (doc.title or "")[:60])


asyncio.run(main())
