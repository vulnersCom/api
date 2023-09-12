#!/usr/bin/env python3

import asyncio
import functools
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import vulners

vulners_api = vulners.Vulners(api_key="YOUR_API_KEY_HERE")

loop = asyncio.get_event_loop()
# pool = ProcessPoolExecutor(max_workers=multiprocessing.cpu_count())
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())


async def get_collection():
    print("Get collections")
    # using default executor
    return await loop.run_in_executor(None, vulners_api.collections)


async def search(query, **kwargs):
    # run using own executor
    print("Run search `%s`." % query)
    ret = await loop.run_in_executor(pool, functools.partial(vulners_api.search, query, **kwargs))
    print("Searching `%s` done." % query)
    return ret


async def main():
    collection_names = await get_collection()
    queries = ["type:%s" % collection for collection in collection_names[:20]]
    futures = [asyncio.ensure_future(search(query, limit=10)) for query in queries]
    results = await asyncio.wait(futures)
    print(results)


loop.run_until_complete(main())
loop.close()
