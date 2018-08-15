#!/usr/bin/env python3

import asyncio
import multiprocessing
import functools
import vulners
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor


vulners_api = vulners.Vulners()

loop = asyncio.get_event_loop()
# pool = ProcessPoolExecutor(max_workers=multiprocessing.cpu_count())
pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count())


async def get_collection():
    print('Get collections')
    # using default executor
    return await loop.run_in_executor(None, vulners_api.collections)


async def search(query, **kwargs):
    # run using own executor
    print('Run search `%s`.' % query)
    ret = await loop.run_in_executor(pool, functools.partial(vulners_api.search, query, **kwargs))
    print('Searching `%s` done.' % query)
    return ret


async def main():
    collection_names = await get_collection()
    queries = ["type:%s" % collection for collection in collection_names[:20]]
    futures = [asyncio.ensure_future(search(query, limit=10)) for query in queries]
    results = await asyncio.wait(futures)
    print(results)


loop.run_until_complete(main())
loop.close()

#
#
# # Using parallel Thread pool for testing thread safety
# with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
#     search_results_pool = [executor.submit(vulners_api.search, query, 10) for query in query_pool]
#     for future in concurrent.futures.as_completed(search_results_pool):
#         print("Collected %s results with Thread Pool" % len(future.result()))
#         merged_results.append(future.result())
#
# # Using parallel Process pool for testing thread safety
# with concurrent.futures.ProcessPoolExecutor(max_workers=20) as executor:
#     search_results_pool = [executor.submit(vulners_api.search, query, 10) for query in query_pool]
#     for future in concurrent.futures.as_completed(search_results_pool):
#         print("Collected %s results with Multiprocess Pool" % len(future.result()))
#         merged_results.append(future.result())
