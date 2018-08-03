#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============
#      Example of multithreaded/multiprocessed data fetching.
#      For ratelimiter testing mostly :)
# ==============

import concurrent.futures
import vulners

vulners_api = vulners.Vulners()

collection_names = vulners_api.collections()

query_pool = ["type:%s" % collection for collection in collection_names]
merged_results = []

# Using parallel Thread pool for testing thread safety
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    search_results_pool = [executor.submit(vulners_api.search, query, 10) for query in query_pool]
    for future in concurrent.futures.as_completed(search_results_pool):
        merged_results.append(future.result())

# Using parallel Process pool for testing thread safety
with concurrent.futures.ProcessPoolExecutor(max_workers=20) as executor:
    search_results_pool = [executor.submit(vulners_api.search, query, 10) for query in query_pool]
    for future in concurrent.futures.as_completed(search_results_pool):
        merged_results.append(future.result())