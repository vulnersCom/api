#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners async API usage example
# ==============

import vulners
import asyncio


async def example_async():
    async with vulners.AioVulners() as api:
        tasks = [
            api.searchExploit('wordpress 4.7.0'),
            api.searchExploit('django 1.9'),
            api.searchExploit('eternalblue')
        ]
        exploits = await asyncio.gather(*tasks)
        for result in exploits:
            for r in result:
                print(f'ID: {r["id"]}')
                print(f'Title: {r["title"]}')
                print(f'Href: {r["href"]}')
                print('-' * 15)
            print('#' * 100)
        sw_results = await api.softwareVulnerabilities('httpd', '1.5')
        sw_exploit_list = sw_results.get('exploit')
        sw_vulnerabilities_list = [sw_results.get(key) for key in sw_results if
                                   key not in ['info', 'blog', 'bugbounty']]
        print(f'{len(sw_vulnerabilities_list)} vulnerabilities found for httpd 1.5')

        cpe_results = await api.cpeVulnerabilities("cpe:/a:cybozu:garoon:4.2.1")
        cpe_exploit_list = cpe_results.get('exploit')
        cpe_vulnerabilities_list = [cpe_results.get(key) for key in cpe_results if key not in ['info', 'blog', 'bugbounty']]
        print(f'{len(cpe_vulnerabilities_list)} vulnerabilities found for cpe:/a:cybozu:garoon:4.2.1')


try:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(example_async())
finally:
    loop.close()





