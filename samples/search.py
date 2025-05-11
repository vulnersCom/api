#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Vulners search API usage example

import os

import vulners

vulners_api = vulners.VulnersApi(api_key=os.environ["KEY"])

possible_autocomplete = vulners_api.misc.query_autocomplete("heartbleed")
heartbleed_related = vulners_api.search.search_bulletins("heartbleed", limit=10)
total_heartbleed = heartbleed_related.total
CVE_2017_14174 = vulners_api.search.get_bulletin("CVE-2017-14174")
