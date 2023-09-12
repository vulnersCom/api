#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Vulners search API usage example

import os

import vulners

vulners_api = vulners.VulnersApi(api_key=os.environ["KEY"])
possible_autocomplete = vulners_api.query_autocomplete("heartbleed")
heartbleed_related = vulners_api.find("heartbleed", limit=10)
total_heartbleed = heartbleed_related.total
CVE_2017_14174 = vulners_api.get_bulletin("CVE-2017-14174")
