#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners search API usage example
# ==============

import vulners

vulners_api = vulners.Vulners(api_key="YOUR_API_KEY_HERE")
possible_autocomplete = vulners_api.autocomplete("heartbleed")
heartbleed_related, total_heartbleed = vulners_api.search("heartbleed", limit=10)
CVE_2017_14174 = vulners_api.document("CVE-2017-14174")
