#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners search API usage example
# ==============

import vulners

vulnersApi = vulners.Vulners()
heartbleed_related = vulnersApi.search("heartbleed", limit=10)
CVE_2017_14174 = vulnersApi.document("CVE-2017-14174")
