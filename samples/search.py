#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners search API usage example
# ==============

import vulners

vulners_api = vulners.Vulners()
heartbleed_related = vulners_api.search("heartbleed", limit=10)
CVE_2017_14174 = vulners_api.document("CVE-2017-14174")
