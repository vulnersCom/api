#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners search API usage example
# ==============

import vulners

vulnersApi = vulners.Vulners()
heartbleed_felated = vulnersApi.search("heartbleed", limit=10)
