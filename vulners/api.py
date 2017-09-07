#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ==============
#      Vulners API wrapper
# ==============

# Imports
import requests
import time

class Vulners(object):
    def __init__(self):
        # Default URL's for the Vulners API
        self.vulners_urls = {
        'search':"https://vulners.com/api/v3/search/lucene/"
        }
        # Default search parameters
        self.search_size = 100

        # Requests opener
        self.opener = requests.session()
        self.opener.headers = {'User-Agent': 'Vulners Python API'}

    def __chech_rate_limit(self, response):
        """
        Check vulners URL ratelimit using rate headers

        X-Vulners-Ratelimit-Rate: 4.186613262227894
        X-Vulners-Ratelimit-Reqlimit: 200

        :param response: Requests response object
        :return: Sleep delay before performing next call
        """
        rate_limit = float(response.headers.get('X-Vulners-Ratelimit-Reqlimit', 1000))
        current_rate = float(response.headers.get('X-Vulners-Ratelimit-Rate', 0))
        if current_rate > rate_limit/2:
            if current_rate > rate_limit:
                return rate_limit / 100
            return (rate_limit - current_rate) / 8 / 100
        return 0.0

    def __search(self, query, skip, size, fields = ()):
        """
        Tech search wrapper for internal lib usage

        :param query: Search query.
        :param skip: How much bulletins to skip.
        :param size: How much results to return.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(query, str):
            raise TypeError("Search query expected to be a string")
        if not isinstance(skip, int) and skip in range(0, 10000):
            raise TypeError("Skip  expected to be a int in range 0-10000")
        if not isinstance(size, int) and size in range(0, 10000):
            raise TypeError("Size  expected to be a int in range 0-10000")
        search_request = {"query":query, 'skip':skip or 0, 'size':size or 0, 'fields':fields or []}
        response = self.opener.post(self.vulners_urls['search'], json=search_request)
        # Check if we need to wait a little bit if we are aproaching rate limit
        sleep_time = self.__chech_rate_limit(response)
        if sleep_time:
            time.sleep(sleep_time)
        # Return result
        return response.json().get('data')

    def search(self, query, limit = 500, fields = ("id", "title", "description", "type", "bulletinFamily", "cvss", "published", "modified", "href")):
        """
        Search Vulners database for the abstract query

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param limit: Search size. Default is 500 elements limit. 10000 is absolute maximum.
        :param fields: Returnable fields of the data model.
        :return: List of the found documents.
        """
        total_bulletins = limit or self.__search(query, 0, 0, ['id']).get('total')
        dataDocs = []

        for skip in range(0, total_bulletins, min(self.search_size, limit or self.search_size)):
            results = self.__search(query, skip, min(self.search_size, limit or self.search_size), fields or [])
            for element in results.get('search'):
                    dataDocs.append(element.get('_source'))
        return dataDocs
