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
        'search':"https://vulners.com/api/v3/search/lucene/",
        'software':"https://vulners.com/api/v3/burp/software",
        }
        # Default search parameters
        self.search_size = 100

        # Requests opener
        self.opener = requests.session()
        self.opener.headers = {'User-Agent': 'Vulners Python API'}

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

        # Return result
        results = response.json().get('data')
        if results.get('error'):
            raise Exception("%s" % results.get('error'))
        return results

    def __burpSoftware(self, software, version, type):
        """
        Tech search wrapper for internal lib usage

        :param query: Search query.
        :param skip: How much bulletins to skip.
        :param size: How much results to return.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(software, str):
            raise TypeError("Software query expected to be a string")
        if not isinstance(version, str):
            raise TypeError("Version query expected to be a string")
        if not isinstance(type, str) or type not in ('software', 'cpe'):
            raise TypeError("Type query expected to be a string and in [software, cpe]")
        search_request = {"software":software, 'version':version, 'type':type}
        response = self.opener.post(self.vulners_urls['software'], json=search_request)

        # Return result
        results = response.json().get('data')
        if results.get('error'):
            raise Exception("%s" % results.get('error'))
        return results

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

    def softwareVulnerabilities(self, name, version):
        """
        Find software vulnerabilities using name and version detection

        :param name: Software name, e.g. 'httpd'
        :param version: Software version, e.g. '2.1'
        :return: {merged by family dict}
        """
        dataDocs = {}
        results = self.__burpSoftware(name, version, type = 'software')
        for element in results.get('search'):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    def cpeVulnerabilities(self, cpeString):
        """
        Find software vulnerabilities using CPE string. See CPE references at https://cpe.mitre.org/specification/

        :param cpe: CPE software string, see https://cpe.mitre.org/specification/
        :return: {merged by family dict}
        """
        dataDocs = {}
        if len(cpeString.split(":")) <= 4:
            raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/. Awaiting like 'cpe:/a:cybozu:garoon:4.2.1'")
        version = cpeString.split(":")[4]
        results = self.__burpSoftware(cpeString, version, type = 'cpe')
        for element in results.get('search'):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs