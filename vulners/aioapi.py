# -*- coding: utf-8 -*-
# ===============================
#    Vulners async API wrapper
# ===============================

# Imports
import re
import json
import aiohttp
from io import BytesIO
from zipfile import ZipFile
import warnings

from . import __version__ as api_version


# Asyncio based API wrapper class

class AioVulners(object):

    def __init__(self, proxies=None, session=None, close_session_on_exit=True):
        """
        Set default URLs and create session object

        :param proxies: {} dict for proxy supporting. Example: {"https": "myproxy.com:3128"}
        :param session: Existing aiohttp.ClientSession or None
        :param close_session_on_exit:
        """

        # Default URL's for the Vulners API
        self.__vulners_urls = {
            'search':       "https://vulners.com/api/v3/search/lucene/",
            'software':     "https://vulners.com/api/v3/burp/software/",
            'id':           "https://vulners.com/api/v3/search/id/",
            'suggest':      "https://vulners.com/api/v3/search/suggest/",
            'ai':           "https://vulners.com/api/v3/ai/scoretext/",
            'archive':      "https://vulners.com/api/v3/archive/collection/"
        }
        # Default search parameters
        self.__search_size = 100

        self.__close_session_on_exit = close_session_on_exit

        if proxies is not None:
            if not isinstance(proxies, dict):
                raise TypeError("Proxies must be a dict type")
        self.__proxies = proxies

        if session is not None:
            if not isinstance(session, aiohttp.ClientSession):
                raise TypeError("Session must be an aiohttp.ClientSession instance or None")
        # Requests opener
        self.__opener = session

    async def __adapt_response_content(self, response):
        """
        Check if response is a JSON and return it. Otherwise - return raw content

        :param response: Requests response
        :return: {} or raw content
        """
        if re.match('.*json.*', response.headers.get('content-type'), re.IGNORECASE):
            results = await response.json()
            data = results.get('data')
            if data.get('error'):
                warnings.warn("%s" % data.get('error'))
            return data
        return response.content

    async def __vulners_get_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if not self.__opener:
            self.__opener = aiohttp.ClientSession(headers={'User-Agent': 'Vulners Python API %s' % api_version})
        async with self.__opener.get(self.__vulners_urls[vulners_url_key], proxy=self.__proxies,
                                     json=json_parameters) as response:
            return await self.__adapt_response_content(response)

    async def __vulners_post_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if not self.__opener:
            self.__opener = aiohttp.ClientSession(headers={'User-Agent': 'Vulners Python API %s' % api_version})
        async with self.__opener.post(self.__vulners_urls[vulners_url_key], proxy=self.__proxies,
                                      json=json_parameters) as response:
            return await self.__adapt_response_content(response)

    async def __archive(self, type, datefrom, dateto):
        """
        Tech wrapper for the archive gathering

        :param type: Collection type
        :param datefrom: Start date
        :param dateto: End date
        :return: ZIP archive
        """
        if not isinstance(type, str):
            raise TypeError("Type expected to be a string")
        if not isinstance(datefrom, str):
            raise TypeError("Datefrom expected to be a string")
        if not isinstance(dateto, str):
            raise TypeError("Dateto expected to be a string")
        return await self.__vulners_get_request('archive', {'type':type, 'datefrom':datefrom, 'dateto':dateto})

    async def __search(self, query, skip, size, fields=()):
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
        return await self.__vulners_post_request('search', {"query":query, 'skip':skip or 0, 'size':size or 0, 'fields':fields or []})

    async def __id(self, identificator, references):
        """
        Tech ID vulnerability get wrapper

        :param id: Search query.
        :param references: How much bulletins to skip.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(identificator, (str, list)):
            raise TypeError("Search ID expected to be a string or list of strings")
        if not isinstance(references, bool):
            raise TypeError("References  expected to be a bool")

        search_request = {"id": identificator}
        if references == True:
            search_request['references'] = "True"
        return await self.__vulners_post_request('id', search_request)

    async def __burpSoftware(self, software, version, type, maxVulnerabilities):
        """
        Tech Burp Software scanner call wrapper for internal lib usage

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
        return await self.__vulners_post_request('software', {"software":software, 'version':version, 'type':type, 'maxVulnerabilities':maxVulnerabilities})

    async def __suggest(self, type, field_name):
        """
        Tech wrapper for the suggest call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(type, str):
            raise TypeError("Type query expected to be a string")
        if not isinstance(field_name, str):
            raise TypeError("field_name query expected to be a string")
        return await self.__vulners_post_request('suggest', {"type":type, 'fieldName':field_name})

    async def __ai_score(self, text):
        """
        Tech wrapper for the AI scoring call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(text, str):
            raise TypeError("Text expected to be a string")
        return await self.__vulners_post_request('ai', {"text":text})

    async def search(self, query, limit=100, fields=("id", "title", "description", "type", "bulletinFamily", "cvss", "published", "modified", "href")):
        """
        Search Vulners database for the abstract query

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param limit: Search size. Default is 100 elements limit. 10000 skip is absolute maximum.
        :param fields: Returnable fields of the data model.
        :return: List of the found documents.
        """
        total_bulletins = limit or await self.__search(query, 0, 0, ['id']).get('total')
        dataDocs = []

        for skip in range(0, total_bulletins, min(self.__search_size, limit or self.__search_size)):
            results = await self.__search(query, skip, min(self.__search_size, limit or self.__search_size), fields or [])
            for element in results.get('search'):
                    dataDocs.append(element.get('_source'))
        return dataDocs

    async def searchExploit(self, query, lookup_fields=None, limit=500, fields=("id", "title", "description", "cvss", "href", "sourceData")):
        """
        Search Vulners database for the exploits

        :param query: Print here software name and criteria
        :param lookup_fileds: Make a strict search using lookup limit. Like ["title"]
        :param limit: Search size. Default is 500 elements limit. 10000 is absolute maximum.
        :param fields: Returnable fields of the data model.
        :return: List of the found documents.
        """
        if lookup_fields:
            if not isinstance(lookup_fields, (list, set, tuple)) or not all(isinstance(item, str) for item in lookup_fields):
                raise TypeError('lookup_fields list is expected to be a list of strings')
            searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join(
                "%s:\"%s\"" % (lField, query) for lField in lookup_fields)
        else:
            searchQuery = "bulletinFamily:exploit AND %s" % query

        total_bulletins = limit or await self.__search(searchQuery, 0, 0, ['id']).get('total')
        dataDocs = []

        for skip in range(0, total_bulletins, min(self.__search_size, limit or self.__search_size)):
            results = await self.__search(searchQuery, skip, min(self.__search_size, limit or self.__search_size), fields or [])
            for element in results.get('search'):
                dataDocs.append(element.get('_source'))
        return dataDocs

    async def softwareVulnerabilities(self, name, version, maxVulnerabilities = 50):
        """
        Find software vulnerabilities using name and version detection

        :param name: Software name, e.g. 'httpd'
        :param version: Software version, e.g. '2.1'
        :param maxVulnerabilities: Maximum count of found vulnerabilities before marking it as False Positive
        :return: {merged by family dict}
        """
        if not isinstance(maxVulnerabilities, int):
            raise TypeError("maxVulnerabilities parameter suggested to be integer")
        dataDocs = {}
        results = await self.__burpSoftware(name, version, type='software', maxVulnerabilities = maxVulnerabilities)
        for element in results.get('search', []):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    async def cpeVulnerabilities(self, cpeString, maxVulnerabilities = 50):
        """
        Find software vulnerabilities using CPE string. See CPE references at https://cpe.mitre.org/specification/

        :param cpe: CPE software string, see https://cpe.mitre.org/specification/
        :param maxVulnerabilities: Maximum count of found vulnerabilities before marking it as False Positive
        :return: {merged by family dict}
        """
        if not isinstance(maxVulnerabilities, int):
            raise TypeError("maxVulnerabilities parameter suggested to be integer")
        dataDocs = {}
        if len(cpeString.split(":")) <= 4:
            raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/. Awaiting like 'cpe:/a:cybozu:garoon:4.2.1'")
        version = cpeString.split(":")[4]
        results = await self.__burpSoftware(cpeString, version, type='cpe', maxVulnerabilities = maxVulnerabilities)
        for element in results.get('search', []):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    async def document(self, identificator):
        """
        Fetch information about bulletin by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = await self.__id(identificator, references=False)
        return results.get('documents', {}).get(identificator, {})

    async def documentList(self, identificatorList):
        """
        Fetch information about multiple bulletin identificators

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """

        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, str) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return await self.__id(identificatorList, references=False).get('documents')

    async def references(self, identificator):
        """
        Fetch information about bulletin references by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = await self.__id(identificator, references=True)
        return results.get('references', {}).get(identificator, {})

    async def referencesList(self, identificatorList):
        """
        Fetch information about multiple bulletin references

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """
        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, str) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return await self.__id(identificatorList, references=True).get('references')

    async def collections(self):
        """
        Get list of the Vulners collection type names

        :return: List of available collections
        """
        return await self.__suggest(type='distinct', field_name='type').get('suggest')

    async def suggest(self, field_name):
        """
        Suggest possible data field values

        :param field_name: Data model field name. As example 'type', 'published'.
        :return: List of possible values
        """
        return await self.__suggest(type='distinct', field_name=field_name).get('suggest')

    async def aiScore(self, text):
        """
        Score free text upon Vulners AI network

        :param text: Text data
        :return: Float score
        """
        return await self.__ai_score(text).get('score', 0)

    async def archive(self, collection, start_date='1950-01-01', end_date='2199-01-01'):
        """
        Get dict with entire collection data

        :param collection: Collection name
        :return: {} collection
        """
        if collection not in await self.collections():
            raise ValueError("Can't get archive for the unknown collection. Available collections: %s" % self.collections())
        zipped_json = await self.__archive(type=collection, datefrom=start_date, dateto=end_date)
        with ZipFile(BytesIO(zipped_json)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            return json.loads(zip_file.open(file_name).read())

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.__close_session_on_exit and self.__opener:
            await self.__opener.close()
