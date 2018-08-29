# -*- coding: utf-8 -*-
# ===============================
#      Vulners API wrapper
# ===============================

# Imports
import re
import json
import requests
from io import BytesIO
from zipfile import ZipFile
import warnings
from six import string_types

from .common.ratelimit import rate_limited
from . import __version__ as api_version


# Base API wrapper class

class Vulners(object):

    """
    This variable holds information that is dynamically updated about current ratelimits for the API.
    Vulners backend dynamic blocking cache is changing this value depending on the server load and client license.
    One more reason to use API key, rate limits are higher.
    """
    api_rate_limits = {
        'default':10
    }

    def __init__(self, api_key = None, proxies=None):
        """
        Set default URLs and create session object

        :param proxies: {} dict for proxy supporting. Example: {"https": "myproxy.com:3128"}
        """

        # Default URL's for the Vulners API
        self.__vulners_urls = {
            'search':       "https://vulners.com/api/v3/search/lucene/",
            'software':     "https://vulners.com/api/v3/burp/software/",
            'id':           "https://vulners.com/api/v3/search/id/",
            'suggest':      "https://vulners.com/api/v3/search/suggest/",
            'ai':           "https://vulners.com/api/v3/ai/scoretext/",
            'archive':      "https://vulners.com/api/v3/archive/collection/",
            'apiKey':       "https://vulners.com/api/v3/apiKey/valid/",
            'audit':        "https://vulners.com/api/v3/audit/audit/",
            'rules':        "https://vulners.com/api/v3/burp/rules/",
            'autocomplete': "https://vulners.com/api/v3/search/autocomplete/",
        }
        # Default search parameters
        self.__search_size = 100

        # Requests opener
        self.__opener = requests.session()
        # Setup pool size and Keep Alive
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100, pool_maxsize=100)
        self.__opener.mount('https://', adapter)
        self.__opener.headers.update({'Connection': 'Keep-Alive'})
        #
        self.__opener.headers.update({'User-Agent': 'Vulners Python API %s' % api_version})
        if proxies is not None:
            if not isinstance(proxies, dict):
                raise TypeError("Proxies must be a dict type")
            self.__opener.proxies.update(proxies)

        # API key validation

        self.__api_key = api_key

        if api_key and not isinstance(api_key, string_types):
            raise TypeError("api_key parameter must be a string value")

        if api_key and not self.__validKey(api_key):
            raise ValueError("Wrong Vulners API key. Please, follow https://vulners.com to obtain correct one.")

    def __adapt_response_content(self, response):
        """
        Check if response is a JSON and return it. Otherwise - return raw content

        :param response: Requests response
        :return: {} or raw content
        """
        if re.match('.*json.*', response.headers.get('content-type'), re.IGNORECASE):
            results = response.json().get('data')
            if results.get('error'):
                warnings.warn("%s" % results.get('error'))
            return results
        return response.content

    def __update_ratelimit(self, api_short_name, response):
        """
        Private method for controlling ratelimit of the API calls

        :param api_short_name: API shortened name from the __vulners_urls
        :param response: requests lib response
        :return: True/False
        """
        headers = response.headers

        ratelimit = headers.get('X-Vulners-Ratelimit-Reqlimit')
        current_rate = headers.get('X-Vulners-Ratelimit-Rate')

        if ratelimit and current_rate:
            # Now we need to make a throttling, not just setting up ratelimit
            # Convert to floats
            # Any ideas how to make it better?

            # Take a 80% not to playing with the banhammer
            ratelimit = float(ratelimit)
            ratelimit = (80 * ratelimit) / 100.0
            current_rate = float(current_rate)

            if current_rate <= ratelimit:
                self.api_rate_limits[api_short_name] = ratelimit
            else:
                rate_difference = (current_rate / (ratelimit / 100)) / 60
                self.api_rate_limits[api_short_name] = (rate_difference * ratelimit) / 100.0
            return True

        return False

    @rate_limited(api_rate_limits)
    def __vulners_get_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if self.__api_key:
            json_parameters['apiKey'] = self.__api_key
        response = self.__opener.get(self.__vulners_urls[vulners_url_key], params=json_parameters)
        # Update rate limits
        self.__update_ratelimit(vulners_url_key, response)
        return self.__adapt_response_content(response)

    @rate_limited(api_rate_limits)
    def __vulners_post_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if self.__api_key:
            json_parameters['apiKey'] = self.__api_key
        response = self.__opener.post(self.__vulners_urls[vulners_url_key], json=json_parameters)
        # Update rate limits
        self.__update_ratelimit(vulners_url_key, response)
        return self.__adapt_response_content(response)

    def __validKey(self, api_key):
        """
        Tech wrapper for validating API key

        :param api_key: Vulners API Key
        :return: True/False
        """
        if not isinstance(api_key, string_types):
            raise TypeError("api_key expected to be a string")

        return self.__vulners_post_request('apiKey', {'keyID':api_key}).get('valid')

    def __archive(self, type, datefrom, dateto):
        """
        Tech wrapper for the archive gathering

        :param type: Collection type
        :param datefrom: Start date
        :param dateto: End date
        :return: ZIP archive
        """
        if not isinstance(type, string_types):
            raise TypeError("Type expected to be a string")
        if not isinstance(datefrom, string_types):
            raise TypeError("Datefrom expected to be a string")
        if not isinstance(dateto, string_types):
            raise TypeError("Dateto expected to be a string")
        return self.__vulners_get_request('archive', {'type':type, 'datefrom':datefrom, 'dateto':dateto})

    def __search(self, query, skip, size, fields=()):
        """
        Tech search wrapper for internal lib usage

        :param query: Search query.
        :param skip: How much bulletins to skip.
        :param size: How much results to return.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(query, string_types):
            raise TypeError("Search query expected to be a string")
        if not isinstance(skip, int) and skip in range(0, 10000):
            raise TypeError("Skip  expected to be a int in range 0-10000")
        if not isinstance(size, int) and size in range(0, 10000):
            raise TypeError("Size  expected to be a int in range 0-10000")
        return self.__vulners_post_request('search', {"query":query, 'skip':skip or 0, 'size':size or 0, 'fields':fields or []})

    def __id(self, identificator, references):
        """
        Tech ID vulnerability get wrapper

        :param id: Search query.
        :param references: How much bulletins to skip.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(identificator, (string_types, list)):
            raise TypeError("Search ID expected to be a string or list of strings")
        if not isinstance(references, bool):
            raise TypeError("References  expected to be a bool")

        search_request = {"id": identificator}
        if references == True:
            search_request['references'] = "True"
        return self.__vulners_post_request('id', search_request)

    def __audit(self, os, os_version, package):
        """
        Tech Audit call wrapper for internal lib usage

        :param os: OS name
        :param os_version: OS version
        :param package: List of the installed packages
        :return: {'packages':[LIST OF VULNERABLE PACKAGES], 'reasons':LIST OF REASONS, 'vulnerabilities':[LIST OF VULNERABILITY IDs]}
        """
        if not isinstance(os, string_types):
            raise TypeError("OS expected to be a string")
        if not isinstance(os_version, string_types):
            raise TypeError("OS Version expected to be a string")
        if not isinstance(package, (list, set)):
            raise TypeError("Package expected to be a list or set")
        return self.__vulners_post_request('audit', {"os":os, 'version':os_version, 'package':package})

    def __burpSoftware(self, software, version, type, maxVulnerabilities):
        """
        Tech Burp Software scanner call wrapper for internal lib usage

        :param query: Search query.
        :param skip: How much bulletins to skip.
        :param size: How much results to return.
        :return: {'search':[SEARCH_RESULTS_HERE], 'total':TOTAL_BULLETINS_FOUND}
        """
        if not isinstance(software, string_types):
            raise TypeError("Software query expected to be a string")
        if not isinstance(version, string_types):
            raise TypeError("Version query expected to be a string")
        if not isinstance(type, string_types) or type not in ('software', 'cpe'):
            raise TypeError("Type query expected to be a string and in [software, cpe]")
        return self.__vulners_post_request('software', {"software":software, 'version':version, 'type':type, 'maxVulnerabilities':maxVulnerabilities})

    def __suggest(self, type, field_name):
        """
        Tech wrapper for the suggest call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(type, string_types):
            raise TypeError("Type query expected to be a string")
        if not isinstance(field_name, string_types):
            raise TypeError("field_name query expected to be a string")
        return self.__vulners_post_request('suggest', {"type":type, 'fieldName':field_name})

    def __ai_score(self, text):
        """
        Tech wrapper for the AI scoring call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(text, string_types):
            raise TypeError("Text expected to be a string")
        return self.__vulners_post_request('ai', {"text":text})

    def __autocomplete(self, query):
        """
        Tech wrapper for the Autocomplete call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(query, string_types):
            raise TypeError("Query expected to be a string")
        return self.__vulners_post_request('autocomplete', {"query":query})

    def search(self, query, limit=100, offset=0, fields=("id", "title", "description", "type", "bulletinFamily", "cvss", "published", "modified", "href")):
        """
        Search Vulners database for the abstract query

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param limit: Search size. Default is 100 elements limit. 10000 skip is absolute maximum.
        :param offset: Skip this amount of documents
        :param fields: Returnable fields of the data model.
        :return: List of the found documents, total found bulletins
        """
        total_bulletins = limit or self.__search(query, 0, 0, ['id']).get('total')
        dataDocs = []
        total = 0
        for skip in range(offset, total_bulletins, min(self.__search_size, limit or self.__search_size)):
            results = self.__search(query, skip, min(self.__search_size, limit or self.__search_size), fields or [])
            total = max(results.get('total'), total)
            for element in results.get('search'):
                    dataDocs.append(element.get('_source'))
        return dataDocs, total

    def searchPage(self, query, pageSize = 20, offset=0, fields=("id", "title", "description", "type", "bulletinFamily", "cvss", "published", "modified", "href")):
        """
        Search Vulners database for the abstract query, page mode

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param pageSize: Search size. Default is 20 in the single hit. 100 is the maximum
        :param offset: Skip this amount of documents
        :param fields: Returnable fields of the data model.
        :return: List of the found documents, total found bulletins
        """

        results = self.__search(query, offset, min(pageSize, self.__search_size), fields or [])
        total = results.get('total')
        dataDocs = [element.get('_source') for element in results.get('search')]
        return dataDocs, total

    def searchExploit(self, query, lookup_fields=None, limit=500, offset=0, fields=("id", "title", "description", "cvss", "href", "sourceData")):
        """
        Search Vulners database for the exploits

        :param query: Print here software name and criteria
        :param lookup_fileds: Make a strict search using lookup limit. Like ["title"]
        :param limit: Search size. Default is 500 elements limit. 10000 is absolute maximum.
        :param offset: Skip this amount of documents
        :param fields: Returnable fields of the data model.
        :return: List of the found documents, total found bulletins
        """
        if lookup_fields:
            if not isinstance(lookup_fields, (list, set, tuple)) or not all(isinstance(item, string_types) for item in lookup_fields):
                raise TypeError('lookup_fields list is expected to be a list of strings')
            searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join(
                "%s:\"%s\"" % (lField, query) for lField in lookup_fields)
        else:
            searchQuery = "bulletinFamily:exploit AND %s" % query

        total_bulletins = limit or self.__search(searchQuery, 0, 0, ['id']).get('total')
        total = 0
        dataDocs = []

        for skip in range(offset, total_bulletins, min(self.__search_size, limit or self.__search_size)):
            results = self.__search(searchQuery, skip, min(self.__search_size, limit or self.__search_size), fields or [])
            total = max(results.get('total'), total)
            for element in results.get('search'):
                dataDocs.append(element.get('_source'))
        return dataDocs, total

    def searchExploitPage(self, query, lookup_fields=None, pageSize=20, offset=0, fields=("id", "title", "description", "cvss", "href", "sourceData")):
        """
        Search Vulners database for the exploits, page mode

        :param query: Print here software name and criteria
        :param lookup_fileds: Make a strict search using lookup limit. Like ["title"]
        :param pageSize: Search size. Default is 20 in the single hit. 100 is the maximum
        :param offset: Skip this amount of documents
        :param fields: Returnable fields of the data model.
        :return: List of the found documents, total found bulletins
        """
        if lookup_fields:
            if not isinstance(lookup_fields, (list, set, tuple)) or not all(isinstance(item, string_types) for item in lookup_fields):
                raise TypeError('lookup_fields list is expected to be a list of strings')
            searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join(
                "%s:\"%s\"" % (lField, query) for lField in lookup_fields)
        else:
            searchQuery = "bulletinFamily:exploit AND %s" % query

        results = self.__search(searchQuery, offset, min(pageSize, self.__search_size), fields or [])
        total = results.get('total')
        dataDocs = [element.get('_source') for element in results.get('search')]
        return dataDocs, total

    def softwareVulnerabilities(self, name, version, maxVulnerabilities = 50):
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
        results = self.__burpSoftware(name, version, type='software', maxVulnerabilities = maxVulnerabilities)
        for element in results.get('search', []):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    def cpeVulnerabilities(self, cpeString, maxVulnerabilities = 50):
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
        results = self.__burpSoftware(cpeString, version, type='cpe', maxVulnerabilities = maxVulnerabilities)
        for element in results.get('search', []):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    def document(self, identificator):
        """
        Fetch information about bulletin by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = self.__id(identificator, references=False)
        return results.get('documents', {}).get(identificator, {})

    def audit(self, os, os_version, package):
        """
        Linux Audit API for analyzing package vulnerabilities.
        Accepts RPM and DEB based package lists.
        For collecting RPM use command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'
        For collecting DEB use command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'

        :param os: Full name of the OS. Like Ubuntu, Debian, rhel, oraclelinux
        :param os_version: OS version
        :param package: List of the installed packages
        :return: {'packages':[LIST OF VULNERABLE PACKAGES], 'reasons':LIST OF REASONS, 'vulnerabilities':[LIST OF VULNERABILITY IDs]}
        """
        return self.__audit(os, os_version, package)

    def documentList(self, identificatorList):
        """
        Fetch information about multiple bulletin identificators

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """

        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, string_types) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return self.__id(identificatorList, references=False).get('documents')

    def references(self, identificator):
        """
        Fetch information about bulletin references by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = self.__id(identificator, references=True)
        return results.get('references', {}).get(identificator, {})

    def referencesList(self, identificatorList):
        """
        Fetch information about multiple bulletin references

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """
        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, string_types) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return self.__id(identificatorList, references=True).get('references')

    def collections(self):
        """
        Get list of the Vulners collection type names

        :return: List of available collections
        """
        return self.__suggest(type='distinct', field_name='type').get('suggest')

    def suggest(self, field_name):
        """
        Suggest possible data field values

        :param field_name: Data model field name. As example 'type', 'published'.
        :return: List of possible values
        """
        return self.__suggest(type='distinct', field_name=field_name).get('suggest')

    def aiScore(self, text):
        """
        Score free text upon Vulners AI network

        :param text: Text data
        :return: Float score
        """
        return self.__ai_score(text).get('score', 0)

    def rules(self):
        """
        Get collection of the regular expressions for the web application vulnerabilities detection

        :return: {'SOFTWARE NAME':{'regex':REGEX, 'alias':'SW NAME', 'type':'software/cpe'}}
        """
        return self.__vulners_get_request('rules', {}).get('rules', {})

    def archive(self, collection, start_date='1950-01-01', end_date='2199-01-01'):
        """
        Get dict with entire collection data

        :param collection: Collection name
        :return: {} collection
        """
        if collection not in self.collections():
            raise ValueError("Can't get archive for the unknown collection. Available collections: %s" % self.collections())
        zipped_json = self.__archive(type=collection, datefrom=start_date, dateto=end_date)
        with ZipFile(BytesIO(zipped_json)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            return json.loads(zip_file.open(file_name).read())

    def autocomplete(self, query):
        """
        Ask Vulners for possible suggestions to complete your query

        :param query: Vulners Search query, Lucene syntax
        :return: Float score
        """
        suggestions = self.__autocomplete(query).get('suggestions')
        return [suggested_query[0] for suggested_query in suggestions]
