# -*- coding: utf-8 -*-
# ===============================
#      Vulners API wrapper
# ===============================

# Imports
import re
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests
from io import BytesIO
from zipfile import ZipFile
import warnings
from six import string_types

from .common.ratelimit import rate_limited
from .common.cookiejar import PersistentCookieJar
from .common.attributeList import AttributeList
from . import __version__ as api_version



# Base API wrapper class

class Vulners(object):

    """
    This variable holds information that is dynamically updated about current ratelimits for the API.
    Vulners backend dynamic blocking cache is changing this value depending on the server load and client license.
    One more reason to use API key, rate limits are higher.

    Security notice:
    This API wrapper is using persistent Cookie Jar that is saved down to the OS tmp dir.
    It's used for better session handling at Vulners server side and really helps a lot not to overcreate sessions.
    But if you feels not comfortable - you can just turn it off at the init state setting "persistent = False"
    """

    # Vulners hostname is setting up individually. For on-premise installations it must be replaced with local one.

    vulners_hostname = 'https://vulners.com'

    # Default rate limits. Will be updated online.
    api_rate_limits = {
        'default':10
    }

    # Default URL's for the Vulners API
    api_endpoints = {
        'search': "/api/v3/search/lucene/",
        'software': "/api/v3/burp/softwareapi/",
        'id': "/api/v3/search/id/",
        'suggest': "/api/v3/search/suggest/",
        'ai': "/api/v3/ai/scoretext/",
        'archive': "/api/v3/archive/collection/",
        'apiKey': "/api/v3/apiKey/valid/",
        'audit': "/api/v3/audit/audit/",
        'rules': "/api/v3/burp/rules/",
        'autocomplete': "/api/v3/search/autocomplete/",
        'distributive': "/api/v3/archive/distributive/",
        'kbAudit':"/api/v3/audit/kb/",
        'softwareAudit':"/api/v3/burp/packages/"
    }

    # Default search size parameter
    search_size = 100

    # Default search fields
    # Can be extended or reduced for the query performance

    default_fields = [
            'id',
            'title',
            'description',
            'type',
            'bulletinFamily',
            'cvss',
            'published',
            'modified',
            'lastseen',
            'href',
            'sourceHref',
            'sourceData',
            'cvelist'
    ]

    # Fail-safe retry parameters

    # Retry status codes
    retry_codes = (500, 502, 503, 504)
    # How many times to retry
    retry_count = 3
    # How many seconds to sleep before next try
    backoff_factor = 1


    def __init__(self, api_key, proxies=None, persistent=True):
        """
        Set default URLs and create session object

        :param proxies: {} dict for proxy supporting. Example: {"https": "myproxy.com:3128"}
        :param api_key: string with Vulners API key. You can obtain one from the https://vulners.com
        :param persistent: Boolean. Regulates cookie storage policy. If set to true - will save down session cookie for reuse.
        """
        self.vulners_urls = dict((key, self.vulners_hostname + self.api_endpoints.get(key)) for key in self.api_endpoints)

        # Requests opener. If persistent option is active - try to load
        self.__opener = requests.session()
        if persistent:
            self.__opener.cookies = PersistentCookieJar()
        # Setup pool size and Keep Alive
        retries = Retry(total=self.retry_count,
                        backoff_factor=self.backoff_factor,
                        status_forcelist=self.retry_codes,
                        method_whitelist = ['POST', 'GET']
                        )
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retries)
        self.__opener.mount(self.vulners_hostname, adapter)
        self.__opener.headers.update({'Connection': 'Keep-Alive'})
        #
        self.__opener.headers.update({'User-Agent': 'Vulners Python API %s' % api_version})
        if proxies is not None:
            if not isinstance(proxies, dict):
                raise TypeError("Proxies must be a dict type")
            self.__opener.proxies.update(proxies)

        # API key validation

        if not api_key:
            raise ValueError("API key must be provided. You can obtain one for free at https://vulners.com")

        if api_key and not isinstance(api_key, string_types):
            raise TypeError("api_key parameter must be a string value")

        self.__api_key = api_key

        if api_key and not self.__validKey(api_key):
            raise ValueError("Wrong Vulners API key. Please, follow https://vulners.com to obtain correct one.")

    def __adapt_response_content(self, response):
        """
        Check if response is a JSON and return it. Otherwise - return raw content
        Also check 402 + 9000 response from backend: API key is invalid

        :param response: Requests response
        :return: {} or raw content
        """
        if response.status_code == 402 and response.json()['data']['errorCode'] == 9000:
            raise AssertionError("Bad or no API key provided. Please, obtain correct one registering at https://vulners.com")

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
    def vulners_get_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if self.__api_key:
            json_parameters['apiKey'] = self.__api_key
        response = self.__opener.get(self.vulners_urls[vulners_url_key], params=json_parameters)
        # Update rate limits
        self.__update_ratelimit(vulners_url_key, response)
        return self.__adapt_response_content(response)

    @rate_limited(api_rate_limits)
    def vulners_post_request(self, vulners_url_key, json_parameters):
        """
        Tech wrapper for the unified

        :param vulners_url_key: Key for the self.vulners_urls dict
        :param json_parameters: {} dict for the API call
        :return: 'data' key from the response
        """
        # Return result
        if self.__api_key:
            json_parameters['apiKey'] = self.__api_key
        response = self.__opener.post(self.vulners_urls[vulners_url_key], json=json_parameters)
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

        return self.vulners_post_request('apiKey', {'keyID':api_key}).get('valid')

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
        return self.vulners_get_request('archive', {'type':type, 'datefrom':'' or datefrom, 'dateto':'' or dateto})

    def __distributive(self, os, version):
        """
        Tech wrapper for the distributive archive gathering

        :param type: Collection type
        :param datefrom: Start date
        :param dateto: End date
        :return: ZIP archive
        """
        if not isinstance(os, string_types):
            raise TypeError("OS expected to be a string")
        if not isinstance(version, string_types):
            raise TypeError("Version expected to be a string")
        return self.vulners_get_request('distributive', {'os':os, 'version':version})

    def __search(self, query, skip, size, fields):
        """
        Tech search wrapper for internal lib usage

        :param query: Search query.
        :param skip: How many bulletins to skip.
        :param size: How many results to return.
        :return: {'search': [SEARCH_RESULTS_HERE], 'exactMatch': <<>>, 'references': <<>>, 'total': TOTAL_BULLETINS_FOUND, 'maxSearchSize': 100}

        """
        if not isinstance(query, string_types):
            raise TypeError("Search query expected to be a string")
        if not isinstance(skip, int) or not 0 <= skip <= 9999:
            raise TypeError(
                "Skip expected to be an int in range 0-9999, Vulners "
                "won't provide records if skip is greater than that.")
        if not isinstance(size, int) or not 0 <= size <= 100:
            raise TypeError(
                "Size expected to be an int in range 0-100. "
                "Vulners has a hard limit on max response size equal to 100")
        return self.vulners_post_request('search', {"query":query, 'skip': skip or 0, 'size': size or 0, 'fields': fields or []})

    def __id(self, identificator, references, fields):
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

        search_request = {"id": identificator, "fields":fields or []}
        if references == True:
            search_request['references'] = "True"
        return self.vulners_post_request('id', search_request)

    def __software_audit(self, packages, os, os_version):
        """
        Tech Software Audit call wrapper for internal lib usage

        :param os: OS name
        :param os_version: OS version
        :param packages: List of the dicts
        :return: {'vulnerabilities':[LIST OF VULNERABLE PACKAGES AND DESC]}
        """
        if not isinstance(os, string_types):
            raise TypeError("OS expected to be a string")
        if not isinstance(os_version, string_types):
            raise TypeError("OS Version expected to be a string")
        if not isinstance(packages, (list, set)):
            raise TypeError("Package expected to be a list or set")
        return self.vulners_post_request('softwareAudit', {"os":os, 'osVersion':os_version, 'packages':packages})

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
        return self.vulners_post_request('audit', {"os":os, 'version':os_version, 'package':package})

    def __kbAudit(self, os, kb_list):
        """
        Tech Windows KB audit call wrapper for internal lib usage

        :param os_name: Window
        :param kb_list: List of installed KB's
        :return: {'cvelist':[], 'kbMissed':[]}
        """
        if not isinstance(os, string_types):
            raise TypeError("OS expected to be a string")
        if not isinstance(kb_list, (list, set)):
            raise TypeError("kb_list expected to be a list or set")
        return self.vulners_post_request('kbAudit', {"os":os, 'kbList':kb_list})

    def __burpSoftware(self, software, version, type, maxVulnerabilities, exactmatch=False):
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
        if not isinstance(exactmatch, bool):
            raise TypeError("exactmatch query expected to be a boolean")
        return self.vulners_post_request('software', {"software":software,
                                                      'version':version,
                                                      'type':type,
                                                      'maxVulnerabilities':maxVulnerabilities,
                                                      'exactmatch':exactmatch})

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
        return self.vulners_post_request('suggest', {"type":type, 'fieldName':field_name})

    def __ai_score(self, text):
        """
        Tech wrapper for the AI scoring call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(text, string_types):
            raise TypeError("Text expected to be a string")
        return self.vulners_post_request('ai', {"text":text})

    def __autocomplete(self, query):
        """
        Tech wrapper for the Autocomplete call

        :param type: Search query.
        :param field_name: How much bulletins to skip.
        :return: List of possible values
        """
        if not isinstance(query, string_types):
            raise TypeError("Query expected to be a string")
        return self.vulners_post_request('autocomplete', {"query":query})

    def search(self, query, limit=100, offset=0, fields=None):
        """
        Search Vulners database for the abstract query

        Retrieves up to 10000 records.

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param limit: a.k.a. search size. Default is 100 records.
        :param offset: Skip this amount of documents. 9999 is Vulners' absolute maximum.
        :param fields: Returnable fields of the data model.
        :return: AttributeList of the found documents. Total number of found bulletins can be retrieved on r.total
        """
        assert type(limit) == int, "limit can only be an int"

        total_bulletins = limit or self.__search(query, 0, 0, ['id']).get('total')
        dataDocs = []
        total = 0
        for skip in range(offset, total_bulletins, min(self.search_size, limit or self.search_size)):
            new_page = self.searchPage(query, min(self.search_size, limit or self.search_size), skip, fields or self.default_fields)
            dataDocs += new_page
            total = max(new_page.total, total)
        return AttributeList(dataDocs, total = total)

    def searchPage(self, query, pageSize = 20, offset=0, fields=None):
        """
        Search Vulners database for the abstract query, page mode

        :param query: Abstract Vulners query. See https://vulners.com/help for the details.
        :param pageSize: Search size. Default is 20 in the single hit. 100 is the maximum
        :param offset: Skip this amount of documents. 9999 is the hard limit
        :param fields: Returnable fields of the data model.
        :return: List of the found documents, total found bulletins
        """

        results = self.__search(query, offset, min(pageSize, self.search_size), fields or self.default_fields)
        if not isinstance(results, dict):
                raise AssertionError(
                    "Asserted result failed. No JSON returned from Vulners.\n"
                    "Returned response: %s..." % results[:100])
        total = results.get('total')
        dataDocs = [element.get('_source') for element in results.get('search')]
        return AttributeList(dataDocs, total = total)

    def searchExploit(self, query, lookup_fields=None, limit=100, offset=0, fields=None):
        """
        Search Vulners database for the exploits

        :param query: Print here software name and criteria
        :param lookup_fields: Make a strict search using lookup limit. Like ["title"]
        :param limit: Search size. Default is 500 elements limit. 10000 is absolute maximum.
        :param offset: Skip this amount of documents. 9999 is absolute maximum.
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

        for skip in range(offset, total_bulletins, min(self.search_size, limit or self.search_size)):
            new_page = self.searchPage(searchQuery, min(self.search_size, limit or self.search_size), skip, fields or self.default_fields + ['sourceData'])
            dataDocs += new_page
            total = max(new_page.total, total)
        return AttributeList(dataDocs, total = total)


    def searchExploitPage(self, query, lookup_fields=None, pageSize=20, offset=0, fields=None):
        """
        Search Vulners database for the exploits, page mode

        :param query: Print here software name and criteria
        :param lookup_fields: Make a strict search using lookup limit. Like ["title"]
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

        results = self.__search(searchQuery, offset, min(pageSize, self.search_size), fields or self.default_fields + ['sourceData'])
        total = results.get('total')
        dataDocs = [element.get('_source') for element in results.get('search')]
        return AttributeList(dataDocs, total = total)


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

    def cpeVulnerabilities(self, cpeString, maxVulnerabilities = 50, exactmatch = False):
        """
        Find software vulnerabilities using CPE string. See CPE references at https://cpe.mitre.org/specification/

        :param cpe: CPE software string, see https://cpe.mitre.org/specification/
        :param maxVulnerabilities: Maximum count of found vulnerabilities before marking it as False Positive
        :param exactmatch: if true searches for bulletins corresponding to the specified minor version and revision
        :return: {merged by family dict}
        """
        if not isinstance(maxVulnerabilities, int):
            raise TypeError("maxVulnerabilities parameter suggested to be integer")
        if not isinstance(exactmatch, bool):
            raise TypeError("exactmatch parameter suggested to be boolean")
        dataDocs = {}

        cpe_split = cpeString.split(":")
        if len(cpe_split) <= 4:
            raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/.")
        if cpe_split[1] == '2.3':
            version = cpe_split[5]
        elif cpe_split[1] in '/a/o/h':
            version = cpe_split[4]
        else:
            raise ValueError("Malformed CPE string. Please, refer to the https://cpe.mitre.org/specification/.")

        results = self.__burpSoftware(cpeString, version, type='cpe', maxVulnerabilities = maxVulnerabilities, exactmatch=exactmatch)
        for element in results.get('search', []):
            elementData = element.get('_source')
            dataDocs[elementData.get('bulletinFamily')] = dataDocs.get(elementData.get('bulletinFamily'), []) + [elementData]
        return dataDocs

    def document(self, identificator, fields = None, references = False):
        """
        Fetch information about bulletin by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = self.__id(identificator, references=references, fields = fields or ["*"])
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

    def software_audit(self, os, os_version, packages):
        """
        Software audit allow you to analyse software name/version pairs for the CVE's.
        Packages input format, list of dicts:
        [{"software":"Mozilla Firefox", "version":"80.0.1"}]

        :param os: Full name of the OS. Like Ubuntu, Debian, rhel, oraclelinux, Mac OS, Windows
        :param os_version: OS version
        :param packages: List of the software dicts
        :return: {}
        """
        return self.__software_audit(packages, os, os_version)

    def kbAudit(self, os, kb_list):
        """
        Windows KB audit function.

        :param os_name: Windows OS name, like "Windows Server 2012 R2"
        :param kb_list: List of installed KB's, ["KB2918614", "KB2918616"....]
        :return: {'cvelist':[], 'kbMissed':[]}
        """
        return self.__kbAudit(os, kb_list)

    def kbSuperseeds(self, kb_identificator):
        """
        Returns list of superseeds KB's and parentseeds KB's.
        Superseeds means "what KB are covered by this KB".
        Parentseeds means "what KB are covering this KB".

        superseeds_list --> KB --> parentseeds_list

        :param kb_identificator: Microsoft KB identificator
        :return: {'superseeds':[], 'parentseeds':[]}
        """
        if not isinstance(kb_identificator, string_types):
            raise TypeError('KB Identificator expected to be a a string')
        kb_candidate = self.__id(identificator=kb_identificator, fields=['superseeds', 'parentseeds'], references=False)
        kb_document = kb_candidate.get('documents',{}).get(kb_identificator, {})
        return {'superseeds':kb_document.get('superseeds', []), 'parentseeds':kb_document.get('parentseeds', [])}

    def kbUpdates(self, kb_identificator, fields = None):
        """
        Returns list of updates for KB
        :param kb_identificator: Microsoft KB identificator
        :return: List of the found documents, total found bulletins
        """
        if not isinstance(kb_identificator, string_types):
            raise TypeError('KB Identificator expected to be a a string')

        query = "type:msupdate AND kb:(%s)" % (kb_identificator)

        total_bulletins = self.__search(query, 0, 0, ['id']).get('total')
        dataDocs = []
        total = 0
        offset = 0
        limit = 1000
        for skip in range(offset, total_bulletins, limit):
            new_page = self.searchPage(query, limit, skip, fields or self.default_fields)
            dataDocs += new_page
            total = max(new_page.total, total)
        return AttributeList(dataDocs, total=total)

    def documentList(self, identificatorList, fields = None, references = False):
        """
        Fetch information about multiple bulletin identificators

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """

        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, string_types) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return self.__id(identificatorList, references=references, fields=fields or ["*"]).get('documents')

    def references(self, identificator, fields = None):
        """
        Fetch information about bulletin references by identificator

        :param identificator: Bulletin ID. As example - CVE-2017-14174
        :param references: Search for the references in all collections
        :return: bulletin data dict
        """
        results = self.__id(identificator, references=True, fields=fields or self.default_fields)
        return results.get('references', {}).get(identificator, {})

    def referencesList(self, identificatorList, fields = None):
        """
        Fetch information about multiple bulletin references

        :param identificatorList: List of ID's. As example - ["CVE-2017-14174"]
        :return: {'documents':{'id1':{DOC_1}, 'id2':{DOC_2}}}
        """
        if not isinstance(identificatorList, (list,set)) or not all(isinstance(item, string_types) for item in identificatorList):
            raise TypeError('Identificator list is expected to be a list of strings')
        return self.__id(identificatorList, references=True, fields=fields or self.default_fields).get('references')

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
        return self.vulners_get_request('rules', {}).get('rules', {})

    def archive(self, collection, start_date='', end_date=''):
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

    def distributive(self, os, version):
        """
        Get dict with data for OS vulnerability assessment

        :param os: OS name
        :param versin: OS version
        :return: {} vulnerability assessment data
        """
        supported_os = self.suggest("affectedPackage.OS")
        if os.lower() not in [os_name.lower() for os_name in supported_os]:
            raise ValueError("Can't get archive for the unknown OS. Available os: %s" % supported_os)
        zipped_json = self.__distributive(os = os, version = version)
        with ZipFile(BytesIO(zipped_json)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            archive_data = json.loads(zip_file.open(file_name).read())
            return [bulletin['_source'] for bulletin in archive_data]

    def autocomplete(self, query):
        """
        Ask Vulners for possible suggestions to complete your query

        :param query: Vulners Search query, Lucene syntax
        :return: Float score
        """
        suggestions = self.__autocomplete(query).get('suggestions')
        return [suggested_query[0] for suggested_query in suggestions]