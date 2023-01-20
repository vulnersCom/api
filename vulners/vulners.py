import warnings
import zipfile
import io
import json
from .base import VulnersApiBase, ParamError, validate_params
from .base import Endpoint, String, Integer, Dict, List, Tuple, Const, ResultSet, Boolean


class VulnersApi(VulnersApiBase):
    search_size = 100
    default_fields = (
        "id",
        "title",
        "description",
        "type",
        "bulletinFamily",
        "cvss",
        "published",
        "modified",
        "lastseen",
        "href",
        "sourceHref",
        "sourceData",
        "cvelist",
    )

    __search = Endpoint(
        method="post",
        url="/api/v3/search/lucene/",
        params=[
            ("query", String()),
            ("skip", Integer()),
            ("size", Integer()),
            ("fields", Tuple()),
        ],
    )

    @validate_params(
        query=String(),
        limit=Integer(minimum=1, maximum=100),
        offset=Integer(minimum=0, maximum=10000),
        fields=Tuple(item=String()),
    )
    def find(self, query, limit=20, offset=0, fields=default_fields):
        """
        Search in Vulners database.

        query: Vulners query. See https://vulners.com/help for the details.
        limit: The maximum number of documents to return.
        offset: Skip this amount of documents. 10000 is the hard limit.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        end = min(10000, offset + limit)
        if offset >= end:
            return ResultSet.from_dataset(
                [], self.__search(query, 0, 1, ["id"])["total"]
            )
        else:
            search = self.__search(query, offset, limit, fields)
            return ResultSet.from_dataset(
                [e["_source"] for e in search["search"]], search["total"]
            )

    @validate_params(
        query=String(),
        limit=Integer(minimum=1, maximum=10000),
        offset=Integer(minimum=0, maximum=10000),
        fields=Tuple(item=String()),
    )
    def find_all(self, query, limit=20, offset=0, fields=default_fields):
        """
        Search in Vulners database and returns up to 10000 documents.

        query: Vulners query. See https://vulners.com/help for the details.
        limit: The maximum number of documents to return..
        offset: The number of documents to skip in the result set. 10000 is the hard limit.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        end = min(10000, offset + limit)
        if offset >= end:
            return ResultSet.from_dataset(
                [], self.__search(query, 0, 1, ["id"])["total"]
            )
        result = ResultSet()
        batch_size = min(self.search_size, limit)
        for skip in range(offset, end, batch_size):
            chunk = self.__search(query, skip, min(batch_size, end - skip), fields)
            result += [e["_source"] for e in chunk["search"]]
            result.total = chunk["total"]
            if len(chunk["search"]) < batch_size:
                break
        return result

    @validate_params(
        query=String(),
        lookup_fields=Tuple(item=String()),
        limit=Integer(minimum=1, maximum=100),
        offset=Integer(minimum=0, maximum=10000),
        fields=Tuple(item=String()),
    )
    def find_exploit(
        self, query, lookup_fields=None, limit=20, offset=0, fields=default_fields
    ):
        """
        Search in Vulners database for the exploits.

        query: Software name and criteria.
        lookup_fields: Make a strict search using lookup fields. Like ["title"]
        limit: The maximum number of documents to return.
        offset: Skip this amount of documents. 10000 is the hard limit.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        if lookup_fields:
            search_query = "bulletinFamily:exploit AND (%s)" % (
                " OR ".join('%s:"%s"' % (field, query) for field in lookup_fields)
            )
        else:
            search_query = "bulletinFamily:exploit AND %s" % query
        return self.find(search_query, limit, offset, fields)

    @validate_params(
        query=String(),
        lookup_fields=Tuple(item=String()),
        limit=Integer(minimum=1, maximum=100),
        offset=Integer(minimum=0, maximum=10000),
        fields=Tuple(item=String()),
    )
    def find_exploit_all(
        self, query, lookup_fields=None, limit=20, offset=0, fields=default_fields
    ):
        """
        Search in Vulners database for the exploits and returns up to 10000 documents.

        query: Software name and criteria.
        lookup_fields: Make a strict search using lookup fields. Like ["title"]
        limit: The maximum number of documents to return.
        offset: Skip this amount of documents. 10000 is the hard limit.
        fields: List of fields to return.

        Returns list of the documents.
        Use .total to get the total number of found documents.
        """
        if lookup_fields:
            search_query = "bulletinFamily:exploit AND (%s)" % (
                " OR ".join('%s:"%s"' % (field, query) for field in lookup_fields)
            )
        else:
            search_query = "bulletinFamily:exploit AND %s" % query
        return self.find_all(search_query, limit, offset, fields)

    get_web_application_rules = Endpoint(method="get", url="/api/v3/burp/rules/")

    def _get_burp_software_content(content, _):
        result = {}
        # noinspection PyUnresolvedReferences
        for elem in content.get("search", ()):
            elem = elem["_source"]
            result.setdefault(elem["bulletinFamily"], []).append(elem)
        return result

    __get_burp_software = Endpoint(
        method="post",
        url="/api/v3/burp/softwareapi/",
        params=[("software", String()), ("version", String()), ("type", String()), ("exactmatch", Boolean(default=False))],
        content_handler=_get_burp_software_content,
    )

    del _get_burp_software_content

    @validate_params(name=String(), version=String())
    def get_software_vulnerabilities(self, name, version):
        """
        Find software vulnerabilities using name and version.

        name: Software name, e.g. 'httpd'
        version: Software version, e.g. '2.1'
        """
        return self.__get_burp_software(name, version, "software")

    @validate_params(cpe=String())
    def get_cpe_vulnerabilities(self, cpe, exactmatch=False):
        """
        Find software vulnerabilities using CPE string. See CPE references at https://cpe.mitre.org/specification/

        cpe: CPE software string, see https://cpe.mitre.org/specification/
        exactmatch:  if true searches only for bulletins corresponding to the specified minor version and revision
        """
        cpe_split = cpe.split(":")
        if len(cpe_split) <= 4:
            raise ParamError("Malformed %s", "cpe")
        if cpe_split[1] == '2.3':
            version = cpe_split[5]
        elif cpe_split[1] in '/a/o/h':
            version = cpe_split[4]
        else:
            raise ParamError("Malformed %s", "cpe")

        return self.__get_burp_software(cpe, version, "cpe", exactmatch=exactmatch)

    get_multiple_bulletins = Endpoint(
        method="post",
        url="/api/v3/search/id/",
        description="Fetch multiple bulletins by ids.",
        params=[
            (
                "id",
                Tuple(
                    item=String(), description="List of ID's. E.g., ['CVE-2017-14174']"
                ),
            ),
            ("fields", Tuple(item=String(), default=default_fields)),
        ],
        content_handler=lambda c, _: c["documents"],
    )

    @validate_params(id=String(), fields=Tuple(item=String()))
    def get_bulletin(self, id, fields=default_fields):
        """
        Fetch bulletin by id.

        id: Bulletin ID. E.g., "CVE-2017-14174"
        """
        return self.get_multiple_bulletins([id], fields).get(id, {})

    get_multiple_bulletin_references = Endpoint(
        method="post",
        url="/api/v3/search/id/",
        description="",
        params=[
            (
                "id",
                List(
                    item=String(), description="List of ID's. E.g., ['CVE-2017-14174']"
                ),
            ),
            ("fields", Tuple(item=String(), default=default_fields)),
            ("references", Const(True)),
        ],
        content_handler=lambda c, _: c["references"],
    )

    @validate_params(id=String(), fields=Tuple(item=String()))
    def get_bulletin_references(self, id, fields=default_fields):
        """
        Fetch bulletin references by identificator

        identificator: Bulletin ID. E.g., "CVE-2017-14174"
        """
        return self.get_multiple_bulletin_references([id], fields=fields).get(id, {})

    @validate_params(kbid=String())
    def get_kb_seeds(self, kbid):
        """
        Returns superseeds and parentseeds for the given KB.
        Superseeds means "KB which are covered by this KB".
        Parentseeds means "KB which are covering this KB".

        superseeds --> KB --> parentseeds

        kbid: Microsoft KB identificator
        """
        candidate = self.get_bulletin(id=kbid, fields=["superseeds", "parentseeds"])
        return {
            "superseeds": candidate.get("superseeds", []),
            "parentseeds": candidate.get("parentseeds", []),
        }

    @validate_params(kbid=String(), fields=Tuple(item=String()))
    def get_kb_updates(self, kbid, fields=default_fields):
        """
        Returns list of updates for KB.

        kbid: Microsoft KB identificator.
        """
        query = "type:msupdate AND kb:(%s)" % kbid
        return self.find_all(query, limit=1000, fields=fields)

    os_audit = Endpoint(
        method="post",
        url="/api/v3/audit/audit/",
        description=(
            "Linux Audit API for analyzing package vulnerabilities.\n"
            "Accepts RPM and DEB based package lists.\n"
            "For collecting RPM use command: rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\\\n'\n"
            "For collecting DEB use command: dpkg-query -W -f='${Package} ${Version} ${Architecture}\\\\n'\n"
        ),
        params=[
            (
                "os",
                String(
                    description="Full name of the OS. Like Ubuntu, Debian, rhel, oraclelinux"
                ),
            ),
            ("version", String(description="OS version")),
            (
                "packages",
                List(
                    item=String(),
                    description="List of the installed packages",
                    param="package",
                ),
            ),
        ],
    )

    software_audit = Endpoint(
        method="post",
        url="/api/v3/burp/packages/",
        description=(
            "Software audit allow you to analyse software name / version pairs for the CVE's.\n"
            "Packages input format, list of dicts:\n"
            "[{'software': 'Mozilla Firefox', 'version': '80.0.1'}]\n"
        ),
        params=[
            (
                "os",
                String(
                    description="Full name of the OS. Like Ubuntu, Debian, rhel, oraclelinux"
                ),
            ),
            ("version", String(description="OS version", param="osVersion")),
            ("packages", List(item=Dict(), description="List of the software dicts")),
        ],
    )

    kb_audit = Endpoint(
        method="post",
        url="/api/v3/audit/kb/",
        description="Windows KB audit function",
        params=[
            (
                "os",
                String(description="Windows OS name, like 'Windows Server 2012 R2'"),
            ),
            (
                "kb_list",
                List(
                    item=String(),
                    description="List of installed KB's, ['KB2918614', 'KB2918616']",
                    param="kbList",
                ),
            ),
        ],
    )

    winaudit = Endpoint(
        method="post",
        url="/api/v3/audit/winaudit/",
        description="Windows KB and software audit function",
        params=[
            (
                "os",
                String(description="Windows OS name, like 'Windows Server 2012 R2'"),
            ),
            (
                "os_version",
                String(description="Windows OS version, like '10.0.19045'"),
            ),
            (
                "kb_list",
                List(
                    item=String(),
                    description="List of installed KB's, ['KB2918614', 'KB2918616']"
                ),
            ),
            (
                "software",
                List(
                    item=Dict(),
                    description="List of the software dicts, {'software': 'Microsoft Edge', 'version': '107.0.1418.56'}",
                ),
            ),
        ],
    )

    get_suggestion = Endpoint(
        method="post",
        url="/api/v3/search/suggest/",
        params=[("type", Const("distinct")), ("field_name", String(param="fieldName"))],
        content_handler=lambda c, _: c["suggest"],
    )

    get_ai_score = Endpoint(
        method="post",
        url="/api/v3/ai/scoretext/",
        params=[
            ("text", String()),
        ],
        content_handler=lambda c, _: c.get("score", 0),
    )

    query_autocomplete = Endpoint(
        method="post",
        url="/api/v3/search/autocomplete/",
        description="Ask Vulners for possible suggestions to complete your query",
        params=[("query", String(description="Vulners Search query"))],
        content_handler=lambda c, _: [q[0] for q in c["suggestions"]],
    )

    # noinspection PyTypeChecker
    def _unpack_json_file(c, _):
        with zipfile.ZipFile(io.BytesIO(c)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            return json.loads(zip_file.open(file_name).read())

    __archive_collection = Endpoint(
        method="get",
        url="/api/v3/archive/collection/",
        params=[("type", String()), ("datefrom", String()), ("dateto", String())],
        result_type="zipjson",
        content_handler=_unpack_json_file,
    )

    __distributive = Endpoint(
        method="get",
        url="/api/v3/archive/distributive/",
        params=[("os", String()), ("version", String())],
        result_type="zipjson",
        content_handler=_unpack_json_file,
    )

    del _unpack_json_file

    @validate_params(collection=String(), start_date=String(), end_date=String())
    def get_collection(
        self, collection, start_date="1950-01-01", end_date="2199-01-01"
    ):
        """
        Get entire collection data

        :param collection: Collection name
        """
        collections = self.get_suggestion("type")
        if collection not in collections:
            raise ParamError(
                "Unknown %%s. Available values are %s" % (collections,), "collection"
            )
        return self.__archive_collection(
            type=collection, datefrom=start_date, dateto=end_date
        )

    @validate_params(os=String(), version=String())
    def get_distributive(self, os, version):
        """
        Get dict with data for OS vulnerability assessment

        os: OS name
        version: OS version
        """
        supported_os = self.get_suggestion("affectedPackage.OS")
        if os.lower() not in [os_name.lower() for os_name in supported_os]:
            raise ParamError(
                "Unknown %%s. Available values are %s" % (supported_os,), "os"
            )
        data = self.__distributive(os=os, version=version)
        return [bulletin["_source"] for bulletin in data]

    __report = Endpoint(
        method="post",
        url="/api/v3/reports/vulnsreport",
        params=[
            ("reporttype", String(description="One of strings [vulnssummary, vulnslist, ipsummary, scanlist]")),
            ("skip", Integer(description="Skip this amount of items. 10000 is the hard limit")),
            ("size", Integer(description="The maximum number of items to return. 10000 is the hard limit")),
            ("filter", Dict(description="Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}")),
            ("sort", String(description="Field to sort, eg 'severity' or '-severity' to sort desc")),
        ],
        content_handler=lambda x, _: x['report']
    )

    @validate_params(
        limit=Integer(minimum=1, maximum=10000),
        offset=Integer(minimum=0, maximum=10000),
        filter=Dict(),
        sort=String()
    )
    def vulnssummary_report(self, limit=30, offset=0, filter=None, sort=''):
        """
        Get Linux Audit results. Return summary for all found vulnerabilities - id, title, score, severity etc

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'severity' or '-severity' to sort desc
        """

        return self.__report("vulnssummary", offset, limit, filter or {}, sort)

    @validate_params(
        limit=Integer(minimum=1, maximum=10000),
        offset=Integer(minimum=0, maximum=10000),
        filter=Dict(),
        sort=String()
    )
    def vulnslist_report(self, limit=30, offset=0, filter=None, sort=''):
        """
        Get Linux Audit results. Return list of vulnerabilities found on hosts:
            vulnerability id, vulnerability title, vulnerability severity, host information,  etc

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'severity' or '-severity' to sort desc
        """

        return self.__report("vulnslist", offset, limit, filter or {}, sort)

    @validate_params(
        limit=Integer(minimum=1, maximum=10000),
        offset=Integer(minimum=0, maximum=10000),
        filter=Dict(),
        sort=String()
    )
    def ipsummary_report(self, limit=30, offset=0, filter=None, sort=''):
        """
        Get Linux Audit results. Return summary for hosts:
            agent id, host ip, host fqdn, os name and version, found vulnerabilities count and severity

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'total' or '-total' to sort desc
        """

        return self.__report("ipsummary", offset, limit, filter or {}, sort)

    @validate_params(
        limit=Integer(minimum=1, maximum=10000),
        offset=Integer(minimum=0, maximum=10000),
        filter=Dict(),
        sort=String()
    )
    def scanlist_report(self, limit=30, offset=0, filter=None, sort=''):
        """
        Get Linux Audit results. Return list of scans:
           host ip and fqdn, os name and version, scan date, cvss score

        limit: The maximum number of items to return. 10000 is the hard limit.
        offset: Skip this amount of items. 10000 is the hard limit.
        filter: Dict of fields to filter, eg { 'OS': 'Centos', 'OSVersion': '7'}
        sort: Field to sort, eg 'modified' or '-modified' to sort desc
        """

        return self.__report("scanlist", offset, limit, filter or {}, sort)


_Unset = object()


# noinspection PyPep8Naming
class DeprecatedVulnersApi(VulnersApi):
    def __init__(self, *args, **kwargs):
        super(DeprecatedVulnersApi, self).__init__(*args, **kwargs)
        warnings.warn(
            "Vulners is deprecated and will be removed in future release. "
            "Use VulnersApi instead.",
            DeprecationWarning,
        )

    def search(self, query, limit=100, offset=0, fields=None):
        warnings.warn(
            "search() is deprecated and will be removed in future release. "
            "Use VulnersApi.find_all() instead.",
            DeprecationWarning,
        )
        return self.find_all(
            query, limit=limit, offset=offset, fields=fields or self.default_fields
        )

    def searchPage(self, query, pageSize=20, offset=0, fields=None):
        warnings.warn(
            "searchPage() is deprecated and will be removed in future release. "
            "Use VulnersApi.find() instead.",
            DeprecationWarning,
        )
        return self.find(
            query, limit=pageSize, offset=offset, fields=fields or self.default_fields
        )

    def searchExploit(
        self, query, lookup_fields=None, limit=100, offset=0, fields=None
    ):
        warnings.warn(
            "searchExploit() is deprecated and will be removed in future release. "
            "Use VulnersApi.find_exploit_all() instead.",
            DeprecationWarning,
        )
        lookup_fields = lookup_fields or ()
        if isinstance(lookup_fields, (set, list)):
            lookup_fields = tuple(lookup_fields)
        return self.find_exploit_all(
            query,
            lookup_fields=lookup_fields,
            limit=limit,
            offset=offset,
            fields=fields or self.default_fields,
        )

    def searchExploitPage(
        self, query, lookup_fields=None, limit=100, offset=0, fields=None
    ):
        warnings.warn(
            "searchExploitPage() is deprecated and will be removed in future release. "
            "Use VulnersApi.find_exploit() instead.",
            DeprecationWarning,
        )
        lookup_fields = lookup_fields or ()
        if isinstance(lookup_fields, (set, list)):
            lookup_fields = tuple(lookup_fields)
        return self.find_exploit(
            query,
            lookup_fields=lookup_fields,
            limit=limit,
            offset=offset,
            fields=fields or self.default_fields,
        )

    def softwareVulnerabilities(self, name, version, maxVulnerabilities=_Unset):
        warnings.warn(
            "softwareVulnerabilities() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_software_vulnerabilities() instead.",
            DeprecationWarning,
        )
        if maxVulnerabilities is not _Unset:
            warnings.warn(
                "maxVulnerabilities is deprecated and will be removed in future release.",
                DeprecationWarning,
            )
        return self.get_software_vulnerabilities(name, version)

    def cpeVulnerabilities(self, cpeString, maxVulnerabilities=_Unset):
        warnings.warn(
            "cpeVulnerabilities() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_cpe_vulnerabilities() instead.",
            DeprecationWarning,
        )
        if maxVulnerabilities is not _Unset:
            warnings.warn(
                "maxVulnerabilities is deprecated and will be removed in future release.",
                DeprecationWarning,
            )
        return self.get_cpe_vulnerabilities(cpeString)

    def audit(self, os, os_version, package):
        warnings.warn(
            "audit() is deprecated and will be removed in future release. "
            "Use VulnersApi.os_audit() instead.",
            DeprecationWarning,
        )
        return self.os_audit(os, os_version, package)

    def kbAudit(self, os, kb_list):
        warnings.warn(
            "kbAudit() is deprecated and will be removed in future release. "
            "Use VulnersApi.kb_audit() instead.",
            DeprecationWarning,
        )
        return self.kb_audit(os, kb_list)

    def document(self, identificator, fields=None):
        warnings.warn(
            "document() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_bulletin() instead.",
            DeprecationWarning,
        )
        return self.get_bulletin(identificator, fields=fields or self.default_fields)

    def documentList(self, identificatorList, fields=None):
        warnings.warn(
            "documentList() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_multiple_bulletins() instead.",
            DeprecationWarning,
        )
        return self.get_multiple_bulletins(
            identificatorList, fields=fields or self.default_fields
        )

    def references(self, identificator, fields=None):
        warnings.warn(
            "references() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_bulletin_references() instead.",
            DeprecationWarning,
        )
        return self.get_bulletin_references(
            identificator, fields=fields or self.default_fields
        )

    def referencesList(self, identificatorList, fields=None):
        warnings.warn(
            "referencesList() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_multiple_bulletin_references() instead.",
            DeprecationWarning,
        )
        return self.get_multiple_bulletin_references(
            identificatorList, fields=fields or self.default_fields
        )

    def collections(self):
        warnings.warn(
            "collections() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_suggestion('type') instead.",
            DeprecationWarning,
        )
        return self.get_suggestion("type")

    def suggest(self, field_name):
        warnings.warn(
            "suggest() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_suggestion() instead.",
            DeprecationWarning,
        )
        return self.get_suggestion(field_name)

    def aiScore(self, text):
        warnings.warn(
            "aiScore() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_ai_score() instead.",
            DeprecationWarning,
        )
        return self.get_ai_score(text)

    def rules(self):
        warnings.warn(
            "rules() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_web_application_rules() instead.",
            DeprecationWarning,
        )
        return self.get_web_application_rules()

    def kbSuperseeds(self, kb_identificator):
        warnings.warn(
            "kbSuperseeds() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_kb_seeds() instead.",
            DeprecationWarning,
        )
        return self.get_kb_seeds(kb_identificator)

    def kbUpdates(self, kb_identificator, fields=None):
        warnings.warn(
            "kbUpdates() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_kb_updates() instead.",
            DeprecationWarning,
        )
        return self.get_kb_updates(
            kb_identificator, fields=fields or self.default_fields
        )

    def autocomplete(self, query):
        warnings.warn(
            "autocomplete() is deprecated and will be removed in future release. "
            "Use VulnersApi.query_autocomplete() instead.",
            DeprecationWarning,
        )
        return self.query_autocomplete(query)

    def archive(self, collection, start_date="1950-01-01", end_date="2199-01-01"):
        warnings.warn(
            "archive() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_collection() instead.",
            DeprecationWarning,
        )
        return self.get_collection(collection, start_date, end_date)

    def distributive(self, os, version):
        warnings.warn(
            "distributive() is deprecated and will be removed in future release. "
            "Use VulnersApi.get_distributive() instead.",
            DeprecationWarning,
        )
        return self.get_distributive(os, version)


Vulners = DeprecatedVulnersApi
